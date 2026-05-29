import os
import time
import threading
import tempfile
import fcntl

from werkzeug.exceptions import RequestEntityTooLarge
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from flask import Flask, request, redirect, url_for, flash, session
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, current_user

from .extensions import limiter, migrate
from .core.file_extraction import MAX_UPLOAD_BYTES
from .services.llm_client import LLMClient
from .services.job_service import JOB_RETRY_SECONDS, process_job
from .models import db, User, Job
from .utils import get_active_profe_lock, is_setup_complete, profe_is_busy, queue_has_work, utcnow

# evita arrancar dos workers en procesos reloader
_worker_started = False
_worker_lock_handle = None


def create_app(config=None):
    from .config import config_from_env
    app = Flask(__name__)
    app.config.from_object(config or config_from_env())

    os.makedirs(app.instance_path, exist_ok=True)
    upload_dir = os.getenv("UPLOAD_DIR") or os.path.join(app.instance_path, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    app.config["UPLOAD_DIR"] = upload_dir

    # LM Studio
    app.config["LMSTUDIO_API_BASE"] = os.getenv("LMSTUDIO_API_BASE", "http://127.0.0.1:1234/v1")
    app.config["LMSTUDIO_MODEL"] = os.getenv("LMSTUDIO_MODEL", "google/gemma-3-1b")
    app.config["LMSTUDIO_TIMEOUT"] = int(os.getenv("LMSTUDIO_TIMEOUT", "300"))
    app.config["ASK_PROFE_SESSION_SECONDS"] = int(os.getenv("ASK_PROFE_SESSION_SECONDS", "300"))

    # App/DB
    _secret = os.getenv("SECRET_KEY")
    if not _secret:
        _secret_file = os.getenv("SECRET_KEY_FILE", "/run/secrets/secret_key")
        if os.path.exists(_secret_file):
            with open(_secret_file) as _f:
                _secret = _f.read().strip()
    if not _secret:
        import secrets as _secrets
        import warnings
        _secret = _secrets.token_hex(32)
        warnings.warn(
            "SECRET_KEY not set — using ephemeral key. All sessions will reset on restart.",
            stacklevel=2,
        )
    app.config["SECRET_KEY"] = _secret
    db_uri = os.getenv("SQLALCHEMY_DATABASE_URI")
    if not db_uri:
        _db_host = os.getenv("DB_HOST")
        if _db_host:
            _pw = ""
            _pw_file = os.getenv("DB_PASSWORD_FILE")
            if _pw_file and os.path.exists(_pw_file):
                with open(_pw_file) as _f:
                    _pw = _f.read().strip()
            _db_user = os.getenv("DB_USER", "postgres")
            _db_port = os.getenv("DB_PORT", "5432")
            _db_name = os.getenv("DB_NAME", "postgres")
            db_uri = f"postgresql+psycopg2://{_db_user}:{_pw}@{_db_host}:{_db_port}/{_db_name}"
        else:
            db_uri = "sqlite:///app.db"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
    if db_uri.startswith("sqlite"):
        engine_options = app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {})
        connect_args = engine_options.setdefault("connect_args", {})
        connect_args.setdefault("timeout", 30)
        connect_args.setdefault("check_same_thread", False)

        @event.listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA busy_timeout=30000;")
            cursor.close()
    else:
        engine_options = app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {})
        engine_options.setdefault("pool_pre_ping", True)

    db.init_app(app)
    migrate.init_app(app, db)

    app.extensions["llm_client"] = LLMClient(
        api_base=app.config["LMSTUDIO_API_BASE"],
        timeout=app.config["LMSTUDIO_TIMEOUT"],
    )

    CSRFProtect(app)
    limiter.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @app.errorhandler(429)
    def ratelimit_handler(e):
        flash("Demasiados intentos. Espera un momento antes de volver a intentarlo.", "danger")
        return redirect(request.referrer or url_for("login")), 429

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_error):
        max_kb = (app.config.get("MAX_CONTENT_LENGTH") or MAX_UPLOAD_BYTES) // 1024
        flash(f"Archivo demasiado grande. Máximo {max_kb} KB.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    @app.context_processor
    def inject_login_flag():
        just_logged_in = session.pop("just_logged_in", None)
        just_registered = session.pop("just_registered", None)
        return {"just_logged_in": bool(just_logged_in), "just_registered": bool(just_registered)}

    @app.context_processor
    def inject_profe_busy_flag():
        if not current_user.is_authenticated:
            return {"profe_busy": False, "llm_busy": False}
        return {"profe_busy": profe_is_busy(current_user.id), "llm_busy": queue_has_work()}

    @app.context_processor
    def inject_deck_helpers():
        def deck_display_title(title: str | None, exam_date) -> str:
            if not title:
                return ""
            if exam_date:
                suffix = f" ({exam_date})"
                if title.endswith(suffix):
                    return title[: -len(suffix)].rstrip()
            return title

        return {"deck_display_title": deck_display_title}

    @app.before_request
    def enforce_setup_completion():
        endpoint = request.endpoint or ""
        # request.endpoint is the blueprint-prefixed name (e.g. "auth.setup");
        # strip the prefix for the allow-list check.
        short_endpoint = endpoint.split(".", 1)[-1]
        if short_endpoint in ("login", "register", "logout", "setup", "static"):
            return None
        if not current_user.is_authenticated:
            return None
        if not is_setup_complete(current_user.id):
            return redirect(url_for("setup"))
        return None

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def acquire_process_lock(name: str, blocking: bool = True):
        lock_path = os.path.join(tempfile.gettempdir(), name)
        lock_file = open(lock_path, "a+")
        flags = fcntl.LOCK_EX
        if not blocking:
            flags |= fcntl.LOCK_NB
        try:
            fcntl.flock(lock_file.fileno(), flags)
        except BlockingIOError:
            lock_file.close()
            return None
        return lock_file

    with app.app_context():
        global _worker_started, _worker_lock_handle
        if not _worker_started:
            if _worker_lock_handle is None:
                _worker_lock_handle = acquire_process_lock("flask-devops-demo-worker.lock", blocking=False)
            if _worker_lock_handle:
                def worker_loop():
                    retry_job_id = None
                    retry_at = None
                    while True:
                        with app.app_context():
                            try:
                                if get_active_profe_lock():
                                    time.sleep(2)
                                    continue

                                job = None
                                if retry_job_id:
                                    now = time.time()
                                    if retry_at and now < retry_at:
                                        time.sleep(min(2, retry_at - now))
                                        continue
                                    job = Job.query.filter_by(id=retry_job_id).first()
                                    if not job:
                                        retry_job_id = None
                                        retry_at = None
                                        time.sleep(1)
                                        continue
                                if not job:
                                    job = (
                                        Job.query.filter_by(status="pending")
                                        .order_by(Job.created_at.asc(), Job.id.asc())
                                        .first()
                                    )
                                    if not job:
                                        time.sleep(2)
                                        continue

                                job.status = "running"
                                db.session.commit()

                                status, msg, err = process_job(app, job)
                                db.session.refresh(job)
                                if job.status == "cancelled":
                                    retry_job_id = None
                                    retry_at = None
                                    continue
                                if status == "error":
                                    job.status = "pending"
                                    job.result_message = None
                                    job.error_message = err
                                    job.updated_at = utcnow()
                                    db.session.commit()
                                    retry_job_id = job.id
                                    retry_at = time.time() + JOB_RETRY_SECONDS
                                    continue

                                job.status = status
                                job.result_message = msg
                                job.error_message = err
                                job.updated_at = utcnow()
                                db.session.commit()
                                retry_job_id = None
                                retry_at = None
                            except OperationalError as exc:
                                db.session.rollback()
                                if "database is locked" in str(exc).lower():
                                    time.sleep(1.5)
                                    continue
                                app.logger.exception("Database error in worker loop")
                                time.sleep(2)
                                continue
                        time.sleep(0.5)

                threading.Thread(target=worker_loop, daemon=True).start()
                _worker_started = True

    from .blueprints.auth import auth_bp
    from .blueprints.main import main_bp
    from .blueprints.calendar import calendar_bp
    from .blueprints.options import options_bp
    from .blueprints.api import api_bp
    from .blueprints.profe import profe_bp
    from .blueprints.notes import notes_bp
    from .blueprints.flashcards import flashcards_bp
    from .blueprints.challenge import challenge_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(calendar_bp)
    app.register_blueprint(options_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(profe_bp)
    app.register_blueprint(notes_bp)
    app.register_blueprint(flashcards_bp)
    app.register_blueprint(challenge_bp)

    # Register short endpoint aliases so url_for("login") works alongside url_for("auth.login").
    # Blueprints prefix every endpoint with "<blueprint_name>.", which would break templates and
    # flask-login's login_view. We copy each prefixed rule/view under its bare name so both forms
    # resolve correctly, without touching any template or url_for() call site.
    for rule in list(app.url_map.iter_rules()):
        if "." in rule.endpoint:
            short = rule.endpoint.split(".", 1)[1]
            if short not in app.view_functions:
                app.add_url_rule(
                    rule.rule,
                    endpoint=short,
                    view_func=app.view_functions[rule.endpoint],
                    methods=rule.methods,
                )

    return app


app = create_app()
