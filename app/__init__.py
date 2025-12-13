import os
import base64
from datetime import datetime

import requests
from requests.exceptions import Timeout, RequestException
from werkzeug.utils import secure_filename

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .models import db, User, Subject, Notes


ALLOWED_EXTENSIONS = {"txt", "pdf"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def fetch_models(app):
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    try:
        resp = requests.get(f"{api_base}/models", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        models = [m.get("id") for m in data.get("data", []) if m.get("id")]
        models = [mid for mid in models if not mid.startswith("text-embedding-")]
        return models or [app.config["LMSTUDIO_MODEL"]]
    except Exception:
        return [app.config["LMSTUDIO_MODEL"]]


def lmstudio_summarize_file(
    app,
    model: str,
    subject: str,
    exam_date: str,
    filename: str,
    file_bytes: bytes,
) -> str:
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    timeout_s = app.config["LMSTUDIO_TIMEOUT"]

    encoded = base64.b64encode(file_bytes).decode("ascii")

    system_prompt = (
        "Eres un profesor experto. A partir del archivo proporcionado, "
        "genera apuntes claros, concisos y orientados a examen. "
        "Devuelve SOLO viñetas (bullet points), sin introducción."
    )

    user_prompt = (
        f"Asignatura: {subject}\n"
        f"Fecha de examen: {exam_date}\n"
        f"Nombre del archivo: {filename}\n\n"
        "El siguiente contenido es un archivo codificado en base64. "
        "Léelo y extrae los apuntes más importantes.\n\n"
        f"ARCHIVO_BASE64:\n{encoded}"
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
    }

    resp = requests.post(
        f"{api_base}/chat/completions",
        json=payload,
        timeout=timeout_s,
    )
    resp.raise_for_status()

    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def create_app():
    app = Flask(__name__)

    # ---------- Config ----------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "SQLALCHEMY_DATABASE_URI", "sqlite:///app.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["LMSTUDIO_API_BASE"] = os.getenv(
        "LMSTUDIO_API_BASE", "http://127.0.0.1:1234/v1"
    )
    app.config["LMSTUDIO_MODEL"] = os.getenv("LMSTUDIO_MODEL", "google/gemma-3-1b")
    app.config["LMSTUDIO_TIMEOUT"] = int(os.getenv("LMSTUDIO_TIMEOUT", "300"))

    app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB

    # ---------- Init ----------
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()

    # ---------- Error handler global (sin bucles) ----------
    @app.errorhandler(500)
    def internal_error(_error):
        try:
            flash(
                "Lo siento, ha ocurrido un error interno. Inténtalo de nuevo.",
                "error",
            )
        except Exception:
            pass

        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    # ---------- Auth ----------
    @app.route("/", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for("dashboard"))

            flash("Usuario o contraseña incorrectos", "error")

        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            if not username or not password:
                flash("Rellena usuario y contraseña.", "error")
                return redirect(url_for("register"))

            existing = User.query.filter_by(username=username).first()
            if existing:
                flash("Ese usuario ya existe.", "error")
                return redirect(url_for("register"))

            pw_hash = generate_password_hash(password, method="pbkdf2:sha256")
            new_user = User(username=username, password_hash=pw_hash)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("dashboard"))

        return render_template("register.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    # ---------- Dashboard ----------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", username=current_user.username)

    # ---------- API: exam dates for a subject ----------
    @app.route("/api/exam-dates")
    @login_required
    def api_exam_dates():
        subject_id = request.args.get("subject_id", type=int)
        if not subject_id:
            return jsonify({"dates": []})

        subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
        if not subject:
            return jsonify({"dates": []})

        rows = (
            db.session.query(Notes.exam_date)
            .filter(
                Notes.user_id == current_user.id,
                Notes.subject_id == subject_id,
                Notes.exam_date.isnot(None),
            )
            .distinct()
            .order_by(Notes.exam_date.asc())
            .all()
        )
        dates = [d[0].isoformat() for d in rows if d[0] is not None]
        return jsonify({"dates": dates})

    # ---------- Add Notes ----------
    @app.route("/add-notes", methods=["GET", "POST"])
    @login_required
    def add_notes():
        subjects = (
            Subject.query.filter_by(user_id=current_user.id)
            .order_by(Subject.name.asc())
            .all()
        )

        models = fetch_models(app)
        selected_model = app.config["LMSTUDIO_MODEL"]

        if request.method == "POST":
            selected_model = request.form.get("model") or selected_model
            upload = request.files.get("file")

            if not upload or not upload.filename:
                flash("Selecciona un archivo", "error")
                return redirect(url_for("add_notes"))

            if not allowed_file(upload.filename):
                flash("Formato no permitido (solo TXT o PDF)", "error")
                return redirect(url_for("add_notes"))

            # ---------- Asignatura ----------
            subject_choice = (request.form.get("subject_choice") or "").strip()
            new_subject_name = (request.form.get("new_subject_name") or "").strip()

            if subject_choice == "__new__":
                if not new_subject_name:
                    flash("Escribe el nombre de la asignatura", "error")
                    return redirect(url_for("add_notes"))

                subject = Subject.query.filter_by(
                    user_id=current_user.id, name=new_subject_name
                ).first()

                if not subject:
                    subject = Subject(user_id=current_user.id, name=new_subject_name)
                    db.session.add(subject)
                    db.session.commit()
            else:
                try:
                    subject_id = int(subject_choice)
                except ValueError:
                    flash("Selecciona una asignatura válida", "error")
                    return redirect(url_for("add_notes"))

                subject = Subject.query.filter_by(
                    id=subject_id, user_id=current_user.id
                ).first()

                if not subject:
                    flash("Asignatura inválida", "error")
                    return redirect(url_for("add_notes"))

            # ---------- Fecha ----------
            exam_str = (
                (request.form.get("exam_date_manual") or "").strip()
                or (request.form.get("exam_date_choice") or "").strip()
            )

            exam_date = None
            if exam_str:
                try:
                    exam_date = datetime.strptime(exam_str, "%Y-%m-%d").date()
                except ValueError:
                    flash("Formato de fecha inválido (YYYY-MM-DD)", "error")
                    return redirect(url_for("add_notes"))

            # ---------- Archivo ----------
            filename = secure_filename(upload.filename)
            file_bytes = upload.read()

            try:
                summary = lmstudio_summarize_file(
                    app,
                    selected_model,
                    subject.name,
                    exam_date.isoformat() if exam_date else "No indicada",
                    filename,
                    file_bytes,
                )
            except Timeout:
                flash("El modelo tardó demasiado en responder", "error")
                return redirect(url_for("dashboard"))
            except RequestException:
                flash("No se puede conectar con LM Studio", "error")
                return redirect(url_for("dashboard"))
            except Exception:
                flash("Error generando apuntes", "error")
                return redirect(url_for("dashboard"))

            if not summary:
                flash("No se pudieron generar apuntes útiles con ese archivo.", "error")
                return redirect(url_for("add_notes"))

            note = Notes(
                user_id=current_user.id,
                subject_id=subject.id,
                exam_date=exam_date,
                source_filename=filename,
                summary=summary,
            )
            db.session.add(note)
            db.session.commit()

            flash("Apuntes guardados correctamente ✅", "success")
            return redirect(url_for("dashboard"))

        return render_template(
            "add_notes.html",
            subjects=subjects,
            models=models,
            selected_model=selected_model,
        )

    return app


app = create_app()
