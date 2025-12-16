import os
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

from .models import db, User, Subject, Note


# ✅ Solo TXT para IA (estable)
ALLOWED_EXTENSIONS = {"txt"}

# ✅ Límite duro de subida (bytes)
MAX_UPLOAD_BYTES = 250 * 1024  # 250 KB

# ✅ Límite de texto que mandamos al modelo (caracteres)
MAX_TEXT_CHARS = 30_000


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def fetch_models(app):
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    try:
        resp = requests.get(f"{api_base}/models", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        all_ids = [m["id"] for m in data.get("data", [])]
        models = [mid for mid in all_ids if not mid.startswith("text-embedding-")]

        return models or [app.config["LMSTUDIO_MODEL"]]
    except Exception:
        return [app.config["LMSTUDIO_MODEL"]]


def lmstudio_summarize_text(app, model: str, subject: str, title: str, exam_date: str, filename: str, text: str) -> str:
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    timeout_s = app.config["LMSTUDIO_TIMEOUT"]

    system_prompt = (
        "Eres un profesor experto. Devuelve apuntes con la información clave "
        "en español, en formato de viñetas (bullet points) y con estructura clara. "
        "No inventes información. No incluyas introducción ni despedida."
    )

    user_prompt = (
        f"Asignatura: {subject}\n"
        f"Título: {title}\n"
        f"Fecha de examen: {exam_date}\n"
        f"Archivo: {filename}\n\n"
        "TEXTO A RESUMIR:\n"
        f"{text}"
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

    # --- Config LM Studio ---
    app.config["LMSTUDIO_API_BASE"] = os.getenv("LMSTUDIO_API_BASE", "http://127.0.0.1:1234/v1")
    app.config["LMSTUDIO_MODEL"] = os.getenv("LMSTUDIO_MODEL", "google/gemma-3-1b")
    app.config["LMSTUDIO_TIMEOUT"] = int(os.getenv("LMSTUDIO_TIMEOUT", "300"))

    # --- Config app / DB ---
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///app.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ✅ límite duro por Flask/Werkzeug (para subidas)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    # --- Extensiones ---
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()

    # ---------- Auth ----------

    @app.route("/", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            user = User.query.filter_by(username=username).first()

            if user and password and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for("dashboard"))

            flash("Usuario o contraseña incorrectos.", "error")
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

            hashed_pw = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
            new_user = User(username=username, password_hash=hashed_pw)
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

    # ---------- API: fechas existentes por asignatura ----------

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
            db.session.query(Note.exam_date)
            .filter(
                Note.user_id == current_user.id,
                Note.subject_id == subject_id,
                Note.exam_date.isnot(None),
            )
            .distinct()
            .order_by(Note.exam_date.asc())
            .all()
        )
        dates = [r[0].isoformat() for r in rows if r[0] is not None]
        return jsonify({"dates": dates})

    # ---------- API: títulos existentes por asignatura ----------

    @app.route("/api/titles")
    @login_required
    def api_titles():
        subject_id = request.args.get("subject_id", type=int)
        if not subject_id:
            return jsonify({"titles": []})

        subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
        if not subject:
            return jsonify({"titles": []})

        rows = (
            db.session.query(Note.title)
            .filter(Note.user_id == current_user.id, Note.subject_id == subject_id)
            .distinct()
            .order_by(Note.title.asc())
            .all()
        )
        titles = [r[0] for r in rows if r[0]]
        return jsonify({"titles": titles})

    # ---------- Ask Profe (lo dejamos tal cual si ya lo tenías) ----------

    @app.route("/ask-profe", methods=["GET", "POST"])
    @login_required
    def ask_profe():
        available_models = fetch_models(app)
        selected_model = app.config["LMSTUDIO_MODEL"]
        messages = []

        if request.method == "POST":
            selected_model = request.form.get("model") or selected_model
            question = request.form.get("question", "").strip()

            if question:
                try:
                    payload = {
                        "model": selected_model,
                        "messages": [
                            {"role": "system", "content": "Actúa como un profesor paciente y claro. Responde de forma concisa"},
                            {"role": "user", "content": question},
                        ],
                        "temperature": 0.7,
                    }

                    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
                    resp = requests.post(
                        f"{api_base}/chat/completions",
                        json=payload,
                        timeout=app.config["LMSTUDIO_TIMEOUT"],
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    answer = data["choices"][0]["message"]["content"]

                    messages = [
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer},
                    ]

                except Timeout:
                    flash("El modelo tardó demasiado en responder.", "error")
                    return redirect(url_for("dashboard"))
                except RequestException:
                    flash("No he podido conectar con LM Studio. ¿Está encendido?", "error")
                    return redirect(url_for("dashboard"))
                except Exception:
                    flash("Error inesperado procesando tu pregunta.", "error")
                    return redirect(url_for("dashboard"))

        return render_template(
            "ask_profe.html",
            messages=messages,
            models=available_models,
            selected_model=selected_model,
        )

    # ---------- Subir apuntes / Generar resumen (TXT o manual) ----------

    @app.route("/add-notes", methods=["GET", "POST"])
    @login_required
    def add_notes():
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()

        available_models = fetch_models(app)
        selected_model = app.config["LMSTUDIO_MODEL"]

        if request.method == "POST":
            selected_model = request.form.get("model") or selected_model

            # ---- Asignatura ----
            subject_choice = (request.form.get("subject_choice") or "").strip()
            new_subject_name = (request.form.get("new_subject_name") or "").strip()

            if subject_choice == "__new__":
                if not new_subject_name:
                    flash("Escribe el nombre de la nueva asignatura.", "error")
                    return redirect(url_for("add_notes"))

                subject = Subject.query.filter_by(user_id=current_user.id, name=new_subject_name).first()
                if not subject:
                    subject = Subject(user_id=current_user.id, name=new_subject_name)
                    db.session.add(subject)
                    db.session.commit()
            else:
                try:
                    subject_id = int(subject_choice)
                except ValueError:
                    flash("Selecciona una asignatura válida.", "error")
                    return redirect(url_for("add_notes"))

                subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
                if not subject:
                    flash("Asignatura inválida.", "error")
                    return redirect(url_for("add_notes"))

            # ---- Título (identificador) ----
            title = (request.form.get("title") or "").strip()
            if not title:
                flash("El título es obligatorio.", "error")
                return redirect(url_for("add_notes"))

            # ---- Fecha evaluación ----
            exam_str = (
                (request.form.get("exam_date_manual") or "").strip()
                or (request.form.get("exam_date_choice") or "").strip()
            )

            exam_date = None
            if exam_str:
                try:
                    exam_date = datetime.strptime(exam_str, "%Y-%m-%d").date()
                except ValueError:
                    flash("Formato de fecha inválido. Usa YYYY-MM-DD.", "error")
                    return redirect(url_for("add_notes"))

            # ---- Modo manual (sin IA) ----
            manual_text = (request.form.get("manual_text") or "").strip()
            manual_mode = request.form.get("manual_mode") == "on"

            if manual_mode:
                if not manual_text:
                    flash("Si eliges modo manual, debes escribir el contenido.", "error")
                    return redirect(url_for("add_notes"))

                note = Note(
                    user_id=current_user.id,
                    subject_id=subject.id,
                    title=title,
                    exam_date=exam_date,
                    original_filename=None,
                    content=manual_text,
                    ai_used=False,
                )
                db.session.add(note)
                db.session.commit()

                flash("Apuntes guardados (manual) ✅", "success")
                return redirect(url_for("dashboard"))

            # ---- Si NO manual, usamos TXT + IA ----
            upload = request.files.get("file")
            if not upload or not upload.filename:
                flash("Selecciona un archivo .txt o usa modo manual.", "error")
                return redirect(url_for("add_notes"))

            if not allowed_file(upload.filename):
                flash("Solo se permiten archivos .txt (o usa modo manual).", "error")
                return redirect(url_for("add_notes"))

            filename = secure_filename(upload.filename)
            file_bytes = upload.read()

            if not file_bytes:
                flash("El archivo está vacío.", "error")
                return redirect(url_for("add_notes"))

            if len(file_bytes) > MAX_UPLOAD_BYTES:
                flash(f"Archivo demasiado grande. Máximo {MAX_UPLOAD_BYTES // 1024} KB.", "error")
                return redirect(url_for("add_notes"))

            try:
                text = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = file_bytes.decode("utf-8", errors="ignore")

            text = text.strip()
            if not text:
                flash("El TXT no contiene texto legible.", "error")
                return redirect(url_for("add_notes"))

            if len(text) > MAX_TEXT_CHARS:
                text = text[:MAX_TEXT_CHARS]

            try:
                exam_date_str = exam_date.isoformat() if exam_date else "No indicada"
                content = lmstudio_summarize_text(
                    app,
                    selected_model,
                    subject.name,
                    title,
                    exam_date_str,
                    filename,
                    text,
                )
            except Timeout:
                flash("El modelo tardó demasiado en responder.", "error")
                return redirect(url_for("dashboard"))
            except RequestException:
                flash("No he podido conectar con LM Studio. ¿Está encendido?", "error")
                return redirect(url_for("dashboard"))
            except Exception:
                flash("Error inesperado generando el resumen.", "error")
                return redirect(url_for("dashboard"))

            if not content.strip():
                flash("El modelo devolvió un resumen vacío.", "error")
                return redirect(url_for("add_notes"))

            note = Note(
                user_id=current_user.id,
                subject_id=subject.id,
                title=title,
                exam_date=exam_date,
                original_filename=filename,
                content=content,
                ai_used=True,
            )
            db.session.add(note)
            db.session.commit()

            flash("Resumen guardado correctamente ✅", "success")
            return redirect(url_for("dashboard"))

        return render_template(
            "add_notes.html",
            subjects=subjects,
            models=available_models,
            selected_model=selected_model,
            max_kb=MAX_UPLOAD_BYTES // 1024,
            max_chars=MAX_TEXT_CHARS,
        )

    # ---------- Consultar apuntes (listado + filtros) ----------

    @app.route("/notes")
    @login_required
    def notes_list():
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()

        subject_id = request.args.get("subject_id", type=int)
        exam_date_str = (request.args.get("exam_date") or "").strip()
        title_q = (request.args.get("title") or "").strip()

        q = Note.query.filter_by(user_id=current_user.id)

        if subject_id:
            q = q.filter(Note.subject_id == subject_id)

        if exam_date_str:
            try:
                d = datetime.strptime(exam_date_str, "%Y-%m-%d").date()
                q = q.filter(Note.exam_date == d)
            except ValueError:
                flash("Formato de fecha inválido (YYYY-MM-DD).", "error")

        if title_q:
            q = q.filter(Note.title.ilike(f"%{title_q}%"))

        notes = q.order_by(Note.updated_at.desc()).all()

        return render_template(
            "notes_list.html",
            subjects=subjects,
            notes=notes,
            filters={
                "subject_id": subject_id or "",
                "exam_date": exam_date_str,
                "title": title_q,
            },
        )

    # ---------- Editar apunte ----------

    @app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
    @login_required
    def note_edit(note_id: int):
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()

        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()

        if request.method == "POST":
            # Subject (puede cambiarse)
            subject_id = request.form.get("subject_id", type=int)
            subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
            if not subject:
                flash("Asignatura inválida.", "error")
                return redirect(url_for("note_edit", note_id=note.id))

            title = (request.form.get("title") or "").strip()
            if not title:
                flash("El título es obligatorio.", "error")
                return redirect(url_for("note_edit", note_id=note.id))

            exam_date_str = (request.form.get("exam_date") or "").strip()
            exam_date = None
            if exam_date_str:
                try:
                    exam_date = datetime.strptime(exam_date_str, "%Y-%m-%d").date()
                except ValueError:
                    flash("Formato de fecha inválido (YYYY-MM-DD).", "error")
                    return redirect(url_for("note_edit", note_id=note.id))

            content = (request.form.get("content") or "").strip()
            if not content:
                flash("El contenido no puede estar vacío.", "error")
                return redirect(url_for("note_edit", note_id=note.id))

            note.subject_id = subject.id
            note.title = title
            note.exam_date = exam_date
            note.content = content
            # si lo editas a mano, ya es manual “de facto”
            note.ai_used = False
            note.original_filename = None

            db.session.commit()
            flash("Apunte actualizado ✅", "success")
            return redirect(url_for("notes_list"))

        return render_template("note_edit.html", note=note, subjects=subjects)

    # ---------- Borrar apunte ----------

    @app.route("/notes/<int:note_id>/delete", methods=["POST"])
    @login_required
    def note_delete(note_id: int):
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
        db.session.delete(note)
        db.session.commit()
        flash("Apunte borrado ✅", "success")
        return redirect(url_for("notes_list"))

    return app


app = create_app()
