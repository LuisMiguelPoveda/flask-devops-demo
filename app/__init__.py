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

from .models import db, User, Subject, Note


def fetch_models(app):
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    try:
        resp = requests.get(f"{api_base}/models", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        all_ids = [m["id"] for m in data.get("data", [])]
        models = [mid for mid in all_ids if not mid.startswith("text-embedding-")]

        if not models:
            models = [app.config["LMSTUDIO_MODEL"]]

        return models
    except Exception:
        return [app.config["LMSTUDIO_MODEL"]]


def lmstudio_summarize_file(app, model: str, subject: str, exam_date: str, filename: str, file_bytes: bytes) -> str:
    """
    Sin preprocesado: enviamos el archivo tal cual (base64 dentro del prompt).
    El modelo se encarga de leerlo.
    """
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    timeout_s = app.config["LMSTUDIO_TIMEOUT"]

    b64 = base64.b64encode(file_bytes).decode("ascii")

    system_prompt = (
        "Eres un profesor experto. Devuelve un resumen con la información clave, "
        "en español, en formato de viñetas (bullet points) y con estructura clara. "
        "No inventes información. No incluyas introducciones ni despedidas."
    )

    user_prompt = (
        f"Asignatura: {subject}\n"
        f"Fecha de evaluación: {exam_date}\n"
        f"Nombre del archivo: {filename}\n\n"
        "El siguiente contenido es un archivo codificado en base64. "
        "Léelo (según su tipo) y genera un resumen con lo más importante.\n\n"
        f"ARCHIVO_BASE64:\n{b64}"
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

    # opcional: límite de subida (20MB)
    app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

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

    # ---------- Rutas ----------

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

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", username=current_user.username)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

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
                            {
                                "role": "system",
                                "content": "Actúa como un profesor paciente y claro. Responde de forma concisa",
                            },
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
                    flash("Lo siento, el modelo ha tardado demasiado en responder.", "error")
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

    # -------- API fechas de evaluación existentes por asignatura --------
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

    # -------- Generar resumen / Añadir apuntes --------
    @app.route("/add-notes", methods=["GET", "POST"])
    @login_required
    def add_notes():
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
        available_models = fetch_models(app)
        selected_model = app.config["LMSTUDIO_MODEL"]

        if request.method == "POST":
            selected_model = request.form.get("model") or selected_model

            # --- Asignatura ---
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

            # --- Fecha evaluación ---
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

            # --- Archivo ---
            upload = request.files.get("file")
            if not upload or not upload.filename:
                flash("Selecciona un archivo.", "error")
                return redirect(url_for("add_notes"))

            filename = secure_filename(upload.filename)
            file_bytes = upload.read()

            if not file_bytes:
                flash("El archivo está vacío.", "error")
                return redirect(url_for("add_notes"))

            # --- LLM resumen ---
            try:
                exam_date_str = exam_date.isoformat() if exam_date else "No indicada"
                summary = lmstudio_summarize_file(
                    app,
                    selected_model,
                    subject.name,
                    exam_date_str,
                    filename,
                    file_bytes,
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

            if not summary.strip():
                flash("El modelo devolvió un resumen vacío.", "error")
                return redirect(url_for("add_notes"))

            note = Note(
                user_id=current_user.id,
                subject_id=subject.id,
                exam_date=exam_date,
                original_filename=filename,
                summary=summary,
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
        )

    return app


app = create_app()
