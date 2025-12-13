import os
import requests
from requests.exceptions import Timeout, RequestException

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .models import db, User


def fetch_models(app):
    """
    Obtiene la lista de modelos disponibles desde LM Studio:
      GET {LMSTUDIO_API_BASE}/models

    Devuelve lista de IDs de modelos. Si falla, devuelve el modelo por defecto.
    Filtra modelos de embeddings (por comodidad).
    """
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    try:
        resp = requests.get(f"{api_base}/models", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        all_ids = [m["id"] for m in data.get("data", [])]

        # Filtrar modelos de embeddings (opcional)
        models = [mid for mid in all_ids if not mid.startswith("text-embedding-")]

        if not models:
            models = [app.config["LMSTUDIO_MODEL"]]

        return models
    except Exception:
        return [app.config["LMSTUDIO_MODEL"]]


def create_app():
    app = Flask(__name__)

    # --- Config LM Studio (para tu flujo Docker + --network host) ---
    app.config["LMSTUDIO_API_BASE"] = os.getenv(
        "LMSTUDIO_API_BASE",
        "http://127.0.0.1:1234/v1",
    )
    app.config["LMSTUDIO_MODEL"] = os.getenv(
        "LMSTUDIO_MODEL",
        "google/gemma-3-1b",
    )
    app.config["LMSTUDIO_TIMEOUT"] = int(os.getenv("LMSTUDIO_TIMEOUT", "300"))

    # --- Config app / DB ---
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:///app.db",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # --- Extensiones ---
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Crear tablas (ok para dev/proyecto pequeño)
    with app.app_context():
        db.create_all()

    # --- Error handler global ---
    @app.errorhandler(500)
    def internal_error(_error):
        flash(
            "Lo siento, ha ocurrido un error interno. "
            "Vuelve a intentarlo en unos momentos.",
            "error",
        )
        # Si no está logueado, acabará en login por @login_required en dashboard
        return redirect(url_for("dashboard"))

    # ---------- Rutas ----------

    @app.route("/", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for("dashboard"))

            flash("Usuario o contraseña incorrectos.", "error")

        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            existing = User.query.filter_by(username=username).first()
            if existing:
                flash("Ese usuario ya existe.", "error")
                return redirect(url_for("register"))

            hashed_pw = generate_password_hash(password)
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
                    flash(
                        "Lo siento, el modelo ha tardado demasiado en responder. "
                        "Prueba otra vez o usa una pregunta más corta.",
                        "error",
                    )
                    return redirect(url_for("dashboard"))

                except RequestException:
                    flash(
                        "Lo siento, no he podido conectar con LM Studio. "
                        "Asegúrate de que el servidor local está encendido.",
                        "error",
                    )
                    return redirect(url_for("dashboard"))

                except Exception:
                    flash(
                        "Lo siento, ha ocurrido un error inesperado procesando tu pregunta.",
                        "error",
                    )
                    return redirect(url_for("dashboard"))

        return render_template(
            "ask_profe.html",
            messages=messages,
            models=available_models,
            selected_model=selected_model,
        )

    return app


# Para que `flask run` funcione también
app = create_app()
