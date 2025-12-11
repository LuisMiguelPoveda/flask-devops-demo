import os
import requests

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
    Ask LM Studio for the list of available models via /v1/models.
    Returns a list of model IDs (strings).

    If something goes wrong (LM Studio down, no endpoint, etc.),
    falls back to a list containing only the default LMSTUDIO_MODEL.
    """
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    try:
        resp = requests.get(f"{api_base}/models", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        # Extract model IDs from the "data" list
        all_ids = [m["id"] for m in data.get("data", [])]

        # Optional: filter out embedding-only models
        models = [
            mid
            for mid in all_ids
            if not mid.startswith("text-embedding-")
        ]

        # Fallback to default model if list is empty
        if not models:
            models = [app.config["LMSTUDIO_MODEL"]]

        return models

    except Exception:
        # If anything fails (LM Studio down, etc.), just use the default model
        return [app.config["LMSTUDIO_MODEL"]]


def create_app():
    app = Flask(__name__)

    # ---- LM Studio config ----
    # For your Linux laptop + Docker-only workflow:
    # - If you use `--network host`, localhost (127.0.0.1) works fine.
    # - If you switch to host.docker.internal, override LMSTUDIO_API_BASE via env var.
    app.config["LMSTUDIO_API_BASE"] = os.getenv(
        "LMSTUDIO_API_BASE",
        "http://127.0.0.1:1234/v1",  # LM Studio local server default
    )
    app.config["LMSTUDIO_MODEL"] = os.getenv(
        "LMSTUDIO_MODEL",
        "google/gemma-3-1b",
    )

    # ---- Basic app config ----
    app.config["SECRET_KEY"] = "change-me-in-production"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ---- Init extensions ----
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Create tables if they don't exist (fine for dev / small projects)
    with app.app_context():
        db.create_all()

    # ---------- Routes ----------

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
            else:
                flash("Invalid username or password", "error")

        return render_template("login.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", username=current_user.username)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            # Check if user exists
            existing = User.query.filter_by(username=username).first()
            if existing:
                flash("Username already taken", "error")
                return redirect(url_for("register"))

            # Create user
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()

            # Auto-login after registration
            login_user(new_user)

            return redirect(url_for("dashboard"))

        return render_template("register.html")

    @app.route("/ask-profe", methods=["GET", "POST"])
    @login_required
    def ask_profe():
        # Get available models from LM Studio (or fallback to default)
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
                                "content": "Actúa como un profesor paciente y claro.",
                            },
                            {"role": "user", "content": question},
                        ],
                        "temperature": 0.7,
                    }

                    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
                    resp = requests.post(
                        f"{api_base}/chat/completions",
                        json=payload,
                        timeout=30,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    answer = data["choices"][0]["message"]["content"]
                except Exception as e:
                    answer = f"Error al hablar con LM Studio: {e}"

                messages = [
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer},
                ]

        return render_template(
            "ask_profe.html",
            messages=messages,
            models=available_models,
            selected_model=selected_model,
        )

    return app


# So `flask run` still works without extra config
app = create_app()
