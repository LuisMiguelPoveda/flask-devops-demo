import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from io import BytesIO

import requests
from requests.exceptions import Timeout, RequestException
from markupsafe import Markup, escape
from werkzeug.utils import secure_filename
from PyPDF2 import PdfReader

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .models import db, User, Subject, Note, FlashcardDeck, Job, AskProfeMessage, StudentProfile, SubjectExam, NoteSourceFile


ALLOWED_EXTENSIONS = {"txt", "pdf"}
# Permitimos hasta ~5 MB para poder subir PDFs grandes
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
# Límite de texto razonable para evitar desbordar la memoria
MAX_TEXT_CHARS = 300_000
# evita arrancar dos workers en procesos reloader
_worker_started = False


def chunk_text_with_overlap(text: str, max_tokens: int = 3000, overlap: int = 500) -> list[str]:
    """
    Corta el texto en fragmentos aproximados de tokens (palabras) con solapamiento
    para minimizar la pérdida de contexto entre partes.
    """
    tokens = (text or "").split()
    if not tokens:
        return []

    max_tokens = max(1, max_tokens)
    overlap = max(0, min(overlap, max_tokens - 1))
    step = max_tokens - overlap if max_tokens > overlap else 1

    chunks: list[str] = []
    start = 0
    while start < len(tokens):
        end = min(len(tokens), start + max_tokens)
        chunk_tokens = tokens[start:end]
        chunks.append(" ".join(chunk_tokens))
        if end >= len(tokens):
            break
        start += step
    return chunks


def build_note_chunks_map(user_id: int, notes: list[Note], max_tokens: int = 3000, overlap: int = 500) -> dict[int, dict]:
    """
    Devuelve un dict {note_id: {"chunks": [str], "total": int}}.
    Usa los trabajos note_ai_chunk si existen para respetar el número de fragmentos originales;
    si no hay trabajos, divide el contenido del apunte.
    """
    if not notes:
        return {}

    note_ids = {n.id for n in notes if n.id}
    jobs = Job.query.filter(Job.user_id == user_id, Job.type == "note_ai_chunk").all()
    by_note: dict[int, list[tuple[int, str, int]]] = {}
    for job in jobs:
        payload = job.payload or {}
        note_id = payload.get("note_id")
        if note_id not in note_ids:
            continue
        try:
            idx = max(0, int(payload.get("chunk_index") or 0))
        except (ValueError, TypeError):
            idx = 0
        try:
            total = max(1, int(payload.get("total_chunks") or 1))
        except (ValueError, TypeError):
            total = 1
        text = payload.get("text") or ""
        by_note.setdefault(note_id, []).append((idx, text, total))

    result: dict[int, dict] = {}
    for note in notes:
        if note.id in by_note:
            chunks_info = sorted(by_note[note.id], key=lambda t: t[0])
            chunks = [t[1] for t in chunks_info if t[1]]
            total_max = max((t[2] for t in chunks_info if t[2]), default=len(chunks))
            result[note.id] = {"chunks": chunks, "total": total_max or len(chunks) or 1}
            continue

        chunks = chunk_text_with_overlap(note.content or "", max_tokens=max_tokens, overlap=overlap)
        result[note.id] = {"chunks": chunks or [note.content or ""], "total": len(chunks) or 1}

    return result


def simple_format_note(text: str) -> Markup:
    """
    Convierte texto plano con encabezados '#' y viñetas '*'/'-' en HTML simple.
    Soporta **negrita** y *cursiva*. Escapa contenido para evitar XSS.
    """
    import re
    from html import unescape as html_unescape

    lines = html_unescape(text or "").splitlines()
    html_parts = []
    in_list = False

    def close_list():
        nonlocal in_list
        if in_list:
            html_parts.append("</ul>")
            in_list = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            close_list()
            continue

        def fmt_inline(txt: str) -> str:
            esc = escape(txt)
            esc = re.sub(r"\*\*(.+?)\*\*", lambda m: f"<strong>{escape(m.group(1))}</strong>", esc)
            esc = re.sub(r"\*(.+?)\*", lambda m: f"<em>{escape(m.group(1))}</em>", esc)
            return esc

        if stripped == "---":
            close_list()
            html_parts.append("<hr />")
        elif stripped.startswith("###"):
            close_list()
            html_parts.append(f"<h4>{fmt_inline(stripped.lstrip('#').strip())}</h4>")
        elif stripped.startswith("##"):
            close_list()
            html_parts.append(f"<h3>{fmt_inline(stripped.lstrip('#').strip())}</h3>")
        elif stripped.startswith("#"):
            close_list()
            html_parts.append(f"<h2>{fmt_inline(stripped.lstrip('#').strip())}</h2>")
        elif stripped.startswith(("* ", "- ")):
            if not in_list:
                html_parts.append("<ul>")
                in_list = True
            html_parts.append(f"<li>{fmt_inline(stripped[2:].strip())}</li>")
        else:
            close_list()
            html_parts.append(f"<p>{fmt_inline(stripped)}</p>")

    close_list()
    return Markup("".join(html_parts))


def fetch_ask_profe_history(user_id: int, limit: int = 12) -> list[dict]:
    rows = (
        AskProfeMessage.query.filter_by(user_id=user_id)
        .order_by(AskProfeMessage.created_at.desc(), AskProfeMessage.id.desc())
        .limit(limit)
        .all()
    )
    rows.reverse()
    return [{"role": row.role, "content": row.content} for row in rows]


def prune_ask_profe_history(user_id: int, keep: int = 12) -> None:
    extras = (
        AskProfeMessage.query.filter_by(user_id=user_id)
        .order_by(AskProfeMessage.created_at.desc(), AskProfeMessage.id.desc())
        .offset(keep)
        .all()
    )
    for msg in extras:
        db.session.delete(msg)


def fetch_tema_options(user_id: int, subject_id: int | None = None) -> list[str]:
    q = (
        db.session.query(SubjectExam.tema)
        .join(Subject, SubjectExam.subject_id == Subject.id)
        .filter(Subject.user_id == user_id)
    )
    if subject_id:
        q = q.filter(SubjectExam.subject_id == subject_id)
    rows = q.distinct().order_by(SubjectExam.tema.asc()).all()
    return [r[0] for r in rows if r[0]]


def resolve_default_model(app, user_id: int | None, available_models: list[str] | None = None) -> str:
    model = app.config["LMSTUDIO_MODEL"]
    if user_id:
        profile = StudentProfile.query.filter_by(user_id=user_id).first()
        if profile and profile.default_model:
            model = profile.default_model
    if available_models and model not in available_models:
        return available_models[0] if available_models else model
    return model


def is_setup_complete(user_id: int) -> bool:
    if not user_id:
        return False
    profile = StudentProfile.query.filter_by(user_id=user_id).first()
    return profile is not None


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_pdf_text(file_bytes: bytes) -> str:
    """Extrae texto simple desde PDF usando PyPDF2."""
    reader = PdfReader(BytesIO(file_bytes))
    chunks: list[str] = []
    for page in reader.pages:
        try:
            txt = page.extract_text() or ""
        except Exception:
            txt = ""
        if txt:
            chunks.append(txt)
    return "\n".join(chunks)


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


def lmstudio_chat(app, model: str, messages: list[dict], response_format: dict | None = None, temperature: float = 0.4) -> str:
    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
    timeout_s = app.config["LMSTUDIO_TIMEOUT"]
    payload = {"model": model, "messages": messages, "temperature": temperature}
    if response_format:
        payload["response_format"] = response_format
    resp = requests.post(f"{api_base}/chat/completions", json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def lmstudio_summarize_text(app, model: str, subject: str, title: str, exam_date: str, filename: str, text: str, chunk_index: int | None = None, total_chunks: int | None = None) -> str:
    system_prompt = (
        "Eres un profesor experto. Devuelve solo el resumen, sin frases introductorias ni notas sobre tu respuesta. "
        "Usa el idioma predominante del texto; si está en español o no hay predominio claro, responde en español. "
        "Mantén un único idioma coherente en todo el resumen, en formato de viñetas claras y concisas. "
        "No inventes información, no mezcles idiomas, no menciones fragmentos, cortes ni títulos añadidos, y no incluyas introducción ni despedida."
    )
    chunk_meta_line = ""
    if total_chunks and total_chunks > 1:
        human_idx = (chunk_index or 0) + 1
        chunk_meta_line = f"Parte: {human_idx}/{total_chunks} (solo para contexto; no lo menciones en tu respuesta)."
    user_prompt = (
        f"Asignatura: {subject}\n"
        f"Título: {title}\n"
        f"Fecha de examen: {exam_date}\n"
        f"Archivo: {filename}\n"
        f"{chunk_meta_line}\n\n"
        f"TEXTO A RESUMIR:\n{text}"
    )
    return lmstudio_chat(
        app,
        model,
        [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
    )


def _parse_and_validate_flashcards_json(raw: str, expected_count: int) -> list[dict]:
    """
    Esperamos EXACTAMENTE expected_count flashcards:
    [
      {"question": str, "options": [str,str,str,str], "correct_index": 0..3}
    ]
    """
    # A veces el modelo devuelve ```json ... ```
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        # si trae 'json\n'
        cleaned = cleaned.replace("json\n", "", 1).strip()

    data = json.loads(cleaned)

    if not isinstance(data, list) or len(data) != expected_count:
        raise ValueError(f"El JSON debe ser una lista de {expected_count} flashcards.")

    for i, card in enumerate(data, start=1):
        if not isinstance(card, dict):
            raise ValueError(f"Flashcard {i} no es un objeto JSON.")
        q = card.get("question")
        opts = card.get("options")
        idx = card.get("correct_index")
        if not isinstance(q, str) or not q.strip():
            raise ValueError(f"Flashcard {i} tiene 'question' inválida.")
        if not isinstance(opts, list) or len(opts) != 4 or not all(isinstance(o, str) and o.strip() for o in opts):
            raise ValueError(f"Flashcard {i} debe tener 4 'options' (strings).")
        if not isinstance(idx, int) or idx < 0 or idx > 3:
            raise ValueError(f"Flashcard {i} debe tener 'correct_index' entre 0 y 3.")
    return data


def lmstudio_generate_flashcards(app, model: str, note: Note, count: int = 5, source_text: str | None = None) -> list[dict]:
    """
    Genera N flashcards a partir del contenido del apunte/resumen.
    Devuelve lista de dicts validada.
    """
    count = max(1, min(count, 50))
    system_prompt = (
        f"Genera exactamente {count} flashcards de examen a partir del texto. "
        "Devuelve SOLO un JSON válido (sin texto extra, sin markdown). "
        "Formato: "
        "["
        '{"question":"...","options":["A","B","C","D"],"correct_index":0},'
        "..."
        "]. "
        "Las preguntas deben ser autocontenidas: no uses referencias como "
        "\"según el texto\", \"en el fragmento\", \"¿qué se mencionó?\" o similares."
    )

    text = source_text if source_text is not None else (note.content or "")
    user_prompt = (
        f"Asignatura: {note.subject.name}\n"
        f"Título: {note.title}\n"
        f"Fecha de examen: {note.exam_date.isoformat() if note.exam_date else 'No indicada'}\n\n"
        f"TEXTO:\n{text}\n\n"
        "Crea preguntas potenciales de examen que se entiendan sin contexto adicional, "
        "4 opciones, solo 1 correcta. No uses referencias al texto o a un fragmento, "
        "y no añadas contexto externo."
    )

    schema = {
        "type": "array",
        "minItems": count,
        "maxItems": count,
        "items": {
            "type": "object",
            "properties": {
                "question": {"type": "string", "minLength": 1},
                "options": {
                    "type": "array",
                    "minItems": 4,
                    "maxItems": 4,
                    "items": {"type": "string", "minLength": 1},
                },
                "correct_index": {"type": "integer", "minimum": 0, "maximum": 3},
            },
            "required": ["question", "options", "correct_index"],
            "additionalProperties": False,
        },
    }

    raw = lmstudio_chat(
        app,
        model,
        [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "flashcards", "schema": schema},
        },
        temperature=0.2,
    )
    cards = _parse_and_validate_flashcards_json(raw, expected_count=count)
    if len(cards) != count:
        raise ValueError(f"El modelo devolvió {len(cards)} flashcards, se esperaban {count}.")
    return cards


def process_job(app, job: Job):
    """
    Ejecuta un trabajo de la cola. Devuelve (status, message, error_message).
    """
    with app.app_context():
        try:
            if job.type == "note_ai":
                payload = job.payload or {}
                user_id = payload.get("user_id")
                subject_id = payload.get("subject_id")
                title = payload.get("title")
                exam_date_str = payload.get("exam_date")
                filename = payload.get("filename") or "input.txt"
                text = payload.get("text") or ""
                model = payload.get("model") or app.config["LMSTUDIO_MODEL"]

                subject = Subject.query.filter_by(id=subject_id, user_id=user_id).first()
                user = User.query.get(user_id)
                if not subject or not user:
                    return "error", None, "Asignatura o usuario inválido."

                content = lmstudio_summarize_text(app, model, subject.name, title, exam_date_str, filename, text)
                if not content.strip():
                    return "error", None, "El modelo devolvió un resumen vacío."
                # Prepend title to content to ensure first line carries it.
                content = f"{title}\n\n{content}"

                exam_date = datetime.strptime(exam_date_str, "%Y-%m-%d").date() if exam_date_str and exam_date_str != "No indicada" else None
                note = Note(
                    user_id=user.id,
                    subject_id=subject.id,
                    title=title,
                    exam_date=exam_date,
                    original_filename=filename,
                    content=content,
                    ai_used=True,
                )
                db.session.add(note)
                db.session.commit()
                return "success", f"Resumen listo: {title}", None

            if job.type == "note_ai_chunk":
                payload = job.payload or {}
                user_id = payload.get("user_id")
                subject_id = payload.get("subject_id")
                note_id = payload.get("note_id")
                filename = payload.get("filename") or "input.txt"
                text = payload.get("text") or ""
                model = payload.get("model") or app.config["LMSTUDIO_MODEL"]
                chunk_index = max(0, int(payload.get("chunk_index") or 0))
                total_chunks = max(1, int(payload.get("total_chunks") or 1))
                exam_date_str = payload.get("exam_date") or "No indicada"

                note = Note.query.filter_by(id=note_id, user_id=user_id).first()
                subject_lookup_id = subject_id or (note.subject_id if note else None)
                subject = Subject.query.filter_by(id=subject_lookup_id, user_id=user_id).first() if subject_lookup_id else None
                if not note or not subject:
                    return "error", None, "Apunte o asignatura inválidos."

                exam_date_str = exam_date_str or (note.exam_date.isoformat() if note.exam_date else "No indicada")
                summary = lmstudio_summarize_text(
                    app,
                    model,
                    subject.name,
                    note.title,
                    exam_date_str,
                    filename,
                    text,
                    chunk_index=chunk_index,
                    total_chunks=total_chunks,
                )
                if not summary.strip():
                    return "error", None, "El modelo devolvió un resumen vacío para el fragmento."

                existing = (note.content or "").rstrip()
                separator = "\n\n" if existing else ""
                note.content = f"{existing}{separator}{summary.strip()}"
                note.ai_used = True
                db.session.commit()

                is_last = total_chunks and (chunk_index + 1) == total_chunks
                progress = f" ({chunk_index + 1}/{total_chunks})" if total_chunks > 1 else ""
                msg = f"Resumen en progreso{progress}: {note.title}"
                if is_last:
                    msg = f"Resumen completo listo: {note.title}"
                return "success", msg, None

            if job.type in ("flashcards_ai_new", "flashcards_ai_append"):
                payload = job.payload or {}
                user_id = payload.get("user_id")
                note_id = payload.get("note_id")
                deck_id = payload.get("deck_id")
                model = payload.get("model") or app.config["LMSTUDIO_MODEL"]
                custom_title = (payload.get("ai_deck_title") or "").strip()
                count = int(payload.get("count") or 5)

                note = Note.query.filter_by(id=note_id, user_id=user_id).first()
                if not note:
                    return "error", None, "Apunte/resumen inválido."

                cards = lmstudio_generate_flashcards(app, model, note, count=count)

                if job.type == "flashcards_ai_append":
                    deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=user_id).first()
                    if not deck:
                        return "error", None, "Deck inválido."
                    deck.flashcards = (deck.flashcards or []) + cards
                    db.session.commit()
                    return "success", f"{len(cards)} flashcards añadidas a {deck.title}", None

                # new deck
                deck = FlashcardDeck(
                    user_id=user_id,
                    subject_id=note.subject_id,
                    title=custom_title or note.title,
                    exam_date=note.exam_date,
                    source_note_id=note.id,
                    flashcards=cards,
                )
                db.session.add(deck)
                db.session.commit()
                return "success", f"Deck creado: {deck.title}", None

            if job.type == "flashcards_ai_chunk":
                payload = job.payload or {}
                user_id = payload.get("user_id")
                note_id = payload.get("note_id")
                deck_id = payload.get("deck_id")
                model = payload.get("model") or app.config["LMSTUDIO_MODEL"]
                count = max(1, min(int(payload.get("count") or 5), 50))
                chunk_index = max(0, int(payload.get("chunk_index") or 0))
                total_chunks = max(1, int(payload.get("total_chunks") or 1))
                chunk_text = payload.get("text") or ""

                note = Note.query.filter_by(id=note_id, user_id=user_id).first()
                deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=user_id).first()
                if not note or not deck:
                    return "error", None, "Apunte o deck inválido."

                cards = lmstudio_generate_flashcards(app, model, note, count=count, source_text=chunk_text)
                deck.flashcards = (deck.flashcards or []) + cards
                db.session.commit()

                msg = f"Flashcards añadidas (fragmento {chunk_index + 1}/{total_chunks}) a {deck.title}"
                if (chunk_index + 1) == total_chunks:
                    msg = f"Flashcards listas para {deck.title}"
                return "success", msg, None

            return "error", None, "Tipo de trabajo desconocido."
        except Timeout:
            db.session.rollback()
            return "error", None, "El modelo tardó demasiado en responder."
        except RequestException:
            db.session.rollback()
            return "error", None, "No se pudo conectar con LM Studio."
        except Exception as e:
            db.session.rollback()
            return "error", None, f"Error procesando el trabajo: {e}"


def create_app():
    app = Flask(__name__)

    # LM Studio
    app.config["LMSTUDIO_API_BASE"] = os.getenv("LMSTUDIO_API_BASE", "http://127.0.0.1:1234/v1")
    app.config["LMSTUDIO_MODEL"] = os.getenv("LMSTUDIO_MODEL", "google/gemma-3-1b")
    app.config["LMSTUDIO_TIMEOUT"] = int(os.getenv("LMSTUDIO_TIMEOUT", "300"))

    # App/DB
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///app.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    def profe_is_busy() -> bool:
        return db.session.query(Job.id).filter(Job.status.in_(("pending", "running"))).first() is not None

    @app.context_processor
    def inject_login_flag():
        # Flags to trigger mascot celebration on first render after login/register.
        just_logged_in = session.pop("just_logged_in", None)
        just_registered = session.pop("just_registered", None)
        return {"just_logged_in": bool(just_logged_in), "just_registered": bool(just_registered)}

    @app.context_processor
    def inject_profe_busy_flag():
        if not current_user.is_authenticated:
            return {"profe_busy": False}
        return {"profe_busy": profe_is_busy()}

    @app.before_request
    def enforce_setup_completion():
        if not current_user.is_authenticated:
            return None
        endpoint = request.endpoint or ""
        if endpoint in ("login", "register", "logout", "setup", "static"):
            return None
        if not is_setup_complete(current_user.id):
            return redirect(url_for("setup"))
        return None

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        global _worker_started
        if not _worker_started:
            def worker_loop():
                while True:
                    with app.app_context():
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
                        job.status = status
                        job.result_message = msg
                        job.error_message = err
                        job.updated_at = datetime.utcnow()
                        db.session.commit()
                    # pequeña pausa para no saturar
                    time.sleep(0.5)

            threading.Thread(target=worker_loop, daemon=True).start()
            _worker_started = True

    # ---------- AUTH ----------
    @app.route("/", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            if not is_setup_complete(current_user.id):
                return redirect(url_for("setup"))
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = User.query.filter_by(username=username).first()

            if user and password and check_password_hash(user.password_hash, password):
                login_user(user)
                flash("Sesión iniciada ✅", "login_success")
                session["just_logged_in"] = True
                if not is_setup_complete(user.id):
                    return redirect(url_for("setup"))
                return redirect(url_for("dashboard"))

            flash("Usuario o contraseña incorrectos.", "error")
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            if not is_setup_complete(current_user.id):
                return redirect(url_for("setup"))
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            if not username or not password:
                flash("Rellena usuario y contraseña.", "error")
                return redirect(url_for("register"))

            if User.query.filter_by(username=username).first():
                flash("Ese usuario ya existe.", "error")
                return redirect(url_for("register"))

            hashed_pw = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash("Cuenta creada e inicio de sesión ✅", "login_success")
            session["just_logged_in"] = True
            session["just_registered"] = True
            return redirect(url_for("setup"))

        return render_template("register.html")

    @app.route("/setup", methods=["GET", "POST"])
    @login_required
    def setup():
        profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
        student_name = profile.student_name if profile else ""
        student_age = str(profile.age) if profile else ""
        personality_notes = profile.personality_notes if profile else ""

        if request.method == "POST":
            student_name = (request.form.get("student_name") or "").strip()
            student_age = (request.form.get("student_age") or "").strip()
            personality_notes = (request.form.get("personality_notes") or "").strip()

            errors: list[str] = []
            if not student_name:
                errors.append("Escribe el nombre del estudiante.")

            age_val = None
            try:
                age_val = int(student_age)
                if age_val < 1:
                    raise ValueError
            except (TypeError, ValueError):
                errors.append("Indica una edad válida.")

            if not personality_notes:
                errors.append("Añade detalles de personalidad para contextualizar al profe.")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template(
                    "setup.html",
                    student_name=student_name,
                    student_age=student_age,
                    personality_notes=personality_notes,
                )

            try:
                profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
                if profile:
                    profile.student_name = student_name
                    profile.age = age_val or 0
                    profile.personality_notes = personality_notes
                else:
                    profile = StudentProfile(
                        user_id=current_user.id,
                        student_name=student_name,
                        age=age_val or 0,
                        personality_notes=personality_notes,
                    )
                    db.session.add(profile)

                db.session.commit()
                flash("Datos guardados ✅", "success")
                return redirect(url_for("setup_subjects"))
            except Exception:
                db.session.rollback()
                flash("Error guardando la configuración.", "error")
                return render_template(
                    "setup.html",
                    student_name=student_name,
                    student_age=student_age,
                    personality_notes=personality_notes,
                )

        return render_template(
            "setup.html",
            student_name=student_name,
            student_age=student_age,
            personality_notes=personality_notes,
        )

    @app.route("/setup/subjects", methods=["GET", "POST"])
    @login_required
    def setup_subjects():
        if not is_setup_complete(current_user.id):
            return redirect(url_for("setup"))

        subjects_seed: list[dict] = []

        if request.method == "POST":
            subjects_payload = request.form.get("subjects_payload") or ""
            subjects_clean: list[dict] = []
            errors: list[str] = []

            raw_subjects = []
            if subjects_payload:
                try:
                    raw_subjects = json.loads(subjects_payload)
                except (TypeError, ValueError):
                    raw_subjects = None
                    errors.append("No se pudo leer la lista de asignaturas.")

            if raw_subjects is not None:
                if not isinstance(raw_subjects, list):
                    errors.append("Formato inválido de asignaturas.")
                else:
                    seen_names: set[str] = set()
                    for subj in raw_subjects:
                        if not isinstance(subj, dict):
                            continue
                        name = (subj.get("name") or "").strip()
                        exams = subj.get("exams") if isinstance(subj, dict) else []
                        if not isinstance(exams, list):
                            exams = []
                        subject_seed = {"name": name, "exams": []}

                        subject_has_content = bool(name)
                        for exam in exams:
                            date_str = (exam.get("date") or "").strip() if isinstance(exam, dict) else ""
                            tema = (exam.get("tema") or "").strip() if isinstance(exam, dict) else ""
                            if date_str or tema:
                                subject_has_content = True
                            subject_seed["exams"].append({"date": date_str, "tema": tema})

                        if not subject_has_content:
                            continue

                        subjects_seed.append(subject_seed)

                        if not name:
                            errors.append("Cada asignatura necesita un nombre.")
                            continue
                        lowered = name.lower()
                        if lowered in seen_names:
                            errors.append(f"La asignatura \"{name}\" está duplicada.")
                            continue
                        seen_names.add(lowered)

                        exam_entries: list[dict] = []
                        for exam in exams:
                            date_str = (exam.get("date") or "").strip() if isinstance(exam, dict) else ""
                            tema = (exam.get("tema") or "").strip() if isinstance(exam, dict) else ""
                            if not date_str and not tema:
                                continue
                            if not date_str or not tema:
                                errors.append(
                                    f"Cada examen de \"{name}\" debe tener fecha y tema."
                                )
                                continue
                            try:
                                exam_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                            except ValueError:
                                errors.append(
                                    f"Formato de fecha inválido en \"{name}\": {date_str}."
                                )
                                continue
                            exam_entries.append({"date": exam_date, "tema": tema})

                        if not exam_entries:
                            errors.append(f"La asignatura \"{name}\" necesita al menos un examen.")
                            continue

                        subjects_clean.append({"name": name, "exams": exam_entries})

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template("setup_subjects.html", subjects_seed=subjects_seed)

            if not subjects_clean:
                return redirect(url_for("setup_generate"))

            try:
                for subj in subjects_clean:
                    subject = Subject.query.filter_by(user_id=current_user.id, name=subj["name"]).first()
                    if not subject:
                        subject = Subject(user_id=current_user.id, name=subj["name"])
                        db.session.add(subject)
                        db.session.flush()
                    for exam in subj["exams"]:
                        exists = SubjectExam.query.filter_by(
                            subject_id=subject.id,
                            exam_date=exam["date"],
                            tema=exam["tema"],
                        ).first()
                        if not exists:
                            db.session.add(
                                SubjectExam(
                                    subject_id=subject.id,
                                    exam_date=exam["date"],
                                    tema=exam["tema"],
                                )
                            )
                db.session.commit()
                flash("Asignaturas guardadas ✅", "success")
                return redirect(url_for("setup_generate"))
            except Exception:
                db.session.rollback()
                flash("Error guardando las asignaturas.", "error")
                return render_template("setup_subjects.html", subjects_seed=subjects_seed)

        return render_template("setup_subjects.html", subjects_seed=subjects_seed)

    @app.route("/setup/generate", methods=["GET", "POST"])
    @login_required
    def setup_generate():
        if not is_setup_complete(current_user.id):
            return redirect(url_for("setup"))

        profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
        available_models = fetch_models(app)
        selected_model = resolve_default_model(app, current_user.id, available_models)

        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
        subject_blocks: list[dict] = []
        for subject in subjects:
            exams = (
                SubjectExam.query.filter_by(subject_id=subject.id)
                .order_by(SubjectExam.exam_date.asc(), SubjectExam.tema.asc())
                .all()
            )
            if exams:
                subject_blocks.append({"subject": subject, "exams": exams})

        if request.method == "POST":
            selected_model = request.form.get("default_model") or selected_model
            if available_models and selected_model not in available_models:
                selected_model = available_models[0]
            if profile:
                profile.default_model = selected_model
                db.session.commit()

            total_files = 0
            total_notes = 0
            total_decks = 0
            total_chunks = 0
            errors: list[str] = []

            try:
                for block in subject_blocks:
                    subject = block["subject"]
                    for exam in block["exams"]:
                        uploads = request.files.getlist(f"files_{exam.id}")
                        for upload in uploads:
                            if not upload or not upload.filename:
                                continue
                            total_files += 1
                            if not allowed_file(upload.filename):
                                errors.append(f"{upload.filename}: solo se permiten archivos .txt o .pdf.")
                                continue

                            filename = secure_filename(upload.filename)
                            file_bytes = upload.read()
                            if not file_bytes:
                                errors.append(f"{filename}: el archivo está vacío.")
                                continue
                            if len(file_bytes) > MAX_UPLOAD_BYTES:
                                errors.append(f"{filename}: archivo demasiado grande (máx {MAX_UPLOAD_BYTES // 1024} KB).")
                                continue

                            ext = filename.rsplit(".", 1)[1].lower()
                            file_mime = upload.mimetype or ("application/pdf" if ext == "pdf" else "text/plain")
                            if ext == "pdf":
                                file_text = extract_pdf_text(file_bytes)
                            else:
                                try:
                                    file_text = file_bytes.decode("utf-8")
                                except UnicodeDecodeError:
                                    file_text = file_bytes.decode("utf-8", errors="ignore")
                            file_text = (file_text or "").strip()
                            if not file_text:
                                errors.append(f"{filename}: no contiene texto legible.")
                                continue
                            if len(file_text) > MAX_TEXT_CHARS:
                                file_text = file_text[:MAX_TEXT_CHARS]

                            chunks = chunk_text_with_overlap(file_text, max_tokens=3000, overlap=500)
                            if not chunks:
                                errors.append(f"{filename}: no se pudo dividir el texto para IA.")
                                continue

                            exam_date_str = exam.exam_date.isoformat() if exam.exam_date else "No indicada"
                            base_name = Path(filename).stem if filename else subject.name
                            title = f"{exam.tema} - {base_name}".strip(" -")
                            if exam_date_str != "No indicada":
                                title = f"{title} ({exam_date_str})"

                            note = Note(
                                user_id=current_user.id,
                                subject_id=subject.id,
                                title=title,
                                exam_date=exam.exam_date,
                                original_filename=filename,
                                content=f"{title}\n\n",
                                ai_used=True,
                            )
                            db.session.add(note)
                            db.session.flush()
                            db.session.add(
                                NoteSourceFile(
                                    note_id=note.id,
                                    filename=filename or "input.txt",
                                    content_type=file_mime or "application/octet-stream",
                                    data=file_bytes,
                                )
                            )

                            deck = FlashcardDeck(
                                user_id=current_user.id,
                                subject_id=subject.id,
                                title=title,
                                exam_date=exam.exam_date,
                                source_note_id=note.id,
                                flashcards=[],
                            )
                            db.session.add(deck)
                            db.session.flush()

                            for idx, chunk in enumerate(chunks):
                                db.session.add(
                                    Job(
                                        user_id=current_user.id,
                                        type="note_ai_chunk",
                                        payload={
                                            "user_id": current_user.id,
                                            "subject_id": subject.id,
                                            "note_id": note.id,
                                            "title": title,
                                            "exam_date": exam_date_str,
                                            "filename": filename or "input.txt",
                                            "text": chunk,
                                            "model": selected_model,
                                            "chunk_index": idx,
                                            "total_chunks": len(chunks),
                                        },
                                    )
                                )
                                db.session.add(
                                    Job(
                                        user_id=current_user.id,
                                        type="flashcards_ai_chunk",
                                        payload={
                                            "user_id": current_user.id,
                                            "note_id": note.id,
                                            "deck_id": deck.id,
                                            "model": selected_model,
                                            "count": 6,
                                            "chunk_index": idx,
                                            "total_chunks": len(chunks),
                                            "text": chunk,
                                        },
                                    )
                                )
                            total_notes += 1
                            total_decks += 1
                            total_chunks += len(chunks)

                if total_notes:
                    db.session.commit()
                    flash(
                        f"Generación encolada ✅ {total_files} archivo(s), {total_notes} resumen(es), "
                        f"{total_decks} deck(s), {total_chunks} fragmento(s).",
                        "success",
                    )
                else:
                    db.session.rollback()
                    if total_files == 0:
                        flash("No has subido archivos. Puedes hacerlo más tarde.", "success")
            except Exception:
                db.session.rollback()
                flash("Error procesando la generación inicial.", "error")
                return redirect(url_for("setup_generate"))

            for err in errors:
                flash(err, "error")
            return redirect(url_for("setup_next"))

        return render_template(
            "setup_generate.html",
            subjects=subject_blocks,
            models=available_models,
            selected_model=selected_model,
            max_kb=MAX_UPLOAD_BYTES // 1024,
            max_chars=MAX_TEXT_CHARS,
        )

    @app.route("/setup/next")
    @login_required
    def setup_next():
        if not is_setup_complete(current_user.id):
            return redirect(url_for("setup"))
        profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
        return render_template("setup_next.html", student_name=profile.student_name if profile else current_user.username)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    # ---------- DASHBOARD ----------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", username=current_user.username)

    @app.route("/options")
    @login_required
    def options():
        return render_template("options.html")

    @app.route("/options/profile", methods=["GET", "POST"])
    @login_required
    def profile_edit():
        profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
        if not profile:
            return redirect(url_for("setup"))

        student_name = profile.student_name or ""
        student_age = str(profile.age or "")
        personality_notes = profile.personality_notes or ""

        if request.method == "POST":
            student_name = (request.form.get("student_name") or "").strip()
            student_age = (request.form.get("student_age") or "").strip()
            personality_notes = (request.form.get("personality_notes") or "").strip()

            errors: list[str] = []
            if not student_name:
                errors.append("Escribe el nombre del estudiante.")

            age_val = None
            try:
                age_val = int(student_age)
                if age_val < 1:
                    raise ValueError
            except (TypeError, ValueError):
                errors.append("Indica una edad válida.")

            if not personality_notes:
                errors.append("Añade detalles de personalidad para contextualizar al profe.")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template(
                    "setup.html",
                    student_name=student_name,
                    student_age=student_age,
                    personality_notes=personality_notes,
                    page_title="Perfil del estudiante",
                    heading="Perfil del estudiante",
                    subtext="Actualiza los datos del estudiante cuando lo necesites.",
                    submit_label="Guardar cambios",
                    back_url=url_for("options"),
                )

            profile.student_name = student_name
            profile.age = age_val or 0
            profile.personality_notes = personality_notes
            db.session.commit()
            flash("Perfil actualizado ✅", "success")
            return redirect(url_for("options"))

        return render_template(
            "setup.html",
            student_name=student_name,
            student_age=student_age,
            personality_notes=personality_notes,
            page_title="Perfil del estudiante",
            heading="Perfil del estudiante",
            subtext="Actualiza los datos del estudiante cuando lo necesites.",
            submit_label="Guardar cambios",
            back_url=url_for("options"),
        )

    @app.route("/options/reset", methods=["POST"])
    @login_required
    def reset_account():
        try:
            note_ids = [row[0] for row in db.session.query(Note.id).filter_by(user_id=current_user.id).all()]
            subject_ids = [row[0] for row in db.session.query(Subject.id).filter_by(user_id=current_user.id).all()]

            AskProfeMessage.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
            Job.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
            FlashcardDeck.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)

            if note_ids:
                NoteSourceFile.query.filter(NoteSourceFile.note_id.in_(note_ids)).delete(synchronize_session=False)
            Note.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)

            if subject_ids:
                SubjectExam.query.filter(SubjectExam.subject_id.in_(subject_ids)).delete(synchronize_session=False)
            Subject.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)

            StudentProfile.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)

            db.session.commit()
            flash("Cuenta reseteada ✅", "success")
        except Exception:
            db.session.rollback()
            flash("Error reseteando la cuenta.", "error")
        return redirect(url_for("setup"))

    # ---------- API: fechas por asignatura ----------
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
            db.session.query(SubjectExam.exam_date, SubjectExam.tema)
            .filter(SubjectExam.subject_id == subject_id)
            .order_by(SubjectExam.exam_date.asc(), SubjectExam.tema.asc())
            .all()
        )
        return jsonify(
            {
                "dates": [
                    {"date": r[0].isoformat(), "tema": r[1]}
                    for r in rows
                    if r[0] is not None and r[1]
                ]
            }
        )

    # ---------- API: títulos por asignatura ----------
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
        return jsonify({"titles": [r[0] for r in rows if r[0]]})

    @app.template_filter("note_fmt")
    def note_fmt_filter(text: str):
        return simple_format_note(text)

    @app.route("/api/jobs/queue")
    @login_required
    def api_jobs_queue():
        jobs = (
            Job.query.filter_by(user_id=current_user.id)
            .order_by(Job.created_at.desc())
            .limit(15)
            .all()
        )
        return jsonify(
            {
                "jobs": [
                    {
                        "id": j.id,
                        "type": j.type,
                        "status": j.status,
                        "result": j.result_message,
                        "error": j.error_message,
                        "created_at": j.created_at.isoformat(),
                        "updated_at": j.updated_at.isoformat() if j.updated_at else None,
                    }
                    for j in jobs
                ]
            }
        )

    @app.route("/api/jobs/updates")
    @login_required
    def api_jobs_updates():
        jobs = (
            Job.query.filter(
                Job.user_id == current_user.id,
                Job.status.in_(("success", "error")),
                Job.notified.is_(False),
            )
            .order_by(Job.updated_at.desc())
            .all()
        )
        payload = [
            {
                "id": j.id,
                "status": j.status,
                "message": j.result_message or j.error_message or "",
            }
            for j in jobs
        ]
        for j in jobs:
            j.notified = True
        db.session.commit()
        return jsonify({"jobs": payload})

    # ---------- Ask Profe ----------
    @app.route("/ask-profe", methods=["GET", "POST"])
    @login_required
    def ask_profe():
        if profe_is_busy():
            flash("El profe está ocupado procesando trabajos. Cuando termine, podrás usar «Pregúntale al profe».", "error")
            return redirect(url_for("dashboard"))

        available_models = fetch_models(app)
        selected_model = resolve_default_model(app, current_user.id, available_models)
        messages = fetch_ask_profe_history(current_user.id)
        profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
        student_context = ""
        if profile:
            student_context = (
                f"Estudiante: {profile.student_name} (edad {profile.age}). "
                f"Características: {profile.personality_notes}"
            )

        if request.method == "POST":
            selected_model = request.form.get("model") or selected_model
            question = request.form.get("question", "").strip()

            if question:
                try:
                    context_messages = messages[-2:]  # ultimo turno (usuario + profe)
                    history = list(context_messages)
                    history.append({"role": "user", "content": question})

                    payload = {
                        "model": selected_model,
                        "messages": [
                            {
                                "role": "system",
                                "content": (
                                    "Eres un profesor humano paciente y amable. Responde de forma clara, completa y conversacional, "
                                    "sin usar asteriscos ni acciones roleplay; escribe como hablarías en la vida real. "
                                    "Adapta tu respuesta al perfil del estudiante, pero no menciones esos datos de forma explícita "
                                    "a menos que sea relevante para la pregunta o el estudiante lo pida. "
                                    f"{student_context}"
                                ),
                            },
                            *history,
                        ],
                        "temperature": 0.7,
                    }
                    api_base = app.config["LMSTUDIO_API_BASE"].rstrip("/")
                    resp = requests.post(f"{api_base}/chat/completions", json=payload, timeout=app.config["LMSTUDIO_TIMEOUT"])
                    resp.raise_for_status()
                    data = resp.json()
                    answer = data["choices"][0]["message"]["content"]
                    history.append({"role": "assistant", "content": answer})
                    db.session.add(AskProfeMessage(user_id=current_user.id, role="user", content=question))
                    db.session.add(AskProfeMessage(user_id=current_user.id, role="assistant", content=answer))
                    prune_ask_profe_history(current_user.id, keep=12)
                    db.session.commit()
                    messages = fetch_ask_profe_history(current_user.id)
                except Timeout:
                    flash("El modelo tardó demasiado en responder.", "error")
                    return redirect(url_for("dashboard"))
                except RequestException:
                    flash("No he podido conectar con LM Studio. ¿Está encendido?", "error")
                    return redirect(url_for("dashboard"))
                except Exception:
                    db.session.rollback()
                    flash("Error inesperado procesando tu pregunta.", "error")
                    return redirect(url_for("dashboard"))

        return render_template("ask_profe.html", messages=messages, models=available_models, selected_model=selected_model)

    # ---------- Subir apuntes / resumen (igual que antes) ----------
    @app.route("/add-notes", methods=["GET", "POST"])
    @login_required
    def add_notes():
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
        available_models = fetch_models(app)
        selected_model = resolve_default_model(app, current_user.id, available_models)

        if request.method == "POST":
            selected_model = request.form.get("model") or selected_model

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

            title = (request.form.get("title") or "").strip()

            exam_str = ((request.form.get("exam_date_manual") or "").strip() or (request.form.get("exam_date_choice") or "").strip())
            exam_date = None
            if exam_str:
                try:
                    exam_date = datetime.strptime(exam_str, "%Y-%m-%d").date()
                except ValueError:
                    flash("Formato de fecha inválido. Usa YYYY-MM-DD.", "error")
                    return redirect(url_for("add_notes"))

            manual_text = (request.form.get("manual_text") or "").strip()
            manual_mode = request.form.get("manual_mode") == "on"
            manual_file_mode = request.form.get("manual_file_mode") == "on"

            upload = request.files.get("file")
            file_text = ""
            file_bytes = None
            file_mime = None
            if upload and upload.filename:
                if not allowed_file(upload.filename):
                    flash("Solo se permiten archivos .txt o .pdf.", "error")
                    return redirect(url_for("add_notes"))
                filename = secure_filename(upload.filename)
                file_bytes = upload.read()
                if not file_bytes:
                    flash("El archivo está vacío.", "error")
                    return redirect(url_for("add_notes"))
                if len(file_bytes) > MAX_UPLOAD_BYTES:
                    flash(f"Archivo demasiado grande. Máximo {MAX_UPLOAD_BYTES // 1024} KB.", "error")
                    return redirect(url_for("add_notes"))
                ext = filename.rsplit(".", 1)[1].lower()
                file_mime = upload.mimetype or ("application/pdf" if ext == "pdf" else "text/plain")
                if ext == "pdf":
                    file_text = extract_pdf_text(file_bytes)
                else:
                    try:
                        file_text = file_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        file_text = file_bytes.decode("utf-8", errors="ignore")
                file_text = (file_text or "").strip()
                if not file_text:
                    flash("El archivo no contiene texto legible.", "error")
                    return redirect(url_for("add_notes"))
                if len(file_text) > MAX_TEXT_CHARS:
                    file_text = file_text[:MAX_TEXT_CHARS]
            else:
                filename = None

            content_text = manual_text if manual_text else file_text
            if manual_mode or manual_file_mode:
                if not content_text:
                    flash("Si eliges guardar sin IA, sube un TXT o escribe contenido.", "error")
                    return redirect(url_for("add_notes"))
                # default title: nombre de archivo sin extensión + " examen " + fecha + " creado " + fecha de subida
                if title.strip():
                    final_title = title.strip()
                else:
                    base_name = Path(filename).stem if filename else subject.name
                    created_str = datetime.utcnow().date().isoformat()
                    exam_part = exam_date.isoformat() if exam_date else ""
                    final_title = f"{base_name} examen {exam_part} creado {created_str}".strip()
                note = Note(
                    user_id=current_user.id,
                    subject_id=subject.id,
                    title=final_title,
                    exam_date=exam_date,
                    original_filename=filename,
                    content=content_text,
                    ai_used=False,
                )
                db.session.add(note)
                db.session.commit()
                flash("Apuntes guardados (sin IA) ✅", "success")
                return redirect(url_for("dashboard"))

            if not file_text:
                flash("Para usar IA sube un TXT o PDF válido.", "error")
                return redirect(url_for("add_notes"))

            if title.strip():
                final_title = title.strip()
            else:
                base_name = Path(filename or "input").stem
                created_str = datetime.utcnow().date().isoformat()
                exam_part = exam_date.isoformat() if exam_date else ""
                final_title = f"{base_name} examen {exam_part} creado {created_str} ({selected_model})".strip()
            exam_date_str = exam_date.isoformat() if exam_date else "No indicada"
            chunks = chunk_text_with_overlap(file_text, max_tokens=3000, overlap=500)
            if not chunks:
                flash("No se pudo dividir el texto en fragmentos para IA.", "error")
                return redirect(url_for("add_notes"))

            note = Note(
                user_id=current_user.id,
                subject_id=subject.id,
                title=final_title,
                exam_date=exam_date,
                original_filename=filename,
                content=f"{final_title}\n\n",
                ai_used=True,
            )
            db.session.add(note)
            db.session.flush()
            if file_bytes:
                db.session.add(
                    NoteSourceFile(
                        note_id=note.id,
                        filename=filename or "input.txt",
                        content_type=file_mime or "application/octet-stream",
                        data=file_bytes,
                    )
                )
            db.session.commit()

            for idx, chunk in enumerate(chunks):
                job = Job(
                    user_id=current_user.id,
                    type="note_ai_chunk",
                    payload={
                        "user_id": current_user.id,
                        "subject_id": subject.id,
                        "note_id": note.id,
                        "title": final_title,
                        "exam_date": exam_date_str,
                        "filename": filename or "input.txt",
                        "text": chunk,
                        "model": selected_model,
                        "chunk_index": idx,
                        "total_chunks": len(chunks),
                    },
                )
                db.session.add(job)
            db.session.commit()

            flash(f"Resumen encolado en {len(chunks)} fragmento(s) ✅ Se irá completando a medida que procesamos cada parte.", "success")
            return redirect(url_for("add_notes"))

        jobs = (
            Job.query.filter_by(user_id=current_user.id)
            .order_by(Job.created_at.desc())
            .limit(10)
            .all()
        )

        return render_template(
            "add_notes.html",
            subjects=subjects,
            models=available_models,
            selected_model=selected_model,
            max_kb=MAX_UPLOAD_BYTES // 1024,
            max_chars=MAX_TEXT_CHARS,
            jobs=jobs,
        )

    # ---------- Consultar apuntes ----------
    @app.route("/notes")
    @login_required
    def notes_list():
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
        subject_id = request.args.get("subject_id", type=int)
        tema_q = (request.args.get("tema") or "").strip()
        title_q = (request.args.get("title") or "").strip()

        q = Note.query.filter_by(user_id=current_user.id)
        if subject_id:
            q = q.filter(Note.subject_id == subject_id)
        if tema_q:
            q = q.join(
                SubjectExam,
                (SubjectExam.subject_id == Note.subject_id) & (SubjectExam.exam_date == Note.exam_date),
            ).filter(SubjectExam.tema == tema_q)
        if title_q:
            q = q.filter(Note.title.ilike(f"%{title_q}%"))

        notes = q.order_by(Note.updated_at.desc()).all()
        tema_options = fetch_tema_options(current_user.id, subject_id)
        filters_active = bool(subject_id or tema_q or title_q)
        chunk_totals: dict[int, int] = {}
        note_models: dict[int, str] = {}
        source_files: dict[int, NoteSourceFile] = {}
        note_temas: dict[int, list[str]] = {}
        if notes:
            note_ids = {n.id for n in notes}
            exam_pairs = {(n.subject_id, n.exam_date) for n in notes if n.exam_date}
            jobs = Job.query.filter(
                Job.user_id == current_user.id,
                Job.type == "note_ai_chunk",
            ).all()
            for job in jobs:
                payload = job.payload or {}
                note_id = payload.get("note_id")
                if note_id not in note_ids:
                    continue
                try:
                    total_chunks = int(payload.get("total_chunks") or 0)
                except (ValueError, TypeError):
                    total_chunks = 0
                if total_chunks:
                    prev = chunk_totals.get(note_id, 0)
                    chunk_totals[note_id] = max(prev, total_chunks)
                model = payload.get("model")
                if model:
                    note_models.setdefault(note_id, model)
            source_rows = NoteSourceFile.query.filter(NoteSourceFile.note_id.in_(note_ids)).all()
            source_files = {s.note_id: s for s in source_rows}
            if exam_pairs:
                subject_ids = {sid for sid, _ in exam_pairs}
                exam_dates = {d for _, d in exam_pairs}
                tema_rows = SubjectExam.query.filter(
                    SubjectExam.subject_id.in_(subject_ids),
                    SubjectExam.exam_date.in_(exam_dates),
                ).all()
                temas_by_pair: dict[tuple, list[str]] = {}
                for row in tema_rows:
                    key = (row.subject_id, row.exam_date)
                    temas_by_pair.setdefault(key, []).append(row.tema)
                for note in notes:
                    if not note.exam_date:
                        continue
                    temas = temas_by_pair.get((note.subject_id, note.exam_date))
                    if temas:
                        note_temas[note.id] = sorted(set(temas))

        return render_template(
            "notes_list.html",
            subjects=subjects,
            notes=notes,
            filters={"subject_id": subject_id or "", "tema": tema_q, "title": title_q},
            chunk_totals=chunk_totals,
            note_models=note_models,
            source_files=source_files,
            note_temas=note_temas,
            temas=tema_options,
            filters_active=filters_active,
        )

    @app.route("/notes/<int:note_id>/source-file")
    @login_required
    def note_source_file(note_id: int):
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
        source = NoteSourceFile.query.filter_by(note_id=note.id).first()
        if not source:
            flash("No se encontró el archivo original.", "error")
            return redirect(url_for("notes_list"))
        return send_file(
            BytesIO(source.data),
            mimetype=source.content_type or "application/octet-stream",
            download_name=source.filename or "archivo_original",
            as_attachment=True,
        )

    @app.route("/notes/merge", methods=["POST"])
    @login_required
    def notes_merge():
        target_id = request.form.get("target_note", type=int)
        source_id = request.form.get("source_note", type=int)
        if not target_id or not source_id or target_id == source_id:
            flash("Elige apuntes válidos (origen y destino distintos).", "error")
            return redirect(url_for("notes_list"))

        target = Note.query.filter_by(id=target_id, user_id=current_user.id).first()
        source = Note.query.filter_by(id=source_id, user_id=current_user.id).first()
        if not target or not source:
            flash("No se encontraron los apuntes seleccionados.", "error")
            return redirect(url_for("notes_list"))

        merged = (target.content or "") + "\n\n" + (source.content or "")
        target.content = merged.strip()
        target.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Apuntes combinados ✅", "success")
        return redirect(url_for("notes_list"))

    @app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
    @login_required
    def note_edit(note_id: int):
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()

        if request.method == "POST":
            subject_id = request.form.get("subject_id", type=int)
            subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
            if not subject:
                flash("Asignatura inválida.", "error")
                return redirect(url_for("note_edit", note_id=note.id))

            title = (request.form.get("title") or "").strip()
            if not title:
                # si no hay título, usamos la primera línea del contenido
                title = (request.form.get("content") or "").strip().splitlines()[0] if (request.form.get("content") or "").strip() else ""
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
            note.ai_used = False
            note.original_filename = None
            NoteSourceFile.query.filter_by(note_id=note.id).delete()

            db.session.commit()
            flash("Apunte actualizado ✅", "success")
            return redirect(url_for("notes_list"))

        return render_template("note_edit.html", note=note, subjects=subjects)

    @app.route("/notes/<int:note_id>/delete", methods=["POST"])
    @login_required
    def note_delete(note_id: int):
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
        NoteSourceFile.query.filter_by(note_id=note.id).delete()
        db.session.delete(note)
        db.session.commit()
        flash("Apunte borrado ✅", "success")
        return redirect(url_for("notes_list"))

    # ===========================
    # FLASHCARDS
    # ===========================

    @app.route("/flashcards/create", methods=["GET", "POST"])
    @login_required
    def flashcards_create():
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
        notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).all()
        decks = (
            FlashcardDeck.query.filter_by(user_id=current_user.id)
            .order_by(FlashcardDeck.updated_at.desc())
            .all()
        )
        available_models = fetch_models(app)
        selected_model = resolve_default_model(app, current_user.id, available_models)
        note_chunk_map = build_note_chunks_map(current_user.id, notes, max_tokens=3000, overlap=500)

        if request.method == "POST":
            mode = (request.form.get("mode") or "ai").strip()
            selected_model = request.form.get("model") or selected_model

            if mode == "ai":
                deck_id = request.form.get("deck_id", type=int)
                target_deck = None
                if deck_id:
                    target_deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=current_user.id).first()
                    if not target_deck:
                        flash("Deck de destino inválido.", "error")
                        return redirect(url_for("flashcards_create"))

                note_id = request.form.get("note_id", type=int)
                if not note_id:
                    flash("Selecciona un resumen/apunte para generar flashcards.", "error")
                    return redirect(url_for("flashcards_create"))

                note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
                if not note:
                    flash("Resumen/apunte inválido.", "error")
                    return redirect(url_for("flashcards_create"))

                custom_title = (request.form.get("ai_deck_title") or "").strip()
                count_per_chunk = max(1, min(request.form.get("count", type=int) or 5, 50))

                chunk_entry = note_chunk_map.get(note.id) or {"chunks": [note.content or ""], "total": 1}
                chunks = chunk_entry.get("chunks") or [note.content or ""]
                chunk_count = len(chunks)
                max_chunks_allowed = max(1, 50 // count_per_chunk) if count_per_chunk else 1
                if chunk_count > max_chunks_allowed:
                    chunks = chunks[:max_chunks_allowed]
                    chunk_count = len(chunks)

                if target_deck:
                    deck = target_deck
                else:
                    deck = FlashcardDeck(
                        user_id=current_user.id,
                        subject_id=note.subject_id,
                        title=custom_title or note.title,
                        exam_date=note.exam_date,
                        source_note_id=note.id,
                        flashcards=[],
                    )
                    db.session.add(deck)
                    db.session.commit()

                for idx, chunk in enumerate(chunks):
                    job = Job(
                        user_id=current_user.id,
                        type="flashcards_ai_chunk",
                        payload={
                            "user_id": current_user.id,
                            "note_id": note.id,
                            "deck_id": deck.id,
                            "model": selected_model,
                            "count": count_per_chunk,
                            "chunk_index": idx,
                            "total_chunks": chunk_count,
                            "text": chunk,
                        },
                    )
                    db.session.add(job)
                db.session.commit()
                total_cards = min(50, count_per_chunk * chunk_count)
                flash(f"Generación encolada ✅ {chunk_count} fragmentos × {count_per_chunk} (máx 50, total estimado {total_cards}).", "success")
                return redirect(url_for("flashcards_create"))

            # ---- MANUAL ----
            deck_id = request.form.get("deck_id", type=int)
            target_deck = None
            if deck_id:
                target_deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=current_user.id).first()
                if not target_deck:
                    flash("Deck de destino inválido.", "error")
                    return redirect(url_for("flashcards_create"))

            subject_choice = (request.form.get("subject_choice") or "").strip()
            new_subject_name = (request.form.get("new_subject_name") or "").strip()

            if not target_deck:
                if subject_choice == "__new__":
                    if not new_subject_name:
                        flash("Escribe el nombre de la nueva asignatura.", "error")
                        return redirect(url_for("flashcards_create"))
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
                        return redirect(url_for("flashcards_create"))
                    subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
                    if not subject:
                        flash("Asignatura inválida.", "error")
                        return redirect(url_for("flashcards_create"))

                title = (request.form.get("title") or "").strip()
                if not title:
                    flash("El título es obligatorio.", "error")
                    return redirect(url_for("flashcards_create"))

                exam_str = (request.form.get("exam_date") or "").strip()
                exam_date = None
                if exam_str:
                    try:
                        exam_date = datetime.strptime(exam_str, "%Y-%m-%d").date()
                    except ValueError:
                        flash("Formato de fecha inválido (YYYY-MM-DD).", "error")
                        return redirect(url_for("flashcards_create"))

            q = (request.form.get("q") or "").strip()
            a = (request.form.get("a") or "").strip()
            b = (request.form.get("b") or "").strip()
            c = (request.form.get("c") or "").strip()
            d = (request.form.get("d") or "").strip()
            correct = request.form.get("correct", type=int)

            if not q or not a or not b or not c or not d or correct is None:
                flash("Rellena pregunta, 4 respuestas y marca la correcta.", "error")
                return redirect(url_for("flashcards_create"))

            if correct not in (0, 1, 2, 3):
                flash("Índice de respuesta correcta inválido.", "error")
                return redirect(url_for("flashcards_create"))

            cards = [{"question": q, "options": [a, b, c, d], "correct_index": correct}]

            if target_deck:
                target_deck.flashcards = (target_deck.flashcards or []) + cards
                db.session.commit()
                flash("Flashcard añadida al deck existente ✅", "success")
                return redirect(url_for("flashcards_list"))
            else:
                deck = FlashcardDeck(
                    user_id=current_user.id,
                    subject_id=subject.id,
                    title=title,
                    exam_date=exam_date,
                    source_note_id=None,
                    flashcards=cards,
                )
                db.session.add(deck)
                db.session.commit()
                flash("Flashcard creada y guardada ✅", "success")
                return redirect(url_for("flashcards_list"))

        return render_template(
            "flashcards_create.html",
            subjects=subjects,
            notes=notes,
            note_chunk_counts={nid: info.get("total", 1) for nid, info in note_chunk_map.items()},
            models=available_models,
            selected_model=selected_model,
            decks=decks,
            jobs=Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).limit(10).all(),
        )

    @app.route("/flashcards")
    @login_required
    def flashcards_list():
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
        subject_id = request.args.get("subject_id", type=int)
        tema_q = (request.args.get("tema") or "").strip()
        title_q = (request.args.get("title") or "").strip()

        q = FlashcardDeck.query.filter_by(user_id=current_user.id)

        if subject_id:
            q = q.filter(FlashcardDeck.subject_id == subject_id)

        if tema_q:
            q = q.join(
                SubjectExam,
                (SubjectExam.subject_id == FlashcardDeck.subject_id)
                & (SubjectExam.exam_date == FlashcardDeck.exam_date),
            ).filter(SubjectExam.tema == tema_q)

        if title_q:
            q = q.filter(FlashcardDeck.title.ilike(f"%{title_q}%"))

        decks = q.order_by(FlashcardDeck.updated_at.desc()).all()
        deck_temas: dict[int, list[str]] = {}
        if decks:
            exam_pairs = {(d.subject_id, d.exam_date) for d in decks if d.exam_date}
            if exam_pairs:
                subject_ids = {sid for sid, _ in exam_pairs}
                exam_dates = {d for _, d in exam_pairs}
                tema_rows = SubjectExam.query.filter(
                    SubjectExam.subject_id.in_(subject_ids),
                    SubjectExam.exam_date.in_(exam_dates),
                ).all()
                temas_by_pair: dict[tuple, list[str]] = {}
                for row in tema_rows:
                    key = (row.subject_id, row.exam_date)
                    temas_by_pair.setdefault(key, []).append(row.tema)
                for deck in decks:
                    if not deck.exam_date:
                        continue
                    temas = temas_by_pair.get((deck.subject_id, deck.exam_date))
                    if temas:
                        deck_temas[deck.id] = sorted(set(temas))
        tema_options = fetch_tema_options(current_user.id, subject_id)
        filters_active = bool(subject_id or tema_q or title_q)

        return render_template(
            "flashcards_list.html",
            subjects=subjects,
            decks=decks,
            filters={"subject_id": subject_id or "", "tema": tema_q, "title": title_q},
            temas=tema_options,
            filters_active=filters_active,
            deck_temas=deck_temas,
        )

    @app.route("/flashcards/<int:deck_id>/edit", methods=["GET", "POST"])
    @login_required
    def flashcards_edit(deck_id: int):
        deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=current_user.id).first_or_404()
        subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
        notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).all()
        other_decks = (
            FlashcardDeck.query.filter(FlashcardDeck.user_id == current_user.id, FlashcardDeck.id != deck.id)
            .order_by(FlashcardDeck.updated_at.desc())
            .all()
        )
        available_models = fetch_models(app)
        selected_model = resolve_default_model(app, current_user.id, available_models)
        note_chunk_map = build_note_chunks_map(current_user.id, notes, max_tokens=3000, overlap=500)

        if request.method == "POST":
            mode = (request.form.get("mode") or "manual").strip()

            if mode == "append_ai":
                note_id = request.form.get("note_id", type=int)
                model = request.form.get("model") or selected_model
                if not note_id:
                    flash("Selecciona un resumen/apunte para generar flashcards.", "error")
                    return redirect(url_for("flashcards_edit", deck_id=deck.id))

                note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
                if not note:
                    flash("Resumen/apunte inválido.", "error")
                    return redirect(url_for("flashcards_edit", deck_id=deck.id))

                count_per_chunk = 5  # fijo en UI actual
                chunk_entry = note_chunk_map.get(note.id) or {"chunks": [note.content or ""], "total": 1}
                chunks = chunk_entry.get("chunks") or [note.content or ""]
                chunk_count = len(chunks)
                max_chunks_allowed = max(1, 50 // count_per_chunk)
                if chunk_count > max_chunks_allowed:
                    chunks = chunks[:max_chunks_allowed]
                    chunk_count = len(chunks)

                for idx, chunk in enumerate(chunks):
                    job = Job(
                        user_id=current_user.id,
                        type="flashcards_ai_chunk",
                        payload={
                            "user_id": current_user.id,
                            "note_id": note.id,
                            "deck_id": deck.id,
                            "model": model,
                            "count": count_per_chunk,
                            "chunk_index": idx,
                            "total_chunks": chunk_count,
                            "text": chunk,
                        },
                    )
                    db.session.add(job)
                db.session.commit()
                total_cards = min(50, count_per_chunk * chunk_count)
                flash(f"Generación de flashcards encolada ✅ {chunk_count} fragmentos × {count_per_chunk} (máx 50, total estimado {total_cards}).", "success")
                return redirect(url_for("flashcards_edit", deck_id=deck.id))

            if mode == "merge":
                merge_deck_id = request.form.get("merge_deck_id", type=int)
                source = None
                if merge_deck_id:
                    source = FlashcardDeck.query.filter_by(id=merge_deck_id, user_id=current_user.id).first()
                if not source:
                    flash("Deck a combinar inválido.", "error")
                    return redirect(url_for("flashcards_edit", deck_id=deck.id))

                deck.flashcards = (deck.flashcards or []) + (source.flashcards or [])
                db.session.commit()
                flash(f"Decks combinados ✅ Ahora hay {len(deck.flashcards)} flashcards.", "success")
                return redirect(url_for("flashcards_edit", deck_id=deck.id))

            subject_id = request.form.get("subject_id", type=int)
            subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
            if not subject:
                flash("Asignatura inválida.", "error")
                return redirect(url_for("flashcards_edit", deck_id=deck.id))

            title = (request.form.get("title") or "").strip()
            if not title:
                flash("El título es obligatorio.", "error")
                return redirect(url_for("flashcards_edit", deck_id=deck.id))

            exam_str = (request.form.get("exam_date") or "").strip()
            exam_date = None
            if exam_str:
                try:
                    exam_date = datetime.strptime(exam_str, "%Y-%m-%d").date()
                except ValueError:
                    flash("Formato de fecha inválido (YYYY-MM-DD).", "error")
                    return redirect(url_for("flashcards_edit", deck_id=deck.id))

            # Recoger cards desde form (permitiendo huecos en índices)
            cards = []
            idxs = sorted(
                {
                    int(k.split("_")[-1])
                    for k in request.form.keys()
                    if k.startswith("card_q_") and k.split("_")[-1].isdigit()
                }
            )
            for i in idxs:
                qtext = (request.form.get(f"card_q_{i}") or "").strip()
                o0 = (request.form.get(f"card_o0_{i}") or "").strip()
                o1 = (request.form.get(f"card_o1_{i}") or "").strip()
                o2 = (request.form.get(f"card_o2_{i}") or "").strip()
                o3 = (request.form.get(f"card_o3_{i}") or "").strip()
                correct = request.form.get(f"card_correct_{i}", type=int)

                # si la fila está vacía, la ignoramos
                if not qtext and not o0 and not o1 and not o2 and not o3:
                    continue

                if not qtext or not o0 or not o1 or not o2 or not o3 or correct is None:
                    flash(f"Flashcard #{i+1}: faltan campos.", "error")
                    return redirect(url_for("flashcards_edit", deck_id=deck.id))
                if correct not in (0, 1, 2, 3):
                    flash(f"Flashcard #{i+1}: correcta inválida.", "error")
                    return redirect(url_for("flashcards_edit", deck_id=deck.id))

                cards.append({"question": qtext, "options": [o0, o1, o2, o3], "correct_index": correct})

            if not cards:
                flash("Debes tener al menos 1 flashcard.", "error")
                return redirect(url_for("flashcards_edit", deck_id=deck.id))

            deck.subject_id = subject.id
            deck.title = title
            deck.exam_date = exam_date
            deck.flashcards = cards
            db.session.commit()

            flash("Flashcards actualizadas ✅", "success")
            return redirect(url_for("flashcards_list"))

        return render_template(
            "flashcards_edit.html",
            deck=deck,
            subjects=subjects,
            notes=notes,
            note_chunk_counts={nid: info.get("total", 1) for nid, info in note_chunk_map.items()},
            other_decks=other_decks,
            models=available_models,
            selected_model=selected_model,
            jobs=Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).limit(10).all(),
        )

    @app.route("/flashcards/<int:deck_id>/delete", methods=["POST"])
    @login_required
    def flashcards_delete(deck_id: int):
        deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=current_user.id).first_or_404()
        db.session.delete(deck)
        db.session.commit()
        flash("Deck de flashcards borrado ✅", "success")
        return redirect(url_for("flashcards_list"))

    return app


app = create_app()
