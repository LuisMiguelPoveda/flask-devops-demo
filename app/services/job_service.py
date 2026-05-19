from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from requests.exceptions import RequestException, Timeout

from app.core.file_extraction import MAX_UPLOAD_BYTES, extract_pdf_text, extract_pptx_text
from app.core.llm_profiles import FLASHCARD_CHUNK_DEFAULT
from app.core.text_processing import chunk_text_with_overlap, estimate_summary_max_tokens
from app.services.llm_client import get_llm_limits

JOB_RETRY_SECONDS = 30
INCOMPLETE_JOB_STATUSES = ("pending", "running")


def payload_int(payload: dict | None, key: str) -> int | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def has_incomplete_jobs_for_payload(user_id: int, key: str, value: int | None) -> bool:
    from app.models import Job

    if value is None:
        return False
    jobs = Job.query.filter(
        Job.user_id == user_id,
        Job.status.in_(INCOMPLETE_JOB_STATUSES),
    ).all()
    for job in jobs:
        if payload_int(job.payload or {}, key) == value:
            return True
    return False


def job_is_cancelled(job_id: int | None) -> bool:
    from app.models import Job, db

    if not job_id:
        return False
    status = db.session.query(Job.status).filter_by(id=job_id).scalar()
    return status == "cancelled"


def commit_if_not_cancelled(job_id: int) -> bool:
    from app.models import db

    with db.session.no_autoflush:
        if job_is_cancelled(job_id):
            db.session.rollback()
            return False
    db.session.commit()
    return True


def build_queue_groups(user_id: int) -> list[dict]:
    from app.models import FlashcardDeck, Job, Note

    jobs = (
        Job.query.filter(
            Job.user_id == user_id,
            Job.type.in_(
                (
                    "file_import",
                    "note_ai",
                    "note_ai_chunk",
                    "flashcards_ai_new",
                    "flashcards_ai_append",
                    "flashcards_ai_chunk",
                )
            ),
        )
        .order_by(Job.created_at.asc(), Job.id.asc())
        .all()
    )
    notes = {note.id: note for note in Note.query.filter_by(user_id=user_id).all()}
    decks = {deck.id: deck for deck in FlashcardDeck.query.filter_by(user_id=user_id).all()}

    note_groups: dict[int, dict] = {}
    file_groups: list[dict] = []

    for job in jobs:
        payload = job.payload or {}
        if job.type == "file_import":
            if job.status in INCOMPLETE_JOB_STATUSES:
                file_groups.append(
                    {
                        "kind": "file_import",
                        "job_id": job.id,
                        "title": payload.get("filename") or "Archivo en cola",
                        "status": job.status,
                        "created_at": job.created_at,
                    }
                )
            continue

        note_id = payload_int(payload, "note_id")
        if not note_id:
            continue
        group = note_groups.setdefault(
            note_id,
            {
                "note_id": note_id,
                "jobs": [],
                "earliest_incomplete": None,
            },
        )
        group["jobs"].append(job)
        if job.status in INCOMPLETE_JOB_STATUSES:
            job_created = job.created_at or datetime.min
            if not group["earliest_incomplete"] or job_created < group["earliest_incomplete"]:
                group["earliest_incomplete"] = job_created

    groups: list[dict] = []
    for note_id, group in note_groups.items():
        start_at = group.get("earliest_incomplete")
        if not start_at:
            continue
        jobs = [
            job
            for job in group["jobs"]
            if (job.created_at or datetime.min) >= start_at
        ]
        if not any(job.status in INCOMPLETE_JOB_STATUSES for job in jobs):
            continue
        deck_ids = set()
        for job in jobs:
            deck_id = payload_int(job.payload or {}, "deck_id")
            if deck_id:
                deck_ids.add(deck_id)
        summary_jobs = [job for job in jobs if job.type in ("note_ai", "note_ai_chunk")]
        flash_jobs = [
            job
            for job in jobs
            if job.type in ("flashcards_ai_new", "flashcards_ai_append", "flashcards_ai_chunk")
        ]
        summary_done = sum(1 for job in summary_jobs if job.status == "success")
        flash_done = sum(1 for job in flash_jobs if job.status == "success")
        deck_titles = [decks[d].title for d in deck_ids if d in decks and decks[d].title]
        note = notes.get(note_id)
        created_at = min(
            (job.created_at for job in jobs if job.created_at),
            default=start_at,
        )
        groups.append(
            {
                "kind": "note",
                "note_id": note_id,
                "title": note.title if note else f"Apunte #{note_id}",
                "summary_done": summary_done,
                "summary_total": len(summary_jobs),
                "flash_done": flash_done,
                "flash_total": len(flash_jobs),
                "deck_titles": deck_titles,
                "created_at": created_at,
            }
        )

    groups.extend(file_groups)
    groups.sort(key=lambda item: item.get("created_at") or datetime.min, reverse=True)
    return groups


def process_job(app, job):
    from app.models import (
        FlashcardDeck,
        Job,
        Note,
        NoteSourceFile,
        Subject,
        SubjectExam,
        User,
        db,
    )

    with app.app_context():
        try:
            if job.type == "file_import":
                payload = job.payload or {}
                user_id = payload.get("user_id")
                subject_id = payload.get("subject_id")
                exam_id = payload.get("exam_id")
                filename = payload.get("filename") or "input.txt"
                file_path = payload.get("file_path") or ""
                content_type = payload.get("content_type") or ""
                model = payload.get("model") or app.config["LMSTUDIO_MODEL"]

                if not file_path or not os.path.exists(file_path):
                    return "error", None, "Archivo subido no encontrado."

                subject = Subject.query.filter_by(id=subject_id, user_id=user_id).first()
                if not subject:
                    return "error", None, "Asignatura inválida para el archivo."
                exam = SubjectExam.query.filter_by(id=exam_id, subject_id=subject.id).first()
                if not exam:
                    return "error", None, "Examen inválido para el archivo."

                file_size = os.path.getsize(file_path)
                if file_size == 0:
                    return "error", None, "El archivo está vacío."
                if file_size > MAX_UPLOAD_BYTES:
                    return "error", None, f"Archivo demasiado grande. Máximo {MAX_UPLOAD_BYTES // 1024} KB."

                with open(file_path, "rb") as handle:
                    file_bytes = handle.read()
                if not file_bytes:
                    return "error", None, "El archivo está vacío."

                ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
                if ext == "pdf":
                    file_mime = content_type or "application/pdf"
                    file_text = extract_pdf_text(file_bytes)
                elif ext == "pptx":
                    file_mime = (
                        content_type
                        or "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    )
                    file_text = extract_pptx_text(file_bytes)
                else:
                    file_mime = content_type or "text/plain"
                    try:
                        file_text = file_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        file_text = file_bytes.decode("utf-8", errors="ignore")
                file_text = (file_text or "").strip()
                if not file_text:
                    return "error", None, "El archivo no contiene texto legible."
                limits = get_llm_limits(user_id)
                chunks = chunk_text_with_overlap(
                    file_text,
                    max_tokens=limits["chunk_tokens"],
                    overlap=limits["chunk_overlap"],
                )
                if not chunks:
                    return "error", None, "No se pudo dividir el texto para IA."
                if job_is_cancelled(job.id):
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)
                    return "cancelled", None, None

                exam_date_str = exam.exam_date.isoformat() if exam.exam_date else "No indicada"
                base_name = Path(filename).stem if filename else subject.name
                note_title = f"{exam.tema} - {base_name}".strip(" -")
                if exam_date_str != "No indicada":
                    note_title = f"{note_title} ({exam_date_str})"
                deck_title = exam.tema

                note = Note(
                    user_id=user_id,
                    subject_id=subject.id,
                    title=note_title,
                    exam_date=exam.exam_date,
                    original_filename=filename,
                    content=f"{note_title}\n\n",
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

                deck = FlashcardDeck.query.filter_by(
                    user_id=user_id,
                    subject_id=subject.id,
                    exam_date=exam.exam_date,
                    title=deck_title,
                ).first()
                if not deck:
                    deck = FlashcardDeck(
                        user_id=user_id,
                        subject_id=subject.id,
                        title=deck_title,
                        exam_date=exam.exam_date,
                        source_note_id=note.id,
                        flashcards=[],
                    )
                    db.session.add(deck)
                    db.session.flush()

                deck_size_before = len(deck.flashcards or [])
                for idx, chunk in enumerate(chunks):
                    db.session.add(
                        Job(
                            user_id=user_id,
                            type="note_ai_chunk",
                            payload={
                                "user_id": user_id,
                                "subject_id": subject.id,
                                "note_id": note.id,
                                "title": note_title,
                                "exam_date": exam_date_str,
                                "filename": filename or "input.txt",
                                "text": chunk,
                                "model": model,
                                "chunk_index": idx,
                                "total_chunks": len(chunks),
                            },
                        )
                    )
                    db.session.add(
                        Job(
                            user_id=user_id,
                            type="flashcards_ai_chunk",
                            payload={
                                "user_id": user_id,
                                "note_id": note.id,
                                "deck_id": deck.id,
                                "deck_size_before": deck_size_before,
                                "model": model,
                                "count": FLASHCARD_CHUNK_DEFAULT,
                                "chunk_index": idx,
                                "total_chunks": len(chunks),
                                "text": chunk,
                            },
                        )
                    )
                if not commit_if_not_cancelled(job.id):
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)
                    return "cancelled", None, None
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                return "success", f"Archivo procesado: {filename}", None

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

                limits = get_llm_limits(user_id)
                max_tokens = estimate_summary_max_tokens(
                    text,
                    max_tokens=limits["summary_max_tokens"],
                    min_tokens=limits["summary_min_tokens"],
                    ratio=limits["summary_ratio"],
                )
                content = app.extensions["llm_client"].summarize(
                    model, subject.name, title, exam_date_str, filename, text, max_tokens=max_tokens,
                )
                if not content.strip():
                    return "error", None, "El modelo devolvió un resumen vacío."
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
                if not commit_if_not_cancelled(job.id):
                    return "cancelled", None, None
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
                limits = get_llm_limits(user_id)
                max_tokens = estimate_summary_max_tokens(
                    text,
                    max_tokens=limits["summary_max_tokens"],
                    min_tokens=limits["summary_min_tokens"],
                    ratio=limits["summary_ratio"],
                )
                summary = app.extensions["llm_client"].summarize(
                    model, subject.name, note.title, exam_date_str, filename, text,
                    max_tokens=max_tokens, chunk_index=chunk_index, total_chunks=total_chunks,
                )
                if not summary.strip():
                    return "error", None, "El modelo devolvió un resumen vacío para el fragmento."

                existing = (note.content or "").rstrip()
                separator = "\n\n" if existing else ""
                note.content = f"{existing}{separator}{summary.strip()}"
                note.ai_used = True
                if not commit_if_not_cancelled(job.id):
                    return "cancelled", None, None

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

                exam_date_str = note.exam_date.isoformat() if note.exam_date else "No indicada"
                cards = app.extensions["llm_client"].generate_flashcards(
                    model, note.subject.name, note.title, exam_date_str, note.content or "", count=count,
                )

                if job.type == "flashcards_ai_append":
                    deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=user_id).first()
                    if not deck:
                        return "error", None, "Deck inválido."
                    deck.flashcards = (deck.flashcards or []) + cards
                    if not commit_if_not_cancelled(job.id):
                        return "cancelled", None, None
                    return "success", f"{len(cards)} flashcards añadidas a {deck.title}", None

                deck = FlashcardDeck(
                    user_id=user_id,
                    subject_id=note.subject_id,
                    title=custom_title or note.title,
                    exam_date=note.exam_date,
                    source_note_id=note.id,
                    flashcards=cards,
                )
                db.session.add(deck)
                if not commit_if_not_cancelled(job.id):
                    return "cancelled", None, None
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

                exam_date_str = note.exam_date.isoformat() if note.exam_date else "No indicada"
                cards = app.extensions["llm_client"].generate_flashcards(
                    model, note.subject.name, note.title, exam_date_str,
                    chunk_text or note.content or "", count=count,
                )
                deck.flashcards = (deck.flashcards or []) + cards
                if not commit_if_not_cancelled(job.id):
                    return "cancelled", None, None

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
