from __future__ import annotations

from datetime import datetime
from io import BytesIO
from pathlib import Path

from flask import Blueprint, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app.core.file_extraction import MAX_UPLOAD_BYTES, allowed_file, extract_pdf_text, extract_pptx_text
from app.core.llm_profiles import FLASHCARD_CHUNK_DEFAULT
from app.core.text_processing import chunk_text_with_overlap
from app.models import (
    FlashcardDeck,
    Job,
    Note,
    NoteSourceFile,
    Subject,
    SubjectExam,
    db,
)
from app.services.job_service import has_incomplete_jobs_for_payload
from app.services.llm_client import get_llm_limits
from app.utils import fetch_tema_options, normalize_subject_color, resolve_default_model, utcnow

notes_bp = Blueprint("notes", __name__)


@notes_bp.route("/add-notes", endpoint="add_notes", methods=["GET", "POST"])
@login_required
def add_notes():
    subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
    available_models = current_app.extensions["llm_client"].fetch_models()
    selected_model = resolve_default_model(current_app.config["LMSTUDIO_MODEL"], current_user.id, available_models)
    llm_limits = get_llm_limits(current_user.id)
    chunk_tokens = llm_limits["chunk_tokens"]
    chunk_overlap = llm_limits["chunk_overlap"]

    if request.method == "POST":
        selected_model = request.form.get("model") or selected_model

        subject_choice = (request.form.get("subject_choice") or "").strip()
        new_subject_name = (request.form.get("new_subject_name") or "").strip()
        new_subject_color = (request.form.get("new_subject_color") or "").strip()
        normalized_color = normalize_subject_color(new_subject_color)

        if subject_choice == "__new__":
            if not new_subject_name:
                flash("Escribe el nombre de la nueva asignatura.", "error")
                return redirect(url_for("add_notes"))
            if new_subject_color and not normalized_color:
                flash("Color de asignatura inválido.", "error")
                return redirect(url_for("add_notes"))
            subject = Subject.query.filter_by(user_id=current_user.id, name=new_subject_name).first()
            if not subject:
                subject = Subject(
                    user_id=current_user.id,
                    name=new_subject_name,
                    color=normalized_color,
                )
                db.session.add(subject)
                db.session.commit()
            elif normalized_color and subject.color != normalized_color:
                subject.color = normalized_color
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

        tema_name = (request.form.get("tema_name") or "").strip()
        if exam_date and tema_name and not (request.form.get("exam_date_choice") or "").strip():
            if not SubjectExam.query.filter_by(
                subject_id=subject.id, exam_date=exam_date, tema=tema_name,
            ).first():
                db.session.add(SubjectExam(subject_id=subject.id, exam_date=exam_date, tema=tema_name))

        manual_text = (request.form.get("manual_text") or "").strip()
        manual_mode = request.form.get("manual_mode") == "on"
        manual_file_mode = request.form.get("manual_file_mode") == "on"
        auto_flashcards = request.form.get("auto_flashcards") == "on"

        uploads = [u for u in request.files.getlist("file") if u and u.filename]
        file_texts: list[str] = []
        filenames: list[str] = []
        source_bytes = None
        source_mime = None
        source_filename = None
        if uploads:
            for upload in uploads:
                if not allowed_file(upload.filename):
                    flash("Solo se permiten archivos .txt, .pdf o .pptx.", "error")
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
                if ext == "pdf":
                    file_mime = upload.mimetype or "application/pdf"
                    file_text = extract_pdf_text(file_bytes)
                elif ext == "pptx":
                    file_mime = (
                        upload.mimetype
                        or "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    )
                    file_text = extract_pptx_text(file_bytes)
                else:
                    file_mime = upload.mimetype or "text/plain"
                    try:
                        file_text = file_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        file_text = file_bytes.decode("utf-8", errors="ignore")
                file_text = (file_text or "").strip()
                if not file_text:
                    flash("El archivo no contiene texto legible.", "error")
                    return redirect(url_for("add_notes"))
                file_texts.append(file_text)
                filenames.append(filename)
                if len(uploads) == 1:
                    source_bytes = file_bytes
                    source_mime = file_mime
                    source_filename = filename
            combined_text = "\n\n".join(file_texts)
            if len(uploads) > 1:
                source_filename = "archivos_combinados.txt"
                source_bytes = combined_text.encode("utf-8")
                source_mime = "text/plain"
        else:
            combined_text = ""
            filename = None

        filename = source_filename if uploads else None

        content_text = manual_text if manual_text else combined_text
        if manual_mode or manual_file_mode:
            if not content_text:
                flash("Si eliges guardar sin IA, sube un TXT/PDF/PPTX o escribe contenido.", "error")
                return redirect(url_for("add_notes"))
            if title.strip():
                final_title = title.strip()
            else:
                base_name = Path(filename).stem if filename else subject.name
                created_str = utcnow().date().isoformat()
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

        if not file_texts:
            flash("Para usar IA sube un TXT, PDF o PPTX válido.", "error")
            return redirect(url_for("add_notes"))

        base_name = Path(filename or "input").stem
        if title.strip():
            final_title = title.strip()
        else:
            created_str = utcnow().date().isoformat()
            exam_part = exam_date.isoformat() if exam_date else ""
            final_title = f"{base_name} examen {exam_part} creado {created_str} ({selected_model})".strip()
        exam_date_str = exam_date.isoformat() if exam_date else "No indicada"
        chunks = []
        for text in file_texts:
            chunks.extend(
                chunk_text_with_overlap(
                    text,
                    max_tokens=chunk_tokens,
                    overlap=chunk_overlap,
                )
            )
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
        if source_bytes:
            db.session.add(
                NoteSourceFile(
                    note_id=note.id,
                    filename=filename or "input.txt",
                    content_type=source_mime or "application/octet-stream",
                    data=source_bytes,
                )
            )
        db.session.commit()

        deck = None
        if auto_flashcards:
            deck_title = None
            if exam_date:
                exam_row = (
                    SubjectExam.query.filter_by(subject_id=subject.id, exam_date=exam_date)
                    .order_by(SubjectExam.tema.asc())
                    .first()
                )
                if exam_row and exam_row.tema:
                    deck_title = exam_row.tema
            if not deck_title:
                deck_title = title.strip() if title.strip() else base_name or final_title
            deck = FlashcardDeck.query.filter_by(
                user_id=current_user.id,
                subject_id=subject.id,
                exam_date=exam_date,
                title=deck_title,
            ).first()
            if not deck:
                deck = FlashcardDeck(
                    user_id=current_user.id,
                    subject_id=subject.id,
                    title=deck_title,
                    exam_date=exam_date,
                    source_note_id=note.id,
                    flashcards=[],
                )
                db.session.add(deck)
                db.session.flush()

        deck_size_before = len(deck.flashcards or []) if deck else 0
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
            if auto_flashcards and deck:
                db.session.add(
                    Job(
                        user_id=current_user.id,
                        type="flashcards_ai_chunk",
                        payload={
                            "user_id": current_user.id,
                            "note_id": note.id,
                            "deck_id": deck.id,
                            "deck_size_before": deck_size_before,
                            "model": selected_model,
                            "count": FLASHCARD_CHUNK_DEFAULT,
                            "chunk_index": idx,
                            "total_chunks": len(chunks),
                            "text": chunk,
                        },
                    )
                )
        db.session.commit()

        if auto_flashcards and deck:
            total_cards = len(chunks) * FLASHCARD_CHUNK_DEFAULT
            flash(
                "Resumen encolado en "
                f"{len(chunks)} fragmento(s) ✅ Flashcards en cola: "
                f"{len(chunks)} × {FLASHCARD_CHUNK_DEFAULT} (total estimado {total_cards}).",
                "success",
            )
        else:
            flash(
                f"Resumen encolado en {len(chunks)} fragmento(s) ✅ Se irá completando a medida que procesamos cada parte.",
                "success",
            )
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
        chunk_tokens=chunk_tokens,
        chunk_overlap=chunk_overlap,
        jobs=jobs,
    )


@notes_bp.route("/notes", endpoint="notes_list")
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


@notes_bp.route("/notes/<int:note_id>/source-file", endpoint="note_source_file")
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


@notes_bp.route("/notes/merge", endpoint="notes_merge", methods=["POST"])
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
    target.updated_at = utcnow()
    db.session.commit()
    flash("Apuntes combinados ✅", "success")
    return redirect(url_for("notes_list"))


@notes_bp.route("/notes/<int:note_id>/edit", endpoint="note_edit", methods=["GET", "POST"])
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


@notes_bp.route("/notes/<int:note_id>/delete", endpoint="note_delete", methods=["POST"])
@login_required
def note_delete(note_id: int):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    if has_incomplete_jobs_for_payload(current_user.id, "note_id", note.id):
        flash("No puedes borrar este apunte mientras haya trabajos en curso.", "error")
        return redirect(url_for("notes_list"))
    try:
        NoteSourceFile.query.filter_by(note_id=note.id).delete()
        FlashcardDeck.query.filter_by(source_note_id=note.id).update({"source_note_id": None})
        db.session.delete(note)
        db.session.commit()
        flash("Apunte borrado ✅", "success")
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Error borrando apunte %s", note_id)
        flash("No se pudo borrar el apunte.", "error")
    return redirect(url_for("notes_list"))
