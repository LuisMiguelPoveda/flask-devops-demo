from __future__ import annotations

from datetime import datetime

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.core.llm_profiles import FLASHCARD_CHUNK_COUNTS, FLASHCARD_CHUNK_DEFAULT
from app.models import FlashcardDeck, Job, Note, Subject, SubjectExam, db
from app.services.job_service import has_incomplete_jobs_for_payload
from app.services.llm_client import get_llm_limits
from app.services.note_service import build_note_chunks_map
from app.utils import fetch_tema_options, normalize_subject_color, resolve_default_model

flashcards_bp = Blueprint("flashcards", __name__)


@flashcards_bp.route("/flashcards/create", endpoint="flashcards_create", methods=["GET", "POST"])
@login_required
def flashcards_create():
    subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
    notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).all()
    decks = (
        FlashcardDeck.query.filter_by(user_id=current_user.id)
        .order_by(FlashcardDeck.updated_at.desc())
        .all()
    )
    available_models = current_app.extensions["llm_client"].fetch_models()
    selected_model = resolve_default_model(current_app.config["LMSTUDIO_MODEL"], current_user.id, available_models)
    llm_limits = get_llm_limits(current_user.id)
    chunk_tokens = llm_limits["chunk_tokens"]
    chunk_overlap = llm_limits["chunk_overlap"]
    note_chunk_map = build_note_chunks_map(
        current_user.id,
        notes,
        max_tokens=chunk_tokens,
        overlap=chunk_overlap,
    )

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
            count_per_chunk = request.form.get("count", type=int) or FLASHCARD_CHUNK_DEFAULT
            if count_per_chunk not in FLASHCARD_CHUNK_COUNTS:
                flash("Selecciona una cantidad válida de flashcards por fragmento.", "error")
                return redirect(url_for("flashcards_create"))

            chunk_entry = note_chunk_map.get(note.id) or {"chunks": [note.content or ""], "total": 1}
            chunks = chunk_entry.get("chunks") or [note.content or ""]
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

            deck_size_before = len(deck.flashcards or [])
            for idx, chunk in enumerate(chunks):
                job = Job(
                    user_id=current_user.id,
                    type="flashcards_ai_chunk",
                    payload={
                        "user_id": current_user.id,
                        "note_id": note.id,
                        "deck_id": deck.id,
                        "deck_size_before": deck_size_before,
                        "model": selected_model,
                        "count": count_per_chunk,
                        "chunk_index": idx,
                        "total_chunks": chunk_count,
                        "text": chunk,
                    },
                )
                db.session.add(job)
            db.session.commit()
            total_cards = count_per_chunk * chunk_count
            flash(f"Generación encolada ✅ {chunk_count} fragmentos × {count_per_chunk} (total estimado {total_cards}).", "success")
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
        new_subject_color = (request.form.get("new_subject_color") or "").strip()
        normalized_color = normalize_subject_color(new_subject_color)

        if not target_deck:
            if subject_choice == "__new__":
                if not new_subject_name:
                    flash("Escribe el nombre de la nueva asignatura.", "error")
                    return redirect(url_for("flashcards_create"))
                if new_subject_color and not normalized_color:
                    flash("Color de asignatura inválido.", "error")
                    return redirect(url_for("flashcards_create"))
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
        chunk_tokens=chunk_tokens,
        chunk_overlap=chunk_overlap,
        decks=decks,
        count_options=FLASHCARD_CHUNK_COUNTS,
        default_count=FLASHCARD_CHUNK_DEFAULT,
        jobs=Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).limit(10).all(),
    )


@flashcards_bp.route("/flashcards", endpoint="flashcards_list")
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

    page = request.args.get("page", 1, type=int)
    pagination = q.order_by(FlashcardDeck.updated_at.desc()).paginate(page=page, per_page=20, error_out=False)
    decks = pagination.items
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
        pagination=pagination,
        filters={"subject_id": subject_id or "", "tema": tema_q, "title": title_q},
        temas=tema_options,
        filters_active=filters_active,
        deck_temas=deck_temas,
    )


@flashcards_bp.route("/flashcards/<int:deck_id>/edit", endpoint="flashcards_edit", methods=["GET", "POST"])
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
    available_models = current_app.extensions["llm_client"].fetch_models()
    selected_model = resolve_default_model(current_app.config["LMSTUDIO_MODEL"], current_user.id, available_models)
    llm_limits = get_llm_limits(current_user.id)
    chunk_tokens = llm_limits["chunk_tokens"]
    chunk_overlap = llm_limits["chunk_overlap"]
    note_chunk_map = build_note_chunks_map(
        current_user.id,
        notes,
        max_tokens=chunk_tokens,
        overlap=chunk_overlap,
    )

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

            count_per_chunk = request.form.get("count", type=int) or FLASHCARD_CHUNK_DEFAULT
            if count_per_chunk not in FLASHCARD_CHUNK_COUNTS:
                flash("Selecciona una cantidad válida de flashcards por fragmento.", "error")
                return redirect(url_for("flashcards_edit", deck_id=deck.id))
            chunk_entry = note_chunk_map.get(note.id) or {"chunks": [note.content or ""], "total": 1}
            chunks = chunk_entry.get("chunks") or [note.content or ""]
            chunk_count = len(chunks)

            deck_size_before = len(deck.flashcards or [])
            for idx, chunk in enumerate(chunks):
                job = Job(
                    user_id=current_user.id,
                    type="flashcards_ai_chunk",
                    payload={
                        "user_id": current_user.id,
                        "note_id": note.id,
                        "deck_id": deck.id,
                        "deck_size_before": deck_size_before,
                        "model": model,
                        "count": count_per_chunk,
                        "chunk_index": idx,
                        "total_chunks": chunk_count,
                        "text": chunk,
                    },
                )
                db.session.add(job)
            db.session.commit()
            total_cards = count_per_chunk * chunk_count
            flash(f"Generación de flashcards encolada ✅ {chunk_count} fragmentos × {count_per_chunk} (total estimado {total_cards}).", "success")
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
        count_options=FLASHCARD_CHUNK_COUNTS,
        default_count=FLASHCARD_CHUNK_DEFAULT,
        jobs=Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).limit(10).all(),
    )


@flashcards_bp.route("/flashcards/<int:deck_id>/study", endpoint="flashcards_study")
@login_required
def flashcards_study(deck_id: int):
    deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=current_user.id).first_or_404()
    return render_template("flashcards_study.html", deck=deck)


@flashcards_bp.route("/flashcards/<int:deck_id>/delete", endpoint="flashcards_delete", methods=["POST"])
@login_required
def flashcards_delete(deck_id: int):
    deck = FlashcardDeck.query.filter_by(id=deck_id, user_id=current_user.id).first_or_404()
    if has_incomplete_jobs_for_payload(current_user.id, "deck_id", deck.id):
        flash("No puedes borrar este deck mientras haya trabajos en curso.", "error")
        return redirect(url_for("flashcards_list"))
    db.session.delete(deck)
    db.session.commit()
    flash("Deck de flashcards borrado ✅", "success")
    return redirect(url_for("flashcards_list"))
