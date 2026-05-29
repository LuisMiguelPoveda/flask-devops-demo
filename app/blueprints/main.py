from __future__ import annotations

import os
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.core.llm_profiles import TASK_WINDOW_LABELS
from app.models import (
    ChallengeResult,
    FlashcardDeck,
    Job,
    Note,
    NoteSourceFile,
    StudentProfile,
    db,
)
from app.services.calendar_service import build_calendar_items, calendar_window_range
from app.services.job_service import INCOMPLETE_JOB_STATUSES, build_queue_groups, payload_int
from app.utils import utcnow

main_bp = Blueprint("main", __name__)


@main_bp.route("/dashboard", endpoint="dashboard")
@login_required
def dashboard():
    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    student_name = profile.student_name if profile else current_user.username
    window_days, window_start, window_end = calendar_window_range(profile)
    calendar_items = build_calendar_items(current_user.id, window_start, window_end, window_start)
    calendar_label = TASK_WINDOW_LABELS.get(window_days, f"{window_days} días")
    queue_groups = build_queue_groups(current_user.id)

    # Per-exam challenge accuracy (last 5 results per exam_date in window)
    exam_accuracy = {}
    if window_start and window_end:
        exam_items = [item for item in calendar_items if item["kind"] == "exam"]
        if exam_items:
            recent_results = (
                ChallengeResult.query
                .filter_by(user_id=current_user.id)
                .order_by(ChallengeResult.created_at.desc())
                .limit(100)
                .all()
            )
            for item in exam_items:
                edate_str = str(item["date"])
                subject_id = item["subject"].id if item["subject"] else None
                exam_key = f"{edate_str}_{subject_id}"
                matching = [
                    r for r in recent_results
                    if edate_str in (r.exam_dates or [])
                ][:5]
                if matching:
                    total_correct = 0
                    total_q = 0
                    for r in matching:
                        es = (r.per_exam_stats or {}).get(exam_key)
                        if es:
                            total_correct += es.get("correct", 0)
                            total_q += es.get("total", 0)
                    if total_q > 0:
                        pct = round(total_correct / total_q * 100)
                        exam_accuracy[exam_key] = {"pct": pct, "count": len(matching)}

    return render_template(
        "dashboard.html",
        student_name=student_name,
        queue_groups=queue_groups,
        calendar_items=calendar_items,
        calendar_window_label=calendar_label,
        calendar_window_start=window_start,
        calendar_window_end=window_end,
        exam_accuracy=exam_accuracy,
    )


@main_bp.route("/jobs/cancel", endpoint="cancel_jobs", methods=["POST"])
@login_required
def cancel_jobs():
    group_kind = (request.form.get("group_kind") or "").strip()
    if group_kind == "note":
        note_id = request.form.get("note_id", type=int)
        if not note_id:
            flash("Apunte inválido para cancelar.", "error")
            return redirect(url_for("dashboard"))

        jobs = (
            Job.query.filter(
                Job.user_id == current_user.id,
                Job.type.in_(
                    (
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
        related_jobs = [job for job in jobs if payload_int(job.payload or {}, "note_id") == note_id]
        if not related_jobs:
            flash("No se encontraron trabajos para ese apunte.", "error")
            return redirect(url_for("dashboard"))

        incomplete_jobs = [job for job in related_jobs if job.status in INCOMPLETE_JOB_STATUSES]
        if not incomplete_jobs:
            flash("No hay trabajos en curso para ese apunte.", "error")
            return redirect(url_for("dashboard"))
        start_at = min((job.created_at or datetime.min) for job in incomplete_jobs)
        related_jobs = [
            job
            for job in related_jobs
            if (job.created_at or datetime.min) >= start_at
        ]
        deck_ids = {
            payload_int(job.payload or {}, "deck_id")
            for job in related_jobs
            if payload_int(job.payload or {}, "deck_id") is not None
        }

        for job in related_jobs:
            if job.status in INCOMPLETE_JOB_STATUSES:
                job.status = "cancelled"
                job.result_message = None
                job.error_message = "Cancelado por el usuario."
                job.updated_at = utcnow()

        has_note_generation = any(
            job.type in ("note_ai", "note_ai_chunk") for job in related_jobs
        )

        decks_to_check = []
        if deck_ids:
            decks_to_check = (
                FlashcardDeck.query.filter(
                    FlashcardDeck.user_id == current_user.id,
                    FlashcardDeck.id.in_(deck_ids),
                )
                .all()
            )

        for deck in decks_to_check:
            if has_note_generation and deck.source_note_id == note_id:
                db.session.delete(deck)
                continue
            deck_jobs = [
                job
                for job in related_jobs
                if payload_int(job.payload or {}, "deck_id") == deck.id
            ]
            sizes = [
                payload_int(job.payload or {}, "deck_size_before")
                for job in deck_jobs
                if payload_int(job.payload or {}, "deck_size_before") is not None
            ]
            if sizes:
                keep_size = min(sizes)
                deck.flashcards = (deck.flashcards or [])[:keep_size]

        if has_note_generation:
            note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
            if note:
                NoteSourceFile.query.filter_by(note_id=note.id).delete()
                db.session.delete(note)

        db.session.commit()
        flash("Generación cancelada ✅ Se han eliminado resultados parciales.", "success")
        return redirect(url_for("dashboard"))

    if group_kind == "file_import":
        job_id = request.form.get("job_id", type=int)
        if not job_id:
            flash("Trabajo inválido para cancelar.", "error")
            return redirect(url_for("dashboard"))
        job = Job.query.filter_by(id=job_id, user_id=current_user.id, type="file_import").first()
        if not job:
            flash("Trabajo no encontrado.", "error")
            return redirect(url_for("dashboard"))
        if job.status in INCOMPLETE_JOB_STATUSES:
            job.status = "cancelled"
            job.result_message = None
            job.error_message = "Cancelado por el usuario."
            job.updated_at = utcnow()
        payload = job.payload or {}
        file_path = payload.get("file_path") if isinstance(payload, dict) else None
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
        db.session.commit()
        flash("Trabajo cancelado ✅", "success")
        return redirect(url_for("dashboard"))

    flash("No se pudo cancelar la cola solicitada.", "error")
    return redirect(url_for("dashboard"))


@main_bp.route("/health", endpoint="health")
def health():
    return jsonify({"status": "ok"}), 200
