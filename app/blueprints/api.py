from __future__ import annotations

from flask import Blueprint, jsonify
from flask_login import current_user, login_required
from sqlalchemy.exc import OperationalError

from app.core.text_processing import simple_format_note
from app.models import Job, Note, Subject, SubjectExam, db
from app.utils import profe_is_busy, queue_has_work

api_bp = Blueprint("api", __name__)


@api_bp.app_template_filter("note_fmt")
def note_fmt_filter(text: str):
    return simple_format_note(text)


@api_bp.route("/api/exam-dates", endpoint="api_exam_dates")
@login_required
def api_exam_dates():
    from flask import request
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


@api_bp.route("/api/titles", endpoint="api_titles")
@login_required
def api_titles():
    from flask import request
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


@api_bp.route("/api/jobs/queue", endpoint="api_jobs_queue")
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


@api_bp.route("/api/profe/status", endpoint="api_profe_status")
@login_required
def api_profe_status():
    return jsonify({"profe_busy": profe_is_busy(current_user.id), "llm_busy": queue_has_work()})


@api_bp.route("/api/jobs/updates", endpoint="api_jobs_updates")
@login_required
def api_jobs_updates():
    try:
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
    except OperationalError as exc:
        db.session.rollback()
        if "database is locked" in str(exc).lower():
            return jsonify({"jobs": [], "llm_busy": queue_has_work()})
        raise
    return jsonify({"jobs": payload, "llm_busy": queue_has_work()})
