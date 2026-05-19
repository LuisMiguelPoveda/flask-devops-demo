from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from flask import current_app

HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def utcnow() -> datetime:
    # DB columns store naive UTC datetimes; strip tzinfo to stay compatible.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_subject_color(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    return value if HEX_COLOR_RE.match(value) else None


def fetch_ask_profe_history(user_id: int, limit: int = 12) -> list[dict]:
    from app.models import AskProfeMessage

    rows = (
        AskProfeMessage.query.filter_by(user_id=user_id)
        .order_by(AskProfeMessage.created_at.desc(), AskProfeMessage.id.desc())
        .limit(limit)
        .all()
    )
    rows.reverse()
    return [{"role": row.role, "content": row.content} for row in rows]


def prune_ask_profe_history(user_id: int, keep: int = 12) -> None:
    from app.models import AskProfeMessage, db

    extras = (
        AskProfeMessage.query.filter_by(user_id=user_id)
        .order_by(AskProfeMessage.created_at.desc(), AskProfeMessage.id.desc())
        .offset(keep)
        .all()
    )
    for msg in extras:
        db.session.delete(msg)


def fetch_tema_options(user_id: int, subject_id: int | None = None) -> list[str]:
    from app.models import Subject, SubjectExam, db

    q = (
        db.session.query(SubjectExam.tema)
        .join(Subject, SubjectExam.subject_id == Subject.id)
        .filter(Subject.user_id == user_id)
    )
    if subject_id:
        q = q.filter(SubjectExam.subject_id == subject_id)
    rows = q.distinct().order_by(SubjectExam.tema.asc()).all()
    return [r[0] for r in rows if r[0]]


def resolve_default_model(default_model: str, user_id: int | None, available_models: list[str] | None = None) -> str:
    from app.core.llm_profiles import LLM_OFFLINE_LABEL
    from app.models import StudentProfile

    if available_models and len(available_models) == 1 and available_models[0] == LLM_OFFLINE_LABEL:
        return LLM_OFFLINE_LABEL
    model = default_model
    if user_id:
        profile = StudentProfile.query.filter_by(user_id=user_id).first()
        if profile and profile.default_model:
            model = profile.default_model
    if available_models and model not in available_models:
        return available_models[0] if available_models else model
    return model


def is_setup_complete(user_id: int) -> bool:
    from app.models import StudentProfile

    if not user_id:
        return False
    profile = StudentProfile.query.filter_by(user_id=user_id).first()
    return profile is not None


def queue_has_work() -> bool:
    from app.models import Job, db

    return db.session.query(Job.id).filter(Job.status.in_(("pending", "running"))).first() is not None


def get_active_profe_lock(now: datetime | None = None):
    from app.models import ProfeSessionLock

    now = now or utcnow()
    lock = ProfeSessionLock.query.order_by(ProfeSessionLock.ends_at.desc()).first()
    if not lock or not lock.ends_at:
        return None
    if lock.ends_at <= now:
        return None
    return lock


def start_profe_lock(user_id: int, now: datetime | None = None):
    from app.models import ProfeSessionLock, db

    now = now or utcnow()
    ends_at = now + timedelta(seconds=current_app.config["ASK_PROFE_SESSION_SECONDS"])
    lock = ProfeSessionLock.query.order_by(ProfeSessionLock.ends_at.desc()).first()
    if lock:
        lock.user_id = user_id
        lock.starts_at = now
        lock.ends_at = ends_at
    else:
        lock = ProfeSessionLock(user_id=user_id, starts_at=now, ends_at=ends_at)
        db.session.add(lock)
    db.session.commit()
    return lock


def profe_is_busy(user_id: int | None = None) -> bool:
    lock = get_active_profe_lock()
    if lock:
        if user_id is not None and lock.user_id == user_id:
            return False
        return True
    return queue_has_work()
