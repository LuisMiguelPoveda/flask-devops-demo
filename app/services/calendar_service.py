from __future__ import annotations

from datetime import timedelta

from app.core.llm_profiles import TASK_WINDOW_DEFAULT, TASK_WINDOW_VALUES
from app.utils import utcnow


def resolve_task_window_days(profile) -> int:
    if profile and profile.task_window_days in TASK_WINDOW_VALUES:
        return profile.task_window_days
    return TASK_WINDOW_DEFAULT


def calendar_window_range(profile):
    window_days = resolve_task_window_days(profile)
    today = utcnow().date()
    if window_days == 0:
        return window_days, None, None
    end_date = today + timedelta(days=max(1, window_days) - 1)
    return window_days, today, end_date


def build_calendar_items(user_id: int, start_date, end_date, today=None) -> list[dict]:
    from app.models import Subject, SubjectExam, TaskItem

    if today is None:
        today = utcnow().date()
    tasks_query = TaskItem.query.filter_by(user_id=user_id)
    exams_query = SubjectExam.query.join(Subject, SubjectExam.subject_id == Subject.id).filter(
        Subject.user_id == user_id
    )
    if start_date is not None and end_date is not None:
        tasks_query = tasks_query.filter(TaskItem.due_date >= start_date, TaskItem.due_date <= end_date)
        exams_query = exams_query.filter(SubjectExam.exam_date >= start_date, SubjectExam.exam_date <= end_date)
    tasks = tasks_query.order_by(TaskItem.due_date.asc(), TaskItem.title.asc()).all()
    exams = exams_query.order_by(SubjectExam.exam_date.asc(), SubjectExam.tema.asc()).all()

    def relative_label(target_date):
        delta_days = (target_date - today).days
        if delta_days < 0:
            days = abs(delta_days)
            return "Hace 1 día" if days == 1 else f"Hace {days} días"
        if delta_days == 0:
            return "Hoy"
        if delta_days == 1:
            return "Mañana"
        return f"En {delta_days} días"

    items: list[dict] = []
    for task in tasks:
        items.append(
            {
                "kind": "task",
                "date": task.due_date,
                "title": task.title,
                "notes": task.notes,
                "subject": task.subject,
                "task": task,
                "relative_label": relative_label(task.due_date),
            }
        )
    for exam in exams:
        items.append(
            {
                "kind": "exam",
                "date": exam.exam_date,
                "title": exam.tema,
                "subject": exam.subject,
                "exam": exam,
                "relative_label": relative_label(exam.exam_date),
            }
        )

    items.sort(key=lambda item: (item["date"], item["kind"], (item["title"] or "").lower()))
    return items
