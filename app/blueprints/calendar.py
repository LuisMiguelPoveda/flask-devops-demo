from __future__ import annotations

from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.core.llm_profiles import TASK_WINDOW_LABELS, TASK_WINDOW_OPTIONS, TASK_WINDOW_VALUES
from app.models import StudentProfile, Subject, SubjectExam, TaskItem, db
from app.services.calendar_service import build_calendar_items, calendar_window_range
from app.utils import normalize_subject_color

calendar_bp = Blueprint("calendar", __name__)


@calendar_bp.route("/calendar", endpoint="task_calendar")
@login_required
def task_calendar():
    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    student_name = profile.student_name if profile else current_user.username
    window_days, window_start, window_end = calendar_window_range(profile)
    calendar_items = build_calendar_items(current_user.id, window_start, window_end, window_start)
    window_label = TASK_WINDOW_LABELS.get(window_days, f"{window_days} días")
    subjects = Subject.query.filter_by(user_id=current_user.id).order_by(Subject.name.asc()).all()
    return render_template(
        "calendar.html",
        student_name=student_name,
        window_options=TASK_WINDOW_OPTIONS,
        window_days=window_days,
        window_label=window_label,
        window_start=window_start,
        window_end=window_end,
        calendar_items=calendar_items,
        subjects=subjects,
    )


@calendar_bp.route("/calendar/window", endpoint="task_calendar_window_update", methods=["POST"])
@login_required
def task_calendar_window_update():
    window_days = request.form.get("window_days", type=int)
    if window_days not in TASK_WINDOW_VALUES:
        flash("Selecciona un periodo válido.", "error")
        return redirect(url_for("task_calendar"))

    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash("Completa el perfil antes de configurar el calendario.", "error")
        return redirect(url_for("setup"))

    try:
        profile.task_window_days = window_days
        db.session.commit()
        flash("Periodo actualizado ✅", "success")
    except Exception:
        db.session.rollback()
        flash("No se pudo actualizar el periodo.", "error")
    return redirect(url_for("task_calendar"))


@calendar_bp.route("/calendar/tasks", endpoint="calendar_task_create", methods=["POST"])
@login_required
def calendar_task_create():
    title = (request.form.get("title") or "").strip()
    due_date_str = (request.form.get("due_date") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    subject_id = request.form.get("subject_id", type=int)
    errors: list[str] = []

    if not title:
        errors.append("Añade un título para la tarea.")

    due_date = None
    if not due_date_str:
        errors.append("Selecciona una fecha límite.")
    else:
        try:
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        except ValueError:
            errors.append("Formato de fecha inválido.")

    subject = None
    if subject_id:
        subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
        if not subject:
            errors.append("Asignatura inválida.")

    if errors:
        for err in errors:
            flash(err, "error")
        return redirect(url_for("task_calendar"))

    try:
        task = TaskItem(
            user_id=current_user.id,
            subject_id=subject.id if subject else None,
            title=title,
            due_date=due_date,
            notes=notes or None,
        )
        db.session.add(task)
        db.session.commit()
        flash("Tarea añadida ✅", "success")
    except Exception:
        db.session.rollback()
        flash("No se pudo guardar la tarea.", "error")
    return redirect(url_for("task_calendar"))


@calendar_bp.route("/calendar/exams", endpoint="calendar_exam_create", methods=["POST"])
@login_required
def calendar_exam_create():
    subject_id = request.form.get("subject_id", type=int)
    exam_date_str = (request.form.get("exam_date") or "").strip()
    tema = (request.form.get("tema") or "").strip()
    new_subject_name = (request.form.get("new_subject") or "").strip()
    new_subject_color_raw = (request.form.get("new_subject_color") or "").strip()
    errors: list[str] = []

    subject = None
    if new_subject_name:
        existing_subject = Subject.query.filter_by(
            user_id=current_user.id,
            name=new_subject_name,
        ).first()
        if existing_subject:
            subject = existing_subject
        else:
            if len(new_subject_name) > 120:
                errors.append("El nombre de la asignatura es demasiado largo.")
            color_value = None
            if new_subject_color_raw:
                color_value = normalize_subject_color(new_subject_color_raw)
                if not color_value:
                    errors.append("Color de asignatura inválido.")
            if not errors:
                subject = Subject(
                    user_id=current_user.id,
                    name=new_subject_name,
                    color=color_value,
                )
                db.session.add(subject)
                db.session.flush()
    else:
        if not subject_id:
            errors.append("Selecciona una asignatura.")
        else:
            subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
            if not subject:
                errors.append("Asignatura inválida.")

    exam_date = None
    if not exam_date_str:
        errors.append("Selecciona una fecha de examen.")
    else:
        try:
            exam_date = datetime.strptime(exam_date_str, "%Y-%m-%d").date()
        except ValueError:
            errors.append("Formato de fecha inválido.")

    if not tema:
        errors.append("Indica el tema del examen.")

    if errors:
        db.session.rollback()
        for err in errors:
            flash(err, "error")
        return redirect(url_for("task_calendar"))

    try:
        existing = SubjectExam.query.filter_by(
            subject_id=subject.id,
            exam_date=exam_date,
            tema=tema,
        ).first()
        if existing:
            flash("Ese examen ya existe.", "error")
            return redirect(url_for("task_calendar"))

        new_exam = SubjectExam(subject_id=subject.id, exam_date=exam_date, tema=tema)
        db.session.add(new_exam)
        db.session.commit()
        flash("Examen añadido ✅", "success")
    except Exception:
        db.session.rollback()
        flash("No se pudo añadir el examen.", "error")
    return redirect(url_for("task_calendar"))


@calendar_bp.route("/calendar/tasks/<int:task_id>/update", endpoint="calendar_task_update", methods=["POST"])
@login_required
def calendar_task_update(task_id: int):
    task = TaskItem.query.filter_by(id=task_id, user_id=current_user.id).first()
    if not task:
        flash("Tarea no encontrada.", "error")
        return redirect(url_for("task_calendar"))

    title = (request.form.get("title") or "").strip()
    due_date_str = (request.form.get("due_date") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    subject_id = request.form.get("subject_id", type=int)
    errors: list[str] = []

    if not title:
        errors.append("El título no puede estar vacío.")

    due_date = None
    if not due_date_str:
        errors.append("Selecciona una fecha límite.")
    else:
        try:
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        except ValueError:
            errors.append("Formato de fecha inválido.")

    subject = None
    if subject_id:
        subject = Subject.query.filter_by(id=subject_id, user_id=current_user.id).first()
        if not subject:
            errors.append("Asignatura inválida.")

    if errors:
        for err in errors:
            flash(err, "error")
        return redirect(url_for("task_calendar"))

    try:
        task.title = title
        task.due_date = due_date
        task.notes = notes or None
        task.subject_id = subject.id if subject else None
        db.session.commit()
        flash("Tarea actualizada ✅", "success")
    except Exception:
        db.session.rollback()
        flash("No se pudo actualizar la tarea.", "error")
    return redirect(url_for("task_calendar"))


@calendar_bp.route("/calendar/tasks/<int:task_id>/delete", endpoint="calendar_task_delete", methods=["POST"])
@login_required
def calendar_task_delete(task_id: int):
    task = TaskItem.query.filter_by(id=task_id, user_id=current_user.id).first()
    if not task:
        flash("Tarea no encontrada.", "error")
        return redirect(url_for("task_calendar"))
    try:
        db.session.delete(task)
        db.session.commit()
        flash("Tarea eliminada ✅", "success")
    except Exception:
        db.session.rollback()
        flash("No se pudo eliminar la tarea.", "error")
    return redirect(url_for("task_calendar"))
