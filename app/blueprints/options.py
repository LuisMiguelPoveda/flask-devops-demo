from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.core.llm_profiles import DEFAULT_LLM_PROFILE, LLM_PROFILE_CHOICES, LLM_PROFILE_PRESETS
from app.models import (
    AskProfeMessage,
    FlashcardDeck,
    Job,
    Note,
    NoteSourceFile,
    StudentProfile,
    Subject,
    SubjectExam,
    TaskItem,
    db,
)

options_bp = Blueprint("options", __name__)


@options_bp.route("/options", endpoint="options")
@login_required
def options():
    return render_template("options.html")


@options_bp.route("/options/profile", endpoint="profile_edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        return redirect(url_for("setup"))

    student_name = profile.student_name or ""
    student_age = str(profile.age or "")
    personality_notes = profile.personality_notes or ""
    llm_profile = profile.llm_profile if profile.llm_profile in LLM_PROFILE_PRESETS else DEFAULT_LLM_PROFILE

    if request.method == "POST":
        student_name = (request.form.get("student_name") or "").strip()
        student_age = (request.form.get("student_age") or "").strip()
        personality_notes = (request.form.get("personality_notes") or "").strip()
        llm_profile = (request.form.get("llm_profile") or llm_profile).strip()

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
        if llm_profile not in LLM_PROFILE_PRESETS:
            errors.append("Selecciona un perfil de VRAM válido.")

        if errors:
            for err in errors:
                flash(err, "error")
            return render_template(
                "setup.html",
                student_name=student_name,
                student_age=student_age,
                personality_notes=personality_notes,
                llm_profiles=LLM_PROFILE_CHOICES,
                llm_profile=llm_profile,
                page_title="Perfil del estudiante",
                heading="Perfil del estudiante",
                subtext="Actualiza los datos del estudiante cuando lo necesites.",
                submit_label="Guardar cambios",
                back_url=url_for("options"),
            )

        profile.student_name = student_name
        profile.age = age_val or 0
        profile.personality_notes = personality_notes
        profile.llm_profile = llm_profile
        db.session.commit()
        flash("Perfil actualizado ✅", "success")
        return redirect(url_for("options"))

    return render_template(
        "setup.html",
        student_name=student_name,
        student_age=student_age,
        personality_notes=personality_notes,
        llm_profiles=LLM_PROFILE_CHOICES,
        llm_profile=llm_profile,
        page_title="Perfil del estudiante",
        heading="Perfil del estudiante",
        subtext="Actualiza los datos del estudiante cuando lo necesites.",
        submit_label="Guardar cambios",
        back_url=url_for("options"),
    )


@options_bp.route("/options/reset", endpoint="reset_account", methods=["POST"])
@login_required
def reset_account():
    try:
        note_ids = [row[0] for row in db.session.query(Note.id).filter_by(user_id=current_user.id).all()]
        subject_ids = [row[0] for row in db.session.query(Subject.id).filter_by(user_id=current_user.id).all()]

        AskProfeMessage.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
        Job.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
        FlashcardDeck.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
        TaskItem.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)

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
