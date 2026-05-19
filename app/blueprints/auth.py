from __future__ import annotations

import json
import os
import uuid
from datetime import datetime

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app.core.file_extraction import MAX_UPLOAD_BYTES, allowed_file, save_upload_stream
from app.core.llm_profiles import (
    DEFAULT_LLM_PROFILE,
    LLM_PROFILE_CHOICES,
    LLM_PROFILE_PRESETS,
    TASK_WINDOW_DEFAULT,
)
from app.extensions import limiter
from app.models import (
    FlashcardDeck,
    Job,
    Note,
    NoteSourceFile,
    StudentProfile,
    Subject,
    SubjectExam,
    db,
)
from app.utils import is_setup_complete, normalize_subject_color, resolve_default_model, utcnow

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", endpoint="login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        if not is_setup_complete(current_user.id):
            return redirect(url_for("setup"))
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        from app.models import User
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


@auth_bp.route("/register", endpoint="register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        if not is_setup_complete(current_user.id):
            return redirect(url_for("setup"))
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        from app.models import User
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


@auth_bp.route("/setup", endpoint="setup", methods=["GET", "POST"])
@login_required
def setup():
    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    student_name = profile.student_name if profile else ""
    student_age = ""
    personality_notes = profile.personality_notes if profile else ""
    llm_profile = (
        profile.llm_profile
        if profile and profile.llm_profile in LLM_PROFILE_PRESETS
        else DEFAULT_LLM_PROFILE
    )

    if request.method == "POST":
        student_name = (request.form.get("student_name") or "").strip()
        student_age = (request.form.get("student_age") or "").strip()
        personality_notes = (request.form.get("personality_notes") or "").strip()
        llm_profile = (request.form.get("llm_profile") or llm_profile).strip()

        errors: list[str] = []
        if not student_name:
            errors.append("Escribe el nombre del estudiante.")

        age_val = None
        birth_date = None
        if student_age:
            if "-" in student_age:
                try:
                    birth_date = datetime.strptime(student_age, "%Y-%m-%d").date()
                except ValueError:
                    birth_date = None
                if birth_date:
                    today = utcnow().date()
                    age_val = today.year - birth_date.year
                    if (today.month, today.day) < (birth_date.month, birth_date.day):
                        age_val -= 1
            else:
                try:
                    age_val = int(student_age)
                except (TypeError, ValueError):
                    age_val = None

        if not age_val or age_val < 1:
            errors.append("Indica una fecha de nacimiento válida.")

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
                age_label="Fecha de nacimiento",
                age_mode="dob",
            )

        try:
            profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
            if profile:
                profile.student_name = student_name
                profile.age = age_val or 0
                profile.personality_notes = personality_notes
                profile.llm_profile = llm_profile
            else:
                profile = StudentProfile(
                    user_id=current_user.id,
                    student_name=student_name,
                    age=age_val or 0,
                    personality_notes=personality_notes,
                    llm_profile=llm_profile,
                    task_window_days=TASK_WINDOW_DEFAULT,
                )
                db.session.add(profile)

            db.session.commit()
            flash("Datos guardados ✅", "success")
            return redirect(url_for("setup_subjects"))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Error en setup al guardar perfil")
            flash("Error guardando la configuración.", "error")
            return render_template(
                "setup.html",
                student_name=student_name,
                student_age=student_age,
                personality_notes=personality_notes,
                llm_profiles=LLM_PROFILE_CHOICES,
                llm_profile=llm_profile,
                age_label="Fecha de nacimiento",
                age_mode="dob",
            )

    return render_template(
        "setup.html",
        student_name=student_name,
        student_age=student_age,
        personality_notes=personality_notes,
        llm_profiles=LLM_PROFILE_CHOICES,
        llm_profile=llm_profile,
        age_label="Fecha de nacimiento",
        age_mode="dob",
    )


@auth_bp.route("/setup/subjects", endpoint="setup_subjects", methods=["GET", "POST"])
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
                    raw_subject_id = subj.get("id")
                    subject_id = None
                    if raw_subject_id is not None:
                        try:
                            subject_id = int(raw_subject_id)
                        except (TypeError, ValueError):
                            subject_id = None
                    name = (subj.get("name") or "").strip()
                    color_raw = (subj.get("color") or "").strip()
                    color = normalize_subject_color(color_raw)
                    exams = subj.get("exams") if isinstance(subj, dict) else []
                    if not isinstance(exams, list):
                        exams = []
                    subject_seed = {
                        "id": subject_id,
                        "name": name,
                        "color": color or color_raw,
                        "exams": [],
                    }

                    subject_has_content = bool(name or color_raw)
                    for exam in exams:
                        raw_exam_id = exam.get("id") if isinstance(exam, dict) else None
                        exam_id = None
                        if raw_exam_id is not None:
                            try:
                                exam_id = int(raw_exam_id)
                            except (TypeError, ValueError):
                                exam_id = None
                        date_str = (exam.get("date") or "").strip() if isinstance(exam, dict) else ""
                        tema = (exam.get("tema") or "").strip() if isinstance(exam, dict) else ""
                        if date_str or tema:
                            subject_has_content = True
                        subject_seed["exams"].append({"id": exam_id, "date": date_str, "tema": tema})

                    if not subject_has_content:
                        continue

                    subjects_seed.append(subject_seed)

                    if not name:
                        errors.append("Cada asignatura necesita un nombre.")
                        continue
                    if color_raw and not color:
                        errors.append(f'Color inválido en "{name}".')
                        continue
                    lowered = name.lower()
                    if lowered in seen_names:
                        errors.append(f"La asignatura \"{name}\" está duplicada.")
                        continue
                    seen_names.add(lowered)

                    exam_entries: list[dict] = []
                    seen_exam_keys: set[tuple] = set()
                    for exam in exams:
                        raw_exam_id = exam.get("id") if isinstance(exam, dict) else None
                        exam_id = None
                        if raw_exam_id is not None:
                            try:
                                exam_id = int(raw_exam_id)
                            except (TypeError, ValueError):
                                exam_id = None
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
                        exam_key = (exam_date, tema.lower())
                        if exam_key in seen_exam_keys:
                            errors.append(
                                f"El examen \"{tema}\" de \"{name}\" está duplicado."
                            )
                            continue
                        seen_exam_keys.add(exam_key)
                        exam_entries.append({"id": exam_id, "date": exam_date, "tema": tema})

                    subjects_clean.append(
                        {"id": subject_id, "name": name, "color": color, "exams": exam_entries}
                    )

        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("setup_subjects.html", subjects_seed=subjects_seed)

        try:
            existing_subjects = Subject.query.filter_by(user_id=current_user.id).all()
            existing_subjects_by_id = {s.id: s for s in existing_subjects}
            incoming_subject_ids: set[int] = set()

            def delete_exam_content(subject_id: int, exam_date):
                note_ids = [
                    row[0]
                    for row in db.session.query(Note.id)
                    .filter_by(user_id=current_user.id, subject_id=subject_id, exam_date=exam_date)
                    .all()
                ]
                if note_ids:
                    NoteSourceFile.query.filter(NoteSourceFile.note_id.in_(note_ids)).delete(
                        synchronize_session=False
                    )
                Note.query.filter_by(
                    user_id=current_user.id, subject_id=subject_id, exam_date=exam_date
                ).delete(synchronize_session=False)
                FlashcardDeck.query.filter_by(
                    user_id=current_user.id, subject_id=subject_id, exam_date=exam_date
                ).delete(synchronize_session=False)

            for subj in subjects_clean:
                subject_id = subj.get("id")
                subject = existing_subjects_by_id.get(subject_id) if subject_id else None
                if subject:
                    subject.name = subj["name"]
                    subject.color = subj.get("color")
                else:
                    subject = Subject(
                        user_id=current_user.id,
                        name=subj["name"],
                        color=subj.get("color"),
                    )
                    db.session.add(subject)
                    db.session.flush()
                incoming_subject_ids.add(subject.id)

                existing_exams = {e.id: e for e in SubjectExam.query.filter_by(subject_id=subject.id).all()}
                incoming_exam_ids: set[int] = set()

                for exam in subj["exams"]:
                    exam_id = exam.get("id")
                    if exam_id and exam_id in existing_exams:
                        exam_row = existing_exams[exam_id]
                        old_date = exam_row.exam_date
                        exam_row.exam_date = exam["date"]
                        exam_row.tema = exam["tema"]
                        incoming_exam_ids.add(exam_row.id)
                        if old_date != exam_row.exam_date:
                            Note.query.filter_by(
                                user_id=current_user.id,
                                subject_id=subject.id,
                                exam_date=old_date,
                            ).update({Note.exam_date: exam_row.exam_date}, synchronize_session=False)
                            FlashcardDeck.query.filter_by(
                                user_id=current_user.id,
                                subject_id=subject.id,
                                exam_date=old_date,
                            ).update({FlashcardDeck.exam_date: exam_row.exam_date}, synchronize_session=False)
                    else:
                        new_exam = SubjectExam(
                            subject_id=subject.id,
                            exam_date=exam["date"],
                            tema=exam["tema"],
                        )
                        db.session.add(new_exam)
                        db.session.flush()
                        incoming_exam_ids.add(new_exam.id)

                for exam_id, exam_row in existing_exams.items():
                    if exam_id not in incoming_exam_ids:
                        delete_exam_content(subject.id, exam_row.exam_date)
                        db.session.delete(exam_row)

            for subject in existing_subjects:
                if subject.id not in incoming_subject_ids:
                    db.session.delete(subject)

            db.session.commit()
            flash("Asignaturas guardadas ✅", "success")
            return redirect(url_for("setup_generate"))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Error en setup_subjects al guardar asignaturas")
            flash("Error guardando las asignaturas.", "error")
            return render_template("setup_subjects.html", subjects_seed=subjects_seed)

    if request.method == "GET":
        subjects = (
            Subject.query.filter_by(user_id=current_user.id)
            .order_by(Subject.name.asc())
            .all()
        )
        subjects_seed = []
        for subject in subjects:
            exams = (
                SubjectExam.query.filter_by(subject_id=subject.id)
                .order_by(SubjectExam.exam_date.asc(), SubjectExam.tema.asc())
                .all()
            )
            subjects_seed.append(
                {
                    "id": subject.id,
                    "name": subject.name,
                    "color": subject.color,
                    "exams": [
                        {
                            "id": exam.id,
                            "date": exam.exam_date.isoformat() if exam.exam_date else "",
                            "tema": exam.tema,
                        }
                        for exam in exams
                    ],
                }
            )
    return render_template("setup_subjects.html", subjects_seed=subjects_seed)


@auth_bp.route("/setup/generate", endpoint="setup_generate", methods=["GET", "POST"])
@login_required
def setup_generate():
    if not is_setup_complete(current_user.id):
        return redirect(url_for("setup"))

    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    available_models = current_app.extensions["llm_client"].fetch_models()
    selected_model = resolve_default_model(current_app.config["LMSTUDIO_MODEL"], current_user.id, available_models)

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
        queued_files = 0
        errors: list[str] = []
        upload_dir = current_app.config.get("UPLOAD_DIR") or current_app.instance_path

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
                            errors.append(f"{upload.filename}: solo se permiten archivos .txt, .pdf o .pptx.")
                            continue

                        filename = secure_filename(upload.filename)
                        if not filename:
                            errors.append("Nombre de archivo inválido.")
                            continue

                        stored_name = f"{uuid.uuid4().hex}_{filename}"
                        stored_path = os.path.join(upload_dir, stored_name)
                        try:
                            size, err = save_upload_stream(upload, stored_path, MAX_UPLOAD_BYTES)
                        except Exception:
                            errors.append(f"{filename}: error guardando el archivo.")
                            if os.path.exists(stored_path):
                                os.remove(stored_path)
                            continue
                        if err == "empty":
                            errors.append(f"{filename}: el archivo está vacío.")
                            continue
                        if err == "too_large":
                            errors.append(f"{filename}: archivo demasiado grande (máx {MAX_UPLOAD_BYTES // 1024} KB).")
                            continue
                        if size <= 0:
                            errors.append(f"{filename}: el archivo está vacío.")
                            continue

                        db.session.add(
                            Job(
                                user_id=current_user.id,
                                type="file_import",
                                payload={
                                    "user_id": current_user.id,
                                    "subject_id": subject.id,
                                    "exam_id": exam.id,
                                    "filename": filename,
                                    "file_path": stored_path,
                                    "content_type": upload.mimetype or "",
                                    "model": selected_model,
                                },
                            )
                        )
                        queued_files += 1

            if queued_files:
                db.session.commit()
                flash(
                    f"Archivos en cola ✅ {queued_files} archivo(s). Se procesarán en segundo plano.",
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
        return redirect(url_for("dashboard"))

    return render_template(
        "setup_generate.html",
        subjects=subject_blocks,
        models=available_models,
        selected_model=selected_model,
        max_kb=MAX_UPLOAD_BYTES // 1024,
    )


@auth_bp.route("/setup/next", endpoint="setup_next")
@login_required
def setup_next():
    if not is_setup_complete(current_user.id):
        return redirect(url_for("setup"))
    return redirect(url_for("dashboard"))


@auth_bp.route("/logout", endpoint="logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
