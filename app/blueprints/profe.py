from __future__ import annotations

import math
from datetime import timezone

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from requests.exceptions import RequestException, Timeout

from app.extensions import limiter
from app.models import AskProfeMessage, StudentProfile, db
from app.utils import (
    fetch_ask_profe_history,
    get_active_profe_lock,
    prune_ask_profe_history,
    queue_has_work,
    resolve_default_model,
    start_profe_lock,
    utcnow,
)

profe_bp = Blueprint("profe", __name__)


@profe_bp.route("/ask-profe", endpoint="ask_profe", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per minute", methods=["POST"])
def ask_profe():
    now = utcnow()
    lock = get_active_profe_lock(now=now)
    if lock and lock.user_id != current_user.id:
        flash("El profe está atendiendo a otro estudiante. Vuelve en unos minutos.", "error")
        return redirect(url_for("dashboard"))

    if not lock:
        if request.method == "POST":
            flash("Tu tiempo con el profe ha terminado. Vuelve al menú para iniciar otro turno.", "error")
            return redirect(url_for("dashboard"))
        if queue_has_work():
            flash("El profe está ocupado procesando trabajos. Cuando termine, podrás usar «Pregúntale al profe».", "error")
            return redirect(url_for("dashboard"))
        lock = start_profe_lock(current_user.id, now=now)

    lock_ends_at = lock.ends_at if lock else now
    if lock_ends_at <= now:
        flash("Tu tiempo con el profe ha terminado.", "error")
        return redirect(url_for("dashboard"))

    available_models = current_app.extensions["llm_client"].fetch_models()
    selected_model = resolve_default_model(current_app.config["LMSTUDIO_MODEL"], current_user.id, available_models)
    messages = fetch_ask_profe_history(current_user.id)
    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    student_context = ""
    if profile:
        student_context = (
            f"Estudiante: {profile.student_name} (edad {profile.age}). "
            f"Características: {profile.personality_notes}"
        )

    if request.method == "POST":
        if utcnow() >= lock_ends_at:
            flash("Tu tiempo con el profe ha terminado.", "error")
            return redirect(url_for("dashboard"))
        selected_model = request.form.get("model") or selected_model
        question = request.form.get("question", "").strip()

        if question:
            try:
                context_messages = messages[-2:]
                history = list(context_messages)
                history.append({"role": "user", "content": question})

                system_content = (
                    "Eres un profesor humano paciente y amable. Responde de forma clara, completa y conversacional, "
                    "sin usar asteriscos ni acciones roleplay; escribe como hablarías en la vida real. "
                    "Adapta tu respuesta al perfil del estudiante, pero no menciones esos datos de forma explícita "
                    "a menos que sea relevante para la pregunta o el estudiante lo pida. "
                    f"{student_context}"
                )
                answer = current_app.extensions["llm_client"].chat(
                    selected_model,
                    [{"role": "system", "content": system_content}, *history],
                    temperature=0.7,
                )
                history.append({"role": "assistant", "content": answer})
                db.session.add(AskProfeMessage(user_id=current_user.id, role="user", content=question))
                db.session.add(AskProfeMessage(user_id=current_user.id, role="assistant", content=answer))
                prune_ask_profe_history(current_user.id, keep=12)
                db.session.commit()
                messages = fetch_ask_profe_history(current_user.id)
            except Timeout:
                flash("El modelo tardó demasiado en responder.", "error")
                return redirect(url_for("dashboard"))
            except RequestException:
                flash("No he podido conectar con LM Studio. ¿Está encendido?", "error")
                return redirect(url_for("dashboard"))
            except Exception:
                db.session.rollback()
                flash("Error inesperado procesando tu pregunta.", "error")
                return redirect(url_for("dashboard"))

    remaining_seconds = max(0, int(math.ceil((lock_ends_at - utcnow()).total_seconds())))
    remaining_label = f"{remaining_seconds // 60:02d}:{remaining_seconds % 60:02d}"
    lock_ends_at_ts = int(lock_ends_at.replace(tzinfo=timezone.utc).timestamp() * 1000)
    return render_template(
        "ask_profe.html",
        messages=messages,
        models=available_models,
        selected_model=selected_model,
        lock_ends_at_ts=lock_ends_at_ts,
        lock_remaining_label=remaining_label,
    )
