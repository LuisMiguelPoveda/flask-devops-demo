from __future__ import annotations

import random

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from app.models import ChallengeResult, FlashcardDeck, StudentProfile, db
from app.services.calendar_service import calendar_window_range
from app.utils import utcnow

challenge_bp = Blueprint("challenge", __name__)


@challenge_bp.route("/challenge", endpoint="challenge")
@login_required
def challenge():
    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()
    _, window_start, window_end = calendar_window_range(profile)

    if window_start is None:
        return render_template("challenge.html", no_cards=True, reason="no_window")

    decks = (
        FlashcardDeck.query
        .filter_by(user_id=current_user.id)
        .filter(
            FlashcardDeck.exam_date >= window_start,
            FlashcardDeck.exam_date <= window_end,
        )
        .all()
    )
    decks = [d for d in decks if d.flashcards]

    subject_ids = list({d.subject_id for d in decks})
    if len(subject_ids) < 2:
        return render_template("challenge.html", no_cards=True, reason="not_enough_subjects")

    all_cards = []
    for deck in decks:
        exam_key = f"{deck.exam_date}_{deck.subject_id}" if deck.exam_date else None
        for card in deck.flashcards:
            all_cards.append({
                "question": card["question"],
                "options": card["options"],
                "correct_index": card["correct_index"],
                "deck_id": deck.id,
                "subject_name": deck.subject.name,
                "exam_date": str(deck.exam_date) if deck.exam_date else None,
                "exam_key": exam_key,
            })

    random.shuffle(all_cards)

    deck_ids = [d.id for d in decks]
    exam_dates = list({str(d.exam_date) for d in decks if d.exam_date})

    return render_template(
        "challenge.html",
        no_cards=False,
        cards_json=all_cards,
        deck_ids=deck_ids,
        subject_ids=subject_ids,
        exam_dates=exam_dates,
    )


@challenge_bp.route("/challenge/save", endpoint="challenge_save", methods=["POST"])
@login_required
def challenge_save():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "bad request"}), 400

    result = ChallengeResult(
        user_id=current_user.id,
        created_at=utcnow(),
        deck_ids=data.get("deck_ids", []),
        subject_ids=data.get("subject_ids", []),
        exam_dates=data.get("exam_dates", []),
        quiz_correct=int(data.get("quiz_correct", 0)),
        quiz_total=int(data.get("quiz_total", 0)),
        blitz_correct=int(data.get("blitz_correct", 0)),
        blitz_total=int(data.get("blitz_total", 0)),
        blitz_seconds=int(data.get("blitz_seconds", 0)),
        per_exam_stats=data.get("per_exam_stats") or {},
    )
    db.session.add(result)
    db.session.commit()
    return jsonify({"ok": True}), 201
