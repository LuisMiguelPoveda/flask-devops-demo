from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    subjects = db.relationship("Subject", back_populates="user", cascade="all, delete-orphan")
    notes = db.relationship("Note", back_populates="user", cascade="all, delete-orphan")
    flashcard_decks = db.relationship("FlashcardDeck", back_populates="user", cascade="all, delete-orphan")


class Subject(db.Model):
    __tablename__ = "subjects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)

    user = db.relationship("User", back_populates="subjects")
    notes = db.relationship("Note", back_populates="subject", cascade="all, delete-orphan")
    flashcard_decks = db.relationship("FlashcardDeck", back_populates="subject", cascade="all, delete-orphan")

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_subject_user_name"),
    )


class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subjects.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    exam_date = db.Column(db.Date, nullable=True)

    original_filename = db.Column(db.String(255), nullable=True)

    content = db.Column(db.Text, nullable=False)
    ai_used = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="notes")
    subject = db.relationship("Subject", back_populates="notes")


class FlashcardDeck(db.Model):
    """
    Guarda flashcards como JSON:
    [
      {"question": "...", "options": ["A","B","C","D"], "correct_index": 2},
      ...
    ]
    """
    __tablename__ = "flashcard_decks"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subjects.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)        # tema/título
    exam_date = db.Column(db.Date, nullable=True)

    source_note_id = db.Column(db.Integer, db.ForeignKey("notes.id"), nullable=True)

    flashcards = db.Column(db.JSON, nullable=False)          # ✅ JSON en BD (SQLite lo serializa)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="flashcard_decks")
    subject = db.relationship("Subject", back_populates="flashcard_decks")
    source_note = db.relationship("Note", foreign_keys=[source_note_id])


class Job(db.Model):
    """
    Cola simple para trabajos de IA (resúmenes y flashcards).
    """

    __tablename__ = "jobs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    type = db.Column(db.String(40), nullable=False)  # note_ai | flashcards_ai_new | flashcards_ai_append
    status = db.Column(db.String(20), default="pending", nullable=False)  # pending | running | success | error
    payload = db.Column(db.JSON, nullable=False)
    result_message = db.Column(db.String(255), nullable=True)
    error_message = db.Column(db.String(255), nullable=True)
    notified = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = db.relationship("User")

    __table_args__ = (
        db.Index("ix_jobs_status_created", "status", "created_at"),
    )
