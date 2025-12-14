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


class Subject(db.Model):
    __tablename__ = "subjects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)

    user = db.relationship("User", back_populates="subjects")
    notes = db.relationship("Note", back_populates="subject", cascade="all, delete-orphan")

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_subject_user_name"),
    )


class Note(db.Model):
    """
    Apuntes guardados por usuario.
    - title: identificador humano (sustituye a 'tema')
    - content: contenido final guardado (puede venir de IA o manual)
    - ai_used: True si se generó con IA, False si el usuario lo escribió a mano
    """
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
