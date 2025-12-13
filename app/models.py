from datetime import datetime, date

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    subjects = db.relationship("Subject", back_populates="user", cascade="all, delete-orphan")
    notes = db.relationship("Notes", back_populates="user", cascade="all, delete-orphan")


class Subject(db.Model):
    __tablename__ = "subjects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    name = db.Column(db.String(120), nullable=False)

    user = db.relationship("User", back_populates="subjects")
    notes = db.relationship("Notes", back_populates="subject", cascade="all, delete-orphan")

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_subject_user_name"),
    )


class Notes(db.Model):
    """
    Guarda el resumen/apuntes generados (NO guarda el archivo original).
    """
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subjects.id"), nullable=False)

    exam_date = db.Column(db.Date, nullable=True)

    source_filename = db.Column(db.String(255), nullable=True)
    summary = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="notes")
    subject = db.relationship("Subject", back_populates="notes")
