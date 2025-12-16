import os
import sys
from datetime import date

import pytest

# Ensure the project root (one level above "tests/") is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from app.models import db, User, Subject, Note


@pytest.fixture
def flask_app(monkeypatch, tmp_path):
    """Create a fresh app + sqlite DB for every test run."""
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("SQLALCHEMY_DATABASE_URI", f"sqlite:///{db_file}")
    monkeypatch.setenv("SECRET_KEY", "testing-secret")
    monkeypatch.setenv("LMSTUDIO_API_BASE", "http://lmstudio.test")
    monkeypatch.setenv("LMSTUDIO_MODEL", "dummy-model")
    monkeypatch.setenv("LMSTUDIO_TIMEOUT", "1")

    app = create_app()
    app.config.update({"TESTING": True})
    return app


def register_user(client, username="ada", password="secret123"):
    response = client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    return username


@pytest.fixture
def authed_client(flask_app):
    client = flask_app.test_client()
    register_user(client)
    return client


def test_dashboard_requires_login(flask_app):
    client = flask_app.test_client()
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/?next=%2Fdashboard" in response.headers.get("Location", "")


def test_dashboard_after_login(authed_client):
    response = authed_client.get("/dashboard")
    assert response.status_code == 200
    assert b"Hola, ada" in response.data


def test_add_notes_manual_flow_creates_note(flask_app, authed_client):
    response = authed_client.post(
        "/add-notes",
        data={
            "model": "dummy-model",
            "subject_choice": "__new__",
            "new_subject_name": "Historia",
            "title": "Tema 1",
            "manual_mode": "on",
            "manual_text": "Contenido generado manualmente",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with flask_app.app_context():
        note = Note.query.one()
        assert note.title == "Tema 1"
        assert note.subject.name == "Historia"
        assert note.user.username == "ada"
        assert note.ai_used is False


def test_notes_list_shows_saved_note(flask_app, authed_client):
    with flask_app.app_context():
        user = User.query.filter_by(username="ada").first()
        subject = Subject(user_id=user.id, name="Física")
        db.session.add(subject)
        db.session.flush()
        note = Note(
            user_id=user.id,
            subject_id=subject.id,
            title="Tema secreto",
            content="Contenido oculto",
            ai_used=False,
        )
        db.session.add(note)
        db.session.commit()

    response = authed_client.get("/notes")
    assert response.status_code == 200
    assert b"Tema secreto" in response.data
    assert b"Manual" in response.data


def test_note_edit_updates_content(flask_app, authed_client):
    with flask_app.app_context():
        user = User.query.filter_by(username="ada").first()
        old_subject = Subject(user_id=user.id, name="Historia")
        new_subject = Subject(user_id=user.id, name="Filosofía")
        db.session.add_all([old_subject, new_subject])
        db.session.flush()

        note = Note(
            user_id=user.id,
            subject_id=old_subject.id,
            title="Tema original",
            content="Borrador",
            ai_used=True,
        )
        db.session.add(note)
        db.session.commit()
        note_id = note.id
        new_subject_id = new_subject.id

    response = authed_client.post(
        f"/notes/{note_id}/edit",
        data={
            "subject_id": new_subject_id,
            "title": "Tema revisado",
            "exam_date": "2024-10-01",
            "content": "Contenido actualizado",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with flask_app.app_context():
        note = Note.query.get(note_id)
        assert note.title == "Tema revisado"
        assert note.subject.name == "Filosofía"
        assert note.exam_date == date(2024, 10, 1)
        assert note.content == "Contenido actualizado"
        assert note.ai_used is False
        assert note.original_filename is None


def test_note_delete_removes_entry(flask_app, authed_client):
    with flask_app.app_context():
        user = User.query.filter_by(username="ada").first()
        subject = Subject(user_id=user.id, name="Química")
        db.session.add(subject)
        db.session.flush()
        note = Note(
            user_id=user.id,
            subject_id=subject.id,
            title="Tema para borrar",
            content="Contenido",
            ai_used=False,
        )
        db.session.add(note)
        db.session.commit()
        note_id = note.id

    response = authed_client.post(
        f"/notes/{note_id}/delete",
        follow_redirects=True,
    )
    assert response.status_code == 200

    with flask_app.app_context():
        assert Note.query.count() == 0
