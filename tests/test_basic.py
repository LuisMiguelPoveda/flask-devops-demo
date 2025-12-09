import os
import sys

# Ensure the project root (one level above "tests/") is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app


def test_home_page():
    app = create_app()
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"Flask DevOps Demo" in response.data
