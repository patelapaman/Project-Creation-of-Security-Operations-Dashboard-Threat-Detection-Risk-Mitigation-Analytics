"""Final milestone smoke tests for API contracts, filtering and feedback validation."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

flask = pytest.importorskip("flask")
from app import create_app


def test_final_project_name_and_health():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    root = client.get("/")
    assert root.status_code == 200
    assert root.get_json()["project"] == "Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics"


def test_events_filter_and_pagination_contract():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    response = client.get("/api/events/?severity=Critical&page=1&page_size=10")
    assert response.status_code in (200, 503)
    if response.status_code == 200:
        body = response.get_json()
        assert body["success"] is True
        assert "pagination" in body
        assert body["pagination"]["page_size"] == 10


def test_invalid_event_pagination_is_client_error():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    response = client.get("/api/events/?page=abc")
    assert response.status_code == 422


def test_feedback_validation():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    response = client.post("/api/m4/feedback", json={"event_id": "E1", "prediction": "Suspicious", "actual_feedback": "Unknown"})
    assert response.status_code == 422
