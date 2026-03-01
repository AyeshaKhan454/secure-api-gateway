import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.middleware.threat_detector import request_counts

client = TestClient(app)

def setup_function():
    """Clear rate limit counters before each test."""
    request_counts.clear()

def test_xss_in_note_title_is_blocked():
    """XSS in note title should return 400."""
    client.post("/auth/register", json={"username": "testuser1", "password": "test123"})
    login = client.post("/auth/login", json={"username": "testuser1", "password": "test123"})
    token = login.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/notes/", json={
        "title": "<script>alert('xss')</script>",
        "content": "Normal content"
    }, headers=headers)
    assert response.status_code == 400

def test_xss_onerror_is_blocked():
    """XSS onerror pattern should be blocked."""
    client.post("/auth/register", json={"username": "testuser2", "password": "test123"})
    login = client.post("/auth/login", json={"username": "testuser2", "password": "test123"})
    token = login.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/notes/", json={
        "title": "Test",
        "content": "<img src=x onerror=alert(1)>"
    }, headers=headers)
    assert response.status_code == 400

def test_xss_iframe_is_blocked():
    """XSS iframe injection should be blocked."""
    client.post("/auth/register", json={"username": "testuser3", "password": "test123"})
    login = client.post("/auth/login", json={"username": "testuser3", "password": "test123"})
    token = login.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/notes/", json={
        "title": "<iframe src='evil.com'>",
        "content": "Normal"
    }, headers=headers)
    assert response.status_code == 400

def test_clean_note_is_allowed():
    """A clean safe note should be created successfully."""
    client.post("/auth/register", json={"username": "testuser4", "password": "test123"})
    login = client.post("/auth/login", json={"username": "testuser4", "password": "test123"})
    token = login.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/notes/", json={
        "title": "My safe note",
        "content": "This is totally safe content."
    }, headers=headers)
    assert response.status_code == 200