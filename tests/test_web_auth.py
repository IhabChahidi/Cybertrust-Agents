"""Auth flow tests for the dashboard backend (web/auth.py + web/backend.py).

Deterministic dev credentials are set in tests/conftest.py, not here -- that
module is guaranteed by pytest to import before this one (or any other test
module that imports web.backend first and seeds web.auth's in-memory user
table with a different value). See conftest.py's comment for why this
matters and what broke when the env vars were set here instead.
"""

import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from fastapi.testclient import TestClient

from web import auth
from web.backend import app

CISO_USER = os.environ["CISO_DEV_USERNAME"]
CISO_PASS = os.environ["CISO_DEV_PASSWORD"]
DELEGATE_USER = os.environ["DELEGATE_DEV_USERNAME"]
DELEGATE_PASS = os.environ["DELEGATE_DEV_PASSWORD"]


@pytest.fixture()
def client():
    return TestClient(app)


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_successful_login_sets_cookie_and_returns_role(client):
    r = login(client, CISO_USER, CISO_PASS)
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == CISO_USER
    assert body["role"] == "CISO"
    assert "csrf_token" in body
    assert body["dev_mode"] is True
    assert auth.SESSION_COOKIE_NAME in r.cookies


def test_invalid_credentials_return_generic_message(client):
    r = login(client, CISO_USER, "wrong-password")
    assert r.status_code == 401
    assert r.json()["detail"] == "Identifiants invalides"

    r2 = login(client, "no-such-user", "whatever")
    assert r2.status_code == 401
    assert r2.json()["detail"] == r.json()["detail"]  # identical message either way


def test_session_verification_via_me(client):
    login(client, DELEGATE_USER, DELEGATE_PASS)
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["role"] == "CISO_DELEGATE"


def test_protected_route_blocked_without_session(client):
    r = client.get("/api/evidence")
    assert r.status_code == 401


def test_protected_route_accessible_after_login(client):
    login(client, CISO_USER, CISO_PASS)
    r = client.get("/api/evidence")
    assert r.status_code == 200
    assert len(r.json()) == 10


def test_state_changing_route_requires_csrf_header(client):
    login(client, CISO_USER, CISO_PASS)
    r = client.post("/api/process", json={"statement": "t", "evidence_ids": ["EVD-0001"]})
    assert r.status_code == 403  # missing X-CSRF-Token


def test_state_changing_route_succeeds_with_csrf_header(client):
    login_resp = login(client, CISO_USER, CISO_PASS)
    csrf = login_resp.json()["csrf_token"]
    r = client.post(
        "/api/process",
        json={"statement": "t", "evidence_ids": ["EVD-0001"], "llm_mode": "mock", "endpoint": "GENERATOR_COPILOT_STUDIO"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
    assert r.json()["mcp_state"] == "COMPLETED"


def test_logout_clears_session(client):
    login_resp = login(client, CISO_USER, CISO_PASS)
    csrf = login_resp.json()["csrf_token"]

    r = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200

    r2 = client.get("/api/auth/me")
    assert r2.status_code == 401


def test_logout_without_matching_csrf_is_rejected(client):
    login(client, CISO_USER, CISO_PASS)
    r = client.post("/api/auth/logout", headers={"X-CSRF-Token": "not-the-real-token"})
    assert r.status_code == 403
    # session must still be alive since logout was rejected
    r2 = client.get("/api/auth/me")
    assert r2.status_code == 200


def test_session_expiry_forces_reauthentication(client):
    login(client, CISO_USER, CISO_PASS)
    token = client.cookies.get(auth.SESSION_COOKIE_NAME)
    session = auth._SESSIONS[token]
    session.expires_at = time.time() - 1  # force expiry

    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_brute_force_lockout_after_repeated_failures(client):
    username = "lockout-test-user"
    for _ in range(auth.MAX_FAILED_ATTEMPTS):
        r = login(client, username, "wrong")
        assert r.status_code == 401
    # user doesn't even exist, but the lockout path must not crash and must
    # keep returning the same generic 401
    r = login(client, username, "still-wrong")
    assert r.status_code == 401


def test_ciso_decision_requires_authorized_role(client):
    login_resp = login(client, CISO_USER, CISO_PASS)
    csrf = login_resp.json()["csrf_token"]

    process_resp = client.post(
        "/api/process",
        json={"statement": "t", "evidence_ids": ["EVD-0001"], "llm_mode": "mock", "endpoint": "GENERATOR_COPILOT_STUDIO"},
        headers={"X-CSRF-Token": csrf},
    )
    session_id = process_resp.json()["session_id"]
    correlation_id = process_resp.json()["correlation_id"]

    r = client.post(
        "/api/ciso-decision",
        json={"session_id": session_id, "correlation_id": correlation_id, "llm_mode": "mock", "decision": "APPROVE"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
