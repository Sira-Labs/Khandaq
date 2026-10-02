"""Integration tests for the OIDC BFF, sessions, CSRF and API tokens (spec 008).

The IdP is replaced by an injected fake client, so the full login→callback→session path runs without
a live Keycloak (the real client is deploy-verified). Requires a Postgres test database.
"""

from __future__ import annotations

import os
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")


class FakeOidc:
    """Stand-in IdP: records the handshake and returns canned claims for the callback."""

    def __init__(self) -> None:
        self.claims_to_return = {"email": "alice@test", "name": "Alice"}

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        return (
            "https://idp.test/authorize"
            f"?state={state}&nonce={nonce}"
            f"&code_challenge={code_challenge}&code_challenge_method=S256"
        )

    def exchange(self, *, code: str, code_verifier: str) -> dict:
        return {"id_token": "fake-jwt", "access_token": "fake-at"}

    def claims(self, *, id_token: str, nonce: str) -> dict:
        return dict(self.claims_to_return, nonce=nonce)

    def end_session_url(self) -> str | None:
        return None


@pytest.fixture(scope="module")
def app_db():
    from khandaq import main, migrate
    from khandaq.auth.oidc import provide_oidc_client
    from khandaq.deps import get_session

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)

    def _get_session():
        with Session(eng) as s:
            try:
                yield s
            except Exception:
                s.rollback()
                raise

    fake = FakeOidc()
    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[provide_oidc_client] = lambda: fake
    yield app, fake
    eng.dispose()


@pytest.fixture
def client(app_db):
    app, _ = app_db
    return TestClient(app)  # fresh cookie jar per test


@pytest.fixture
def fake(app_db):
    _, fake = app_db
    return fake


def _login(client: TestClient, fake: FakeOidc, email: str = "alice@test") -> None:
    fake.claims_to_return = {"email": email, "name": email.split("@")[0]}
    r = client.get("/api/auth/login", follow_redirects=False)
    assert r.status_code == 307
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    r2 = client.get(f"/api/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert r2.status_code == 307


def test_login_redirects_to_idp_with_pkce(client):
    r = client.get("/api/auth/login?next=/engagements", follow_redirects=False)
    assert r.status_code == 307
    loc = r.headers["location"]
    assert loc.startswith("https://idp.test/authorize")
    assert "code_challenge=" in loc and "code_challenge_method=S256" in loc and "state=" in loc
    assert "khandaq_login" in r.headers.get("set-cookie", "")


def test_callback_creates_session_and_me(client, fake):
    _login(client, fake, "alice@test")
    me = client.get("/api/auth/me").json()
    assert me["email"] == "alice@test"
    assert me["auth"] == "session"
    assert me["csrf_token"]


def test_callback_tampered_state_rejected(client, fake):
    client.get("/api/auth/login", follow_redirects=False)  # sets the login cookie
    r = client.get("/api/auth/callback?code=abc&state=TAMPERED", follow_redirects=False)
    assert r.status_code == 400


def test_csrf_enforced_on_session_mutation(client, fake):
    _login(client, fake, "carol@test")
    # No CSRF header on a state-changing request → refused.
    r = client.post("/api/engagements", json={"name": "x"})
    assert r.status_code == 403
    # With the session's CSRF token → allowed.
    csrf = client.get("/api/auth/me").json()["csrf_token"]
    r2 = client.post("/api/engagements", json={"name": "x"}, headers={"X-Khandaq-CSRF": csrf})
    assert r2.status_code == 201


def test_api_token_create_use_revoke(client):
    dev = {"X-Khandaq-Dev-User": "bob@test"}
    created = client.post("/api/auth/tokens", json={"name": "ci"}, headers=dev)
    assert created.status_code == 201
    token = created.json()["token"]
    token_id = created.json()["id"]
    assert token.startswith("kqt_")

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["email"] == "bob@test" and me["auth"] == "token"

    assert client.delete(f"/api/auth/tokens/{token_id}", headers=dev).status_code == 204
    after = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert after.status_code == 401


def test_logout_revokes_session(client, fake):
    _login(client, fake, "dave@test")
    csrf = client.get("/api/auth/me").json()["csrf_token"]
    out = client.post("/api/auth/logout", headers={"X-Khandaq-CSRF": csrf})
    assert out.status_code == 200 and out.json()["status"] == "logged_out"
    # The session cookie is cleared, so /me no longer resolves via the session (falls back to dev).
    assert client.get("/api/auth/me").json()["auth"] == "dev"


def test_prod_requires_real_credentials(client, monkeypatch):
    from khandaq.settings import Settings

    monkeypatch.setattr("khandaq.deps.get_settings", lambda: Settings(env="prod"))
    r = client.post("/api/engagements", json={"name": "x"})
    assert r.status_code == 401
