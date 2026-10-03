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
        self.claims_to_return = {"email": "alice@test", "name": "Alice", "email_verified": True}

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        return (
            "https://idp.test/authorize"
            f"?state={state}&nonce={nonce}"
            f"&code_challenge={code_challenge}&code_challenge_method=S256"
        )

    def exchange(self, *, code: str, code_verifier: str) -> dict:
        return {"id_token": "fake-jwt", "access_token": "fake-at"}

    def claims(self, *, id_token: str, nonce: str) -> dict:
        # A real id_token always carries iss and sub (the client requires both); default the sub
        # to one IdP account per email unless a test names its own.
        defaults = {"iss": ISSUER, "sub": f"sub-{self.claims_to_return.get('email')}"}
        return dict(defaults, **self.claims_to_return, nonce=nonce)

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

    from khandaq.settings import get_settings

    settings = get_settings()
    previous_allowed = settings.allowed_emails
    settings.allowed_emails = ALLOWED

    fake = FakeOidc()
    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[provide_oidc_client] = lambda: fake
    yield app, fake, eng
    settings.allowed_emails = previous_allowed
    eng.dispose()


ALLOWED = (
    "alice@test,bob@test,carol@test,dave@test,erin@test,"
    "frank@test,grace@test,heidi@test,heidi.new@test,ivan@test,judy@test"
)
ISSUER = "https://idp.test/realms/khandaq"


@pytest.fixture
def client(app_db):
    app, _, _ = app_db
    return TestClient(app)  # fresh cookie jar per test


@pytest.fixture
def fake(app_db):
    _, fake, _ = app_db
    return fake


@pytest.fixture
def db(app_db):
    _, _, eng = app_db
    return eng


def _callback(client: TestClient, fake: FakeOidc, claims: dict):
    """Run login → callback with the fake IdP returning ``claims``; return the callback response."""
    fake.claims_to_return = claims
    r = client.get("/api/auth/login", follow_redirects=False)
    assert r.status_code == 307
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    return client.get(f"/api/auth/callback?code=abc&state={state}", follow_redirects=False)


def _login(client: TestClient, fake: FakeOidc, email: str = "alice@test") -> None:
    claims = {"email": email, "name": email.split("@")[0], "email_verified": True}
    r2 = _callback(client, fake, claims)
    assert r2.status_code == 307
    assert r2.headers["location"] != "/?signin=denied", "login unexpectedly denied"


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


# --- review hardening (allow-list, verified email, cookies, token attribution) -----------------


def _audit_rows(db, action: str) -> list:
    with db.connect() as conn:
        return conn.execute(
            text("SELECT actor_user_id, actor_token_id, detail FROM audit_log WHERE action = :a"),
            {"a": action},
        ).all()


def test_sign_in_denied_when_not_allow_listed(client, fake, db):
    r = _callback(client, fake, {"email": "stranger@gmail.test", "email_verified": True})
    assert r.status_code == 307 and r.headers["location"] == "/?signin=denied"
    assert "khandaq_session" not in r.headers.get("set-cookie", "")
    denied = [
        row
        for row in _audit_rows(db, "auth.denied")
        if row.detail["email"] == "stranger@gmail.test"
    ]
    assert denied and "ALLOWED_EMAILS" in denied[0].detail["reason"]
    with db.connect() as conn:  # no user row is created for a refused stranger
        assert (
            conn.execute(
                text("SELECT count(*) FROM users WHERE email = 'stranger@gmail.test'")
            ).scalar()
            == 0
        )


def test_sign_in_denied_when_email_unverified(client, fake):
    # erin@test is allow-listed, but an unverified address could be anyone's.
    r = _callback(client, fake, {"email": "erin@test", "email_verified": False})
    assert r.headers["location"] == "/?signin=denied"


def test_removal_from_allow_list_revokes_access(client, fake, app_db):
    from khandaq.settings import get_settings

    _login(client, fake, "dave@test")
    assert client.get("/api/auth/me").status_code == 200
    settings = get_settings()
    try:
        settings.allowed_emails = ALLOWED.replace("dave@test", "")
        assert client.get("/api/auth/me").status_code == 403
    finally:
        settings.allowed_emails = ALLOWED


def test_token_actions_are_attributed_to_the_token(client, db):
    dev = {"X-Khandaq-Dev-User": "bob@test"}
    created = client.post("/api/auth/tokens", json={"name": "ci"}, headers=dev).json()
    auth = {"Authorization": f"Bearer {created['token']}"}
    eng = client.post("/api/engagements", json={"name": "via-token"}, headers=auth)
    assert eng.status_code == 201
    rows = [
        row for row in _audit_rows(db, "engagement.created") if row.actor_token_id == created["id"]
    ]
    assert rows, "engagement.created by an API token must record actor_token_id"


def test_malformed_login_cookie_is_400_not_500(client):
    client.cookies.set("khandaq_login", "e30.not*valid*base64", path="/api/auth")
    r = client.get("/api/auth/callback?code=abc&state=x", follow_redirects=False)
    assert r.status_code == 400


def test_prod_ignores_the_non_host_cookie(client, fake, monkeypatch):
    from khandaq.settings import Settings

    _login(client, fake, "alice@test")  # dev sets the plain `khandaq_session` cookie
    monkeypatch.setattr(
        "khandaq.deps.get_settings", lambda: Settings(env="prod", allowed_emails=ALLOWED)
    )
    # In prod only __Host-khandaq_session counts, so the plain cookie authenticates nobody.
    assert client.get("/api/auth/me").status_code == 401


def test_logout_audit_names_the_actor(client, fake, db):
    _login(client, fake, "carol@test")
    csrf = client.get("/api/auth/me").json()["csrf_token"]
    assert client.post("/api/auth/logout", headers={"X-Khandaq-CSRF": csrf}).status_code == 200
    assert all(row.actor_user_id for row in _audit_rows(db, "auth.logout"))


# --- users are keyed by the IdP account (iss, sub) ------------------------------------------------


def _claims(email: str, sub: str, **extra) -> dict:
    return {
        "email": email,
        "name": email.split("@")[0],
        "email_verified": True,
        "sub": sub,
        **extra,
    }


def _user_rows(db, email: str) -> list:
    with db.connect() as conn:
        return conn.execute(
            text("SELECT id, email, oidc_issuer, oidc_subject FROM users WHERE email = :e"),
            {"e": email},
        ).all()


def _audit(db, action: str) -> list[dict]:
    with db.connect() as conn:
        return list(
            conn.execute(
                text("SELECT detail FROM audit_log WHERE action = :a ORDER BY at"), {"a": action}
            ).scalars()
        )


def test_a_new_user_is_keyed_by_issuer_and_subject(client, fake, db):
    r = _callback(client, fake, _claims("frank@test", "kc-frank"))
    assert r.headers["location"] == "/"
    [row] = _user_rows(db, "frank@test")
    assert (row.oidc_issuer, row.oidc_subject) == (ISSUER, "kc-frank")


def test_a_user_from_before_identity_keying_is_linked_on_sign_in(client, fake, db):
    with db.begin() as conn:
        conn.execute(text("INSERT INTO users (id, email) VALUES ('usr_legacy', 'grace@test')"))
    r = _callback(client, fake, _claims("grace@test", "kc-grace"))
    assert r.headers["location"] == "/"
    [row] = _user_rows(db, "grace@test")
    assert row.id == "usr_legacy"  # the same user, so its memberships and history carry over
    assert (row.oidc_issuer, row.oidc_subject) == (ISSUER, "kc-grace")
    assert {"oidc_issuer": ISSUER, "oidc_subject": "kc-grace"} in _audit(db, "user.identity_linked")


def test_an_email_change_at_the_idp_follows_the_same_account(client, fake, db):
    _callback(client, fake, _claims("heidi@test", "kc-heidi"))
    [before] = _user_rows(db, "heidi@test")
    r = _callback(TestClient(client.app), fake, _claims("heidi.new@test", "kc-heidi"))
    assert r.headers["location"] == "/"
    assert _user_rows(db, "heidi@test") == []
    [after] = _user_rows(db, "heidi.new@test")
    assert after.id == before.id
    assert {"from": "heidi@test", "to": "heidi.new@test"} in _audit(db, "user.email_changed")


def test_another_idp_account_with_a_linked_email_is_refused(client, fake, db):
    """Keyed by email, a second IdP account that verified the same address became the first
    user and inherited their engagements. Now it is refused and audited."""
    _callback(client, fake, _claims("ivan@test", "kc-ivan"))
    other = TestClient(client.app)
    r = _callback(other, fake, _claims("ivan@test", "kc-impostor"))
    assert r.headers["location"] == "/?signin=denied"
    assert "khandaq_session" not in r.headers.get("set-cookie", "")  # no session was issued
    [row] = _user_rows(db, "ivan@test")
    assert row.oidc_subject == "kc-ivan"
    assert any(
        d.get("email") == "ivan@test" and "another identity-provider account" in d.get("reason", "")
        for d in _audit(db, "auth.denied")
    )


def test_an_email_change_onto_another_users_email_is_refused(client, fake, db):
    _callback(client, fake, _claims("judy@test", "kc-judy"))
    other = TestClient(client.app)
    r = _callback(other, fake, _claims("alice@test", "kc-judy"))  # alice@test is someone else's
    assert r.headers["location"] == "/?signin=denied"
    [row] = _user_rows(db, "judy@test")
    assert row.oidc_subject == "kc-judy"


def test_an_id_token_without_a_subject_is_rejected(client, fake):
    r = _callback(client, fake, _claims("frank@test", ""))
    assert r.status_code == 400


# --- An unreachable identity provider (staging, 2026-10-03) --------------------------------------


def test_an_unreachable_idp_sends_login_to_a_notice_not_a_500(client, fake, monkeypatch):
    from khandaq.auth.oidc import IdentityProviderUnavailable

    def down(**_):
        raise IdentityProviderUnavailable("the identity provider cannot be reached")

    monkeypatch.setattr(fake, "authorization_url", down)
    r = client.get("/api/auth/login", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"] == "/?signin=unavailable"


def test_an_idp_failing_during_the_callback_sends_it_to_the_notice(client, fake, monkeypatch):
    from khandaq.auth.oidc import IdentityProviderUnavailable

    r = client.get("/api/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]

    def down(**_):
        raise IdentityProviderUnavailable("token endpoint unreachable")

    monkeypatch.setattr(fake, "exchange", down)
    r2 = client.get(f"/api/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert r2.status_code == 307 and r2.headers["location"] == "/?signin=unavailable"
    assert client.get("/api/auth/me").json()["auth"] != "session"  # no session was created
