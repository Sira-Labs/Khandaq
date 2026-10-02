"""Read endpoints that back the web console (spec 007): list engagements, targets, scope, members."""  # noqa: E501

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
OUTSIDER = {"X-Khandaq-Dev-User": "outsider@test"}


@pytest.fixture(scope="module")
def client():
    from khandaq import main, migrate
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

    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app)
    eng.dispose()


def test_reads(client):
    eng_id = client.post("/api/engagements", json={"name": "reads"}, headers=OWNER).json()["id"]
    client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "gw.acme.test"}},
        headers=OWNER,
    )
    client.put(
        f"/api/engagements/{eng_id}/scope",
        json={"allow": {"llm_endpoint": [{"host": "gw.acme.test"}]}, "deny": [], "roe": {}},
        headers=OWNER,
    )

    # owner@test is a non-admin who owns this engagement → it appears in their list
    listed = client.get("/api/engagements", headers=OWNER).json()
    assert any(e["id"] == eng_id for e in listed)

    targets = client.get(f"/api/engagements/{eng_id}/targets", headers=OWNER).json()
    assert len(targets) == 1 and targets[0]["type"] == "llm_endpoint"

    scope = client.get(f"/api/engagements/{eng_id}/scope", headers=OWNER).json()
    assert scope["allow"]["llm_endpoint"][0]["host"] == "gw.acme.test"

    members = client.get(f"/api/engagements/{eng_id}/members", headers=OWNER).json()
    assert any(m["role"] == "owner" and m["email"] == "owner@test" for m in members)


def test_outsider_sees_empty_list_and_is_denied_detail(client):
    eng_id = client.post("/api/engagements", json={"name": "private"}, headers=OWNER).json()["id"]
    # outsider is a member of nothing
    assert client.get("/api/engagements", headers=OUTSIDER).json() == []
    assert client.get(f"/api/engagements/{eng_id}/targets", headers=OUTSIDER).status_code == 403
