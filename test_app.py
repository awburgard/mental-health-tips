"""
Minimal tests that verify the privacy guarantees we promised.

Run with: pytest -q
"""
import os
import sqlite3
import tempfile
from unittest.mock import patch

import pytest

# Configure env BEFORE importing the app module.
os.environ.setdefault("ADMIN_PASSWORD", "test-password")
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-not-for-prod")
os.environ.setdefault("ALLOWED_ORIGIN", "")
os.environ.setdefault("ENABLE_SCHEDULER", "0")  # don't start APScheduler in tests


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
    # Re-import the module so it picks up the new DB_PATH.
    import importlib
    import app as app_module
    importlib.reload(app_module)
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c, app_module, str(db_path)


def test_schema_has_no_pii_columns(client):
    _, _, db_path = client
    conn = sqlite3.connect(db_path)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(submissions)")]
    conn.close()

    forbidden = {"ip", "ip_address", "user_agent", "session", "session_id",
                 "submitter", "submitter_id", "email", "name", "user", "user_id"}
    leaked = [c for c in cols if c.lower() in forbidden]
    assert not leaked, f"DB schema contains forbidden columns: {leaked}"


def test_submission_stores_only_expected_fields(client):
    c, app_module, db_path = client
    with patch.object(app_module, "post_to_slack", return_value=(True, "ok")):
        resp = c.post("/submit", data={"content": "drink water", "category": "General"})
    assert resp.status_code in (302, 303)

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT * FROM submissions").fetchone()
    cols = [d[0] for d in conn.execute("SELECT * FROM submissions").description]
    conn.close()
    record = dict(zip(cols, row))

    assert record["content"] == "drink water"
    assert record["category"] == "General"
    assert record["status"] == "pending"
    assert record["created_at"] % 3600 == 0, "created_at must be rounded to the hour"


def test_admin_requires_auth(client):
    c, _, _ = client
    # Unauthed visits get redirected to the login page.
    resp = c.get("/admin")
    assert resp.status_code in (302, 303)
    assert "/admin/login" in resp.headers["Location"]


def test_admin_login_rejects_wrong_password(client):
    c, _, _ = client
    resp = c.post("/admin/login", data={"password": "wrong"})
    assert resp.status_code == 401


def test_admin_can_approve_and_post(client):
    c, app_module, db_path = client
    with patch.object(app_module, "post_to_slack", return_value=(True, "ok")) as p:
        c.post("/submit", data={"content": "go for a walk", "category": "Stress"})
        conn = sqlite3.connect(db_path)
        sub_id = conn.execute("SELECT id FROM submissions").fetchone()[0]
        conn.close()

        # Authenticate via the login form (session cookie is set on the test client).
        login = c.post("/admin/login", data={"password": "test-password"})
        assert login.status_code in (302, 303)

        resp = c.post("/admin/approve", data={"id": sub_id})
        assert resp.status_code in (302, 303)
        p.assert_called_once()
        args, _kw = p.call_args
        assert args[0] == "go for a walk"
        assert args[1] == "Stress"


def test_denied_submission_keeps_no_identifying_data(client):
    c, app_module, db_path = client
    c.post("/submit", data={"content": "rest your eyes", "category": "General"})
    conn = sqlite3.connect(db_path)
    sub_id = conn.execute("SELECT id FROM submissions").fetchone()[0]
    conn.close()

    c.post("/admin/login", data={"password": "test-password"})
    c.post("/admin/deny", data={"id": sub_id, "reason": "duplicate"})

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT status, deny_reason FROM submissions WHERE id=?", (sub_id,)).fetchone()
    conn.close()
    assert row[0] == "denied"
    assert row[1] == "duplicate"
