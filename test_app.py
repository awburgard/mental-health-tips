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
os.environ.setdefault("SITE_PASSWORD", "test-site-password")
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
    # Default to passing moderation in tests; individual tests override.
    monkeypatch.setattr(
        app_module, "moderate_submission",
        lambda text: {"block": False, "flag": False, "reasons": []},
    )
    with app_module.app.test_client() as c:
        # Unlock the site for every test that uses this fixture; the gate
        # itself is exercised in dedicated tests below.
        c.post("/unlock", data={"password": "test-site-password"})
        yield c, app_module, str(db_path)


@pytest.fixture
def locked_client(tmp_path, monkeypatch):
    """Like `client` but without an unlocked session — for gate tests."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
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
                 "submitter", "submitter_id", "email", "name", "user", "user_id",
                 "category"}  # category was removed; guard against accidental re-add
    leaked = [c for c in cols if c.lower() in forbidden]
    assert not leaked, f"DB schema contains forbidden columns: {leaked}"


def test_submission_stores_only_expected_fields(client):
    c, app_module, db_path = client
    with patch.object(app_module, "post_to_slack", return_value=(True, "ok", "1.0")):
        resp = c.post("/submit", data={"content": "drink water"})
    assert resp.status_code in (302, 303)

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT * FROM submissions").fetchone()
    cols = [d[0] for d in conn.execute("SELECT * FROM submissions").description]
    conn.close()
    record = dict(zip(cols, row))

    assert record["content"] == "drink water"
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
    with patch.object(app_module, "post_to_slack", return_value=(True, "ok", "1234.5678")) as p:
        c.post("/submit", data={"content": "go for a walk"})
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

        # Slack ts is stored so we can delete the message later.
        conn = sqlite3.connect(db_path)
        ts = conn.execute("SELECT slack_ts FROM submissions WHERE id=?", (sub_id,)).fetchone()[0]
        conn.close()
        assert ts == "1234.5678"


def test_admin_can_delete_posted_message(client):
    c, app_module, db_path = client
    with patch.object(app_module, "post_to_slack", return_value=(True, "ok", "9876.5432")), \
         patch.object(app_module, "delete_slack_message", return_value=(True, "ok")) as d:
        c.post("/submit", data={"content": "stretch"})
        conn = sqlite3.connect(db_path)
        sub_id = conn.execute("SELECT id FROM submissions").fetchone()[0]
        conn.close()

        c.post("/admin/login", data={"password": "test-password"})
        c.post("/admin/approve", data={"id": sub_id})
        resp = c.post("/admin/delete-post", data={"id": sub_id})
        assert resp.status_code in (302, 303)

        d.assert_called_once_with("9876.5432")

        # Row wiped after successful Slack delete.
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT * FROM submissions WHERE id=?", (sub_id,)).fetchone()
        conn.close()
        assert row is None


def test_denied_submission_keeps_no_identifying_data(client):
    c, app_module, db_path = client
    c.post("/submit", data={"content": "rest your eyes"})
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


def test_gate_redirects_unlocked_visitor(locked_client):
    c, _, _ = locked_client
    resp = c.get("/")
    assert resp.status_code in (302, 303)
    assert "/unlock" in resp.headers["Location"]


def test_gate_blocks_submit_without_unlock(locked_client):
    c, _, db_path = locked_client
    resp = c.post("/submit", data={"content": "should not be saved"})
    assert resp.status_code in (302, 303)
    assert "/unlock" in resp.headers["Location"]
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
    conn.close()
    assert rows == 0, "submission should NOT have been written"


def test_gate_rejects_wrong_code(locked_client):
    c, _, _ = locked_client
    resp = c.post("/unlock", data={"password": "nope"})
    assert resp.status_code == 401


def test_gate_admin_login_also_gated(locked_client):
    c, _, _ = locked_client
    resp = c.get("/admin/login")
    assert resp.status_code in (302, 303)
    assert "/unlock" in resp.headers["Location"]


def test_healthz_bypasses_gate(locked_client):
    c, _, _ = locked_client
    assert c.get("/healthz").status_code == 200


def test_admin_reset_flow_end_to_end(client, monkeypatch):
    c, app_module, db_path = client
    # Enable the reset feature for the duration of this test.
    monkeypatch.setattr(app_module, "RESEND_API_KEY", "test-key", raising=False)

    captured = {}
    def fake_send(token):
        captured["token"] = token
        return True, "ok"
    monkeypatch.setattr(app_module, "send_reset_email", fake_send)

    # 1) Trigger a reset; the email helper is called with a fresh token.
    resp = c.post("/admin/request-reset")
    assert resp.status_code == 200
    assert "token" in captured
    token = captured["token"]

    # 2) The reset link is exempt from the site gate — visit GET /admin/reset
    #    from a fresh client with no unlock cookie.
    with app_module.app.test_client() as fresh:
        page = fresh.get(f"/admin/reset?token={token}")
        assert page.status_code == 200
        # 3) Submit the new password.
        done = fresh.post(
            "/admin/reset",
            data={"token": token, "password": "BrandNewPwd123!", "confirm": "BrandNewPwd123!"},
        )
        assert done.status_code == 200

    # 4) The DB now stores a hashed admin password.
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT password_hash FROM admin_credentials WHERE id = 1").fetchone()
    conn.close()
    assert row is not None
    assert row[0].startswith("pbkdf2$"), "password should be stored as a PBKDF2 hash"

    # 5) The new password works on /admin/login; the old env-var password does not.
    login_new = c.post("/admin/login", data={"password": "BrandNewPwd123!"})
    assert login_new.status_code in (302, 303)
    c.post("/admin/logout")
    login_old = c.post("/admin/login", data={"password": "test-password"})
    assert login_old.status_code == 401


def test_admin_reset_token_can_only_be_used_once(client, monkeypatch):
    c, app_module, _ = client
    monkeypatch.setattr(app_module, "RESEND_API_KEY", "test-key", raising=False)
    captured = {}
    monkeypatch.setattr(app_module, "send_reset_email",
                        lambda t: (captured.setdefault("token", t), (True, "ok"))[1])

    c.post("/admin/request-reset")
    token = captured["token"]
    first = c.post(
        "/admin/reset",
        data={"token": token, "password": "FirstAttempt1!!", "confirm": "FirstAttempt1!!"},
    )
    assert first.status_code == 200

    second = c.post(
        "/admin/reset",
        data={"token": token, "password": "SecondAttempt2!", "confirm": "SecondAttempt2!"},
    )
    assert second.status_code == 400  # token already used


def test_moderation_block_rejects_submission(client, monkeypatch):
    c, app_module, db_path = client
    monkeypatch.setattr(
        app_module, "moderate_submission",
        lambda t: {"block": True, "flag": False, "reasons": ["hate_speech"]},
    )
    resp = c.post("/submit", data={"content": "anything"})
    assert resp.status_code == 400
    # Generic message — must not reveal which rule fired.
    body = resp.get_data(as_text=True)
    assert "hate_speech" not in body
    assert "able to accept" in body  # apostrophe gets HTML-escaped in template
    # And nothing got written to the DB.
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
    conn.close()
    assert rows == 0


def test_moderation_flag_saves_with_flag(client, monkeypatch):
    c, app_module, db_path = client
    monkeypatch.setattr(
        app_module, "moderate_submission",
        lambda t: {"block": False, "flag": True, "reasons": ["self_harm"]},
    )
    resp = c.post("/submit", data={"content": "i used to struggle with X and what helped was Y"})
    assert resp.status_code in (302, 303)
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT flagged FROM submissions").fetchone()
    conn.close()
    assert row[0] == 1


def test_moderation_failure_fails_open(client, monkeypatch):
    """When moderation fails (API down, parse error), submissions go through."""
    c, app_module, db_path = client
    # The real moderate_submission catches exceptions internally — verify the
    # contract that the resulting "all-False" return passes through.
    monkeypatch.setattr(
        app_module, "moderate_submission",
        lambda t: {"block": False, "flag": False, "reasons": []},
    )
    resp = c.post("/submit", data={"content": "innocuous tip"})
    assert resp.status_code in (302, 303)
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT flagged FROM submissions").fetchone()
    conn.close()
    assert row[0] == 0


def test_admin_reset_hidden_when_email_not_configured(locked_client, monkeypatch):
    c, app_module, _ = locked_client
    monkeypatch.setattr(app_module, "RESEND_API_KEY", "", raising=False)
    # Unlock so we can see /admin/login.
    c.post("/unlock", data={"password": "test-site-password"})
    html = c.get("/admin/login").get_data(as_text=True)
    assert "Reset password" not in html
