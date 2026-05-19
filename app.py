"""
Anonymous mental health tips — submission, review, and Slack posting.

Privacy notes for anyone reading this file:
- The app never logs request bodies.
- The app never records the submitter's IP, user-agent, cookies, or session.
- The DB schema has no submitter columns.
- created_at is rounded to the hour before insert.
- Pending submissions are shown to reviewers in random order, not by time.
- Approved submissions purge 30 days after posting; denied submissions purge after 7 days.
"""
import hmac
import logging
import os
import random
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

load_dotenv()

# ---------- Config ----------

DB_PATH = os.environ.get("DB_PATH", "tips.db")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID", "")
SITE_PASSWORD = os.environ.get("SITE_PASSWORD", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "")  # e.g. https://tips.example.com
MAX_CONTENT_LEN = 2000

APPROVED_PURGE_DAYS = int(os.environ.get("APPROVED_PURGE_DAYS", "30"))
DENIED_PURGE_DAYS = int(os.environ.get("DENIED_PURGE_DAYS", "7"))

if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD env var is required")
if not SITE_PASSWORD:
    raise RuntimeError("SITE_PASSWORD env var is required (gates the whole site)")
if not FLASK_SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY env var is required (used to sign admin session cookies)")

# ---------- Logging: deliberately minimal ----------

# Silence Werkzeug's default access log so we don't accidentally record IPs/paths.
logging.getLogger("werkzeug").setLevel(logging.ERROR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("tips")


def log_event(event: str, **kwargs) -> None:
    """Log only structured event names + non-identifying metadata. Never content."""
    parts = " ".join(f"{k}={v}" for k, v in kwargs.items())
    log.info(f"event={event} {parts}")


# ---------- DB helpers ----------


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    schema = Path(__file__).parent / "schema.sql"
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(schema.read_text())
        cols = [r[1] for r in conn.execute("PRAGMA table_info(submissions)")]
        # Defensive migration: add slack_ts to any pre-existing DB that lacks it.
        if "slack_ts" not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN slack_ts TEXT")
        # Defensive migration: drop the legacy category column if it exists.
        # SQLite >= 3.35 supports DROP COLUMN directly; older falls back to
        # a table rebuild.
        if "category" in cols:
            try:
                conn.execute("ALTER TABLE submissions DROP COLUMN category")
            except sqlite3.OperationalError:
                conn.executescript("""
                    CREATE TABLE submissions_new (
                        id            TEXT PRIMARY KEY,
                        content       TEXT NOT NULL,
                        status        TEXT NOT NULL DEFAULT 'pending',
                        created_at    INTEGER NOT NULL,
                        reviewed_at   INTEGER,
                        deny_reason   TEXT,
                        slack_posted  INTEGER NOT NULL DEFAULT 0,
                        slack_ts      TEXT
                    );
                    INSERT INTO submissions_new
                        (id, content, status, created_at, reviewed_at,
                         deny_reason, slack_posted, slack_ts)
                    SELECT id, content, status, created_at, reviewed_at,
                           deny_reason, slack_posted, slack_ts
                    FROM submissions;
                    DROP TABLE submissions;
                    ALTER TABLE submissions_new RENAME TO submissions;
                    CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
                    CREATE INDEX IF NOT EXISTS idx_submissions_reviewed_at ON submissions(reviewed_at);
                """)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def standalone_db():
    """For use outside Flask request context (scheduler jobs)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------- Time / id helpers ----------


def now_hour() -> int:
    """Unix seconds rounded DOWN to the current hour."""
    return (int(time.time()) // 3600) * 3600


def new_id() -> str:
    return str(uuid.uuid4())


# ---------- Slack ----------


SLACK_API = "https://slack.com/api"


def _slack_call(method: str, payload: dict) -> tuple[bool, str, dict]:
    """Common Slack Web API caller. Returns (ok, detail, raw_response_json)."""
    if not SLACK_BOT_TOKEN or not SLACK_CHANNEL_ID:
        return False, "Slack bot token / channel id not configured", {}
    try:
        resp = requests.post(
            f"{SLACK_API}/{method}",
            headers={
                "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                "Content-Type": "application/json; charset=utf-8",
            },
            json=payload,
            timeout=10,
        )
    except requests.RequestException as e:
        return False, f"network: {type(e).__name__}", {}
    if resp.status_code != 200:
        return False, f"http {resp.status_code}", {}
    data = resp.json()
    if not data.get("ok"):
        return False, f"slack: {data.get('error', 'unknown')}", data
    return True, "ok", data


def post_to_slack(text: str):
    """Post a tip to Slack. Returns (ok: bool, detail: str, slack_ts: str | None).

    We use Block Kit with plain_text blocks so anything the submitter wrote is
    rendered literally — no markdown, no `<https://evil|click here>` style
    fake links, no @here pings. Slack also cannot interpret stray characters
    in user content as formatting.
    """
    title = "Anonymous tip"
    ok, detail, data = _slack_call(
        "chat.postMessage",
        {
            "channel": SLACK_CHANNEL_ID,
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text", "text": title}},
                {"type": "section",
                 "text": {"type": "plain_text", "text": text}},
            ],
            "text": title,  # fallback for notifications / accessibility
        },
    )
    return ok, detail, data.get("ts") if ok else None


def delete_slack_message(slack_ts: str) -> tuple[bool, str]:
    """Delete a previously-posted tip. Returns (ok, detail)."""
    ok, detail, _ = _slack_call(
        "chat.delete",
        {"channel": SLACK_CHANNEL_ID, "ts": slack_ts},
    )
    return ok, detail


# ---------- Admin auth (single shared password) ----------
#
# CSRF strategy:
#   The admin session cookie is set with SameSite=Strict, which means the
#   browser will not include it on any cross-site request. A malicious site
#   that POSTs to /admin/approve from a victim's browser will hit our endpoint
#   without the session cookie, fail the auth check, and be redirected to
#   /admin/login. No tokens needed; the cookie attribute is the defense.
#   We do not rely on Origin/Referer headers because some browsers and
#   privacy-protection extensions strip them.


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)

    return wrapper


# ---------- Flask app ----------

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_NAME="adm",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=bool(ALLOWED_ORIGIN),  # require HTTPS in production
)
app.teardown_appcontext(close_db)


# ---------- Site-wide access gate ----------
#
# Everything except /unlock, /healthz and static assets is server-side gated
# behind SITE_PASSWORD. A user without an unlocked session never receives the
# form HTML — so clearing cookies or "removing the gate" in DevTools just
# bounces them back to /unlock. The unlock state lives in the signed session
# cookie (HttpOnly, Secure in prod, SameSite=Strict).

_GATE_EXEMPT_PATHS = {"/unlock", "/healthz"}


@app.before_request
def _gate_site():
    p = request.path
    if p in _GATE_EXEMPT_PATHS or p.startswith("/static/"):
        return None
    if not session.get("unlocked"):
        return redirect(url_for("unlock", next=p))
    return None


@app.after_request
def add_security_headers(resp):
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # Stop the browser from caching gated pages — back-button shouldn't be
    # able to resurrect the form view after the user clears their session.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )
    # HSTS only when we're behind real HTTPS (i.e. deployed).
    if ALLOWED_ORIGIN.startswith("https://"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Strict CSP: no inline scripts/styles, no remote loads, no <base> abuse,
    # forms can only post to our own origin.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    return resp


@app.route("/", methods=["GET"])
def form():
    return render_template("form.html", max_len=MAX_CONTENT_LEN)


@app.route("/submit", methods=["POST"])
def submit():
    # No CSRF token / origin check here: /submit is unauthenticated, has no
    # session, and accepts public input — there is no privilege to abuse.
    # CSRF on the admin routes is handled by SameSite=Strict on the cookie.
    content = (request.form.get("content") or "").strip()

    if not content or len(content) > MAX_CONTENT_LEN:
        return render_template(
            "form.html",
            max_len=MAX_CONTENT_LEN,
            error=f"Tip must be 1–{MAX_CONTENT_LEN} characters.",
        ), 400

    # Strip non-printable characters defensively (paste hygiene).
    clean = "".join(ch for ch in content if ch == "\n" or ch == "\t" or ch.isprintable())

    db = get_db()
    db.execute(
        "INSERT INTO submissions (id, content, status, created_at) "
        "VALUES (?, ?, 'pending', ?)",
        (new_id(), clean, now_hour()),
    )
    db.commit()
    log_event("submission_received", length=len(clean))
    return redirect(url_for("thanks"))


@app.route("/thanks", methods=["GET"])
def thanks():
    return render_template("thanks.html")


@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    # Only honor `next` if it is a relative path on our own origin.
    raw_next = request.args.get("next") or request.form.get("next") or "/"
    next_path = raw_next if raw_next.startswith("/") and not raw_next.startswith("//") else "/"

    if request.method == "POST":
        password = request.form.get("password") or ""
        if hmac.compare_digest(password, SITE_PASSWORD):
            session["unlocked"] = True
            return redirect(next_path)
        return render_template("unlock.html", next=next_path, error="Incorrect access code."), 401
    return render_template("unlock.html", next=next_path)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password") or ""
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            # Rotate session (defense against fixation) but keep the unlock
            # flag — they had to be unlocked to even reach this page.
            session.clear()
            session["unlocked"] = True
            session["admin"] = True
            return redirect(url_for("admin"))
        return render_template("login.html", error="Incorrect password."), 401
    return render_template("login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    # Only drop the admin flag. The site unlock stays so they don't have to
    # re-enter the access code just to use the form.
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin", methods=["GET"])
@require_admin
def admin():
    db = get_db()
    pending = db.execute(
        "SELECT id, content, created_at FROM submissions "
        "WHERE status = 'pending'"
    ).fetchall()
    pending = list(pending)
    random.shuffle(pending)  # never show submission order to a reviewer

    failed = db.execute(
        "SELECT id, content FROM submissions "
        "WHERE status = 'approved' AND slack_posted = 0"
    ).fetchall()

    posted = db.execute(
        "SELECT id, content, reviewed_at FROM submissions "
        "WHERE status = 'approved' AND slack_posted = 1 AND slack_ts IS NOT NULL "
        "ORDER BY reviewed_at DESC"
    ).fetchall()

    return render_template(
        "admin.html",
        pending=pending,
        failed=failed,
        posted=posted,
    )


@app.route("/admin/approve", methods=["POST"])
@require_admin
def admin_approve():
    sub_id = request.form.get("id", "")
    db = get_db()
    row = db.execute(
        "SELECT content FROM submissions WHERE id = ? AND status = 'pending'",
        (sub_id,),
    ).fetchone()
    if not row:
        return redirect(url_for("admin"))

    ok, detail, ts = post_to_slack(row["content"])
    db.execute(
        "UPDATE submissions SET status='approved', reviewed_at=?, slack_posted=?, slack_ts=? "
        "WHERE id = ?",
        (now_hour(), 1 if ok else 0, ts, sub_id),
    )
    db.commit()
    log_event("review_completed", action="approved", slack_ok=ok, detail=detail)
    return redirect(url_for("admin"))


@app.route("/admin/retry", methods=["POST"])
@require_admin
def admin_retry():
    sub_id = request.form.get("id", "")
    db = get_db()
    row = db.execute(
        "SELECT content FROM submissions "
        "WHERE id = ? AND status = 'approved' AND slack_posted = 0",
        (sub_id,),
    ).fetchone()
    if not row:
        return redirect(url_for("admin"))

    ok, detail, ts = post_to_slack(row["content"])
    if ok:
        db.execute(
            "UPDATE submissions SET slack_posted=1, slack_ts=? WHERE id = ?",
            (ts, sub_id),
        )
        db.commit()
    log_event("slack_retry", slack_ok=ok, detail=detail)
    return redirect(url_for("admin"))


@app.route("/admin/delete-post", methods=["POST"])
@require_admin
def admin_delete_post():
    sub_id = request.form.get("id", "")
    db = get_db()
    row = db.execute(
        "SELECT slack_ts FROM submissions "
        "WHERE id = ? AND status = 'approved' AND slack_posted = 1",
        (sub_id,),
    ).fetchone()
    if not row or not row["slack_ts"]:
        return redirect(url_for("admin"))

    ok, detail = delete_slack_message(row["slack_ts"])
    if ok:
        # On successful Slack delete we wipe the row entirely — the post is gone,
        # there's no reason to retain content waiting for the scheduled purge.
        db.execute("DELETE FROM submissions WHERE id = ?", (sub_id,))
        db.commit()
    log_event("slack_delete", slack_ok=ok, detail=detail)
    return redirect(url_for("admin"))


@app.route("/admin/deny", methods=["POST"])
@require_admin
def admin_deny():
    sub_id = request.form.get("id", "")
    reason = (request.form.get("reason") or "").strip()[:200] or None
    db = get_db()
    db.execute(
        "UPDATE submissions SET status='denied', reviewed_at=?, deny_reason=? "
        "WHERE id = ? AND status='pending'",
        (now_hour(), reason, sub_id),
    )
    db.commit()
    log_event("review_completed", action="denied", had_reason=bool(reason))
    return redirect(url_for("admin"))


@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200


# ---------- Purge job ----------


def purge_old_records() -> None:
    """Delete denied submissions older than DENIED_PURGE_DAYS and
    approved submissions older than APPROVED_PURGE_DAYS.

    We delete by reviewed_at so the clock starts when HR acted on the item,
    not when it was submitted.
    """
    now = int(time.time())
    approved_cutoff = now - APPROVED_PURGE_DAYS * 86400
    denied_cutoff = now - DENIED_PURGE_DAYS * 86400
    with standalone_db() as db:
        cur = db.execute(
            "DELETE FROM submissions WHERE status='approved' AND reviewed_at < ?",
            (approved_cutoff,),
        )
        approved_removed = cur.rowcount
        cur = db.execute(
            "DELETE FROM submissions WHERE status='denied' AND reviewed_at < ?",
            (denied_cutoff,),
        )
        denied_removed = cur.rowcount
        db.commit()
    log_event("purge_run", approved_removed=approved_removed, denied_removed=denied_removed)


def start_scheduler() -> None:
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(purge_old_records, "interval", hours=6, id="purge")
    sched.start()


# ---------- Bootstrap ----------

init_db()
if os.environ.get("ENABLE_SCHEDULER", "1") == "1":
    start_scheduler()


if __name__ == "__main__":
    # Local dev only. Production uses gunicorn (see Dockerfile).
    app.run(host="127.0.0.1", port=8000, debug=False)
