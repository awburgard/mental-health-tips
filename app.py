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
    abort,
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
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "")  # e.g. https://tips.example.com
MAX_CONTENT_LEN = 2000
CATEGORIES = ["Stress", "Burnout", "Work-Life", "Sleep", "General"]

APPROVED_PURGE_DAYS = int(os.environ.get("APPROVED_PURGE_DAYS", "30"))
DENIED_PURGE_DAYS = int(os.environ.get("DENIED_PURGE_DAYS", "7"))

if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD env var is required")
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


def post_to_slack(text: str, category: str) -> tuple[bool, str]:
    if not SLACK_WEBHOOK_URL:
        return False, "SLACK_WEBHOOK_URL not configured"
    body = {
        "text": f"*Anonymous tip — {category}*\n>>> {text}",
        "mrkdwn": True,
    }
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=body, timeout=10)
    except requests.RequestException as e:
        return False, f"network: {type(e).__name__}"
    if resp.status_code != 200:
        return False, f"http {resp.status_code}"
    return True, "ok"


# ---------- Origin guard ----------


def origin_ok(req) -> bool:
    """Reject cross-site POSTs. We don't want to depend on cookies for CSRF."""
    if not ALLOWED_ORIGIN:
        return True  # local dev: allow
    origin = req.headers.get("Origin") or req.headers.get("Referer", "")
    return origin.startswith(ALLOWED_ORIGIN)


# ---------- Admin auth (single shared password) ----------


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


@app.after_request
def add_security_headers(resp):
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'"
    )
    return resp


@app.route("/", methods=["GET"])
def form():
    return render_template("form.html", categories=CATEGORIES, max_len=MAX_CONTENT_LEN)


@app.route("/submit", methods=["POST"])
def submit():
    if not origin_ok(request):
        abort(403)
    content = (request.form.get("content") or "").strip()
    category = (request.form.get("category") or "").strip()

    if not content or len(content) > MAX_CONTENT_LEN:
        return render_template(
            "form.html",
            categories=CATEGORIES,
            max_len=MAX_CONTENT_LEN,
            error=f"Tip must be 1–{MAX_CONTENT_LEN} characters.",
        ), 400
    if category not in CATEGORIES:
        return render_template(
            "form.html",
            categories=CATEGORIES,
            max_len=MAX_CONTENT_LEN,
            error="Please pick a category.",
        ), 400

    # Strip non-printable characters defensively (paste hygiene).
    clean = "".join(ch for ch in content if ch == "\n" or ch == "\t" or ch.isprintable())

    db = get_db()
    db.execute(
        "INSERT INTO submissions (id, content, category, status, created_at) "
        "VALUES (?, ?, ?, 'pending', ?)",
        (new_id(), clean, category, now_hour()),
    )
    db.commit()
    log_event("submission_received", category=category, length=len(clean))
    return redirect(url_for("thanks"))


@app.route("/thanks", methods=["GET"])
def thanks():
    return render_template("thanks.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if not origin_ok(request):
            abort(403)
        password = request.form.get("password") or ""
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            return redirect(url_for("admin"))
        return render_template("login.html", error="Incorrect password."), 401
    return render_template("login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    if not origin_ok(request):
        abort(403)
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin", methods=["GET"])
@require_admin
def admin():
    db = get_db()
    pending = db.execute(
        "SELECT id, content, category, created_at FROM submissions "
        "WHERE status = 'pending'"
    ).fetchall()
    pending = list(pending)
    random.shuffle(pending)  # never show submission order to a reviewer

    failed = db.execute(
        "SELECT id, content, category FROM submissions "
        "WHERE status = 'approved' AND slack_posted = 0"
    ).fetchall()

    return render_template(
        "admin.html",
        pending=pending,
        failed=failed,
    )


@app.route("/admin/approve", methods=["POST"])
@require_admin
def admin_approve():
    if not origin_ok(request):
        abort(403)
    sub_id = request.form.get("id", "")
    db = get_db()
    row = db.execute(
        "SELECT content, category FROM submissions WHERE id = ? AND status = 'pending'",
        (sub_id,),
    ).fetchone()
    if not row:
        return redirect(url_for("admin"))

    ok, detail = post_to_slack(row["content"], row["category"])
    db.execute(
        "UPDATE submissions SET status='approved', reviewed_at=?, slack_posted=? "
        "WHERE id = ?",
        (now_hour(), 1 if ok else 0, sub_id),
    )
    db.commit()
    log_event("review_completed", action="approved", slack_ok=ok, detail=detail)
    return redirect(url_for("admin"))


@app.route("/admin/retry", methods=["POST"])
@require_admin
def admin_retry():
    if not origin_ok(request):
        abort(403)
    sub_id = request.form.get("id", "")
    db = get_db()
    row = db.execute(
        "SELECT content, category FROM submissions "
        "WHERE id = ? AND status = 'approved' AND slack_posted = 0",
        (sub_id,),
    ).fetchone()
    if not row:
        return redirect(url_for("admin"))

    ok, detail = post_to_slack(row["content"], row["category"])
    if ok:
        db.execute(
            "UPDATE submissions SET slack_posted=1 WHERE id = ?",
            (sub_id,),
        )
        db.commit()
    log_event("slack_retry", slack_ok=ok, detail=detail)
    return redirect(url_for("admin"))


@app.route("/admin/deny", methods=["POST"])
@require_admin
def admin_deny():
    if not origin_ok(request):
        abort(403)
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
