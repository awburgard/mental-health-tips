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
import hashlib
import hmac
import logging
import os
import random
import secrets
import sqlite3
import time
import uuid
from typing import List
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

# Pre-submission content moderation (Claude API). When ANTHROPIC_API_KEY is
# empty the moderation check is skipped entirely and submissions pass straight
# to the HR review queue (same behaviour as before this feature existed).
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-7")

# Password-reset email (Resend). When RESEND_API_KEY is empty the reset
# feature is hidden from the UI and the endpoints no-op.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESET_EMAIL_TO = os.environ.get("RESET_EMAIL_TO", "kimberly.rascon@realworklabs.com")
RESET_EMAIL_FROM = os.environ.get("RESET_EMAIL_FROM", "Mental Health Tips <onboarding@resend.dev>")
RESET_TOKEN_TTL_SECONDS = 3600  # 1 hour
RESET_MIN_PASSWORD_LEN = 12

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
        # Defensive migration: add flagged column (added with moderation feature).
        if "flagged" not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN flagged INTEGER NOT NULL DEFAULT 0")
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


# ---------- Password hashing (PBKDF2-SHA256) ----------


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    iters = 200_000
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters)
    return f"pbkdf2${iters}${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
    except (ValueError, AttributeError):
        return False
    if algo != "pbkdf2":
        return False
    try:
        expected = hashlib.pbkdf2_hmac(
            "sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), int(iters)
        )
    except ValueError:
        return False
    return hmac.compare_digest(expected.hex(), hash_hex)


def stored_admin_password_hash():
    db = get_db()
    row = db.execute(
        "SELECT password_hash FROM admin_credentials WHERE id = 1"
    ).fetchone()
    return row["password_hash"] if row else None


def check_admin_password(pw: str) -> bool:
    """Prefer DB-stored hash (set via reset flow). Fall back to env var until first reset."""
    h = stored_admin_password_hash()
    if h:
        return verify_password(pw, h)
    if not ADMIN_PASSWORD:
        return False
    return hmac.compare_digest(pw, ADMIN_PASSWORD)


# ---------- Reset-email transport (Resend) ----------


def send_reset_email(token: str) -> tuple:
    if not RESEND_API_KEY:
        return False, "RESEND_API_KEY not configured"
    base = ALLOWED_ORIGIN.rstrip("/") if ALLOWED_ORIGIN else "http://127.0.0.1:8000"
    link = f"{base}/admin/reset?token={token}"
    body = {
        "from": RESET_EMAIL_FROM,
        "to": [RESET_EMAIL_TO],
        "subject": "Anonymous mental health tips — admin password reset",
        "text": (
            "Someone requested a reset of the admin reviewer password for the "
            "anonymous mental health tips app.\n\n"
            "To set a new password, click this one-time link (valid for 1 hour):\n\n"
            f"{link}\n\n"
            "If you didn't request this, you can ignore this email. The link "
            "only changes anything once you click it AND submit a new "
            "password — until then, no change is made."
        ),
    }
    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=10,
        )
    except requests.RequestException as e:
        return False, f"network: {type(e).__name__}"
    if resp.status_code not in (200, 202):
        return False, f"http {resp.status_code}"
    return True, "ok"


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------- Pre-submission content moderation (Claude API) ----------
#
# The form is anonymous and HR-moderated. Moderation here is a pre-filter for
# obvious abuse so HR doesn't see slurs, threats, doxxing, or sexual content.
# It is intentionally "fail open" — if the API errors or the key is missing,
# submissions pass through to HR review unchanged. HR moderation is the
# safety net; the model is the first pass.

import anthropic
from pydantic import BaseModel

_anthropic_client = None


def _get_anthropic_client():
    global _anthropic_client
    if not ANTHROPIC_API_KEY:
        return None
    if _anthropic_client is None:
        _anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return _anthropic_client


MODERATION_SYSTEM_PROMPT = """\
You are a content moderator for an anonymous mental health tips submission form at a workplace. Each submission is meant to be a tip, idea, or practice that has helped someone with stress, burnout, work-life balance, sleep, or general wellbeing — to be reviewed by HR and posted anonymously to a Slack channel.

Classify the submission against the following categories. Set a field to true if and ONLY if the submission contains content matching that category. Be precise — do not flag a tip simply because it mentions difficult emotions. Be especially careful: identity, religion, or demographic mentions in a positive or neutral context are NOT hate speech. Only flag hate_speech when the submission expresses hostility, slurs, or advocates discrimination toward a protected group. Tips about meditation, therapy, boundaries, journaling, exercise, faith practices, coming out, etc. should NOT trigger any category.

BLOCK categories (auto-rejected before HR sees them):
- hate_speech: hostility, slurs, or advocacy of discrimination toward a protected class (race, ethnicity, national origin, religion, sex, gender identity, sexual orientation, age, disability, pregnancy/family status, veteran status, genetic info).
- targeted_harassment: insults, intimidation, or attacks aimed at a named or identifiable individual.
- sexual_content: adult content, sexually suggestive material, or sexual references to coworkers. (Statements of identity like "as a lesbian I..." are NOT sexual content.)
- threats_violence: direct threats, advocacy of violence, or descriptions of attacks.
- doxxing: naming coworkers, sharing emails/addresses/phone numbers, or distinctive identifying descriptions of specific individuals.
- illegal_advocacy: advocating illegal activities (drug use at work, theft, fraud, etc.).

FLAG categories (saved, but HR sees a warning):
- self_harm: content describing self-harm behaviors, suicidal ideation, or similar. A tip about recovery FROM such struggles is valuable; flag so HR can review the framing.
- self_identifying: the submitter discloses something that could identify them (unique role/team references such as "as the only X on team Y").
- workplace_grievance: reads as a complaint about a specific person, team, or policy rather than a wellbeing tip.

When in doubt, do NOT flag. The downside of a false flag is wasted HR attention; the downside of over-blocking is a chilled submission space. A submission about an ordinary wellbeing practice should classify with every field set to false."""


class ModerationResult(BaseModel):
    hate_speech: bool
    targeted_harassment: bool
    sexual_content: bool
    threats_violence: bool
    doxxing: bool
    illegal_advocacy: bool
    self_harm: bool
    self_identifying: bool
    workplace_grievance: bool


_BLOCK_CATEGORIES = (
    "hate_speech", "targeted_harassment", "sexual_content",
    "threats_violence", "doxxing", "illegal_advocacy",
)
_FLAG_CATEGORIES = ("self_harm", "self_identifying", "workplace_grievance")


def moderate_submission(text: str) -> dict:
    """Classify a submission. Returns a dict:
        block (bool)   - reject before HR
        flag  (bool)   - save, warn HR
        reasons (list) - category names that triggered

    Fails OPEN — on missing key, API error, or parse failure, returns
    {block: False, flag: False, reasons: []} so legitimate submissions are
    not silently dropped when the upstream service is unhappy. HR review is
    the safety net.
    """
    client = _get_anthropic_client()
    if client is None:
        return {"block": False, "flag": False, "reasons": []}
    try:
        response = client.messages.parse(
            model=ANTHROPIC_MODEL,
            max_tokens=512,
            system=[{
                "type": "text",
                "text": MODERATION_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{
                "role": "user",
                "content": f"Classify this submission:\n\n<<<\n{text}\n>>>",
            }],
            output_format=ModerationResult,
        )
        result = response.parsed_output
    except Exception as e:
        log_event("moderation_api_error", error=type(e).__name__)
        return {"block": False, "flag": False, "reasons": []}

    block_hits: List[str] = [c for c in _BLOCK_CATEGORIES if getattr(result, c)]
    flag_hits: List[str] = [c for c in _FLAG_CATEGORIES if getattr(result, c)]
    return {
        "block": bool(block_hits),
        "flag": bool(flag_hits),
        "reasons": block_hits + flag_hits,
    }


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

_GATE_EXEMPT_PATHS = {"/unlock", "/healthz", "/admin/reset"}


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

    mod = moderate_submission(clean)
    if mod["block"]:
        log_event("submission_blocked", reasons=",".join(mod["reasons"]))
        return render_template(
            "form.html",
            max_len=MAX_CONTENT_LEN,
            error="We weren't able to accept that submission. Please review the guidance above and try again.",
        ), 400

    db = get_db()
    db.execute(
        "INSERT INTO submissions (id, content, status, created_at, flagged) "
        "VALUES (?, ?, 'pending', ?, ?)",
        (new_id(), clean, now_hour(), 1 if mod["flag"] else 0),
    )
    db.commit()
    if mod["flag"]:
        log_event("submission_received", length=len(clean), flagged=True,
                  reasons=",".join(mod["reasons"]))
    else:
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
        if check_admin_password(password):
            # Rotate session (defense against fixation) but keep the unlock
            # flag — they had to be unlocked to even reach this page.
            session.clear()
            session["unlocked"] = True
            session["admin"] = True
            return redirect(url_for("admin"))
        return render_template(
            "login.html",
            error="Incorrect password.",
            reset_enabled=bool(RESEND_API_KEY),
        ), 401
    return render_template("login.html", reset_enabled=bool(RESEND_API_KEY))


@app.route("/admin/request-reset", methods=["POST"])
def admin_request_reset():
    """Trigger an admin-password reset email to RESET_EMAIL_TO.
    The visitor must be unlocked (gated by SITE_PASSWORD). To avoid leaking
    whether a reset is already pending we always render the same confirmation
    page regardless of whether we actually sent an email this time.
    """
    if not RESEND_API_KEY:
        return render_template("reset_sent.html")
    db = get_db()
    now = int(time.time())
    # Clean up expired/used tokens, then invalidate any still-active token so
    # a fresh email superseeds the old link.
    db.execute(
        "DELETE FROM password_resets WHERE expires_at < ? OR used = 1",
        (now,),
    )
    db.execute("UPDATE password_resets SET used = 1")
    # Throttle: at most one new reset per 60 seconds across the whole app.
    recent = db.execute(
        "SELECT 1 FROM password_resets WHERE created_at > ?",
        (now - 60,),
    ).fetchone()
    if recent:
        db.commit()
        return render_template("reset_sent.html")
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO password_resets (token_hash, created_at, expires_at, used) "
        "VALUES (?, ?, ?, 0)",
        (_token_hash(token), now, now + RESET_TOKEN_TTL_SECONDS),
    )
    db.commit()
    ok, detail = send_reset_email(token)
    log_event("admin_reset_requested", email_ok=ok, detail=detail)
    return render_template("reset_sent.html")


@app.route("/admin/reset", methods=["GET", "POST"])
def admin_reset():
    """One-time link Kimberly (or whoever holds the email) clicks to set a
    new admin password. This route is exempt from the site-wide gate — the
    token IS the auth."""
    token = (
        request.args.get("token")
        or request.form.get("token")
        or ""
    )
    th = _token_hash(token) if token else ""
    now = int(time.time())
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM password_resets WHERE token_hash = ? AND expires_at >= ? AND used = 0",
        (th, now),
    ).fetchone()
    if not row:
        return render_template(
            "reset_form.html",
            token="",
            error="This reset link is invalid or has expired. Please request a new one.",
        ), 400

    if request.method == "GET":
        return render_template("reset_form.html", token=token)

    new_pw = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    if len(new_pw) < RESET_MIN_PASSWORD_LEN:
        return render_template(
            "reset_form.html",
            token=token,
            error=f"Password must be at least {RESET_MIN_PASSWORD_LEN} characters.",
        ), 400
    if not hmac.compare_digest(new_pw, confirm):
        return render_template(
            "reset_form.html",
            token=token,
            error="The two passwords do not match.",
        ), 400

    pw_hash = hash_password(new_pw)
    db.execute(
        "INSERT INTO admin_credentials (id, password_hash, updated_at) VALUES (1, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash, updated_at = excluded.updated_at",
        (pw_hash, now),
    )
    db.execute(
        "UPDATE password_resets SET used = 1 WHERE token_hash = ?",
        (th,),
    )
    db.commit()
    log_event("admin_password_changed")
    return render_template("reset_done.html")


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
        "SELECT id, content, created_at, flagged FROM submissions "
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
