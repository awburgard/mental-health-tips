# Anonymous mental health tips

A small, privacy-first web app for collecting anonymous mental-health tips from
coworkers, reviewing them, and posting approved ones to a Slack channel.

The app is deliberately tiny — about 300 lines of Python and one HTML file per
page — because the strongest privacy promise is "you don't have to trust us,
here is the code."

## What we promise

- The app **does not** ask for, log, or store: your name, email, IP address,
  user agent, browser fingerprint, cookies, or any session identifier.
- The database schema has no submitter column. There is literally nowhere in
  the DB for an identity to go.
- Submission timestamps are rounded to the hour before saving.
- The HR review queue shows submissions in **random order**, not the order they
  arrived — so a reviewer can't correlate "tip #3 came in right after Sarah
  Slacked me."
- The form page loads no third-party scripts, no analytics, no fonts/CDNs from
  outside the server. View source: there is one `<script>` tag, six lines, for
  the character counter.
- Approved submissions are purged from the DB 30 days after they post to Slack.
  Denied submissions purge after 7 days. (Both windows are configurable.)
- The Slack integration uses an **incoming webhook**, not a bot. It can post to
  one channel and nothing else. It has no read permissions.

## What we can't promise

- **Hosting platform metadata.** Fly.io (or any hosting platform) sees standard
  HTTP request metadata, including client IPs, at their edge as part of how the
  internet works. Their retention is short and they don't share this with us,
  but it isn't zero. We can't change that — we can only choose not to read or
  store it ourselves, which is what this app does. This is the same caveat that
  applies to literally any website you visit.
- **Writing-style fingerprinting.** If you write the way you always write,
  someone who knows you could recognize your voice. This is intrinsic to
  anonymous writing and can't be fixed by code — only by you.
- **Self-identification in content.** If your tip says "as the only person on
  the data team who…" we can't unidentify you. The review portal flags obvious
  self-references with a soft warning so a reviewer can deny those tips.
- **Insider threat against the hosting account.** Anyone who can read the
  Fly.io account and the SQLite volume can read pending submissions until they
  are purged. That blast radius is limited (no IP, no identity) but the content
  itself exists during the review window.
- **You cannot edit or delete a submission after sending it.** We have no way
  to know which tip is yours, so we cannot honor a request like "please remove
  the one I sent yesterday." The form reminds the submitter of this before they
  click submit.

## Architecture

- **Backend:** Flask (Python 3.12), single `app.py`.
- **Database:** SQLite, single file on a Fly.io persistent volume.
- **Hosting:** Fly.io, single small VM, gunicorn behind Fly's edge.
- **Slack:** Incoming webhook URL stored in `SLACK_WEBHOOK_URL` env var.
- **Admin auth:** HTTP Basic with a single shared password (`ADMIN_PASSWORD`).
  For 1–3 reviewers sharing the password is appropriate; no third-party identity
  provider is involved.
- **Purge job:** APScheduler running in-process, every 6 hours.

## Setup (local dev)

```bash
cd mental-health-tips
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env: paste your Slack webhook URL and admin password
python app.py     # the activated venv's python — NOT system python3
```

(If you skip `source .venv/bin/activate`, run `.venv/bin/python app.py`
explicitly — `python3 app.py` will use the system Python and fail with
`ModuleNotFoundError: No module named 'requests'`.)

Visit `http://127.0.0.1:8000` for the form.
Visit `http://127.0.0.1:8000/admin` and use any username + the password from
`.env` for the review queue.

## Tests

```bash
pip install pytest
pytest -q
```

Tests assert the DB schema has no PII columns, submissions store only the
expected fields, `created_at` is hour-rounded, and the admin portal requires
auth.

## Deploy (Fly.io)

```bash
# one-time: install flyctl, sign in
brew install flyctl
fly auth signup   # or fly auth login

# from the project directory
fly launch --no-deploy
# accept defaults; pick an app name; pick a region
# (this writes a generated fly.toml; replace it with the one in this repo, or
#  let flyctl overwrite and re-add the volume mount + env block by hand)

fly volumes create tips_data --size 1 --region <your-region>

fly secrets set \
  SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..." \
  ADMIN_PASSWORD="<your generated password>" \
  ALLOWED_ORIGIN="https://<your-app>.fly.dev"

fly deploy
```

After deploy: confirm the form loads at `https://<your-app>.fly.dev` and the
review queue at `https://<your-app>.fly.dev/admin`. Share the form URL with
coworkers.

### A note about hosting choice

This app is hosted on Fly.io because:

- It runs as a single Docker container we control.
- We can disable HTTP access logs (no client IPs reach our app logs).
- The SQLite volume lives on hardware we lease, not a managed database service
  whose log retention we can't see.
- It's cheap (~$0 at this scale) and trivially removable.

Vercel and Cloudflare Workers would work too, but they involve more layers
between the user and the code, and they have edge-level logs that capture
client IPs for their own retention window. Fly does too at the platform layer,
but the surface above (our app) is fully ours.

## Threat model (short version)

| Risk | Mitigation |
| --- | --- |
| App logs leaking IP | gunicorn `--access-logfile=/dev/null`; app logger never logs request bodies |
| Sequential IDs revealing submission order | UUIDv4 primary keys |
| Timing correlation by HR reviewer | `created_at` rounded to hour; queue shuffled |
| CSRF on the public form | `Origin` header check; no cookies/sessions to forge |
| CSRF on admin actions | `Origin` header check; basic auth + same-origin form |
| Slack webhook over-scoped | Incoming webhook can only post to one channel |
| Submissions lingering | 30-day / 7-day purge cron |
| Reviewer wants to edit a tip | Not possible — approve as-written or deny. Editing without submitter consent would break the anonymity contract. |
| Crisis content | Reviewer can deny; every approved post auto-appends a crisis-resources footer with 988 and an EAP pointer. |
| Insider read of pending submissions | Limited blast radius (no identity stored). Mitigation: short retention. |

## License

Internal use. No license, no warranty, no claims.
