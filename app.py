import json

from flask import (
    Flask, request, session, redirect,
    url_for, render_template
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
    {"id": "SW-1", "location": "Factory siding A",  "state": "NORMAL"},
    {"id": "SW-2", "location": "DB InfraGo junction","state": "NORMAL"},
    {"id": "SW-3", "location": "Depot entry",         "state": "DIVERGE"},
    {"id": "SW-4", "location": "Factory siding B",    "state": "IDLE"},
]
SIGNALS = [
    {"id":"SIG-A", "location": "DB InfraGo junction", "state": "HALT"},
    {"id":"SIG-B", "location": "Depot Entry", "state": "GO"},
    {"id":"SIG-C", "location": "Factory siding A", "state": "GO"},
    {"id":"SIG-D", "location": "Factory siding B", "state": "HALT"},
    {"id":"SIG-E", "location": "Endpoint", "state": "HALT"},
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

USER_FLAG = "FLAG{s3ss10n_h1j4ck_succ3ss}"

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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        bypass   = request.args.get("debug", "").lower() == "true"

        if bypass and username:
            # Vulnerability 1: debug parameter skips password validation.
            # TODO: remove ?debug=true before deploying to production — app.js
            account = ACCOUNTS.get(username)
            if account:
                session["username"] = username
                session["role"]     = account["role"]
                return redirect(url_for("dashboard"))
            error = "Unknown user."

        elif username and password:
            account = ACCOUNTS.get(username)
            if account and account["password"] == password:
                session["username"] = username
                session["role"]     = account["role"]
                return redirect(url_for("dashboard"))
            else:
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
    )


@app.route("/signal", methods=["POST"])
def signal():
    """
    Accepts a signal name and stores it unsanitised in the session.
    Rendered via {{ signal_banner | safe }} in dashboard.html.
    The automated bot (cron job as supervisor) polls /dashboard, causing
    it to render any injected payload and exfiltrate its session cookie.
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
    return render_template("internal_help.html", role=role, user_flag=USER_FLAG)


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# Add this to SWITCHES constant at the top of app.py (or derive from DB later

# Add this route to app.py
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
        signals_json = json.dumps(SIGNALS),
        switches=SWITCHES,
        switches_json=json.dumps(SWITCHES),
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
        saved = True

    current = {}
    for key, default in DEFAULT_SETTINGS.items():
        current[key] = session.get("settings_" + key, default)

    return render_template("settings.html", role=role, settings=current, saved=saved)

# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Flask debug mode OFF — the vulnerability is the ?debug=true param,
    # not the Flask debugger.
    app.run(host="127.0.0.1", port=5000, debug=False)
