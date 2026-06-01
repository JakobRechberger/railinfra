from flask import (
    Flask, request, session, redirect,
    url_for, render_template, make_response
)
from config import Config
from flask_mysqldb import MySQL

app = Flask(__name__)
app.config.from_object(Config)
mysql = MySQL(app)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ACCOUNTS = {
    "operator":   {"password": "operator123", "role": "operator"},
    "supervisor": {"password": "supervisor123", "role": "supervisor"},
}

def get_session_user():
    """Return (username, role) for the current session, or (None, None)."""
    username = session.get("username")
    role = session.get("role")
    if not username or not role:
        return None, None
    return username, role

def require_auth(min_role="operator"):
    """
    Returns a redirect response if the session does not meet the minimum role,
    otherwise returns None. Call at the top of each protected route.

    Role hierarchy: operator < supervisor
    """
    role_rank = {"operator": 1, "supervisor": 2}
    _, role = get_session_user()
    if role is None or role_rank.get(role, 0) < role_rank.get(min_role, 0):
        return redirect(url_for("login"))
    return None

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        bypass   = request.args.get("debug", "").lower() == "true"

        if bypass and username:
            # Vulnerability 1: debug parameter skips password validation.
            # TODO: remove ?debug=true before deploying to production -- app.js line 12
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
    # signal_banner is populated by /signal POST and stored in session.
    # It is rendered unescaped in the template — intentional XSS sink.
    signal_banner = session.get("signal_banner", "")
    return render_template(
        "dashboard.html",
        username=username,
        role=role,
        signal_banner=signal_banner,
    )


@app.route("/signal", methods=["POST"])
def signal():
    """
    Accepts a signal name and stores it in the session for display.
    The value is rendered WITHOUT escaping in dashboard.html.
    This is the XSS sink — the automated bot polls this endpoint,
    causing it to render any injected payload.
    """
    guard = require_auth("operator")
    if guard:
        return guard

    signal_name = request.form.get("signal_name", "")
    # Vulnerability 2: no sanitisation before storing for display.
    session["signal_banner"] = signal_name
    return redirect(url_for("dashboard"))


@app.route("/internal-help", methods=["GET"])
def internal_help():
    guard = require_auth("supervisor")
    if guard:
        return guard

    return render_template("internal_help.html")


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Debug mode OFF — vulnerability is the ?debug=true param, not Flask debug.
    app.run(host="127.0.0.1", port=5000, debug=False)