import os

class Config:
    # Flask session signing key — Ansible sets this to a random value at
    # provisioning time via the SECRET_KEY environment variable.
    # The same key is used by bot.py to pre-sign its session cookie, so
    # both must match.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")

    # MySQL connection — Ansible injects these via environment variables
    # in the systemd unit (EnvironmentFile=/etc/railinfra/webapp.env)
    MYSQL_HOST     = os.environ.get("MYSQL_HOST",     "127.0.0.1")
    MYSQL_USER     = os.environ.get("MYSQL_USER",     "railinfra_app")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "dbpassword")
    MYSQL_DB       = os.environ.get("MYSQL_DB",       "railinfra")

    # Intentional vulnerabilities — do not fix
    SESSION_COOKIE_HTTPONLY = False   # JS can read document.cookie (XSS target)
    SESSION_COOKIE_SECURE   = False   # no HTTPS required
