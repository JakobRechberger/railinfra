import os

class Config:
    SECRET_KEY          = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")
    MYSQL_HOST          = os.environ.get("MYSQL_HOST", "127.0.0.1")
    MYSQL_USER          = os.environ.get("MYSQL_USER", "railinfra")
    MYSQL_PASSWORD      = os.environ.get("MYSQL_PASSWORD", "dbpassword")
    MYSQL_DB            = os.environ.get("MYSQL_DB", "railinfra")
    # Intentional vulnerabilities — do not fix
    SESSION_COOKIE_HTTPONLY = False   # allows JS cookie access (XSS target)
    SESSION_COOKIE_SECURE   = False   # no HTTPS
