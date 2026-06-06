#!/usr/bin/env python3
"""
RailInfra — Internal Switch Control API
========================================
Localhost-only control interface for the ESTW railway switch hardware.
Bound to 127.0.0.1:8001 — not reachable from outside the VM.

Only reachable as root (firewall + binding). Players reach this after:
  sysadmin → sudo switch-ctl (no args) → root shell → discover port 8001
  → POST /api/switch → root flag returned in JSON response

Discovery hint: /internal-help network diagram shows "Switch control API :8001"
as a localhost-only service. Players use `ss -tlnp` or `curl localhost:8001`
once they have a root shell.

Deployed by Ansible to: /opt/railinfra/switch_api.py
Runs as:                root (systemd unit: railinfra-switchapi.service)
"""

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Injected by Ansible via environment variable at provisioning time.
ROOT_FLAG = os.environ.get("ROOT_FLAG", "FLAG{sw1tch_c0ntr0l_0wn3d}")

# Current switch state (in-memory; resets on service restart)
SWITCH_STATE = {
    "Switch1": "STRAIGHT",
    "Switch2": "STRAIGHT",
    "Switch3": "STRAIGHT",
}

# Narrative impact strings — returned alongside the flag to reward the
# attacker with story context when they successfully set a switch.
IMPACTS = {
    "Switch1": "Track 1 now routes to Factory Siding A — freight collision imminent",
    "Switch2": "DB InfraGo junction misaligned — public rail network disrupted",
    "Switch3": "Depot entry set to DIVERGE — runaway risk on maintenance track",
}


@app.route("/api/switch", methods=["GET"])
def list_switches():
    """
    Returns the list of controllable switches and their current positions.
    Discovery endpoint — players call this first to see what's available.
    """
    return jsonify({
        "status":   "ok",
        "switches": [
            {"id": sw_id, "position": pos}
            for sw_id, pos in SWITCH_STATE.items()
        ],
    })


@app.route("/api/switch", methods=["POST"])
def set_switch():
    """
    Set a switch position. Returns the root flag on success.

    Expected request body (JSON):
        {"switch": "Switch1", "position": "DIVERGE"}

    Valid positions: STRAIGHT, DIVERGE

    Any valid switch + any valid position returns the flag — players don't
    need domain knowledge of railway systems to complete this step.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    sw_id    = data.get("switch",   "")
    position = data.get("position", "").upper()

    if sw_id not in SWITCH_STATE:
        return jsonify({
            "error":            "unknown switch",
            "available_switches": list(SWITCH_STATE.keys()),
        }), 404

    if position not in ("STRAIGHT", "DIVERGE"):
        return jsonify({
            "error":            "invalid position",
            "valid_positions":  ["STRAIGHT", "DIVERGE"],
        }), 400

    old_pos = SWITCH_STATE[sw_id]
    SWITCH_STATE[sw_id] = position

    status_code = f"{sw_id.upper().replace(' ', '_')}_SET_{position}"

    return jsonify({
        "status":        status_code,
        "switch":        sw_id,
        "old_position":  old_pos,
        "new_position":  position,
        "impact":        IMPACTS.get(sw_id, "Switch position changed"),
        "flag":          ROOT_FLAG,
    })


@app.route("/api/status", methods=["GET"])
def status():
    """Health check / discovery endpoint."""
    return jsonify({
        "service":  "RailInfra Switch Control API",
        "version":  "1.0.0",
        "status":   "operational",
        "note":     "Internal use only — authorised personnel only",
    })


if __name__ == "__main__":
    # Bind to localhost only — UFW also blocks 8001 externally, but
    # binding here ensures the service is unreachable even if UFW is off.
    app.run(host="127.0.0.1", port=8001, debug=False)
