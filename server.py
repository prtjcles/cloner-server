"""
License Key Server (with HWID locking + lockout system)
========================================================
Host this on Railway.

Requirements:
    pip install flask

Environment variables:
    ADMIN_PASSWORD  — secret password to manage keys
    PORT            — port to run on (default: 5000)
"""

import os
import json
import string
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")
KEYS_FILE      = "keys.json"
LOCKOUT_HOURS  = 24

def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)

def generate_key():
    chars = string.ascii_uppercase + string.digits
    segments = ["".join(random.choices(chars, k=5)) for _ in range(4)]
    return "-".join(segments)

DURATIONS = {
    "1day":    timedelta(days=1),
    "1week":   timedelta(weeks=1),
    "1month":  timedelta(days=30),
    "lifetime": None,
}

def lockout_time_remaining(locked_until_str: str) -> str:
    locked_until = datetime.fromisoformat(locked_until_str)
    now          = datetime.utcnow()
    if now >= locked_until:
        return None  # Lockout expired
    delta   = locked_until - now
    hours   = int(delta.total_seconds() // 3600)
    minutes = int((delta.total_seconds() % 3600) // 60)
    if hours > 0:
        return f"{hours} hour{'s' if hours != 1 else ''}, {minutes} minute{'s' if minutes != 1 else ''}"
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


@app.route("/validate", methods=["POST"])
def validate():
    data = request.json or {}
    key  = data.get("key", "").strip().upper()
    hwid = data.get("hwid", "").strip()

    if not key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400
    if not hwid:
        return jsonify({"valid": False, "reason": "No HWID provided"}), 400

    keys  = load_keys()

    if key not in keys:
        return jsonify({"valid": False, "reason": "Invalid key"}), 200

    entry = keys[key]

    if entry.get("revoked"):
        return jsonify({"valid": False, "reason": "Key has been revoked"}), 200

    # ── Check if key is currently locked out ──────────────────
    if entry.get("locked_until"):
        remaining = lockout_time_remaining(entry["locked_until"])
        if remaining:
            return jsonify({
                "valid":    False,
                "reason":   "Key is locked due to use on another machine",
                "locked":   True,
                "remaining": remaining,
            }), 200
        else:
            # Lockout expired — clear it but keep original HWID
            entry["locked_until"] = None
            keys[key] = entry
            save_keys(keys)

    # ── HWID check ────────────────────────────────────────────
    if entry.get("hwid"):
        if entry["hwid"] != hwid:
            # Wrong machine — trigger 24hr lockout for everyone
            entry["locked_until"] = (datetime.utcnow() + timedelta(hours=LOCKOUT_HOURS)).isoformat()
            entry["lockout_reason"] = f"Used on unknown machine at {datetime.utcnow().isoformat()}"
            keys[key] = entry
            save_keys(keys)
            return jsonify({
                "valid":     False,
                "reason":    "Key is locked due to use on another machine",
                "locked":    True,
                "remaining": f"{LOCKOUT_HOURS} hours, 0 minutes",
            }), 200
    else:
        # First time use — lock to this machine
        entry["hwid"]           = hwid
        entry["hwid_locked_at"] = datetime.utcnow().isoformat()
        keys[key] = entry
        save_keys(keys)

    # ── Expiry check ──────────────────────────────────────────
    if entry["expires"] is None:
        return jsonify({
            "valid":     True,
            "plan":      entry["plan"],
            "time_left": "Lifetime",
            "expires":   "Never",
        }), 200

    expires_at = datetime.fromisoformat(entry["expires"])
    now        = datetime.utcnow()

    if now > expires_at:
        return jsonify({"valid": False, "reason": "Key has expired"}), 200

    delta   = expires_at - now
    days    = delta.days
    hours   = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60

    if days > 0:
        time_left = f"{days} day{'s' if days != 1 else ''}, {hours} hour{'s' if hours != 1 else ''}"
    elif hours > 0:
        time_left = f"{hours} hour{'s' if hours != 1 else ''}, {minutes} minute{'s' if minutes != 1 else ''}"
    else:
        time_left = f"{minutes} minute{'s' if minutes != 1 else ''}"

    return jsonify({
        "valid":     True,
        "plan":      entry["plan"],
        "time_left": time_left,
        "expires":   entry["expires"],
    }), 200


@app.route("/generate", methods=["POST"])
def generate():
    data     = request.json or {}
    password = data.get("password", "")
    plan     = data.get("plan", "1week")

    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401
    if plan not in DURATIONS:
        return jsonify({"error": f"Invalid plan. Choose from: {list(DURATIONS.keys())}"}), 400

    keys    = load_keys()
    new_key = generate_key()
    while new_key in keys:
        new_key = generate_key()

    duration = DURATIONS[plan]
    expires  = (datetime.utcnow() + duration).isoformat() if duration else None

    keys[new_key] = {
        "plan":           plan,
        "expires":        expires,
        "created":        datetime.utcnow().isoformat(),
        "revoked":        False,
        "hwid":           None,
        "hwid_locked_at": None,
        "locked_until":   None,
        "lockout_reason": None,
    }
    save_keys(keys)

    return jsonify({
        "key":     new_key,
        "plan":    plan,
        "expires": expires or "Never",
    }), 200


@app.route("/revoke", methods=["POST"])
def revoke():
    data     = request.json or {}
    password = data.get("password", "")
    key      = data.get("key", "").strip().upper()

    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    keys = load_keys()
    if key not in keys:
        return jsonify({"error": "Key not found"}), 404

    keys[key]["revoked"] = True
    save_keys(keys)
    return jsonify({"message": f"Key {key} revoked"}), 200


@app.route("/reset-hwid", methods=["POST"])
def reset_hwid():
    """Reset HWID and clear any lockout. Use if user gets a new PC."""
    data     = request.json or {}
    password = data.get("password", "")
    key      = data.get("key", "").strip().upper()

    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    keys = load_keys()
    if key not in keys:
        return jsonify({"error": "Key not found"}), 404

    keys[key]["hwid"]           = None
    keys[key]["hwid_locked_at"] = None
    keys[key]["locked_until"]   = None
    keys[key]["lockout_reason"] = None
    save_keys(keys)
    return jsonify({"message": f"HWID and lockout reset for {key}"}), 200


@app.route("/unlock", methods=["POST"])
def unlock():
    """Manually clear a lockout without resetting HWID."""
    data     = request.json or {}
    password = data.get("password", "")
    key      = data.get("key", "").strip().upper()

    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    keys = load_keys()
    if key not in keys:
        return jsonify({"error": "Key not found"}), 404

    keys[key]["locked_until"]   = None
    keys[key]["lockout_reason"] = None
    save_keys(keys)
    return jsonify({"message": f"Lockout cleared for {key}"}), 200


@app.route("/list", methods=["POST"])
def list_keys():
    data     = request.json or {}
    password = data.get("password", "")

    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    keys = load_keys()
    return jsonify(keys), 200


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "License server running"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)