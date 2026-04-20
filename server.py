"""
License Key Server
==================
Host this on Railway, Render, or Replit.

Requirements:
    pip install flask

Run locally:
    python server.py

Environment variables (set on your host):
    ADMIN_PASSWORD  — secret password to manage keys (default: changeme123)
    PORT            — port to run on (default: 5000)
"""

import os
import json
import uuid
import string
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")
KEYS_FILE = "keys.json"

# ── Key storage ───────────────────────────────────────────────

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

# ── Routes ────────────────────────────────────────────────────

@app.route("/validate", methods=["POST"])
def validate():
    """Check if a key is valid and return time remaining."""
    data = request.json or {}
    key  = data.get("key", "").strip().upper()

    if not key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    keys = load_keys()

    if key not in keys:
        return jsonify({"valid": False, "reason": "Invalid key"}), 200

    entry = keys[key]

    if entry.get("revoked"):
        return jsonify({"valid": False, "reason": "Key has been revoked"}), 200

    if entry["expires"] is None:
        return jsonify({
            "valid": True,
            "plan": entry["plan"],
            "time_left": "Lifetime",
            "expires": "Never",
        }), 200

    expires_at = datetime.fromisoformat(entry["expires"])
    now        = datetime.utcnow()

    if now > expires_at:
        return jsonify({"valid": False, "reason": "Key has expired"}), 200

    delta      = expires_at - now
    days       = delta.days
    hours      = delta.seconds // 3600
    minutes    = (delta.seconds % 3600) // 60

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
    """Generate a new key. Requires admin password."""
    data     = request.json or {}
    password = data.get("password", "")
    plan     = data.get("plan", "1week")

    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    if plan not in DURATIONS:
        return jsonify({"error": f"Invalid plan. Choose from: {list(DURATIONS.keys())}"}), 400

    keys    = load_keys()
    new_key = generate_key()

    # Ensure uniqueness
    while new_key in keys:
        new_key = generate_key()

    duration = DURATIONS[plan]
    expires  = (datetime.utcnow() + duration).isoformat() if duration else None

    keys[new_key] = {
        "plan":    plan,
        "expires": expires,
        "created": datetime.utcnow().isoformat(),
        "revoked": False,
    }
    save_keys(keys)

    return jsonify({
        "key":     new_key,
        "plan":    plan,
        "expires": expires or "Never",
    }), 200


@app.route("/revoke", methods=["POST"])
def revoke():
    """Revoke a key. Requires admin password."""
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
    return jsonify({"message": f"Key {key} revoked successfully"}), 200


@app.route("/list", methods=["POST"])
def list_keys():
    """List all keys. Requires admin password."""
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
