"""
License Key Server — Full Featured v2
======================================
Requirements:
    pip install flask

Environment variables:
    ADMIN_PASSWORD  — secret password
    ALERT_WEBHOOK   — Discord webhook URL for notifications
    PORT            — port (default 5000)
    VERSION         — current app version (e.g. 2.0.0)
"""

import os
import json
import string
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")
ALERT_WEBHOOK  = os.environ.get("ALERT_WEBHOOK", "")
CURRENT_VERSION= os.environ.get("VERSION", "2.0.0")
KEYS_FILE      = "keys.json"
IP_LOG_FILE    = "ip_logs.json"
LOCKOUT_HOURS  = 24

def load_keys():
    if not os.path.exists(KEYS_FILE): return {}
    with open(KEYS_FILE) as f: return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, "w") as f: json.dump(keys, f, indent=2)

def load_ip_logs():
    if not os.path.exists(IP_LOG_FILE): return {}
    with open(IP_LOG_FILE) as f: return json.load(f)

def save_ip_logs(logs):
    with open(IP_LOG_FILE, "w") as f: json.dump(logs, f, indent=2)

def generate_key():
    chars = string.ascii_uppercase + string.digits
    return "-".join("".join(random.choices(chars, k=5)) for _ in range(4))

DURATIONS = {
    "1day":    timedelta(days=1),
    "1week":   timedelta(weeks=1),
    "1month":  timedelta(days=30),
    "lifetime": None,
}

def lockout_remaining(locked_until_str):
    locked_until = datetime.fromisoformat(locked_until_str)
    now          = datetime.utcnow()
    if now >= locked_until: return None
    delta   = locked_until - now
    hours   = int(delta.total_seconds() // 3600)
    minutes = int((delta.total_seconds() % 3600) // 60)
    if hours > 0: return f"{hours} hour{'s' if hours!=1 else ''}, {minutes} minute{'s' if minutes!=1 else ''}"
    return f"{minutes} minute{'s' if minutes!=1 else ''}"

def send_webhook(title, colour, fields):
    if not ALERT_WEBHOOK: return
    try:
        import urllib.request
        payload = json.dumps({"embeds":[{"title":title,"color":colour,"fields":fields,"footer":{"text":"Discord Cloner System"}}]}).encode()
        req = urllib.request.Request(ALERT_WEBHOOK, data=payload, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception: pass

def format_time_left(expires_str):
    expires_at = datetime.fromisoformat(expires_str)
    now        = datetime.utcnow()
    if now > expires_at: return None, None
    delta   = expires_at - now
    days    = delta.days
    hours   = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60
    if days > 0:   return f"{days} day{'s' if days!=1 else ''}, {hours} hour{'s' if hours!=1 else ''}", delta
    if hours > 0:  return f"{hours} hour{'s' if hours!=1 else ''}, {minutes} min{'s' if minutes!=1 else ''}", delta
    return f"{minutes} minute{'s' if minutes!=1 else ''}", delta

# ── Validate ──────────────────────────────────────────────────

@app.route("/validate", methods=["POST"])
def validate():
    data = request.json or {}
    key  = data.get("key","").strip().upper()
    hwid = data.get("hwid","").strip()

    if not key:  return jsonify({"valid":False,"reason":"No key provided"}), 400
    if not hwid: return jsonify({"valid":False,"reason":"No HWID provided"}), 400

    keys  = load_keys()
    if key not in keys: return jsonify({"valid":False,"reason":"Invalid key"}), 200

    entry = keys[key]

    if entry.get("revoked"):
        return jsonify({"valid":False,"reason":"Key has been revoked","revoked":True,
                        "revoke_message":entry.get("revoke_message","No reason provided.")}), 200

    if entry.get("locked_until"):
        remaining = lockout_remaining(entry["locked_until"])
        if remaining:
            return jsonify({"valid":False,"reason":"Key locked","locked":True,"remaining":remaining}), 200
        else:
            entry["locked_until"] = None
            keys[key] = entry
            save_keys(keys)

    if entry.get("hwid"):
        if entry["hwid"] != hwid:
            entry["locked_until"]   = (datetime.utcnow() + timedelta(hours=LOCKOUT_HOURS)).isoformat()
            entry["lockout_reason"] = f"Used on unknown machine at {datetime.utcnow().isoformat()}"
            entry["usage_count"]    = entry.get("usage_count", 0)
            keys[key] = entry
            save_keys(keys)
            send_webhook("🔒 Key Locked", 0xFF6600, [
                {"name":"Key","value":key,"inline":True},
                {"name":"Reason","value":"Used on unknown HWID","inline":True},
            ])
            return jsonify({"valid":False,"reason":"Key locked","locked":True,"remaining":f"{LOCKOUT_HOURS} hours, 0 minutes"}), 200
    else:
        entry["hwid"]           = hwid
        entry["hwid_locked_at"] = datetime.utcnow().isoformat()

    # Track usage
    entry["usage_count"] = entry.get("usage_count", 0) + 1
    entry["last_seen"]   = datetime.utcnow().isoformat()

    if entry["expires"] is None:
        keys[key] = entry
        save_keys(keys)
        return jsonify({"valid":True,"plan":entry["plan"],"time_left":"Lifetime","expires":"Never"}), 200

    time_left, delta = format_time_left(entry["expires"])
    if time_left is None:
        return jsonify({"valid":False,"reason":"Key has expired"}), 200

    # Warn if expiring in 24hrs
    expiry_warning = delta.total_seconds() < 86400

    keys[key] = entry
    save_keys(keys)

    return jsonify({
        "valid":          True,
        "plan":           entry["plan"],
        "time_left":      time_left,
        "expires":        entry["expires"],
        "expiry_warning": expiry_warning,
        "usage_count":    entry["usage_count"],
    }), 200

# ── Generate ──────────────────────────────────────────────────

@app.route("/generate", methods=["POST"])
def generate():
    data     = request.json or {}
    password = data.get("password","")
    plan     = data.get("plan","1week")
    count    = min(int(data.get("count", 1)), 50)  # bulk: up to 50

    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401
    if plan not in DURATIONS:      return jsonify({"error":f"Invalid plan"}), 400

    keys     = load_keys()
    duration = DURATIONS[plan]
    expires  = (datetime.utcnow() + duration).isoformat() if duration else None
    new_keys = []

    for _ in range(count):
        new_key = generate_key()
        while new_key in keys: new_key = generate_key()
        keys[new_key] = {
            "plan":           plan,
            "expires":        expires,
            "created":        datetime.utcnow().isoformat(),
            "revoked":        False,
            "hwid":           None,
            "hwid_locked_at": None,
            "locked_until":   None,
            "lockout_reason": None,
            "revoke_message": None,
            "usage_count":    0,
            "last_seen":      None,
        }
        new_keys.append(new_key)

    save_keys(keys)

    if ALERT_WEBHOOK:
        send_webhook("🔑 Key(s) Generated", 0x00FF00, [
            {"name":"Count","value":str(count),"inline":True},
            {"name":"Plan","value":plan,"inline":True},
            {"name":"Expires","value":expires or "Never","inline":True},
        ])

    if count == 1:
        return jsonify({"key":new_keys[0],"plan":plan,"expires":expires or "Never"}), 200
    return jsonify({"keys":new_keys,"plan":plan,"expires":expires or "Never","count":count}), 200

# ── Revoke ────────────────────────────────────────────────────

@app.route("/revoke", methods=["POST"])
def revoke():
    data           = request.json or {}
    password       = data.get("password","")
    key            = data.get("key","").strip().upper()
    revoke_message = data.get("revoke_message","").strip()

    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401

    keys = load_keys()
    if key not in keys: return jsonify({"error":"Key not found"}), 404

    keys[key]["revoked"]        = True
    keys[key]["revoked_at"]     = datetime.utcnow().isoformat()
    keys[key]["revoke_message"] = revoke_message or "No reason provided."
    save_keys(keys)

    send_webhook("❌ Key Revoked", 0xFF0000, [
        {"name":"Key","value":key,"inline":True},
        {"name":"Reason","value":revoke_message or "No reason","inline":True},
    ])

    return jsonify({"message":f"Key {key} revoked"}), 200

# ── Unlock ────────────────────────────────────────────────────

@app.route("/unlock", methods=["POST"])
def unlock():
    data     = request.json or {}
    password = data.get("password","")
    key      = data.get("key","").strip().upper()

    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401

    keys = load_keys()
    if key not in keys: return jsonify({"error":"Key not found"}), 404

    keys[key]["locked_until"]   = None
    keys[key]["lockout_reason"] = None
    save_keys(keys)
    return jsonify({"message":f"Lockout cleared for {key}"}), 200

# ── Reset HWID ────────────────────────────────────────────────

@app.route("/reset-hwid", methods=["POST"])
def reset_hwid():
    data     = request.json or {}
    password = data.get("password","")
    key      = data.get("key","").strip().upper()

    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401

    keys = load_keys()
    if key not in keys: return jsonify({"error":"Key not found"}), 404

    keys[key]["hwid"]           = None
    keys[key]["hwid_locked_at"] = None
    keys[key]["locked_until"]   = None
    keys[key]["lockout_reason"] = None
    save_keys(keys)
    return jsonify({"message":f"HWID reset for {key}"}), 200

# ── IP Logging ────────────────────────────────────────────────

@app.route("/log-ip", methods=["POST"])
def log_ip():
    data     = request.json or {}
    key      = data.get("key","").strip().upper()
    ip       = data.get("ip","unknown")
    username = data.get("username","unknown")
    t        = data.get("time", datetime.utcnow().isoformat())

    logs = load_ip_logs()
    if key not in logs: logs[key] = []
    logs[key].append({"ip":ip,"username":username,"time":t})
    logs[key] = logs[key][-20:]  # Keep last 20 per key
    save_ip_logs(logs)

    return jsonify({"message":"Logged"}), 200

# ── Active Users ──────────────────────────────────────────────

@app.route("/active", methods=["POST"])
def active_users():
    data     = request.json or {}
    password = data.get("password","")

    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401

    keys   = load_keys()
    now    = datetime.utcnow()
    active = []

    for key, entry in keys.items():
        if entry.get("revoked"): continue
        last_seen = entry.get("last_seen")
        if not last_seen: continue
        delta = (now - datetime.fromisoformat(last_seen)).total_seconds()
        if delta <= 300:
            active.append({
                "key":         key,
                "plan":        entry.get("plan","unknown"),
                "last_seen":   last_seen,
                "seconds_ago": int(delta),
                "usage_count": entry.get("usage_count",0),
            })

    active.sort(key=lambda x: x["seconds_ago"])
    return jsonify({"active":active,"count":len(active)}), 200

# ── Stats ─────────────────────────────────────────────────────

@app.route("/stats", methods=["POST"])
def stats():
    data     = request.json or {}
    password = data.get("password","")

    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401

    keys    = load_keys()
    now     = datetime.utcnow()
    total   = len(keys)
    revoked = sum(1 for e in keys.values() if e.get("revoked"))
    expired = 0
    active_5m = 0
    expiring_24h = 0

    for entry in keys.values():
        if entry.get("revoked"): continue
        if entry.get("expires"):
            exp = datetime.fromisoformat(entry["expires"])
            if now > exp:
                expired += 1
            elif (exp - now).total_seconds() < 86400:
                expiring_24h += 1
        ls = entry.get("last_seen")
        if ls and (now - datetime.fromisoformat(ls)).total_seconds() <= 300:
            active_5m += 1

    return jsonify({
        "total":         total,
        "active":        total - revoked - expired,
        "revoked":       revoked,
        "expired":       expired,
        "online_now":    active_5m,
        "expiring_24h":  expiring_24h,
    }), 200

# ── Version ───────────────────────────────────────────────────

@app.route("/version", methods=["GET"])
def version():
    return jsonify({"version": CURRENT_VERSION}), 200

# ── List ──────────────────────────────────────────────────────

@app.route("/list", methods=["POST"])
def list_keys():
    data     = request.json or {}
    password = data.get("password","")
    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401
    return jsonify(load_keys()), 200

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status":"License server running","version":CURRENT_VERSION}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


# ── Announcement ──────────────────────────────────────────────

ANNOUNCEMENT_FILE = "announcement.json"
MAINTENANCE_FILE  = "maintenance.json"

def load_announcement():
    if not os.path.exists(ANNOUNCEMENT_FILE): return {"message": ""}
    with open(ANNOUNCEMENT_FILE) as f: return json.load(f)

def save_announcement(data):
    with open(ANNOUNCEMENT_FILE, "w") as f: json.dump(data, f)

def load_maintenance():
    if not os.path.exists(MAINTENANCE_FILE): return {"enabled": False, "message": ""}
    with open(MAINTENANCE_FILE) as f: return json.load(f)

def save_maintenance(data):
    with open(MAINTENANCE_FILE, "w") as f: json.dump(data, f)

@app.route("/announcement", methods=["GET"])
def get_announcement():
    return jsonify(load_announcement()), 200

@app.route("/announcement", methods=["POST"])
def set_announcement():
    data     = request.json or {}
    password = data.get("password","")
    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401
    ann = {"message": data.get("message","")}
    save_announcement(ann)
    return jsonify({"message":"Announcement updated."}), 200

@app.route("/maintenance", methods=["GET"])
def get_maintenance():
    return jsonify(load_maintenance()), 200

@app.route("/maintenance", methods=["POST"])
def set_maintenance():
    data     = request.json or {}
    password = data.get("password","")
    if password != ADMIN_PASSWORD: return jsonify({"error":"Unauthorized"}), 401
    maint = {"enabled": data.get("enabled", False), "message": data.get("message","Maintenance in progress.")}
    save_maintenance(maint)
    return jsonify({"message":"Maintenance updated."}), 200