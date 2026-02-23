"""
SoremMacro License API Server
Despliega esto en Render.com como un Web Service Python.
Variables de entorno requeridas (las configuras en Render, NUNCA en el código):
  ADMIN_TOKEN   → contraseña secreta para el KeyGen (invéntatela tú)
  LICENSE_SECRET → secreto HMAC para verificar keys (igual que en el KeyGen)
"""

import os
import json
import hmac
import hashlib
import secrets
import time
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Configuración desde variables de entorno ──────────────────────────────────
ADMIN_TOKEN    = os.environ.get("ADMIN_TOKEN", "")
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "SoremMacro_LicenseSystem_v1_2026").encode()

# ── Base de datos en memoria (persistida en archivo) ──────────────────────────
# En Render el filesystem es efímero, pero para uso básico funciona.
# Para persistencia real usarías una DB como PostgreSQL (Render la ofrece gratis).
DATA_FILE = "keys_data.json"

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"keys": [], "banned": [], "deactivated": []}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ── Rate limiting simple en memoria ──────────────────────────────────────────
_rate_limits = {}  # ip -> [timestamp, ...]
RATE_WINDOW  = 60   # segundos
RATE_MAX     = 15   # max requests por ventana por IP

def is_rate_limited(ip):
    now = time.time()
    hits = _rate_limits.get(ip, [])
    hits = [t for t in hits if now - t < RATE_WINDOW]
    _rate_limits[ip] = hits
    if len(hits) >= RATE_MAX:
        return True
    _rate_limits[ip].append(now)
    return False

# ── Decoradores ───────────────────────────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Admin-Token", "")
        if not ADMIN_TOKEN or not hmac.compare_digest(token, ADMIN_TOKEN):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
        if is_rate_limited(ip):
            return jsonify({"error": "Too many requests. Try again later."}), 429
        return f(*args, **kwargs)
    return decorated

# ── Helpers ───────────────────────────────────────────────────────────────────
def verify_key_hmac(key, hwid):
    """Verifica que la key sea matemáticamente válida para ese HWID."""
    try:
        parts = key.replace(" ", "").upper().split("-")
        if len(parts) != 5 or parts[0] != "SRM":
            return False
        rand     = parts[1] + parts[2]
        sig_given = parts[3] + parts[4]
        sig_expected = hmac.new(LICENSE_SECRET, (rand + hwid).encode(), hashlib.sha256).hexdigest()[:8].upper()
        return hmac.compare_digest(sig_given, sig_expected)
    except Exception:
        return False

def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# ─────────────────────────────────────────────────────────────────────────────
# RUTAS PÚBLICAS (usadas por la macro)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])
@rate_limit
def verify():
    """
    La macro llama a esto al arrancar y cada 10 min.
    Body JSON: { "key": "SRM-...", "hwid": "XXXX" }
    Respuesta: { "valid": true/false, "reason": "..." }
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"valid": False, "reason": "Bad request"}), 400

    key  = str(body.get("key",  "")).strip().upper()
    hwid = str(body.get("hwid", "")).strip().upper()

    if not key or not hwid:
        return jsonify({"valid": False, "reason": "Missing key or hwid"}), 400

    # 1. Verificar firma HMAC
    if not verify_key_hmac(key, hwid):
        return jsonify({"valid": False, "reason": "Key inválida para este HWID."})

    data = load_data()

    # 2. ¿Key existe en el sistema?
    all_keys = [k["key"] for k in data.get("keys", [])]
    if key not in all_keys:
        return jsonify({"valid": False, "reason": "Key no registrada en el sistema."})

    # 3. ¿Key baneada?
    for b in data.get("banned", []):
        if b.get("key") == key:
            return jsonify({"valid": False, "reason": f"Tu licencia ha sido BANEADA. Motivo: {b.get('reason', 'Sin motivo')}"})
        if b.get("hwid") == hwid:
            return jsonify({"valid": False, "reason": "Tu HWID ha sido BANEADO por el administrador."})

    # 4. ¿Key desactivada?
    for d in data.get("deactivated", []):
        if d.get("key") == key:
            return jsonify({"valid": False, "reason": f"Tu licencia ha sido DESACTIVADA. Motivo: {d.get('reason', 'Sin motivo')}"})

    # 5. Todo OK — registrar activación
    found = False
    for k in data["keys"]:
        if k["key"] == key:
            k["last_seen"] = now_str()
            k["hwid"] = hwid
            found = True
            break
    if not found:
        data["keys"].append({"key": key, "hwid": hwid, "last_seen": now_str()})
    save_data(data)

    return jsonify({"valid": True, "reason": ""})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": now_str()})


# ─────────────────────────────────────────────────────────────────────────────
# RUTAS DE ADMIN (solo KeyGen — requieren X-Admin-Token)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/keys", methods=["GET"])
@require_admin
def admin_get_keys():
    """Devuelve todos los datos: keys, banned, deactivated."""
    return jsonify(load_data())


@app.route("/admin/keys/create", methods=["POST"])
@require_admin
def admin_create_key():
    """
    Registra una key nueva en el servidor.
    Body: { "key": "SRM-...", "hwid": "XXXX" }
    """
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key",  "")).strip().upper()
    hwid = str(body.get("hwid", "")).strip().upper()
    if not key or not hwid:
        return jsonify({"error": "Missing key or hwid"}), 400

    data = load_data()
    if any(k["key"] == key for k in data["keys"]):
        return jsonify({"error": "Key ya existe"}), 409

    data["keys"].append({
        "key":     key,
        "hwid":    hwid,
        "created": now_str(),
        "last_seen": None,
    })
    save_data(data)
    return jsonify({"ok": True, "key": key})


@app.route("/admin/ban", methods=["POST"])
@require_admin
def admin_ban():
    """Banea una key. Body: { "key": "SRM-...", "reason": "..." }"""
    body = request.get_json(silent=True) or {}
    key    = str(body.get("key",    "")).strip().upper()
    reason = str(body.get("reason", "Sin motivo")).strip()
    if not key:
        return jsonify({"error": "Missing key"}), 400

    data = load_data()
    # Quitar de deactivated si estaba
    data["deactivated"] = [d for d in data["deactivated"] if d.get("key") != key]
    # Añadir a banned si no está
    if not any(b.get("key") == key for b in data["banned"]):
        # Buscar hwid
        hwid = next((k["hwid"] for k in data["keys"] if k["key"] == key), "")
        data["banned"].append({"key": key, "hwid": hwid, "reason": reason, "banned_at": now_str()})
    save_data(data)
    return jsonify({"ok": True})


@app.route("/admin/unban", methods=["POST"])
@require_admin
def admin_unban():
    """Quita el ban de una key. Body: { "key": "SRM-..." }"""
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key", "")).strip().upper()
    if not key:
        return jsonify({"error": "Missing key"}), 400

    data = load_data()
    data["banned"] = [b for b in data["banned"] if b.get("key") != key]
    save_data(data)
    return jsonify({"ok": True})


@app.route("/admin/deactivate", methods=["POST"])
@require_admin
def admin_deactivate():
    """Desactiva una key. Body: { "key": "SRM-...", "reason": "..." }"""
    body = request.get_json(silent=True) or {}
    key    = str(body.get("key",    "")).strip().upper()
    reason = str(body.get("reason", "Sin motivo")).strip()
    if not key:
        return jsonify({"error": "Missing key"}), 400

    data = load_data()
    if not any(d.get("key") == key for d in data["deactivated"]):
        data["deactivated"].append({"key": key, "reason": reason, "deactivated_at": now_str()})
    save_data(data)
    return jsonify({"ok": True})


@app.route("/admin/reactivate", methods=["POST"])
@require_admin
def admin_reactivate():
    """Reactiva una key (quita de deactivated y banned). Body: { "key": "SRM-..." }"""
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key", "")).strip().upper()
    if not key:
        return jsonify({"error": "Missing key"}), 400

    data = load_data()
    data["deactivated"] = [d for d in data["deactivated"] if d.get("key") != key]
    data["banned"]      = [b for b in data["banned"]      if b.get("key") != key]
    save_data(data)
    return jsonify({"ok": True})


@app.route("/admin/delete", methods=["POST"])
@require_admin
def admin_delete():
    """Elimina una key de todo. Body: { "key": "SRM-..." }"""
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key", "")).strip().upper()
    if not key:
        return jsonify({"error": "Missing key"}), 400

    data = load_data()
    data["keys"]        = [k for k in data["keys"]        if k.get("key") != key]
    data["banned"]      = [b for b in data["banned"]      if b.get("key") != key]
    data["deactivated"] = [d for d in data["deactivated"] if d.get("key") != key]
    save_data(data)
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
