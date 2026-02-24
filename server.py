"""
SoremMacro License API Server v2 — con PostgreSQL persistente
Variables de entorno requeridas en Render:
  ADMIN_TOKEN     → contraseña secreta para el KeyGen
  LICENSE_SECRET  → secreto HMAC para verificar keys
  DATABASE_URL    → se añade automáticamente al conectar la DB de Render
"""

import os
import hmac
import hashlib
import time
import psycopg2
import psycopg2.extras
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Config desde variables de entorno ─────────────────────────────────────────
ADMIN_TOKEN    = os.environ.get("ADMIN_TOKEN", "")
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "").encode()
DATABASE_URL   = os.environ.get("DATABASE_URL", "")

# ── Conexión a PostgreSQL ─────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    conn.autocommit = True
    return conn

def init_db():
    """Crea las tablas si no existen."""
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key        TEXT PRIMARY KEY,
            hwid       TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen  TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS banned (
            key       TEXT PRIMARY KEY,
            hwid      TEXT,
            reason    TEXT,
            banned_at TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS deactivated (
            key            TEXT PRIMARY KEY,
            reason         TEXT,
            deactivated_at TEXT NOT NULL
        );
    """)
    cur.close()
    conn.close()

# Inicializar tablas al arrancar
try:
    init_db()
except Exception as e:
    print(f"[WARN] No se pudo inicializar la DB: {e}")

# ── Rate limiting en memoria ──────────────────────────────────────────────────
_rate_limits = {}
RATE_WINDOW  = 60
RATE_MAX     = 15

def is_rate_limited(ip):
    now  = time.time()
    hits = [t for t in _rate_limits.get(ip, []) if now - t < RATE_WINDOW]
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
    try:
        parts = key.replace(" ", "").upper().split("-")
        if len(parts) != 5 or parts[0] != "SRM":
            return False
        rand      = parts[1] + parts[2]
        sig_given = parts[3] + parts[4]
        sig_exp   = hmac.new(LICENSE_SECRET, (rand + hwid).encode(), hashlib.sha256).hexdigest()[:8].upper()
        return hmac.compare_digest(sig_given, sig_exp)
    except Exception:
        return False

def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# ─────────────────────────────────────────────────────────────────────────────
# RUTAS PÚBLICAS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])
@rate_limit
def verify():
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

    try:
        conn = get_db()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # 2. ¿Key existe?
        cur.execute("SELECT * FROM keys WHERE key = %s", (key,))
        key_row = cur.fetchone()
        if not key_row:
            cur.close(); conn.close()
            return jsonify({"valid": False, "reason": "Key no registrada en el sistema."})

        # 3. ¿Key baneada?
        cur.execute("SELECT * FROM banned WHERE key = %s OR hwid = %s", (key, hwid))
        ban_row = cur.fetchone()
        if ban_row:
            reason = ban_row["reason"] or "Sin motivo"
            if ban_row["key"] == key:
                msg = f"Tu licencia ha sido BANEADA. Motivo: {reason}"
            else:
                msg = "Tu HWID ha sido BANEADO por el administrador."
            cur.close(); conn.close()
            return jsonify({"valid": False, "reason": msg})

        # 4. ¿Key desactivada?
        cur.execute("SELECT * FROM deactivated WHERE key = %s", (key,))
        deact_row = cur.fetchone()
        if deact_row:
            reason = deact_row["reason"] or "Sin motivo"
            cur.close(); conn.close()
            return jsonify({"valid": False, "reason": f"Tu licencia ha sido DESACTIVADA. Motivo: {reason}"})

        # 5. Todo OK — actualizar last_seen
        cur.execute("UPDATE keys SET last_seen = %s, hwid = %s WHERE key = %s", (now_str(), hwid, key))
        cur.close(); conn.close()
        return jsonify({"valid": True, "reason": ""})

    except Exception as e:
        return jsonify({"valid": False, "reason": f"Error del servidor. Inténtalo de nuevo."}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": now_str()})


# ─────────────────────────────────────────────────────────────────────────────
# RUTAS DE ADMIN
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/keys", methods=["GET"])
@require_admin
def admin_get_keys():
    try:
        conn = get_db()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM keys ORDER BY created_at DESC")
        keys = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM banned ORDER BY banned_at DESC")
        banned = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM deactivated ORDER BY deactivated_at DESC")
        deactivated = [dict(r) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({"keys": keys, "banned": banned, "deactivated": deactivated})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/keys/create", methods=["POST"])
@require_admin
def admin_create_key():
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key",  "")).strip().upper()
    hwid = str(body.get("hwid", "")).strip().upper()
    if not key or not hwid:
        return jsonify({"error": "Missing key or hwid"}), 400
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO keys (key, hwid, created_at, last_seen) VALUES (%s, %s, %s, NULL)",
            (key, hwid, now_str())
        )
        cur.close(); conn.close()
        return jsonify({"ok": True, "key": key})
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Key ya existe"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/ban", methods=["POST"])
@require_admin
def admin_ban():
    body   = request.get_json(silent=True) or {}
    key    = str(body.get("key",    "")).strip().upper()
    reason = str(body.get("reason", "Sin motivo")).strip()
    if not key:
        return jsonify({"error": "Missing key"}), 400
    try:
        conn = get_db()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        # Buscar hwid
        cur.execute("SELECT hwid FROM keys WHERE key = %s", (key,))
        row  = cur.fetchone()
        hwid = row["hwid"] if row else ""
        # Quitar de deactivated
        cur.execute("DELETE FROM deactivated WHERE key = %s", (key,))
        # Insertar en banned
        cur.execute("""
            INSERT INTO banned (key, hwid, reason, banned_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (key) DO UPDATE SET reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at
        """, (key, hwid, reason, now_str()))
        cur.close(); conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/unban", methods=["POST"])
@require_admin
def admin_unban():
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key", "")).strip().upper()
    if not key:
        return jsonify({"error": "Missing key"}), 400
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("DELETE FROM banned WHERE key = %s", (key,))
        cur.close(); conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/deactivate", methods=["POST"])
@require_admin
def admin_deactivate():
    body   = request.get_json(silent=True) or {}
    key    = str(body.get("key",    "")).strip().upper()
    reason = str(body.get("reason", "Sin motivo")).strip()
    if not key:
        return jsonify({"error": "Missing key"}), 400
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO deactivated (key, reason, deactivated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (key) DO UPDATE SET reason = EXCLUDED.reason, deactivated_at = EXCLUDED.deactivated_at
        """, (key, reason, now_str()))
        cur.close(); conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/reactivate", methods=["POST"])
@require_admin
def admin_reactivate():
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key", "")).strip().upper()
    if not key:
        return jsonify({"error": "Missing key"}), 400
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("DELETE FROM deactivated WHERE key = %s", (key,))
        cur.execute("DELETE FROM banned      WHERE key = %s", (key,))
        cur.close(); conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/delete", methods=["POST"])
@require_admin
def admin_delete():
    body = request.get_json(silent=True) or {}
    key  = str(body.get("key", "")).strip().upper()
    if not key:
        return jsonify({"error": "Missing key"}), 400
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("DELETE FROM keys        WHERE key = %s", (key,))
        cur.execute("DELETE FROM banned      WHERE key = %s", (key,))
        cur.execute("DELETE FROM deactivated WHERE key = %s", (key,))
        cur.close(); conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
