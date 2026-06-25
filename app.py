import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, redirect, render_template, request, url_for


load_dotenv()

app = Flask(__name__)

MP_API_BASE = "https://api.mercadopago.com"
DATABASE_PATH = os.getenv("DATABASE_PATH", "payments.db")
ACCESS_TOKEN = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "")
WEBHOOK_SECRET = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "")
VIEW_PASSWORD = os.getenv("VIEW_PASSWORD", "")


def db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                status TEXT,
                status_detail TEXT,
                amount TEXT,
                currency TEXT,
                payer_name TEXT,
                payer_email TEXT,
                payer_identification_type TEXT,
                payer_identification_number TEXT,
                payment_method TEXT,
                operation_type TEXT,
                date_created TEXT,
                date_approved TEXT,
                last_seen TEXT NOT NULL,
                raw_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                topic TEXT,
                action TEXT,
                resource_id TEXT,
                signature_valid INTEGER,
                payload TEXT NOT NULL
            )
            """
        )


def check_view_password():
    if not VIEW_PASSWORD:
        return True

    auth = request.authorization
    return bool(auth and hmac.compare_digest(auth.password or "", VIEW_PASSWORD))


@app.before_request
def protect_dashboard():
    public_paths = {"/health", "/webhook/mercadopago"}
    if request.path in public_paths:
        return None
    if check_view_password():
        return None
    return Response(
        "Autenticacion requerida",
        401,
        {"WWW-Authenticate": 'Basic realm="Mercado Pago LAN"'},
    )


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def money(value):
    if value is None:
        return ""
    try:
        return str(Decimal(str(value)))
    except InvalidOperation:
        return str(value)


def payer_name(payment):
    payer = payment.get("payer") or {}
    first_name = payer.get("first_name") or ""
    last_name = payer.get("last_name") or ""
    full_name = " ".join(part for part in [first_name, last_name] if part).strip()
    return full_name or payer.get("nickname") or payer.get("email") or "Sin nombre informado"


def normalize_payment(payment):
    payer = payment.get("payer") or {}
    identification = payer.get("identification") or {}
    payment_method = payment.get("payment_method") or {}
    return {
        "id": str(payment.get("id", "")),
        "status": payment.get("status") or "",
        "status_detail": payment.get("status_detail") or "",
        "amount": money(payment.get("transaction_amount")),
        "currency": payment.get("currency_id") or "",
        "payer_name": payer_name(payment),
        "payer_email": payer.get("email") or "",
        "payer_identification_type": identification.get("type") or "",
        "payer_identification_number": identification.get("number") or "",
        "payment_method": payment_method.get("type") or payment_method.get("id") or "",
        "operation_type": payment.get("operation_type") or "",
        "date_created": payment.get("date_created") or "",
        "date_approved": payment.get("date_approved") or "",
        "last_seen": now_iso(),
        "raw_json": json.dumps(payment, ensure_ascii=False, sort_keys=True),
    }


def save_payment(payment):
    row = normalize_payment(payment)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO payments (
                id, status, status_detail, amount, currency, payer_name, payer_email,
                payer_identification_type, payer_identification_number, payment_method,
                operation_type, date_created, date_approved, last_seen, raw_json
            )
            VALUES (
                :id, :status, :status_detail, :amount, :currency, :payer_name, :payer_email,
                :payer_identification_type, :payer_identification_number, :payment_method,
                :operation_type, :date_created, :date_approved, :last_seen, :raw_json
            )
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                status_detail = excluded.status_detail,
                amount = excluded.amount,
                currency = excluded.currency,
                payer_name = excluded.payer_name,
                payer_email = excluded.payer_email,
                payer_identification_type = excluded.payer_identification_type,
                payer_identification_number = excluded.payer_identification_number,
                payment_method = excluded.payment_method,
                operation_type = excluded.operation_type,
                date_created = excluded.date_created,
                date_approved = excluded.date_approved,
                last_seen = excluded.last_seen,
                raw_json = excluded.raw_json
            """,
            row,
        )
    return row


def fetch_mp_payment(payment_id):
    if not ACCESS_TOKEN:
        raise RuntimeError("Falta MERCADOPAGO_ACCESS_TOKEN en .env")

    response = requests.get(
        f"{MP_API_BASE}/v1/payments/{payment_id}",
        headers={"Authorization": f"Bearer {ACCESS_TOKEN}"},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def parse_signature_header(value):
    parts = {}
    for item in (value or "").split(","):
        if "=" in item:
            key, part_value = item.split("=", 1)
            parts[key.strip()] = part_value.strip()
    return parts


def verify_mp_signature():
    if not WEBHOOK_SECRET:
        return None

    signature = parse_signature_header(request.headers.get("x-signature"))
    request_id = request.headers.get("x-request-id", "")
    ts = signature.get("ts", "")
    received_hash = signature.get("v1", "")
    data_id = request.args.get("data.id") or request.args.get("id") or ""

    manifest = ""
    if data_id:
        manifest += f"id:{data_id.lower()};"
    if request_id:
        manifest += f"request-id:{request_id};"
    if ts:
        manifest += f"ts:{ts};"

    calculated = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        manifest.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(calculated, received_hash)


def extract_payment_id(payload):
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict) and data.get("id"):
        return str(data["id"])
    for key in ("data.id", "id"):
        if request.args.get(key):
            return request.args[key]
    resource = payload.get("resource") if isinstance(payload, dict) else None
    if isinstance(resource, str) and "/payments/" in resource:
        return resource.rstrip("/").split("/")[-1]
    return None


def record_webhook(payload, payment_id, signature_valid):
    with db() as conn:
        conn.execute(
            """
            INSERT INTO webhook_events (
                received_at, topic, action, resource_id, signature_valid, payload
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso(),
                payload.get("type") or request.args.get("topic") or request.args.get("type"),
                payload.get("action") or request.args.get("action"),
                payment_id,
                None if signature_valid is None else int(signature_valid),
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
            ),
        )


@app.get("/")
def index():
    with db() as conn:
        payments = conn.execute(
            "SELECT * FROM payments ORDER BY COALESCE(date_approved, date_created, last_seen) DESC LIMIT 100"
        ).fetchall()
        events = conn.execute(
            "SELECT * FROM webhook_events ORDER BY id DESC LIMIT 10"
        ).fetchall()
    return render_template("index.html", payments=payments, events=events)


@app.get("/api/payments")
def api_payments():
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM payments ORDER BY COALESCE(date_approved, date_created, last_seen) DESC LIMIT 100"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/sync/<payment_id>")
def sync_payment(payment_id):
    payment = fetch_mp_payment(payment_id)
    save_payment(payment)
    return redirect(url_for("index"))


@app.post("/webhook/mercadopago")
def mercadopago_webhook():
    payload = request.get_json(silent=True) or {}
    signature_valid = verify_mp_signature()
    if signature_valid is False:
        record_webhook(payload, None, signature_valid)
        return jsonify({"error": "invalid signature"}), 401

    payment_id = extract_payment_id(payload)
    record_webhook(payload, payment_id, signature_valid)

    if payment_id and (payload.get("type") in (None, "payment") or request.args.get("topic") == "payment"):
        payment = fetch_mp_payment(payment_id)
        saved = save_payment(payment)
        return jsonify({"ok": True, "payment": saved}), 200

    return jsonify({"ok": True, "ignored": True}), 200


@app.get("/health")
def health():
    return jsonify({"ok": True})


init_db()


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", os.getenv("FLASK_PORT", "8081")))
    debug = os.getenv("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)
