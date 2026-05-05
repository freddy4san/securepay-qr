import base64
import hashlib
import hmac
import io
import json
import secrets
import time
from datetime import datetime

from flask import Flask, redirect, render_template, request, session, url_for
import qrcode


app = Flask(__name__)
SECRET_KEY = "securepay-qr-server-side-secret-key"
app.config["SECRET_KEY"] = SECRET_KEY

QR_TTL_SECONDS = 120
HIGH_VALUE_LIMIT = 1000
REQUIRED_QR_FIELDS = {
    "merchant_id",
    "merchant_name",
    "amount",
    "invoice_id",
    "issued_at",
    "expires_at",
}

USERS = {
    "alice": {
        "name": "Alice Nguyen",
        "pin": "1234",
        "balance": 2450.00,
    },
    "student": {
        "name": "Demo Student",
        "pin": "0000",
        "balance": 850.00,
    },
}

MERCHANTS = {
    "MER123": {
        "name": "Campus Cafe",
        "verified": True,
        "category": "Food and drink",
    },
    "BOOK123": {
        "name": "Campus Bookshop",
        "verified": True,
        "category": "Education",
    },
    "BAD999": {
        "name": "Unknown Pop-up Kiosk",
        "verified": False,
        "category": "Unverified",
    },
}

TRANSACTIONS = {}


def current_user():
    username = session.get("username")
    if not username:
        return None
    return USERS.get(username)


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sign_payload(payload):
    message = canonical_json(payload).encode()
    return hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()


def encode_signed_qr(payload):
    signed_qr = {
        "payload": payload,
        "signature": sign_payload(payload),
    }
    return json.dumps(signed_qr, sort_keys=True)


def decode_signed_qr(token):
    signed_qr = json.loads(token)
    payload = signed_qr["payload"]
    signature = signed_qr["signature"]
    return payload, signature


def make_qr_token(merchant_id, amount, invoice_id=None):
    merchant = MERCHANTS[merchant_id]
    issued_at = int(time.time())
    payload = {
        "amount": round(float(amount), 2),
        "expires_at": issued_at + QR_TTL_SECONDS,
        "invoice_id": invoice_id or f"INV-{secrets.token_hex(3).upper()}",
        "issued_at": issued_at,
        "merchant_id": merchant_id,
        "merchant_name": merchant["name"],
    }
    return encode_signed_qr(payload)


def make_signed_payload(payload):
    return encode_signed_qr(payload)


def make_qr_image(token):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(token)
    qr.make(fit=True)
    image = qr.make_image(fill_color="#17211c", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{encoded}"


def tamper_token(token):
    payload, signature = decode_signed_qr(token)
    payload["amount"] = payload["amount"] + 750
    return json.dumps({"payload": payload, "signature": signature}, sort_keys=True)


def expired_token():
    issued_at = int(time.time()) - 180
    payload = {
        "amount": 8.50,
        "expires_at": int(time.time()) - 15,
        "invoice_id": f"INV-{secrets.token_hex(3).upper()}",
        "issued_at": issued_at,
        "merchant_id": "MER123",
        "merchant_name": MERCHANTS["MER123"]["name"],
    }
    return encode_signed_qr(payload)


def unknown_merchant_token():
    issued_at = int(time.time())
    payload = {
        "amount": 35.00,
        "expires_at": issued_at + QR_TTL_SECONDS,
        "invoice_id": "INV-UNKNOWN-2001",
        "issued_at": issued_at,
        "merchant_id": "UNKNOWN999",
        "merchant_name": "Unknown Merchant",
    }
    return make_signed_payload(payload)


def validate_token(token):
    checks = []

    try:
        payload, signature = decode_signed_qr(token.strip())
    except Exception:
        return None, ["Invalid QR"], False, "Blocked", "Invalid QR"

    if not isinstance(payload, dict):
        return None, ["Invalid QR"], False, "Blocked", "Invalid QR"

    expected_signature = sign_payload(payload)
    if not hmac.compare_digest(signature, expected_signature):
        checks.append("HMAC signature failed")
        return payload, checks, False, "Blocked", "Invalid QR"

    checks.append("HMAC signature valid")

    missing_fields = sorted(REQUIRED_QR_FIELDS - set(payload))
    if missing_fields:
        checks.append("Missing required fields: " + ", ".join(missing_fields))
        return payload, checks, False, "Blocked", "Invalid QR"

    try:
        current_time = int(time.time())
        expiry = int(payload["expires_at"])
    except (TypeError, ValueError):
        checks.append("Invalid QR expiry value")
        return payload, checks, False, "Blocked", "Invalid QR"

    if current_time > expiry:
        checks.append("QR has expired")
        return payload, checks, False, "Blocked", "Expired QR"

    checks.append("QR has not expired")

    merchant = MERCHANTS.get(payload.get("merchant_id"))
    if not merchant or not merchant["verified"] or merchant["name"] != payload["merchant_name"]:
        checks.append("Merchant is not verified")
        return payload, checks, False, "Blocked", "Unverified Merchant"

    checks.append("Merchant is verified")

    try:
        amount = float(payload["amount"])
    except (TypeError, ValueError):
        checks.append("Invalid QR amount value")
        return payload, checks, False, "Blocked", "Invalid QR"

    if amount > HIGH_VALUE_LIMIT:
        checks.append("Blocked by high-value fraud rule")
        return payload, checks, False, "High risk", "Suspicious High Amount"

    checks.append("Amount is within fraud threshold")
    checks.append("Required fields are present")
    return payload, checks, True, "Low risk", None


def require_login():
    if not current_user():
        return redirect(url_for("login"))
    return None


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        if username in USERS:
            session["username"] = username
            return redirect(url_for("home"))
        error = "Use alice or student for the demo."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/home")
def home():
    guard = require_login()
    if guard:
        return guard
    return render_template("home.html", user=current_user(), merchants=MERCHANTS)


@app.route("/merchant", methods=["GET", "POST"])
def merchant():
    guard = require_login()
    if guard:
        return guard

    token = None
    tampered = None
    payload = None
    merchant_id = request.form.get("merchant_id", "MER123")
    amount = request.form.get("amount", "12.50")
    invoice_id = request.form.get("invoice_id", "INV-1001")
    qr_image = None

    if request.method == "POST":
        token = make_qr_token(merchant_id, amount, invoice_id)
        tampered = tamper_token(token)
        payload, _ = decode_signed_qr(token)
        qr_image = make_qr_image(token)

    return render_template(
        "merchant.html",
        merchants=MERCHANTS,
        selected_merchant=merchant_id,
        amount=amount,
        invoice_id=invoice_id,
        token=token,
        tampered=tampered,
        payload=payload,
        qr_image=qr_image,
        ttl=QR_TTL_SECONDS,
    )


@app.route("/scan")
def scan():
    guard = require_login()
    if guard:
        return guard

    valid_demo = make_qr_token("MER123", 12.50, "INV-CAFE-1001")
    tampered_demo = tamper_token(valid_demo)
    high_value_demo = make_qr_token("BOOK123", 1750.00, "INV-BOOK-9001")
    unknown_merchant_demo = unknown_merchant_token()
    expired_demo = expired_token()

    demos = [
        ("Use valid demo QR", valid_demo, "Passes signature, expiry, merchant, and fraud checks."),
        ("Use tampered QR", tampered_demo, "Amount changed after signing, so HMAC fails."),
        ("Use expired QR", expired_demo, "Signature is real, but the QR is outside its time window."),
        (
            "Use unknown merchant QR",
            unknown_merchant_demo,
            "Merchant ID is not in the trusted merchant list.",
        ),
        (
            "Use high-value QR",
            high_value_demo,
            f"Amount is above the ${HIGH_VALUE_LIMIT:,.0f} fraud threshold.",
        ),
    ]
    return render_template("scan.html", demos=demos)


@app.route("/validate", methods=["POST"])
def validate():
    guard = require_login()
    if guard:
        return guard

    token = request.form.get("token", "")
    payload, checks, valid, risk_status, failure_reason = validate_token(token)
    tx_id = secrets.token_hex(8)
    TRANSACTIONS[tx_id] = {
        "checks": checks,
        "created_at": datetime.now().strftime("%d %b %Y, %H:%M:%S"),
        "failure_reason": failure_reason,
        "payload": payload,
        "risk_status": risk_status,
        "status": "pending_pin" if valid else "blocked",
        "token": token,
        "valid": valid,
    }

    if valid:
        return render_template(
            "validate.html",
            tx_id=tx_id,
            payload=payload,
            checks=checks,
            risk_status=risk_status,
            valid=True,
        )
    return render_template(
        "result.html",
        title=failure_reason or "Payment Blocked",
        status="blocked",
        tx=TRANSACTIONS[tx_id],
        tx_id=tx_id,
        user=current_user(),
    )


@app.route("/confirm/<tx_id>", methods=["GET", "POST"])
def confirm(tx_id):
    guard = require_login()
    if guard:
        return guard

    tx = TRANSACTIONS.get(tx_id)
    if not tx:
        return redirect(url_for("scan"))

    error = None
    if request.method == "POST":
        pin = request.form.get("pin", "")
        if pin == current_user()["pin"]:
            tx["status"] = "success"
            tx["confirmed_at"] = datetime.now().strftime("%d %b %Y, %H:%M:%S")
            return render_template(
                "result.html",
                title="Payment Successful",
                status="success",
                tx=tx,
                tx_id=tx_id,
                user=current_user(),
            )

        tx["status"] = "blocked"
        tx["checks"].append("PIN confirmation failed")
        error = "Incorrect PIN. Transaction blocked for safety."
        return render_template(
            "result.html",
            title="Payment Blocked",
            status="blocked",
            tx=tx,
            tx_id=tx_id,
            user=current_user(),
            error=error,
        )

    return render_template("confirm.html", tx_id=tx_id, tx=tx, user=current_user())


if __name__ == "__main__":
    app.run(debug=True, port=5000)
