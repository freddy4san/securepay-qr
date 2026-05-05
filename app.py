import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime

from flask import Flask, redirect, render_template, request, session, url_for


app = Flask(__name__)
app.secret_key = "securepay-qr-demo-secret"

HMAC_SECRET = b"classroom-demo-hmac-key"
QR_TTL_SECONDS = 120
HIGH_VALUE_LIMIT = 1000

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
    "uni-cafe": {
        "name": "University Cafe",
        "verified": True,
        "category": "Food and drink",
    },
    "bookshop": {
        "name": "Campus Bookshop",
        "verified": True,
        "category": "Education",
    },
    "unknown-kiosk": {
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


def encode_payload(payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(body).decode().rstrip("=")


def decode_payload(encoded):
    padding = "=" * (-len(encoded) % 4)
    raw = base64.urlsafe_b64decode(encoded + padding)
    return json.loads(raw.decode())


def sign_payload(encoded_payload):
    digest = hmac.new(HMAC_SECRET, encoded_payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def make_qr_token(merchant_id, amount, note="SecurePay QR demo"):
    payload = {
        "amount": round(float(amount), 2),
        "currency": "AUD",
        "exp": int(time.time()) + QR_TTL_SECONDS,
        "iat": int(time.time()),
        "merchant_id": merchant_id,
        "note": note,
        "nonce": secrets.token_hex(6),
    }
    encoded = encode_payload(payload)
    signature = sign_payload(encoded)
    return f"{encoded}.{signature}"


def tamper_token(token):
    encoded, signature = token.split(".", 1)
    payload = decode_payload(encoded)
    payload["amount"] = payload["amount"] + 750
    payload["note"] = "Tampered amount"
    return f"{encode_payload(payload)}.{signature}"


def expired_token():
    payload = {
        "amount": 8.50,
        "currency": "AUD",
        "exp": int(time.time()) - 15,
        "iat": int(time.time()) - 180,
        "merchant_id": "uni-cafe",
        "note": "Expired lunch QR",
        "nonce": secrets.token_hex(6),
    }
    encoded = encode_payload(payload)
    return f"{encoded}.{sign_payload(encoded)}"


def validate_token(token):
    checks = []

    try:
        encoded, signature = token.strip().split(".", 1)
        payload = decode_payload(encoded)
    except Exception:
        return None, ["QR format is invalid"], False

    expected_signature = sign_payload(encoded)
    signature_ok = hmac.compare_digest(signature, expected_signature)
    checks.append("HMAC signature valid" if signature_ok else "HMAC signature failed")

    merchant = MERCHANTS.get(payload.get("merchant_id"))
    merchant_ok = bool(merchant and merchant["verified"])
    checks.append("Merchant is verified" if merchant_ok else "Merchant is not verified")

    expiry_ok = payload.get("exp", 0) >= int(time.time())
    checks.append("QR has not expired" if expiry_ok else "QR has expired")

    amount = float(payload.get("amount", 0))
    high_value_ok = amount <= HIGH_VALUE_LIMIT
    checks.append(
        "Amount is within fraud threshold"
        if high_value_ok
        else "Blocked by high-value fraud rule"
    )

    valid = signature_ok and merchant_ok and expiry_ok and high_value_ok
    return payload, checks, valid


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
    merchant_id = request.form.get("merchant_id", "uni-cafe")
    amount = request.form.get("amount", "12.50")

    if request.method == "POST":
        token = make_qr_token(merchant_id, amount, request.form.get("note", "Class demo"))
        tampered = tamper_token(token)
        payload = decode_payload(token.split(".", 1)[0])

    return render_template(
        "merchant.html",
        merchants=MERCHANTS,
        selected_merchant=merchant_id,
        amount=amount,
        token=token,
        tampered=tampered,
        payload=payload,
        ttl=QR_TTL_SECONDS,
    )


@app.route("/scan")
def scan():
    guard = require_login()
    if guard:
        return guard

    valid_demo = make_qr_token("uni-cafe", 12.50, "Coffee and sandwich")
    tampered_demo = tamper_token(valid_demo)
    high_value_demo = make_qr_token("bookshop", 1750.00, "Laptop purchase")
    unverified_demo = make_qr_token("unknown-kiosk", 35.00, "Phone accessory")
    expired_demo = expired_token()

    demos = [
        ("Valid QR", valid_demo, "Passes signature, expiry, merchant, and fraud checks."),
        ("Tampered QR", tampered_demo, "Amount changed after signing, so HMAC fails."),
        ("Expired QR", expired_demo, "Signature is real, but the QR is outside its time window."),
        (
            "Unverified merchant",
            unverified_demo,
            "Merchant record exists but is not approved.",
        ),
        (
            "High-value payment",
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
    payload, checks, valid = validate_token(token)
    tx_id = secrets.token_hex(8)
    TRANSACTIONS[tx_id] = {
        "checks": checks,
        "created_at": datetime.now().strftime("%d %b %Y, %H:%M:%S"),
        "payload": payload,
        "status": "pending_pin" if valid else "blocked",
        "token": token,
        "valid": valid,
    }

    if valid:
        return render_template(
            "validate.html", tx_id=tx_id, payload=payload, checks=checks, valid=True
        )
    return render_template(
        "result.html",
        title="Payment Blocked",
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
