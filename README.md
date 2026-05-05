# SecurePay QR

SecurePay QR is a small Flask prototype for a university FinTech cybersecurity assessment. It simulates a mobile QR payment flow with signed QR tokens, validation checks, customer PIN confirmation, and clear success or blocked outcomes.

## Features

- Customer login simulation with in-memory users
- Merchant QR generator
- Real QR images generated with the Python `qrcode` library
- Customer scan page with ready-made demo QR flows
- HMAC signature validation
- QR expiry validation
- Merchant verification
- High-value transaction fraud rule
- PIN confirmation step (Multi-factor Auth)
- Payment success and blocked transaction screens
- Simple mobile-app style interface

## Tech Stack
- Python (Flask)
- HTML/CSS
- QRCode library

## Project Structure

```text
app.py
templates/
  base.html
  login.html
  home.html
  merchant.html
  scan.html
  validate.html
  confirm.html
  result.html
static/
  style.css
README.md
```

## Run Locally

```bash
git clone https://github.com/freddy4san/securepay-qr.git
cd securepay-qr
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run
```

Open `http://127.0.0.1:5000`.

## Demo Login

- Username: `alice`, PIN: `1234`
- Username: `student`, PIN: `0000`

## Example Merchant

- Merchant ID: `MER123`
- Merchant name: `Campus Cafe`

## Suggested Classroom Demo Flow

1. Log in as `alice`.
2. Open **Generate merchant QR** and create a QR for `University Cafe`.
3. Scan the valid QR and confirm with PIN `1234`.
4. Open **Scan or run demo QR**.
5. Run the tampered, expired, unverified merchant, and high-value demos to show why each transaction is blocked.

## Security Concepts Demonstrated

- The QR encodes JSON containing a payment payload and an HMAC-SHA256 signature.
- The signed payload includes `merchant_id`, `merchant_name`, `amount`, `invoice_id`, `issued_at`, and `expires_at`.
- If the payload is changed after signing, the signature check fails.
- Expired QRs are blocked even when their signature is valid.
- Unverified merchants are blocked.
- Transactions above the configured high-value threshold are blocked by a fraud rule.
- A valid QR still requires customer PIN confirmation before success.
