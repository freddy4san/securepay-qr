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
- Transaction log for successful and failed payments
- Demo balance decreases after each successful payment
- Editable signed QR JSON for live tamper testing
- Simple mobile-app style interface

## Tech Stack

- Python 3
- Flask
- qrcode with Pillow image support
- HTML/CSS

## Project Structure

```text
app.py
requirements.txt
templates/
  base.html
  login.html
  home.html
  merchant.html
  scan.html
  validate.html
  confirm.html
  result.html
  transactions.html
static/
  style.css
README.md
```

## Setup and Run

### 1. Clone or Download

Clone the repository:

```bash
git clone https://github.com/freddy4san/securepay-qr.git
cd securepay-qr
```

If you downloaded a ZIP file instead, extract it and open a terminal in the extracted `securepay-qr` folder.

### 2. Create a Virtual Environment

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the App

```bash
flask --app app run
```

Open `http://127.0.0.1:5000`.

Alternative run command:

```bash
python app.py
```

## If Setup Fails

- Make sure Python 3 is installed: `python3 --version` or `py --version`.
- Make sure the virtual environment is activated before installing packages.
- If `flask` is not found, run `pip install -r requirements.txt` again.
- If port `5000` is already busy, use another port:

```bash
flask --app app run --port 5001
```

## Demo Login

- Username: `alice`, PIN: `1234`
- Username: `student`, PIN: `0000`

## Example Merchant

- Merchant ID: `MER123`
- Merchant name: `Campus Cafe`

## Suggested Classroom Demo Flow

1. Log in as `alice`.
2. Open **Generate merchant QR** and create a QR for `Campus Cafe`.
3. Validate the generated QR without editing it.
4. Confirm with PIN `1234` and show the successful receipt.
5. Return home and show that Alice's demo balance decreased.
6. Open **Transaction log** and show the successful transaction.
7. Generate another QR, edit the signed JSON amount or merchant name, then validate it to show tamper detection.
8. Open **Scan or run demo QR**.
9. Run the expired, unknown merchant, high-value, and tampered demo QRs to show why each transaction is blocked.

## Security Concepts Demonstrated

- The QR encodes JSON containing a payment payload and an HMAC-SHA256 signature.
- The signed payload includes `merchant_id`, `merchant_name`, `amount`, `invoice_id`, `issued_at`, and `expires_at`.
- If the payload is changed after signing, the signature check fails.
- Expired QRs are blocked even when their signature is valid.
- Unverified merchants are blocked.
- Transactions above the configured high-value threshold are blocked by a fraud rule.
- A valid QR still requires customer PIN confirmation before success.
- Successful payments debit the in-memory demo balance.
- Failed and successful transactions are logged for review.

## Notes

- This is a classroom prototype, not production payment software.
- Data is stored in memory only. Restarting the Flask server resets users, balances, and transaction history.
- The HMAC secret is hard-coded for demonstration. A real system would load secrets from secure environment configuration.
