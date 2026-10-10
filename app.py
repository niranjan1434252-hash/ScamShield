import os
import re
import io
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "scamshield-development-key")
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


# ---------------- DATABASE HELPERS ----------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(conn, table):
    return {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT
        )
    """)

    user_cols = table_columns(conn, "users")
    if "password" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN password TEXT")
    if "password_hash" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            scanned_value TEXT,
            scan_input TEXT,
            result TEXT,
            risk TEXT NOT NULL DEFAULT 'Low Risk',
            score INTEGER DEFAULT 0,
            reasons TEXT DEFAULT '',
            created_at TEXT
        )
    """)

    scan_cols = table_columns(conn, "scan_history")
    required_columns = {
        "user_id": "INTEGER",
        "scan_type": "TEXT",
        "scanned_value": "TEXT",
        "scan_input": "TEXT",
        "result": "TEXT",
        "risk": "TEXT DEFAULT 'Low Risk'",
        "score": "INTEGER DEFAULT 0",
        "reasons": "TEXT DEFAULT ''",
        "created_at": "TEXT",
    }
    for column, definition in required_columns.items():
        if column not in scan_cols:
            conn.execute(
                f"ALTER TABLE scan_history ADD COLUMN {column} {definition}"
            )

    scan_cols = table_columns(conn, "scan_history")
    if "scan_input" in scan_cols and "scanned_value" in scan_cols:
        conn.execute("""
            UPDATE scan_history
            SET scanned_value = scan_input
            WHERE (scanned_value IS NULL OR scanned_value = '')
              AND scan_input IS NOT NULL
        """)
        conn.execute("""
            UPDATE scan_history
            SET scan_input = scanned_value
            WHERE (scan_input IS NULL OR scan_input = '')
              AND scanned_value IS NOT NULL
        """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            report_value TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            if request.path in {
                "/scan", "/history", "/history/clear", "/chatbot",
                "/report-scam", "/my-reports", "/dashboard-stats",
                "/report.pdf"
            }:
                return jsonify({
                    "success": False,
                    "error": "Please log in first.",
                    "message": "Please log in first."
                }), 401
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def save_scan(user_id, scan_type, value, result, risk, score, reasons, created_at):
    conn = get_db()
    cols = table_columns(conn, "scan_history")
    values = {
        "user_id": user_id,
        "scan_type": scan_type,
        "scan_input": value,
        "scanned_value": value,
        "result": result,
        "risk": risk,
        "score": score,
        "reasons": "\n".join(reasons),
        "created_at": created_at,
    }
    names = [name for name in values if name in cols]
    placeholders = ", ".join("?" for _ in names)
    name_sql = ", ".join(names)
    try:
        conn.execute(
            f"INSERT INTO scan_history ({name_sql}) VALUES ({placeholders})",
            [values[name] for name in names]
        )
        conn.commit()
    finally:
        conn.close()


# ---------------- SCAM DETECTION ----------------

SUSPICIOUS_WORDS = [
    "urgent", "verify your account", "account blocked",
    "click here", "claim your prize", "winner",
    "free gift", "limited offer", "password", "otp",
    "bank details", "send money", "suspended account",
    "kyc update", "lottery", "investment guaranteed",
    "act now", "account will be blocked", "share your otp",
    "verify immediately", "atm pin", "account number",
    "permanent account closure", "reactivate your account"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at"
]


def assess_text(text):
    """Rule-based message/email-content analysis; not a guarantee."""
    lower = text.lower()
    reasons = []
    score = 0

    matched_phrases = [word for word in SUSPICIOUS_WORDS if word in lower]
    if matched_phrases:
        reasons.extend("Suspicious phrase: " + word for word in matched_phrases)
        score += min(30, len(matched_phrases) * 8)

    urgency_words = [
        "urgent", "immediately", "within 30 minutes", "act now",
        "failure to comply", "right now", "expires today"
    ]
    if any(word in lower for word in urgency_words):
        reasons.append("Uses urgent or time-pressure language")
        score += 20

    threat_words = [
        "account will be blocked", "account blocked", "account suspension",
        "permanent account closure", "account will be closed",
        "your account will be suspended"
    ]
    if any(word in lower for word in threat_words):
        reasons.append("Threatens account blocking or closure")
        score += 20

    sensitive_words = [
        "otp", "one-time password", "atm pin", "pin number",
        "password", "bank details", "account number", "card number",
        "security code"
    ]
    request_words = [
        "enter", "share", "send", "provide", "submit",
        "give us", "tell us", "reply with", "confirm"
    ]
    if any(word in lower for word in sensitive_words) and any(
        word in lower for word in request_words
    ):
        reasons.append("Requests sensitive banking or account information")
        score += 30

    has_link = bool(re.search(r"https?://|www\.", lower))
    click_instruction = any(word in lower for word in [
        "click this link", "click here", "tap this link",
        "verify your account", "reactivate your account"
    ])
    if has_link:
        reasons.append("Contains a web link")
        score += 10
    if click_instruction:
        reasons.append("Urges the reader to click or verify details")
        score += 15

    if any(word in lower for word in [
        "send money", "transfer money", "pay immediately",
        "urgent payment", "pay now"
    ]):
        reasons.append("Urgent payment request")
        score += 20

    if any(word in lower for word in [
        "guaranteed profit", "investment guaranteed",
        "you have won", "claim your prize", "lottery winner"
    ]):
        reasons.append("Prize or guaranteed-return claim")
        score += 20

    return min(score, 100), list(dict.fromkeys(reasons))


def assess_url(value):
    reasons = []
    value = value.strip()
    if not value:
        return ["URL is empty"]

    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname or ""
    except ValueError:
        return ["URL format appears invalid"]

    if not hostname or "." not in hostname:
        reasons.append("Domain format appears unusual")
    if value.lower().startswith("http://"):
        reasons.append("Uses HTTP instead of HTTPS")
    if "@" in parsed.netloc:
        reasons.append("URL contains an @ symbol in its address")
    if "xn--" in hostname.lower():
        reasons.append("Domain contains encoded international characters")
    if hostname.count(".") >= 4:
        reasons.append("URL contains many subdomains")
    if any(word in value.lower() for word in [
        "login", "verify", "free-gift", "prize", "account-locked",
        "banking-secure", "claim-reward", "password-reset"
    ]):
        reasons.append("URL contains suspicious keywords")
    if any(shortener in hostname.lower() for shortener in SHORTENERS):
        reasons.append("Uses a URL shortening service")
    if re.search(r"%[0-9a-fA-F]{2}", value):
        reasons.append("URL contains percent-encoded characters")
    if len(value) > 200:
        reasons.append("URL is unusually long")

    return list(dict.fromkeys(reasons))


def classify_score(score):
    if score >= 70:
        return (
            "High Risk",
            "Multiple strong warning signs detected. Do not click links or share sensitive information."
        )
    if score >= 40:
        return "Suspicious", "Several warning signs detected. Verify independently."
    if score > 0:
        return "Caution", "Some warning signs need review."
    return (
        "Low Risk",
        "No obvious warning signs detected. This is not a guarantee of safety."
    )


def make_result(scan_type, value):
    reasons = []
    score = 0

    if scan_type == "message":
        score, reasons = assess_text(value)

    elif scan_type == "url":
        reasons = assess_url(value)
        score = min(100, len(reasons) * 25)

    elif scan_type == "phone":
        digits = re.sub(r"\D", "", value)
        if len(digits) < 7 or len(digits) > 15:
            reasons.append("Phone number has an unusual length")
            score += 25
        if re.search(r"(.)\1{6,}", digits):
            reasons.append("Phone number contains repeated digits")
            score += 25
        if any(word in value.lower() for word in [
            "unknown", "suspicious", "spam"
        ]):
            reasons.append("Number is labelled as suspicious")
            score += 35

    elif scan_type == "email":
        # An email scan accepts an address OR pasted email content.
        if "@" not in value or any(char.isspace() for char in value):
            score, reasons = assess_text(value)
            if not reasons:
                reasons.append(
                    "Email content has no obvious known scam indicators"
                )
        else:
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                reasons.append("Email address format appears invalid")
                score += 35

            domain = value.split("@")[-1].lower()
            disposable_domains = {
                "tempmail.com", "10minutemail.com",
                "guerrillamail.com", "mailinator.com"
            }
            if domain in disposable_domains:
                reasons.append("Uses a known disposable email domain")
                score += 35

            if any(word in value.lower() for word in [
                "prize", "winner", "claim-reward"
            ]):
                reasons.append("Email contains suspicious wording")
                score += 25

            if not reasons:
                reasons.append(
                    "Email format looks valid; sender authenticity is not verified"
                )

    else:
        reasons.append("Unsupported scan type")
        score = 100

    score = min(score, 100)
    risk, result_text = classify_score(score)
    reasons = list(dict.fromkeys(reasons))

    return {
        "success": True,
        "scan_type": scan_type,
        "input": value,
        "scanned_value": value,
        "result": result_text,
        "risk": risk,
        "status": risk,
        "score": score,
        "reasons": reasons,
        "message": result_text
    }


# ---------------- AUTHENTICATION ----------------

@app.route("/")
@login_required
def home():
    return render_template("index.html", username=session.get("username", "User"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password or not confirm:
            return render_template(
                "auth.html", mode="signup", error="Please fill in all fields."
            )
        if len(password) < 6:
            return render_template(
                "auth.html", mode="signup",
                error="Password must contain at least 6 characters."
            )
        if password != confirm:
            return render_template(
                "auth.html", mode="signup", error="Passwords do not match."
            )
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return render_template(
                "auth.html", mode="signup",
                error="Please enter a valid email address."
            )

        conn = get_db()
        password_hash = generate_password_hash(password)
        try:
            cols = table_columns(conn, "users")
            names, vals = ["username", "email"], [username, email]
            if "password" in cols:
                names.append("password")
                vals.append(password_hash)
            if "password_hash" in cols:
                names.append("password_hash")
                vals.append(password_hash)

            conn.execute(
                f"INSERT INTO users ({', '.join(names)}) "
                f"VALUES ({', '.join('?' for _ in names)})",
                vals
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template(
                "auth.html", mode="signup",
                error="This email is already registered."
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass

        return redirect(url_for("login"))

    return render_template("auth.html", mode="signup")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        valid = False
        if user:
            keys = user.keys()
            stored_password = (
                user["password_hash"]
                if "password_hash" in keys and user["password_hash"]
                else user["password"]
                if "password" in keys and user["password"]
                else ""
            )
            if stored_password:
                try:
                    valid = check_password_hash(stored_password, password)
                except (ValueError, TypeError):
                    valid = False
                # Compatibility for older records stored as plain text.
                if not valid and stored_password == password:
                    valid = True

        if valid:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("home"))

        return render_template(
            "auth.html", mode="login", error="Invalid email or password."
        )

    return render_template("auth.html", mode="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- SCAN API ----------------

@app.route("/scan", methods=["POST"])
@login_required
def scan():
    data = request.get_json(silent=True) or {}
    scan_type = str(data.get("type", "")).strip().lower()
    value = str(data.get("input", data.get("value", ""))).strip()

    if scan_type not in {"message", "url", "phone", "email"}:
        return jsonify({
            "success": False,
            "error": "Choose a valid scan type.",
            "message": "Choose a valid scan type."
        }), 400
    if not value:
        return jsonify({
            "success": False,
            "error": "Please enter something to scan.",
            "message": "Please enter something to scan."
        }), 400
    if len(value) > 5000:
        return jsonify({
            "success": False,
            "error": "Input is too long.",
            "message": "Input is too long."
        }), 400

    result = make_result(scan_type, value)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_scan(
        session["user_id"], scan_type, value,
        result["result"], result["risk"], result["score"],
        result["reasons"], now
    )
    result["created_at"] = now
    return jsonify(result)


# ---------------- SCAN HISTORY ----------------

@app.route("/history")
@login_required
def history():
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM scan_history
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 100
    """, (session["user_id"],)).fetchall()
    conn.close()

    items = []
    for row in rows:
        item = dict(row)
        value = item.get("scanned_value") or item.get("scan_input") or ""
        item["scanned_value"] = value
        item["scan_input"] = value
        item["risk"] = item.get("risk") or "Low Risk"
        if item.get("score") is None:
            item["score"] = (
                100 if item["risk"] == "High Risk"
                else 60 if item["risk"] == "Suspicious"
                else 25 if item["risk"] == "Caution"
                else 0
            )
        raw_reasons = item.get("reasons") or ""
        item["reasons"] = (
            [line for line in raw_reasons.splitlines() if line]
            if isinstance(raw_reasons, str) else []
        )
        items.append(item)

    return jsonify({"success": True, "history": items, "items": items})


@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    conn = get_db()
    conn.execute("DELETE FROM scan_history WHERE user_id = ?", (session["user_id"],))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Scan history cleared."})


# ---------------- SCAM AWARENESS CHATBOT ----------------

@app.route("/chatbot", methods=["POST"])
@login_required
def chatbot():
    data = request.get_json(silent=True) or {}
    question = str(data.get("message", "")).strip().lower()
    if not question:
        return jsonify({"success": False, "reply": "Please type your question."}), 400

    if any(w in question for w in ["otp", "one time password"]):
        reply = "Never share your OTP with anyone, even if they claim to be from your bank or a government department."
    elif any(w in question for w in ["upi", "payment", "money"]):
        reply = "Never enter your UPI PIN to receive money. Verify the recipient before paying and never approve an unknown request."
    elif any(w in question for w in ["link", "url", "website"]):
        reply = "Check the domain carefully. Avoid unexpected links and never enter passwords or banking details on an unverified website."
    elif any(w in question for w in ["call", "phone", "number"]):
        reply = "Never share OTPs or banking details with callers. Contact the organisation using its official number."
    elif any(w in question for w in ["report", "complaint"]):
        reply = "Use the Report a Scam section. In India, visit cybercrime.gov.in. For financial cyber fraud, call 1930 as soon as possible."
    else:
        reply = "Ask me about OTP safety, suspicious links, payment fraud, phone scams, or how to report fraud."

    return jsonify({"success": True, "reply": reply})


# ---------------- REPORT A SCAM ----------------

@app.route("/report-scam", methods=["POST"])
@login_required
def report_scam():
    data = request.get_json(silent=True) or {}
    category = str(data.get("category", "")).strip()
    value = str(data.get("value", "")).strip()
    description = str(data.get("description", "")).strip()
    allowed = {
        "SMS", "Phone Call", "Website", "Email",
        "Social Media", "Payment Fraud", "Other"
    }

    if category not in allowed:
        return jsonify({"success": False, "message": "Choose a valid report category."}), 400
    if not value or not description:
        return jsonify({"success": False, "message": "Please fill in all report fields."}), 400
    if len(value) > 500 or len(description) > 3000:
        return jsonify({"success": False, "message": "Report details are too long."}), 400

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO scam_reports
            (user_id, category, report_value, description, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["user_id"], category, value, description,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "Your report was saved in ScamShield."})


@app.route("/my-reports")
@login_required
def my_reports():
    conn = get_db()
    rows = conn.execute("""
        SELECT id, category, report_value, description, created_at
        FROM scam_reports
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 100
    """, (session["user_id"],)).fetchall()
    conn.close()
    return jsonify({"success": True, "reports": [dict(row) for row in rows]})


# ---------------- DASHBOARD STATISTICS ----------------

@app.route("/dashboard-stats")
@login_required
def dashboard_stats():
    user_id = session["user_id"]
    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM scan_history WHERE user_id = ?", (user_id,)
    ).fetchone()["n"]
    suspicious = conn.execute("""
        SELECT COUNT(*) AS n FROM scan_history
        WHERE user_id = ? AND risk IN ('Suspicious', 'High Risk')
    """, (user_id,)).fetchone()["n"]
    rows = conn.execute("""
        SELECT scan_type, COUNT(*) AS n FROM scan_history
        WHERE user_id = ? GROUP BY scan_type
    """, (user_id,)).fetchall()
    by_type = {row["scan_type"]: row["n"] for row in rows}

    daily = []
    today = datetime.now().date()
    for offset in range(6, -1, -1):
        day = (today - timedelta(days=offset)).strftime("%Y-%m-%d")
        count = conn.execute("""
            SELECT COUNT(*) AS n FROM scan_history
            WHERE user_id = ? AND created_at LIKE ?
        """, (user_id, day + "%")).fetchone()["n"]
        daily.append({"date": day, "count": count})
    conn.close()

    return jsonify({
        "success": True,
        "total_scans": total,
        "suspicious_scans": suspicious,
        "safe_scans": total - suspicious,
        "by_type": by_type,
        "daily": daily
    })


# ---------------- PDF SECURITY REPORT ----------------

@app.route("/report.pdf")
@login_required
def download_report():
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM scan_history
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 200
    """, (session["user_id"],)).fetchall()
    conn.close()

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    _, height = A4
    y = height - 50

    pdf.setTitle("ScamShield Security Report")
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(40, y, "ScamShield Security Report")
    y -= 28
    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M"))
    y -= 25
    pdf.drawString(40, y, "Recent scan records (maximum 200):")
    y -= 22

    if not rows:
        pdf.drawString(40, y, "No scan records are available yet.")

    for row in rows:
        item = dict(row)
        value = item.get("scanned_value") or item.get("scan_input") or ""
        if y < 100:
            pdf.showPage()
            y = height - 50

        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(40, y, "Type: " + str(item.get("scan_type", ""))[:50])
        y -= 15
        pdf.setFont("Helvetica", 9)
        lines = [
            "Risk: " + str(item.get("risk", "")),
            "Score: " + str(item.get("score", 0)) + "/100",
            "Input: " + str(value)[:90],
            "Result: " + str(item.get("result") or "")[:90],
            "Date: " + str(item.get("created_at") or "")
        ]
        for line in lines:
            if y < 50:
                pdf.showPage()
                y = height - 50
                pdf.setFont("Helvetica", 9)
            safe_line = line.encode("latin-1", "replace").decode("latin-1")
            pdf.drawString(48, y, safe_line)
            y -= 13
        y -= 10

    pdf.save()
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="ScamShield_Security_Report.pdf"
    )


# ---------------- START APPLICATION ----------------

init_db()

if __name__ == "__main__":
    # For testing on the same private Wi-Fi network only.
    # Do not expose Flask's debug server to the public internet.
    app.run(host="0.0.0.0", port=5000, debug=True)