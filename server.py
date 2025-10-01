from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import pyotp, base64, binascii
from collections import deque

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ----------------------
# Database Model
# ----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    secret = db.Column(db.String(64), nullable=False)  # Base32 secret
    counter = db.Column(db.Integer, default=0)        # Server counter
    key_counter = db.Column(db.Integer, default=0)    # Last key counter from device
    drift = db.Column(db.Integer, default=0)          # Drift = key_counter - server counter
    resync = db.Column(db.Integer, default=0)         # 1 if device needs resync, else 0

with app.app_context():
    db.create_all()

# ----------------------
# OTP Logging (last 10 events)
# ----------------------
otp_logs = deque(maxlen=10)

def log_otp(user, message, category):
    """Flash message to user and log to server-side deque."""
    flash(message, category)
    otp_logs.appendleft(f"User: {user.username} | {category.upper()} | {message}")

# ----------------------
# Helper Functions
# ----------------------
def hex_to_base32(hex_secret):
    try:
        raw = bytes.fromhex(hex_secret)
        return base64.b32encode(raw).decode("utf-8")
    except Exception:
        return None

def base32_to_hex(b32_secret):
    try:
        raw_bytes = base64.b32decode(b32_secret, casefold=True)
        return raw_bytes.hex().upper()
    except binascii.Error:
        return b32_secret

# ----------------------
# Routes
# ----------------------
@app.route("/")
def index():
    return redirect(url_for("user_page"))

# ----------------------
# User Page - OTP Verification
# ----------------------
@app.route("/user", methods=["GET", "POST"])
def user_page():
    if request.method == "POST":
        username = request.form["username"].strip()
        otp_input = request.form["otp"].strip()

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("❌ User not found!", "error")
            return redirect(url_for("user_page"))

        hotp = pyotp.HOTP(user.secret)
        server_counter = user.counter
        user.resync = 0  # reset by default

        # Exact match → increment server counter
        if hotp.verify(otp_input, server_counter):
            user.counter += 1
            user.key_counter = server_counter + 1
            user.drift = 0
            user.resync = 0
            log_otp(user, "✅ OTP Verified successfully!", "success")
        else:
            # Look 1–5 steps ahead
            found_drift = None
            for i in range(1, 6):
                if hotp.verify(otp_input, server_counter + i):
                    found_drift = i
                    break

            if found_drift:
                user.key_counter = server_counter + found_drift
                user.drift = found_drift
                user.resync = 0
                log_otp(user, f"⚠️ OTP is {found_drift} step(s) ahead. Drift tracked. Server counter unchanged.", "warning")
            else:
                user.drift = 0
                user.resync = 1
                log_otp(user, "❌ OTP too far ahead. Please reset the secret on server and device.", "error")

        db.session.commit()
        return redirect(url_for("user_page"))

    return render_template("user.html")

# ----------------------
# Admin Page
# ----------------------
@app.route("/admin")
def admin_page():
    users = User.query.all()
    users_with_data = []

    for u in users:
        users_with_data.append({
            "id": u.id,
            "username": u.username,
            "secret_hex": base32_to_hex(u.secret),
            "counter": u.counter,
            "key_counter": u.key_counter,
            "drift": u.drift,
            "resync": u.resync
        })

    return render_template("admin.html", users=users_with_data, otp_logs=list(otp_logs))

# ----------------------
# Add User
# ----------------------
@app.route("/add_user", methods=["POST"])
def add_user():
    username = request.form["username"].strip()
    hex_secret = request.form["secret"].strip()

    if User.query.filter_by(username=username).first():
        flash("❌ Username already exists!", "error")
        return redirect(url_for("admin_page"))

    b32_secret = hex_to_base32(hex_secret)
    if not b32_secret:
        flash("❌ Invalid HEX secret!", "error")
        return redirect(url_for("admin_page"))

    user = User(username=username, secret=b32_secret)
    db.session.add(user)
    db.session.commit()
    flash(f"✅ User {username} added successfully!", "success")
    return redirect(url_for("admin_page"))

# ----------------------
# Delete User
# ----------------------
@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"🗑️ User {user.username} deleted.", "info")
    return redirect(url_for("admin_page"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
