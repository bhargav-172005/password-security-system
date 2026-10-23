import os
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATABASE = BASE_DIR / "users.db"


def get_db():
    if "db" not in g:
        database_path = current_app_config_database()
        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def current_app_config_database():
    # Import lazily so this helper works with Flask's current app context.
    from flask import current_app
    return current_app.config["DATABASE"]


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()


def validate_password(password):
    if len(password) < 8:
        return "Password must contain at least 8 characters."
    if len(password) > 128:
        return "Password must be no more than 128 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain a number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain a special character."
    return None


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def verify_csrf():
    submitted = request.form.get("_csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not submitted or not expected or not secrets.compare_digest(submitted, expected):
        abort(400, description="Invalid or missing CSRF token. Refresh the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=str(DEFAULT_DATABASE),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,  # Set True when deployed over HTTPS.
    )
    if test_config:
        app.config.update(test_config)

    app.teardown_appcontext(close_db)
    app.jinja_env.globals["csrf_token"] = csrf_token

    with app.app_context():
        init_db()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

    @app.route("/")
    def home():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            verify_csrf()
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not username or not email or not password or not confirm_password:
                flash("All fields are required.", "error")
                return render_template("register.html"), 400
            if len(username) < 3 or len(username) > 30:
                flash("Username must be between 3 and 30 characters.", "error")
                return render_template("register.html"), 400
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
                flash("Username may contain only letters, numbers, dots, underscores, and hyphens.", "error")
                return render_template("register.html"), 400
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                flash("Please enter a valid email address.", "error")
                return render_template("register.html"), 400

            password_error = validate_password(password)
            if password_error:
                flash(password_error, "error")
                return render_template("register.html"), 400
            if password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template("register.html"), 400

            password_hash = generate_password_hash(password)
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, password_hash),
                )
                db.commit()
            except sqlite3.IntegrityError:
                flash("Username or email already exists.", "error")
                return render_template("register.html"), 409

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            verify_csrf()
            identifier = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
                (identifier, identifier),
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                csrf_token()  # Generate a fresh token after authentication.
                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))

            flash("Invalid username/email or password.", "error")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", username=session.get("username"))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        verify_csrf()
        session.clear()
        flash("You have logged out successfully.", "success")
        return redirect(url_for("login"))

    return app


app = create_app()

if __name__ == "__main__":
    # Development only. Set SECRET_KEY in your environment before deployment.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
