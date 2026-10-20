from flask import Flask, request, redirect, session, render_template_string
import sqlite3
import logging
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

app = Flask(__name__)
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

ph = PasswordHasher()

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Web Application</title>
    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #14213d, #087e8b);
            color: white;
            padding: 20px;
        }

        .card {
            width: 100%;
            max-width: 440px;
            padding: 35px;
            background: rgba(255, 255, 255, 0.13);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 20px;
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.2);
        }

        h1 {
            text-align: center;
            font-size: 27px;
            margin-bottom: 10px;
        }

        .subtitle {
            text-align: center;
            color: #e1f5fe;
            margin-bottom: 28px;
        }

        h2 {
            font-size: 20px;
            margin-top: 24px;
        }

        input {
            width: 100%;
            padding: 13px;
            margin: 8px 0;
            border: none;
            border-radius: 8px;
            font-size: 15px;
        }

        button {
            width: 100%;
            padding: 13px;
            margin-top: 10px;
            border: none;
            border-radius: 8px;
            background: #20c9b5;
            color: #062b35;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #49e0cf;
        }

        .message {
            padding: 10px;
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.2);
            overflow-wrap: anywhere;
        }

        a {
            color: #6ffff0;
        }

        .welcome {
            text-align: center;
        }

        .logout {
            display: inline-block;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <main class="card">
        {% if username %}
            <div class="welcome">
                <h1>Welcome!</h1>
                <p>You are securely logged in, {{ username }}.</p>
                <a class="logout" href="{{ url_for('logout') }}">Logout</a>
            </div>
        {% else %}
            <h1>Secure Web Application</h1>
            <p class="subtitle">Web Security Testing Lab</p>

            {% if message %}
                <p class="message">{{ message }}</p>
            {% endif %}

            <h2>Create Account</h2>
            <form action="{{ url_for('register') }}" method="POST">
                <input
                    type="text"
                    name="username"
                    placeholder="Username"
                    maxlength="50"
                    required
                >
                <input
                    type="password"
                    name="password"
                    placeholder="Password (8+ characters)"
                    minlength="8"
                    required
                >
                <button type="submit">Register</button>
            </form>

            <h2>Sign In</h2>
            <form action="{{ url_for('login') }}" method="POST">
                <input
                    type="text"
                    name="username"
                    placeholder="Username"
                    maxlength="50"
                    required
                >
                <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    required
                >
                <button type="submit">Login</button>
            </form>
        {% endif %}
    </main>
</body>
</html>
"""


@app.route("/")
def home():
    username = session.get("username")

    return render_template_string(
        PAGE,
        username=username,
        message=request.args.get("message", "")
    )


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return redirect("/?message=Enter+username+and+password")

    if len(username) > 50 or len(password) < 8:
        return redirect("/?message=Check+username+or+password+length")

    password_hash = ph.hash(password)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )

        return redirect("/?message=Account+created.+Please+login")

    except sqlite3.IntegrityError:
        return redirect("/?message=Username+already+exists")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if user is None:
        logging.warning("Failed login attempt: unknown username")
        return redirect("/?message=Invalid+username+or+password")

    try:
        ph.verify(user["password_hash"], password)
    except Exception:
        logging.warning("Failed login attempt: incorrect password")
        return redirect("/?message=Invalid+username+or+password")

    session.clear()
    session["username"] = user["username"]

    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/?message=Logged+out+successfully")


if __name__ == "__main__":
    initialize_db()
    app.run(debug=True)