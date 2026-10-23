# Basic Password Security & User Authentication System

**Project ID:** CYB-W1-001  
**Category:** Cybersecurity — Week 1  
**Stack:** Python, Flask, SQLite, HTML, CSS, JavaScript

## Overview

A beginner-friendly web application demonstrating secure registration and login practices. Users can create an account, receive live password-strength feedback, log in using a username or email, view an authenticated dashboard, and log out.

## Features

- Registration with username, email, password, and confirmation.
- Server-side input validation and password policy checks.
- Live Weak / Medium / Strong password-strength indicator.
- Passwords stored as Werkzeug-generated password hashes, never as plaintext.
- Login with username **or** email.
- Session-protected dashboard with account and login status.
- CSRF token checks on registration, login, and logout forms.
- Parameterized SQL queries, unique username/email constraints, and basic security headers.
- Automated tests for core registration and authentication behaviour.

## Requirements

- Python 3.10 or newer recommended.
- pip.

## Setup on Windows

Open Command Prompt or PowerShell in the project folder.

```powershell
py -m venv venv
.\venv\Scripts\activate
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt and run:

```bat
venv\Scripts\activate.bat
```

## Run the app

Set a development secret key for the current PowerShell window and start Flask:

```powershell
$env:SECRET_KEY = "replace-this-with-a-long-random-secret"
python app.py
```

Open the local address printed in the terminal (usually `http://127.0.0.1:5000`).

For Command Prompt:

```bat
set SECRET_KEY=replace-this-with-a-long-random-secret
python app.py
```

The SQLite database `users.db` is created automatically in the project folder. It is intentionally excluded from Git because it is a local runtime file.

## Run automated tests

With the virtual environment activated:

```powershell
python -m unittest discover -s tests -v
```

The tests use a temporary database and do not use your local `users.db`.

## Suggested manual test cases

| Test | Action | Expected result |
|---|---|---|
| Register valid user | Enter unique username/email and a compliant password | Registration success message |
| Weak password | Enter password without required rules | Registration rejected with helpful message |
| Password mismatch | Enter different password and confirmation | Registration rejected |
| Duplicate account | Register an existing username or email | Duplicate-account message |
| Login by username | Use registered username and correct password | Dashboard opens |
| Login by email | Use registered email and correct password | Dashboard opens |
| Incorrect password | Enter wrong password | Login rejected |
| Protected page | Open `/dashboard` while logged out | Redirect to login |
| Logout | Click Log out | Session ends and dashboard is no longer accessible |
| CSRF validation | Submit a form without its CSRF token | Request rejected |

## Screenshots for submission

Create a `screenshots/` folder and capture these screens after running the application:

1. `01-register.png` — registration page and password-strength indicator.
2. `02-password-strength.png` — a strong password showing all rules passed (do not expose a real personal password).
3. `03-login.png` — login page.
4. `04-dashboard.png` — dashboard showing Account Status: Active and Login Status: Successful.
5. `05-test-results.png` — terminal output from the automated tests.

Do not include passwords, private data, `.env` files, the virtual environment, or the local database in screenshots or public repositories.

## GitHub submission checklist

```bash
git init
git add app.py templates static tests requirements.txt README.md .gitignore
git commit -m "Complete password security and authentication system"
```

Create an empty GitHub repository, then follow GitHub's instructions to add its remote and push the branch. Do not commit `venv/`, `users.db`, or secrets.

## Security notes and limitations

This is an educational project, not a production-ready identity system. Before deployment, use HTTPS, set a strong persistent `SECRET_KEY` through the environment, set `SESSION_COOKIE_SECURE=True`, add rate limiting and account lockout/monitoring, consider email verification and password reset flows, and review the application with a security professional. The live strength indicator is user guidance; server-side validation remains authoritative.
