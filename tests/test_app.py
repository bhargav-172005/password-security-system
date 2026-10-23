import os
import tempfile
import unittest

from app import create_app


class PasswordSecuritySystemTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self.temp_dir.name, "test_users.db")
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-secret-key",
            "DATABASE": db_path,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self, response):
        # CSRF tokens are rendered in hidden form inputs.
        import re
        html = response.get_data(as_text=True)
        match = re.search(r'name="_csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match, "CSRF token was not rendered")
        return match.group(1)

    def register_user(self, username="testuser", email="test@example.com", password="StrongPass1!"):
        response = self.client.get("/register")
        token = self.csrf_token(response)
        return self.client.post("/register", data={
            "_csrf_token": token,
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        }, follow_redirects=True)

    def login_user(self, identifier="testuser", password="StrongPass1!"):
        response = self.client.get("/login")
        token = self.csrf_token(response)
        return self.client.post("/login", data={
            "_csrf_token": token,
            "username": identifier,
            "password": password,
        }, follow_redirects=True)

    def test_registration_and_password_hashing(self):
        response = self.register_user()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration successful", response.data)
        with self.app.app_context():
            from app import get_db
            user = get_db().execute("SELECT * FROM users WHERE username = ?", ("testuser",)).fetchone()
            self.assertIsNotNone(user)
            self.assertNotEqual(user["password_hash"], "StrongPass1!")
            self.assertTrue(user["password_hash"])

    def test_login_with_username(self):
        self.register_user()
        response = self.login_user("testuser")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Account Status", response.data)
        self.assertIn(b"Active", response.data)

    def test_login_with_email(self):
        self.register_user()
        response = self.login_user("test@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome, testuser", response.data)

    def test_weak_password_is_rejected(self):
        response = self.client.get("/register")
        token = self.csrf_token(response)
        result = self.client.post("/register", data={
            "_csrf_token": token,
            "username": "weakuser",
            "email": "weak@example.com",
            "password": "weak",
            "confirm_password": "weak",
        })
        self.assertEqual(result.status_code, 400)
        self.assertIn(b"at least 8 characters", result.data)

    def test_password_mismatch_is_rejected(self):
        response = self.client.get("/register")
        token = self.csrf_token(response)
        result = self.client.post("/register", data={
            "_csrf_token": token,
            "username": "mismatch",
            "email": "mismatch@example.com",
            "password": "StrongPass1!",
            "confirm_password": "DifferentPass1!",
        })
        self.assertEqual(result.status_code, 400)
        self.assertIn(b"Passwords do not match", result.data)

    def test_invalid_login_is_rejected(self):
        self.register_user()
        result = self.login_user("testuser", "WrongPass1!")
        self.assertEqual(result.status_code, 401)
        self.assertIn(b"Invalid username/email or password", result.data)

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_logout_clears_session(self):
        self.register_user()
        self.login_user()
        dashboard = self.client.get("/dashboard")
        token = self.csrf_token(dashboard)
        response = self.client.post("/logout", data={"_csrf_token": token}, follow_redirects=True)
        self.assertIn(b"You have logged out successfully", response.data)
        dashboard_after_logout = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dashboard_after_logout.status_code, 302)

    def test_missing_csrf_token_is_rejected(self):
        result = self.client.post("/login", data={"username": "someone", "password": "anything"})
        self.assertEqual(result.status_code, 400)


if __name__ == "__main__":
    unittest.main()
