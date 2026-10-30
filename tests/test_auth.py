import re
import sqlite3
import tempfile
from contextlib import closing
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch

from app import LOOKER_STUDIO_SCOPE, create_app
from crypto_store import decrypt_bytes, encrypt_bytes
from database import save_encrypted_record, save_user


class AuthFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temp_dir.name) / "test.sqlite")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": "test-encryption-key-that-is-long-enough",
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
                "SESSION_COOKIE_SECURE": False,
            }
        )
        self.client = self.app.test_client()
        self.google_sub = "google-account-123"
        save_user(self.database_path, self.google_sub, "person@example.com", "Test Person")
        with self.client.session_transaction() as flask_session:
            flask_session["google_sub"] = self.google_sub
            flask_session["csrf_token"] = "known-csrf-token"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_home_displays_real_auth_action_and_demo_notice(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"person@example.com", response.data)
        self.assertIn(b"demo mode", response.data.lower())
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertIn(b'property="og:title"', response.data)
        self.assertIn(b"favicon.svg", response.data)
        self.assertIn(b"social-preview.png", response.data)
        self.assertNotIn(b"fonts.googleapis.com", response.data)

    def test_oauth_client_secret_is_encrypted_before_database_storage(self) -> None:
        response = self.client.get("/auth/credentials")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(csrf)
        secret = "very-private-google-client-secret"
        client_id = "123456789012-example.apps.googleusercontent.com"
        response = self.client.post(
            "/auth/credentials",
            data={"csrf_token": csrf.group(1).decode(), "client_id": client_id, "client_secret": secret},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/auth/data/start")
        with closing(sqlite3.connect(self.database_path)) as connection:
            stored = connection.execute(
                "SELECT nonce, ciphertext FROM saved_credentials WHERE google_sub = ?",
                (self.google_sub,),
            ).fetchone()
        self.assertIsNotNone(stored)
        self.assertNotIn(secret.encode(), stored[1])
        plaintext = decrypt_bytes(
            stored[0], stored[1], self.app.config["ENCRYPTION_KEY"], "google-client", self.google_sub
        )
        self.assertIn(secret, plaintext.decode())
        self.assertNotIn(secret.encode(), response.data)

    def test_credentials_form_rejects_missing_csrf_token(self) -> None:
        response = self.client.post(
            "/auth/credentials",
            data={
                "client_id": "123456789012-example.apps.googleusercontent.com",
                "client_secret": "client-secret-value",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"form expired", response.data.lower())

    def test_consumer_gmail_account_can_enter_oauth_client_credentials(self) -> None:
        save_user(self.database_path, "consumer-sub", "person@gmail.com", "Personal User")
        client = self.app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["google_sub"] = "consumer-sub"
            flask_session["csrf_token"] = "consumer-csrf"
        response = client.get("/auth/credentials")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"person@gmail.com", response.data)
        self.assertIn(b'name="client_secret"', response.data)
        response = client.post(
            "/auth/credentials",
            data={
                "csrf_token": "consumer-csrf",
                "client_id": "123456789012-example.apps.googleusercontent.com",
                "client_secret": "consumer-test-client-secret",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/auth/data/start")

    def test_credentials_route_requires_identity_session(self) -> None:
        self.client.post("/auth/logout", data={"csrf_token": "known-csrf-token"})
        response = self.client.get("/auth/credentials")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/auth/google")

    def test_data_authorization_requests_only_looker_scope(self) -> None:
        secret = "very-private-google-client-secret"
        nonce, ciphertext = encrypt_bytes(
            f'{{"client_id":"123456789012-example.apps.googleusercontent.com","client_secret":"{secret}"}}'.encode(),
            self.app.config["ENCRYPTION_KEY"],
            "google-client",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "saved_credentials", self.google_sub, nonce, ciphertext)
        response = self.client.get("/auth/data/start")
        self.assertEqual(response.status_code, 302)
        target = urlsplit(response.headers["Location"])
        query = parse_qs(target.query)
        self.assertEqual(target.netloc, "accounts.google.com")
        self.assertIn(LOOKER_STUDIO_SCOPE, query["scope"][0].split())
        self.assertIn("openid", query["scope"][0].split())
        self.assertIn("https://www.googleapis.com/auth/userinfo.profile", query["scope"][0].split())
        self.assertEqual(query["redirect_uri"], ["http://localhost:5000/auth/data/callback"])
        self.assertEqual(query["login_hint"], ["person@example.com"])
        self.assertNotIn(secret, response.headers["Location"])

    def test_data_callback_rejects_invalid_state_without_token_exchange(self) -> None:
        with self.client.session_transaction() as flask_session:
            flask_session["data_oauth_state"] = "expected-state"
        response = self.client.get("/auth/data/callback?code=fake&state=wrong-state")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b"access_token", response.data)

    def test_data_callback_encrypts_tokens_at_rest(self) -> None:
        secret = "very-private-google-client-secret"
        nonce, ciphertext = encrypt_bytes(
            f'{{"client_id":"123456789012-example.apps.googleusercontent.com","client_secret":"{secret}"}}'.encode(),
            self.app.config["ENCRYPTION_KEY"],
            "google-client",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "saved_credentials", self.google_sub, nonce, ciphertext)
        with self.client.session_transaction() as flask_session:
            flask_session["data_oauth_state"] = "expected-state"
        token_response = {
            "access_token": "access-token-never-returned-to-browser",
            "refresh_token": "refresh-token-never-returned-to-browser",
            "scope": f"openid email profile {LOOKER_STUDIO_SCOPE}",
            "expires_in": 3600,
            "expires_at": 1_900_000_000,
        }
        identity_response = Mock()
        identity_response.json.return_value = {"sub": self.google_sub}
        with patch("app.OAuth2Session.fetch_token", return_value=token_response), patch(
            "app.requests.get", return_value=identity_response
        ):
            response = self.client.get("/auth/data/callback?code=fake-code&state=expected-state")
        self.assertEqual(response.status_code, 302)
        with closing(sqlite3.connect(self.database_path)) as connection:
            stored = connection.execute(
                "SELECT nonce, ciphertext FROM oauth_tokens WHERE google_sub = ?",
                (self.google_sub,),
            ).fetchone()
        self.assertIsNotNone(stored)
        self.assertNotIn(token_response["access_token"].encode(), stored[1])
        decoded = decrypt_bytes(
            stored[0], stored[1], self.app.config["ENCRYPTION_KEY"], "google-tokens", self.google_sub
        ).decode()
        self.assertIn(token_response["refresh_token"], decoded)
        self.assertNotIn(token_response["access_token"].encode(), response.data)

    def test_data_callback_rejects_a_different_google_account(self) -> None:
        secret = "very-private-google-client-secret"
        nonce, ciphertext = encrypt_bytes(
            f'{{"client_id":"123456789012-example.apps.googleusercontent.com","client_secret":"{secret}"}}'.encode(),
            self.app.config["ENCRYPTION_KEY"],
            "google-client",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "saved_credentials", self.google_sub, nonce, ciphertext)
        with self.client.session_transaction() as flask_session:
            flask_session["data_oauth_state"] = "expected-state"
        identity_response = Mock()
        identity_response.json.return_value = {"sub": "another-google-account"}
        with patch(
            "app.OAuth2Session.fetch_token",
            return_value={"access_token": "access-token", "scope": LOOKER_STUDIO_SCOPE},
        ), patch("app.requests.get", return_value=identity_response):
            response = self.client.get("/auth/data/callback?code=fake-code&state=expected-state")
        self.assertEqual(response.status_code, 403)
        with closing(sqlite3.connect(self.database_path)) as connection:
            stored = connection.execute(
                "SELECT 1 FROM oauth_tokens WHERE google_sub = ?", (self.google_sub,)
            ).fetchone()
        self.assertIsNone(stored)

    def test_session_cookie_is_opaque_and_http_only(self) -> None:
        self.app.config["SESSION_COOKIE_SECURE"] = True
        response = self.client.get("/auth/credentials", base_url="https://localhost")
        cookie = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Secure", cookie)
        self.assertNotIn("person@example.com", cookie)

    def test_identity_callback_creates_server_account_and_starts_setup(self) -> None:
        identity_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": "test-encryption-key-that-is-long-enough",
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
                "GOOGLE_CLIENT_ID": "app-client-id",
                "GOOGLE_CLIENT_SECRET": "app-client-secret",
                "ADMIN_EMAIL": "admin@example.com",
            }
        )
        client = identity_app.test_client()
        profile = {
            "sub": "new-google-sub",
            "email": "new-person@example.com",
            "email_verified": True,
            "name": "New Person",
        }
        with patch.object(
            identity_app.extensions["google_identity_client"],
            "authorize_access_token",
            return_value={"userinfo": profile},
        ):
            response = client.get("/auth/callback")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/auth/credentials")
        self.assertEqual(
            client.get("/auth/credentials").status_code,
            200,
        )
        with closing(sqlite3.connect(self.database_path)) as connection:
            user = connection.execute(
                "SELECT email, name FROM users WHERE google_sub = ?", ("new-google-sub",)
            ).fetchone()
        self.assertEqual(user, ("new-person@example.com", "New Person"))

    def test_account_deletion_removes_local_data_and_revokes_google_token(self) -> None:
        nonce, ciphertext = encrypt_bytes(
            b'{"client_id":"test-client","client_secret":"private-client-secret"}',
            self.app.config["ENCRYPTION_KEY"],
            "google-client",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "saved_credentials", self.google_sub, nonce, ciphertext)
        nonce, ciphertext = encrypt_bytes(
            b'{"access_token":"access-token","refresh_token":"refresh-token"}',
            self.app.config["ENCRYPTION_KEY"],
            "google-tokens",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "oauth_tokens", self.google_sub, nonce, ciphertext)
        google_response = Mock(ok=True)
        with patch("app.requests.post", return_value=google_response) as revoke:
            response = self.client.post(
                "/auth/account/delete", data={"csrf_token": "known-csrf-token"}
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(revoke.call_args.kwargs["data"]["token"], "refresh-token")
        with closing(sqlite3.connect(self.database_path)) as connection:
            for table in ("users", "saved_credentials", "oauth_tokens"):
                self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)

    def test_missing_app_oauth_configuration_routes_to_setup(self) -> None:
        response = self.client.get("/auth/google")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/setup")
        setup_response = self.client.get("/setup")
        self.assertEqual(setup_response.status_code, 200)
        self.assertIn(b"One-time setup key", setup_response.data)


if __name__ == "__main__":
    unittest.main()
