import json
import os
import re
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app import create_app
from crypto_store import decrypt_bytes
from database import get_installation_settings, initialize_database, save_encrypted_record, save_user


class InstallationSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temp_dir.name) / "setup.sqlite")
        self.encryption_key = "test-encryption-key-that-is-long-enough"
        self.setup_key = "temporary-setup-key-value-for-tests-123456"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "SETUP_KEY": self.setup_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_server_keys_are_generated_once_and_setup_code_is_available_by_cli(self) -> None:
        key_path = str(Path(self.temp_dir.name) / "private" / "keys.json")
        environment = {
            "AUVRILO_SECRET_KEY": "",
            "AUVRILO_ENCRYPTION_KEY": "",
            "AUVRILO_SETUP_KEY": "",
            "GOOGLE_CLIENT_ID": "",
            "GOOGLE_CLIENT_SECRET": "",
            "AUVRILO_ADMIN_EMAIL": "",
        }
        with patch.dict(os.environ, environment):
            first_app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": self.database_path,
                    "KEY_FILE_PATH": key_path,
                    "PUBLIC_BASE_URL": "http://localhost:5000",
                }
            )
            first_code = first_app.test_cli_runner().invoke(args=["setup-code"])
            second_app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": self.database_path,
                    "KEY_FILE_PATH": key_path,
                    "PUBLIC_BASE_URL": "http://localhost:5000",
                }
            )
        self.assertEqual(first_code.exit_code, 0)
        self.assertEqual(first_code.output.strip(), first_app.config["SETUP_KEY"])
        self.assertEqual(first_app.config["SECRET_KEY"], second_app.config["SECRET_KEY"])
        self.assertEqual(first_app.config["ENCRYPTION_KEY"], second_app.config["ENCRYPTION_KEY"])
        stored_keys = json.loads(Path(key_path).read_text(encoding="utf-8"))
        self.assertNotIn("setup_key", stored_keys)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode) & 0o077, 0)

    def test_local_alias_redirects_to_canonical_oauth_host(self) -> None:
        app = create_app(
            {
                "TESTING": False,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": "test-encryption-key-that-is-long-enough",
                "DATABASE_PATH": str(Path(self.temp_dir.name) / "canonical.sqlite"),
                "KEY_FILE_PATH": str(Path(self.temp_dir.name) / "canonical-keys.json"),
                "PUBLIC_BASE_URL": "http://localhost:5000",
            }
        )
        response = app.test_client().get("/", base_url="http://127.0.0.1:5000")
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["Location"], "http://localhost:5000/")

    def test_database_initialization_drops_legacy_feedback_data(self) -> None:
        initialize_database(self.database_path)
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "CREATE TABLE feedback (id INTEGER PRIMARY KEY, message TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO feedback (message) VALUES ('old message')")
            connection.commit()
        initialize_database(self.database_path)
        with closing(sqlite3.connect(self.database_path)) as connection:
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'feedback'"
            ).fetchone()
        self.assertIsNone(table)

    def test_missing_key_file_fails_closed_when_encrypted_data_exists(self) -> None:
        initialize_database(self.database_path)
        save_user(self.database_path, "saved-user", "user@example.com", "Saved User")
        save_encrypted_record(
            self.database_path,
            "saved_credentials",
            "saved-user",
            b"n" * 12,
            b"encrypted-client-ciphertext",
        )
        missing_key_path = str(Path(self.temp_dir.name) / "missing-keys.json")
        with patch.dict(
            os.environ,
            {"AUVRILO_SECRET_KEY": "", "AUVRILO_ENCRYPTION_KEY": "", "AUVRILO_KEY_FILE": ""},
        ):
            with self.assertRaisesRegex(RuntimeError, "Restore the key file"):
                create_app(
                    {
                        "TESTING": True,
                        "SECRET_KEY": "",
                        "ENCRYPTION_KEY": "",
                        "DATABASE_PATH": self.database_path,
                        "KEY_FILE_PATH": missing_key_path,
                    }
                )

    def test_local_keys_are_generated_persisted_and_setup_code_is_printed_by_cli(self) -> None:
        key_path = str(Path(self.temp_dir.name) / "private" / "keys.json")
        environment = {
            "AUVRILO_SECRET_KEY": "",
            "AUVRILO_ENCRYPTION_KEY": "",
            "AUVRILO_SETUP_KEY": "",
            "GOOGLE_CLIENT_ID": "",
            "GOOGLE_CLIENT_SECRET": "",
            "AUVRILO_ADMIN_EMAIL": "",
        }
        with patch.dict(os.environ, environment):
            first_app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": self.database_path,
                    "KEY_FILE_PATH": key_path,
                    "PUBLIC_BASE_URL": "http://localhost:5000",
                }
            )
            first_code = first_app.test_cli_runner().invoke(args=["setup-code"])
            second_app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": self.database_path,
                    "KEY_FILE_PATH": key_path,
                    "PUBLIC_BASE_URL": "http://localhost:5000",
                }
            )
        self.assertEqual(first_code.exit_code, 0)
        self.assertEqual(first_code.output.strip(), first_app.config["SETUP_KEY"])
        self.assertEqual(first_app.config["SECRET_KEY"], second_app.config["SECRET_KEY"])
        self.assertEqual(first_app.config["ENCRYPTION_KEY"], second_app.config["ENCRYPTION_KEY"])
        stored_keys = json.loads(Path(key_path).read_text(encoding="utf-8"))
        self.assertNotIn("setup_key", stored_keys)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode) & 0o077, 0)

    def test_setup_page_saves_oauth_secret_encrypted_and_sets_admin(self) -> None:
        response = self.client.get("/setup")
        self.assertEqual(response.status_code, 200)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(csrf)
        client_id = "123456789012-example.apps.googleusercontent.com"
        client_secret = "installation-client-secret-private"
        response = self.client.post(
            "/setup",
            data={
                "csrf_token": csrf.group(1).decode(),
                "setup_key": self.setup_key,
                "client_id": client_id,
                "client_secret": client_secret,
                "admin_email": "admin@example.com",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        self.assertNotIn(client_secret.encode(), response.data)
        self.assertEqual(self.app.config["SETUP_KEY"], "")
        self.assertTrue(self.app.config["INSTALLATION_CONFIGURED"])
        self.assertEqual(self.app.config["ADMIN_EMAIL"], "admin@example.com")
        self.assertIsNotNone(self.app.extensions.get("google_identity_client"))
        settings = get_installation_settings(self.database_path)
        self.assertEqual(set(settings), {"identity_google_client", "admin_email"})
        client_setting = settings["identity_google_client"]
        self.assertEqual(client_setting["value"], client_id)
        self.assertNotIn(client_secret.encode(), client_setting["ciphertext"])
        decrypted = decrypt_bytes(
            bytes(client_setting["nonce"]),
            bytes(client_setting["ciphertext"]),
            self.encryption_key,
            "installation-google-client",
            "installation",
        )
        self.assertIn(client_secret, decrypted.decode())
        self.assertEqual(settings["admin_email"]["value"], "admin@example.com")
        self.assertNotIn(self.setup_key.encode(), client_setting["ciphertext"])

        save_user(self.database_path, "admin-sub", "admin@example.com", "Installation Admin")
        with self.client.session_transaction() as flask_session:
            flask_session["google_sub"] = "admin-sub"
            flask_session["csrf_token"] = "admin-csrf"
        settings_response = self.client.get("/setup")
        self.assertEqual(settings_response.status_code, 200)
        self.assertNotIn(b'name="setup_key"', settings_response.data)
        self.assertNotIn(client_secret.encode(), settings_response.data)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', settings_response.data)
        response = self.client.post(
            "/setup",
            data={
                "csrf_token": csrf.group(1).decode(),
                "client_id": "987654321098-another.apps.googleusercontent.com",
                "client_secret": "",
                "admin_email": "admin@example.com",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.app.config["GOOGLE_CLIENT_SECRET"], client_secret)

    def test_setup_rejects_incorrect_one_time_key(self) -> None:
        response = self.client.get("/setup")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        response = self.client.post(
            "/setup",
            data={
                "csrf_token": csrf.group(1).decode(),
                "setup_key": "wrong-setup-key",
                "client_id": "123456789012-example.apps.googleusercontent.com",
                "client_secret": "client-secret-private",
                "admin_email": "admin@example.com",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.app.config["INSTALLATION_CONFIGURED"])
        self.assertEqual(get_installation_settings(self.database_path), {})


if __name__ == "__main__":
    unittest.main()
