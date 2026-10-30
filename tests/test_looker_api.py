import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

from app import create_app
from crypto_store import decrypt_bytes, encrypt_bytes
from database import save_encrypted_record, save_user
from google_tokens import get_valid_access_token
from lookerstudio_api import LookerStudioAPIError, LookerStudioClient, normalize_report


class LookerStudioApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temp_dir.name) / "test.sqlite")
        self.google_sub = "workspace-user-123"
        self.encryption_key = "test-encryption-key-that-is-long-enough"
        from database import initialize_database

        initialize_database(self.database_path)
        save_user(self.database_path, self.google_sub, "owner@example.com", "Report Owner")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_search_reports_paginates_and_caps_results(self) -> None:
        first_page = Mock()
        first_page.ok = True
        first_page.json.return_value = {
            "assets": [{"name": "report-a"}],
            "nextPageToken": "next-page",
        }
        second_page = Mock()
        second_page.ok = True
        second_page.json.return_value = {"assets": [{"name": "report-b"}, {"name": "report-c"}]}
        with patch("lookerstudio_api.requests.get", side_effect=[first_page, second_page]) as get:
            assets = LookerStudioClient("private-token").search_reports(limit=2)
        self.assertEqual([asset["name"] for asset in assets], ["report-a", "report-b"])
        self.assertEqual(get.call_count, 2)
        self.assertEqual(get.call_args_list[0].kwargs["params"]["assetTypes"], "REPORT")
        self.assertEqual(get.call_args_list[1].kwargs["params"]["pageToken"], "next-page")
        self.assertNotIn("private-token", get.call_args_list[0].args[0])
        self.assertIn("Bearer private-token", get.call_args_list[0].kwargs["headers"]["Authorization"])

    def test_search_api_error_is_sanitized(self) -> None:
        response = Mock()
        response.ok = False
        response.status_code = 403
        with patch("lookerstudio_api.requests.get", return_value=response):
            with self.assertRaises(LookerStudioAPIError) as error:
                LookerStudioClient("private-token").search_reports()
        self.assertEqual(error.exception.status_code, 403)
        self.assertIn("Google denied this request", str(error.exception))
        self.assertNotIn("private-token", str(error.exception))

    def test_add_members_uses_official_endpoint_and_never_includes_owner_role(self) -> None:
        response = Mock()
        response.ok = True
        response.status_code = 200
        response.content = b"{}"
        response.json.return_value = {}
        with patch("lookerstudio_api.requests.request", return_value=response) as send:
            LookerStudioClient("private-token").add_members(
                "report-id", "EDITOR", ["user:editor@example.com"]
            )
        self.assertEqual(send.call_args.args[0], "POST")
        self.assertTrue(send.call_args.args[1].endswith("/assets/report-id/permissions:addMembers"))
        self.assertEqual(
            send.call_args.kwargs["json"],
            {"role": "EDITOR", "members": ["user:editor@example.com"]},
        )

    def test_role_change_revokes_and_readds_only_the_selected_member(self) -> None:
        client = LookerStudioClient("private-token")
        with patch.object(
            client,
            "get_permissions",
            return_value={"permissions": {"VIEWER": {"members": ["user:viewer@example.com"]}}},
        ), patch.object(client, "revoke_members") as revoke, patch.object(
            client, "add_members", return_value={"etag": "new-etag"}
        ) as add:
            result = client.set_member_role("report-id", "user:viewer@example.com", "EDITOR")
        revoke.assert_called_once_with("report-id", ["user:viewer@example.com"])
        add.assert_called_once_with("report-id", "EDITOR", ["user:viewer@example.com"])
        self.assertEqual(result["etag"], "new-etag")

    def test_role_change_refuses_to_change_an_owner(self) -> None:
        client = LookerStudioClient("private-token")
        with patch.object(
            client,
            "get_permissions",
            return_value={"permissions": {"OWNER": {"members": ["user:owner@example.com"]}}},
        ), patch.object(client, "revoke_members") as revoke:
            with self.assertRaisesRegex(ValueError, "Owners cannot be changed"):
                client.set_member_role("report-id", "user:owner@example.com", "VIEWER")
        revoke.assert_not_called()

    def test_normalization_preserves_owner_and_all_member_types(self) -> None:
        report = normalize_report(
            {"name": "report-id", "title": "Pipeline", "owner": "owner@example.com"},
            {
                "etag": "etag-1",
                "permissions": {
                    "OWNER": {"members": ["user:owner@example.com"]},
                    "EDITOR": {"members": ["user:editor@example.com", "group:team@example.com"]},
                    "VIEWER": {"members": ["user:viewer@example.com", "allUsers"]},
                },
            },
            "owner@example.com",
        )
        self.assertIsNotNone(report)
        self.assertTrue(report["is_owner"])
        self.assertTrue(report["can_manage"])
        self.assertEqual(report["etag"], "etag-1")
        self.assertEqual({member["kind"] for member in report["members"]}, {"user", "group", "link"})
        viewer_report = normalize_report(
            {"name": "other-report", "title": "Read only"},
            {"permissions": {"VIEWER": {"members": ["user:owner@example.com"]}}},
            "owner@example.com",
        )
        self.assertFalse(viewer_report["can_manage"])

    def test_expired_token_is_refreshed_and_reencrypted(self) -> None:
        nonce, ciphertext = encrypt_bytes(
            json.dumps({
                "access_token": "expired-access-token",
                "refresh_token": "refresh-token-private",
                "scope": "https://www.googleapis.com/auth/datastudio",
            }).encode(),
            self.encryption_key,
            "google-tokens",
            self.google_sub,
        )
        save_encrypted_record(
            self.database_path, "oauth_tokens", self.google_sub, nonce, ciphertext, int(time.time()) - 1
        )
        refreshed_token = {
            "access_token": "fresh-access-token",
            "expires_in": 3600,
            "expires_at": int(time.time()) + 3600,
        }
        with patch("google_tokens.OAuth2Session.refresh_token", return_value=refreshed_token) as refresh:
            token = get_valid_access_token(
                self.database_path,
                self.encryption_key,
                self.google_sub,
                "client-id",
                "client-secret",
            )
        self.assertEqual(token, "fresh-access-token")
        self.assertEqual(refresh.call_args.args[0], "https://oauth2.googleapis.com/token")
        with closing(sqlite3.connect(self.database_path)) as connection:
            stored = connection.execute(
                "SELECT nonce, ciphertext, expires_at FROM oauth_tokens WHERE google_sub = ?",
                (self.google_sub,),
            ).fetchone()
        self.assertNotIn(b"fresh-access-token", stored[1])
        decoded = decrypt_bytes(
            stored[0], stored[1], self.encryption_key, "google-tokens", self.google_sub
        )
        self.assertIn(b"refresh-token-private", decoded)
        self.assertGreater(stored[2], int(time.time()))

    def test_unexpired_token_does_not_call_refresh(self) -> None:
        nonce, ciphertext = encrypt_bytes(
            json.dumps({"access_token": "still-valid", "refresh_token": "refresh"}).encode(),
            self.encryption_key,
            "google-tokens",
            self.google_sub,
        )
        save_encrypted_record(
            self.database_path, "oauth_tokens", self.google_sub, nonce, ciphertext, int(time.time()) + 3600
        )
        with patch("google_tokens.OAuth2Session.refresh_token") as refresh:
            token = get_valid_access_token(
                self.database_path,
                self.encryption_key,
                self.google_sub,
                "client-id",
                "client-secret",
            )
        self.assertEqual(token, "still-valid")
        refresh.assert_not_called()

    def test_workspace_endpoint_reports_missing_oauth_credentials(self) -> None:
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
            }
        )
        client = app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["google_sub"] = self.google_sub
        response = client.get("/api/workspace")
        self.assertEqual(response.status_code, 409)
        self.assertIn("setup_url", response.get_json())

    def test_workspace_endpoint_returns_read_only_workspace_data(self) -> None:
        nonce, ciphertext = encrypt_bytes(
            json.dumps({"client_id": "client-id", "client_secret": "client-secret"}).encode(),
            self.encryption_key,
            "google-client",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "saved_credentials", self.google_sub, nonce, ciphertext)
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
            }
        )
        client = app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["google_sub"] = self.google_sub
        api_client = Mock()
        api_client.load_manageable_workspace.return_value = {
            "reports": [{"id": "report-1", "title": "Quarterly results"}],
            "people": [],
            "errors": [],
            "stats": {"dashboards": 1, "people": 0, "grants": 0},
        }
        with patch("app.get_valid_access_token", return_value="access-token"), patch(
            "app.LookerStudioClient", return_value=api_client
        ):
            response = client.get("/api/workspace")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["reports"][0]["title"], "Quarterly results")
        self.assertEqual(response.get_json()["user"]["email"], "owner@example.com")
        api_client.load_manageable_workspace.assert_called_once_with("owner@example.com")

    def test_api_access_protects_owners_and_reports_per_dashboard_results(self) -> None:
        nonce, ciphertext = encrypt_bytes(
            json.dumps({"client_id": "client-id", "client_secret": "client-secret"}).encode(),
            self.encryption_key,
            "google-client",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "saved_credentials", self.google_sub, nonce, ciphertext)
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
            }
        )
        client = app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["google_sub"] = self.google_sub
            flask_session["csrf_token"] = "csrf-value"
        api_client = Mock()
        api_client.get_permissions.return_value = {
            "permissions": {"OWNER": {"members": ["user:owner@example.com"]}}
        }
        with patch("app.get_valid_access_token", return_value="access-token"), patch(
            "app.LookerStudioClient", return_value=api_client
        ):
            response = client.post(
                "/api/access",
                headers={"X-CSRF-Token": "csrf-value"},
                json={
                    "action": "grant",
                    "role": "editor",
                    "emails": ["owner@example.com", "new-editor@example.com"],
                    "report_ids": ["report-1"],
                },
            )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result["partial"])
        self.assertEqual(result["results"][0]["owner_protected"], ["owner@example.com"])
        self.assertEqual(result["results"][0]["succeeded"], 1)
        api_client.add_members.assert_called_once_with(
            "report-1", "EDITOR", ["user:new-editor@example.com"]
        )

    def test_remove_of_nonmember_is_reported_as_unchanged(self) -> None:
        nonce, ciphertext = encrypt_bytes(
            json.dumps({"client_id": "client-id", "client_secret": "client-secret"}).encode(),
            self.encryption_key,
            "google-client",
            self.google_sub,
        )
        save_encrypted_record(self.database_path, "saved_credentials", self.google_sub, nonce, ciphertext)
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
            }
        )
        client = app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["google_sub"] = self.google_sub
            flask_session["csrf_token"] = "csrf-value"
        api_client = Mock()
        api_client.get_permissions.return_value = {
            "permissions": {"OWNER": {"members": ["user:owner@example.com"]}}
        }
        with patch("app.get_valid_access_token", return_value="access-token"), patch(
            "app.LookerStudioClient", return_value=api_client
        ):
            response = client.post(
                "/api/access",
                headers={"X-CSRF-Token": "csrf-value"},
                json={
                    "action": "remove",
                    "emails": ["viewer@example.com"],
                    "report_ids": ["report-1"],
                    "report_titles": {"report-1": "Quarterly results"},
                },
            )
        result = response.get_json()["results"][0]
        self.assertEqual(result["title"], "Quarterly results")
        self.assertEqual(result["unchanged"], 1)
        self.assertEqual(result["succeeded"], 0)
        api_client.revoke_members.assert_not_called()

    def test_admin_view_requires_configured_admin_identity(self) -> None:
        save_user(self.database_path, "admin-sub", "admin@example.com", "Installation Admin")
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
                "ADMIN_EMAIL": "admin@example.com",
            }
        )
        client = app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["google_sub"] = "admin-sub"
        response = client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Installation Admin", response.data)
        self.assertIn(b"Sign-ins recorded", response.data)

    def test_admin_view_rejects_other_signed_in_users(self) -> None:
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
                "ADMIN_EMAIL": "admin@example.com",
            }
        )
        client = app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["google_sub"] = self.google_sub
        self.assertEqual(client.get("/admin").status_code, 403)

    def test_workspace_endpoint_needs_a_signed_in_user(self) -> None:
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-that-is-long-enough",
                "ENCRYPTION_KEY": self.encryption_key,
                "DATABASE_PATH": self.database_path,
                "PUBLIC_BASE_URL": "http://localhost:5000",
            }
        )
        response = app.test_client().get("/api/workspace")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Sign in with Google", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
