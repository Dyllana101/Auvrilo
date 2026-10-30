import hashlib
import hmac
import json
import os
import re
import secrets
import time
from functools import wraps
from typing import Any, Callable, TypeVar, cast
from urllib.parse import urlsplit

import click
import requests
from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session
from dotenv import load_dotenv
from flask import Flask, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.wrappers import Response as WerkzeugResponse

from crypto_store import EncryptionKeyError, decrypt_bytes, encrypt_bytes
from google_tokens import ReconnectRequired, get_valid_access_token
from key_store import load_or_create_keys
from lookerstudio_api import LookerStudioAPIError, LookerStudioClient, normalize_report
from database import (
    connect,
    has_encrypted_records,
    delete_user,
    delete_user_records,
    get_admin_data,
    get_encrypted_record,
    get_installation_settings,
    get_user,
    has_saved_credentials,
    has_saved_tokens,
    initialize_database,
    save_encrypted_record,
    save_installation_settings,
    save_user,
)
from server_sessions import SQLiteSessionInterface, ServerSession

load_dotenv()

GOOGLE_METADATA_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
LOOKER_STUDIO_SCOPE = "https://www.googleapis.com/auth/datastudio"
DATA_SCOPES = f"openid https://www.googleapis.com/auth/userinfo.profile {LOOKER_STUDIO_SCOPE}"
F = TypeVar("F", bound=Callable[..., Any])


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("AUVRILO_SECRET_KEY", ""),
        ENCRYPTION_KEY=os.environ.get("AUVRILO_ENCRYPTION_KEY", ""),
        KEY_FILE_PATH=os.environ.get("AUVRILO_KEY_FILE", "instance/keys.json"),
        DATABASE_PATH=os.environ.get("AUVRILO_DATABASE_PATH", "instance/auvrilo.sqlite"),
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", ""),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        ADMIN_EMAIL=os.environ.get("AUVRILO_ADMIN_EMAIL", "").strip().lower(),
        SETUP_KEY=os.environ.get("AUVRILO_SETUP_KEY", ""),
        PUBLIC_BASE_URL=os.environ.get("AUVRILO_PUBLIC_BASE_URL", "http://localhost:5000"),
        SESSION_COOKIE_NAME="auvrilo_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=_env_bool("AUVRILO_COOKIE_SECURE"),
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=30 * 24 * 60 * 60,
        TRUSTED_HOSTS=[host.strip() for host in os.environ.get("AUVRILO_TRUSTED_HOSTS", "").split(",") if host.strip()] or None,
        MAX_CONTENT_LENGTH=32 * 1024,
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)

    key_file_path = str(app.config["KEY_FILE_PATH"])
    if (
        not app.config["ENCRYPTION_KEY"]
        and not os.path.exists(key_file_path)
        and has_encrypted_records(str(app.config["DATABASE_PATH"]))
    ):
        raise RuntimeError(
            "The local key file is missing while encrypted OAuth data exists. Restore the key file before starting Auvrilo."
        )
    if app.config["TESTING"] and app.config["SECRET_KEY"] and app.config["ENCRYPTION_KEY"]:
        key_material = {
            "secret_key": str(app.config["SECRET_KEY"]),
            "encryption_key": str(app.config["ENCRYPTION_KEY"]),
            "path": None,
        }
    else:
        key_material = load_or_create_keys(
            str(app.config["KEY_FILE_PATH"]),
            str(app.config["SECRET_KEY"]),
            str(app.config["ENCRYPTION_KEY"]),
        )
    app.config["SECRET_KEY"] = key_material["secret_key"]
    app.config["ENCRYPTION_KEY"] = key_material["encryption_key"]
    app.config["KEY_FILE_PATH"] = key_material["path"] or app.config["KEY_FILE_PATH"]

    database_path = str(app.config["DATABASE_PATH"])
    initialize_database(database_path)
    stored_settings = get_installation_settings(database_path)
    stored_identity = stored_settings.get("identity_google_client")
    if stored_identity and stored_identity.get("nonce") and stored_identity.get("ciphertext"):
        try:
            identity_config = json.loads(
                decrypt_bytes(
                    bytes(stored_identity["nonce"]),
                    bytes(stored_identity["ciphertext"]),
                    str(app.config["ENCRYPTION_KEY"]),
                    "installation-google-client",
                    "installation",
                )
            )
        except Exception as error:
            raise RuntimeError("Stored installation OAuth credentials could not be decrypted") from error
        app.config["GOOGLE_CLIENT_ID"] = str(stored_identity["value"] or "")
        app.config["GOOGLE_CLIENT_SECRET"] = str(identity_config["client_secret"])
    stored_admin = stored_settings.get("admin_email")
    if stored_admin and stored_admin.get("value"):
        app.config["ADMIN_EMAIL"] = str(stored_admin["value"]).strip().lower()
    app.config["INSTALLATION_CONFIGURED"] = bool(
        app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"] and app.config["ADMIN_EMAIL"]
    )
    if app.config["INSTALLATION_CONFIGURED"] and not os.environ.get("AUVRILO_SETUP_KEY"):
        app.config["SETUP_KEY"] = ""
    elif not app.config["INSTALLATION_CONFIGURED"] and not app.config["SETUP_KEY"]:
        app.config["SETUP_KEY"] = hmac.new(
            str(app.config["SECRET_KEY"]).encode("utf-8"),
            b"auvrilo-first-run-setup-v1",
            hashlib.sha256,
        ).hexdigest()

    if not app.config["TESTING"] and os.environ.get("AUVRILO_ENV", "development").lower() == "production":
        secret_key = str(app.config["SECRET_KEY"])
        encryption_key = str(app.config["ENCRYPTION_KEY"])
        if len(secret_key) < 32 or secret_key.startswith("replace-with"):
            raise RuntimeError("Set a unique AUVRILO_SECRET_KEY of at least 32 characters in production")
        if len(encryption_key) < 32 or encryption_key.startswith("replace-with"):
            raise RuntimeError("Set a unique AUVRILO_ENCRYPTION_KEY of at least 32 characters in production")
        if secret_key == encryption_key:
            raise RuntimeError("Use different values for AUVRILO_SECRET_KEY and AUVRILO_ENCRYPTION_KEY")
        if not app.config["INSTALLATION_CONFIGURED"] and (
            len(str(app.config["SETUP_KEY"])) < 32
            or str(app.config["SETUP_KEY"]).startswith("replace-with")
        ):
            raise RuntimeError("Could not create a secure first-run setup code; check the local key file")
        if app.config["INSTALLATION_CONFIGURED"] and not re.fullmatch(
            r"[^\s@]+@[^\s@]+\.[^\s@]+", str(app.config["ADMIN_EMAIL"])
        ):
            raise RuntimeError("Set a valid installation admin email in the setup wizard")
        if not str(app.config["PUBLIC_BASE_URL"]).startswith("https://"):
            raise RuntimeError("AUVRILO_PUBLIC_BASE_URL must use HTTPS in production")
        if not app.config["SESSION_COOKIE_SECURE"]:
            raise RuntimeError("Set AUVRILO_COOKIE_SECURE=true in production")
        if not app.config["TRUSTED_HOSTS"]:
            raise RuntimeError("Set AUVRILO_TRUSTED_HOSTS in production")

    app.session_interface = SQLiteSessionInterface(
        database_path,
        lifetime_seconds=int(app.config["PERMANENT_SESSION_LIFETIME"]),
    )

    oauth = OAuth()
    oauth.init_app(app)

    def register_identity_client(client_id: str, client_secret: str) -> None:
        nonlocal oauth
        oauth = OAuth()
        oauth.init_app(app)
        oauth.register(
            name="google",
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url=GOOGLE_METADATA_URL,
            client_kwargs={"scope": "openid email profile"},
        )
        app.extensions["google_identity_client"] = oauth.create_client("google")

    if app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"]:
        register_identity_client(str(app.config["GOOGLE_CLIENT_ID"]), str(app.config["GOOGLE_CLIENT_SECRET"]))

    @app.before_request
    def use_canonical_local_host() -> Any:
        if app.config["TESTING"]:
            return None
        public_url = urlsplit(str(app.config["PUBLIC_BASE_URL"]))
        canonical_host = (public_url.hostname or "").lower()
        request_host = (urlsplit(f"//{request.host}").hostname or "").lower()
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if public_url.scheme == "http" and canonical_host in local_hosts and request_host in local_hosts and request_host != canonical_host:
            path = request.full_path[:-1] if request.full_path.endswith("?") else request.full_path
            return redirect(f"{str(app.config['PUBLIC_BASE_URL']).rstrip('/')}{path}", code=307)
        return None

    @app.before_request
    def load_current_user() -> None:
        google_sub = session.get("google_sub")
        g.current_user = get_user(database_path, google_sub) if google_sub else None

    @app.after_request
    def set_security_headers(response: WerkzeugResponse) -> WerkzeugResponse:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
                        "font-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self' https://accounts.google.com",
        )
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.context_processor
    def inject_auth_context() -> dict[str, Any]:
        current_user = getattr(g, "current_user", None)
        return {
            "current_user": current_user,
            "callback_uri": external_url("data_callback"),
            "identity_callback_uri": external_url("auth_callback"),
            "csrf_token": csrf_token() if current_user else "",
            "is_admin": bool(current_user and app.config["ADMIN_EMAIL"] and current_user["email"].lower() == app.config["ADMIN_EMAIL"]),
            "installation_configured": bool(app.config["INSTALLATION_CONFIGURED"]),
        }

    def external_url(endpoint: str) -> str:
        return f"{app.config['PUBLIC_BASE_URL'].rstrip('/')}{url_for(endpoint)}"

    def csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def require_csrf() -> None:
        expected = session.get("csrf_token", "")
        submitted = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if not expected or not submitted or not hmac.compare_digest(expected.encode("utf-8"), submitted.encode("utf-8")):
            abort(400, description="The form expired. Reload the page and try again.")

    def require_login(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not session.get("google_sub") or not getattr(g, "current_user", None):
                session.clear()
                return redirect(url_for("auth_start"))
            return view(*args, **kwargs)

        return cast(F, wrapped)

    def message_page(title: str, message: str, status: int = 400) -> tuple[str, int]:
        return render_template("auth_message.html", title=title, message=message), status

    def get_credentials(google_sub: str) -> dict[str, str] | None:
        record = get_encrypted_record(database_path, "saved_credentials", google_sub)
        if record is None:
            return None
        nonce, ciphertext, _ = record
        plaintext = decrypt_bytes(
            nonce,
            ciphertext,
            str(app.config["ENCRYPTION_KEY"]),
            "google-client",
            google_sub,
        )
        result = json.loads(plaintext)
        return {"client_id": result["client_id"], "client_secret": result["client_secret"]}

    def get_stored_tokens(google_sub: str) -> dict[str, Any] | None:
        record = get_encrypted_record(database_path, "oauth_tokens", google_sub)
        if record is None:
            return None
        nonce, ciphertext, _ = record
        return json.loads(
            decrypt_bytes(nonce, ciphertext, str(app.config["ENCRYPTION_KEY"]), "google-tokens", google_sub)
        )

    def revoke_google_tokens(google_sub: str) -> None:
        try:
            stored_tokens = get_stored_tokens(google_sub)
            token = (stored_tokens or {}).get("refresh_token") or (stored_tokens or {}).get("access_token")
            if token:
                response = requests.post(
                    "https://oauth2.googleapis.com/revoke",
                    data={"token": token},
                    timeout=10,
                )
                if not response.ok:
                    current_app.logger.warning("Google token revocation was not confirmed")
        except Exception:
            current_app.logger.warning("Google token revocation failed during local data removal")

    @app.get("/")
    def index() -> str:
        return render_template("index.html")

    @app.route("/setup", methods=["GET", "POST"])
    def installation_setup() -> Any:
        configured = bool(app.config["INSTALLATION_CONFIGURED"])
        account = getattr(g, "current_user", None)
        admin_session = bool(
            configured
            and account
            and account["email"].lower() == str(app.config["ADMIN_EMAIL"]).lower()
        )
        if configured and account and not admin_session:
            abort(403, description="Only the configured installation admin can change setup.")
        setup_key = str(app.config["SETUP_KEY"])
        setup_key_required = not admin_session
        if setup_key_required and (len(setup_key) < 32 or setup_key.startswith("replace-with")):
            if configured:
                return redirect(url_for("auth_start"))
            return message_page(
                "First-run setup is locked",
                "Run `flask --app app setup-code` to get the generated code. If AUVRILO_SETUP_KEY is set as an override, use at least 32 characters.",
                503,
            )
        if request.method == "POST":
            require_csrf()
            if setup_key_required:
                submitted_key = request.form.get("setup_key", "")
                if not hmac.compare_digest(setup_key.encode("utf-8"), submitted_key.encode("utf-8")):
                    abort(403, description="The setup key is incorrect.")
            client_id = request.form.get("client_id", "").strip()
            client_secret = request.form.get("client_secret", "").strip()
            admin_email = request.form.get("admin_email", "").strip().lower()
            if not re.fullmatch(r"[A-Za-z0-9._-]{8,300}\.apps\.googleusercontent\.com", client_id):
                return render_template("installation_setup.html", **setup_context(error="Enter a valid Google OAuth client ID.", setup_key_required=setup_key_required, client_id=client_id, admin_email=admin_email)), 400
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", admin_email):
                return render_template("installation_setup.html", **setup_context(error="Enter a valid Workspace admin email address.", setup_key_required=setup_key_required, client_id=client_id, admin_email=admin_email)), 400
            if not client_secret and configured:
                try:
                    existing_secret = str(app.config["GOOGLE_CLIENT_SECRET"])
                    client_secret = existing_secret
                except Exception:
                    client_secret = ""
            if not 8 <= len(client_secret) <= 500:
                return render_template("installation_setup.html", **setup_context(error="Enter the client secret from your Google Cloud OAuth client.", setup_key_required=setup_key_required, client_id=client_id, admin_email=admin_email)), 400
            try:
                nonce, ciphertext = encrypt_bytes(
                    json.dumps({"client_secret": client_secret}).encode("utf-8"),
                    str(app.config["ENCRYPTION_KEY"]),
                    "installation-google-client",
                    "installation",
                )
                save_installation_settings(database_path, client_id, nonce, ciphertext, admin_email)
            except EncryptionKeyError as error:
                return render_template("installation_setup.html", **setup_context(error=str(error), setup_key_required=setup_key_required, client_id=client_id, admin_email=admin_email)), 503
            app.config["GOOGLE_CLIENT_ID"] = client_id
            app.config["GOOGLE_CLIENT_SECRET"] = client_secret
            app.config["ADMIN_EMAIL"] = admin_email
            app.config["INSTALLATION_CONFIGURED"] = True
            app.config["SETUP_KEY"] = ""
            register_identity_client(client_id, client_secret)
            return redirect(url_for("index"))
        return render_template("installation_setup.html", **setup_context(error=None, setup_key_required=setup_key_required))

    def setup_context(
        error: str | None,
        setup_key_required: bool,
        client_id: str | None = None,
        admin_email: str | None = None,
    ) -> dict[str, Any]:
        return {
            "csrf_token": csrf_token(),
            "setup_key_required": setup_key_required,
            "client_id": client_id if client_id is not None else str(app.config["GOOGLE_CLIENT_ID"]),
            "admin_email": admin_email if admin_email is not None else str(app.config["ADMIN_EMAIL"]),
            "error": error,
            "saved": request.args.get("saved") == "1",
        }

    @app.get("/api/workspace")
    def api_workspace() -> Any:
        account = getattr(g, "current_user", None)
        if not account:
            return jsonify(error="Sign in with Google to load your workspace."), 401
        google_sub = str(account["google_sub"])
        try:
            credentials_data = get_credentials(google_sub)
            if not credentials_data:
                return jsonify(error="Add your Google OAuth client to continue.", setup_url=url_for("credentials")), 409
            access_token = get_valid_access_token(
                database_path,
                str(app.config["ENCRYPTION_KEY"]),
                google_sub,
                credentials_data["client_id"],
                credentials_data["client_secret"],
            )
        except ReconnectRequired as error:
            return jsonify(error=str(error), reconnect_url=url_for("data_authorize")), 401
        except Exception:
            current_app.logger.exception("Could not prepare Google API authorization")
            return jsonify(error="Could not load your saved Google authorization."), 500

        try:
            workspace = LookerStudioClient(access_token).load_manageable_workspace(account["email"])
        except LookerStudioAPIError as error:
            status = error.status_code if error.status_code in {401, 403, 429} else 502
            payload: dict[str, Any] = {"error": str(error)}
            if status == 401:
                payload["reconnect_url"] = url_for("data_authorize")
            return jsonify(payload), status
        workspace["user"] = {"email": account["email"], "name": account["name"]}
        workspace["synced_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return jsonify(workspace)

    @app.post("/api/access")
    def api_access() -> Any:
        require_csrf()
        account = getattr(g, "current_user", None)
        if not account:
            return jsonify(error="Sign in with Google to change access."), 401
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="Send a valid JSON request."), 400
        action = payload.get("action")
        role_map = {"viewer": "VIEWER", "editor": "EDITOR"}
        role = role_map.get(str(payload.get("role", "")).lower())
        if action not in {"grant", "remove", "set_role"} or (action != "remove" and role is None):
            return jsonify(error="Choose a supported access action and role."), 400
        raw_emails = payload.get("emails")
        raw_report_ids = payload.get("report_ids")
        if not isinstance(raw_emails, list) or not isinstance(raw_report_ids, list):
            return jsonify(error="Select people and dashboards before continuing."), 400
        emails = list(dict.fromkeys(
            item.strip().lower()
            for item in raw_emails
            if isinstance(item, str) and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", item.strip())
        ))
        report_ids = list(dict.fromkeys(
            item for item in raw_report_ids if isinstance(item, str) and 0 < len(item) <= 512
        ))
        if not emails or not report_ids or len(emails) > 100 or len(report_ids) > 200:
            return jsonify(error="Select 1-100 valid email addresses and 1-200 dashboards."), 400
        if len(emails) * len(report_ids) > 500:
            return jsonify(error="A single request is limited to 500 potential access changes."), 400

        google_sub = str(account["google_sub"])
        try:
            credentials_data = get_credentials(google_sub)
            if not credentials_data:
                return jsonify(error="Add your Google OAuth client to continue.", setup_url=url_for("credentials")), 409
            access_token = get_valid_access_token(
                database_path,
                str(app.config["ENCRYPTION_KEY"]),
                google_sub,
                credentials_data["client_id"],
                credentials_data["client_secret"],
            )
            client = LookerStudioClient(access_token)
            reports: dict[str, dict[str, Any]] = {}
            report_errors: dict[str, str] = {}
            for report_id in report_ids:
                try:
                    permissions = client.get_permissions(report_id)
                except LookerStudioAPIError as error:
                    if error.status_code == 401:
                        raise
                    report_errors[report_id] = str(error)
                    continue
                report = normalize_report(
                    {"name": report_id, "title": report_id},
                    permissions,
                    str(account["email"]),
                )
                if report:
                    reports[report_id] = report
        except ReconnectRequired as error:
            return jsonify(error=str(error), reconnect_url=url_for("data_authorize")), 401
        except LookerStudioAPIError as error:
            status = error.status_code if error.status_code in {401, 403, 429} else 502
            return jsonify(error=str(error)), status
        except Exception:
            current_app.logger.exception("Could not prepare Google API mutation")
            return jsonify(error="Could not load the Google workspace."), 500

        report_titles = payload.get("report_titles", {})
        if not isinstance(report_titles, dict):
            report_titles = {}
        results: list[dict[str, Any]] = []
        for report_id in report_ids:
            report = reports.get(report_id)
            if report_id in report_errors:
                results.append({
                    "report_id": report_id,
                    "title": str(report_titles.get(report_id, report_id))[:200],
                    "succeeded": 0,
                    "failed": len(emails),
                    "message": report_errors[report_id],
                })
                continue
            if not report or not report["can_manage"]:
                results.append({
                    "report_id": report_id,
                    "title": str(report_titles.get(report_id, report["title"] if report else report_id))[:200],
                    "succeeded": 0,
                    "failed": len(emails),
                    "message": "This report is not manageable by your signed-in account.",
                })
                continue
            owner_emails = {
                member.get("email", "").lower()
                for member in report["members"]
                if member["role"] == "OWNER" and member["kind"] == "user"
            }
            if report.get("owner"):
                owner_emails.add(report["owner"].lower())
            protected = [email for email in emails if email in owner_emails]
            actionable = [email for email in emails if email not in owner_emails]
            succeeded = 0
            unchanged = 0
            failures: list[dict[str, str]] = []
            if action == "grant":
                members_by_email = {
                    member.get("email", "").lower(): member
                    for member in report["members"]
                    if member["kind"] == "user"
                }
                new_members: list[str] = []
                for email in actionable:
                    existing = members_by_email.get(email)
                    if existing and existing["role"] == role:
                        unchanged += 1
                    elif existing:
                        try:
                            client.set_member_role(report_id, f"user:{email}", str(role))
                            succeeded += 1
                        except (LookerStudioAPIError, ValueError) as error:
                            failures.append({"email": email, "message": str(error)})
                    else:
                        new_members.append(f"user:{email}")
                if new_members:
                    try:
                        client.add_members(report_id, str(role), new_members)
                        succeeded += len(new_members)
                    except LookerStudioAPIError as error:
                        failures.extend(
                            {"email": member.removeprefix("user:"), "message": str(error)}
                            for member in new_members
                        )
            elif action == "remove" and actionable:
                current_members = {
                    member.get("email", "").lower()
                    for member in report["members"]
                    if member["kind"] == "user" and member["role"] in {"EDITOR", "VIEWER"}
                }
                members_to_remove = [email for email in actionable if email in current_members]
                unchanged += len(actionable) - len(members_to_remove)
                if members_to_remove:
                    try:
                        client.revoke_members(report_id, [f"user:{email}" for email in members_to_remove])
                        succeeded = len(members_to_remove)
                    except LookerStudioAPIError as error:
                        failures.extend({"email": email, "message": str(error)} for email in members_to_remove)
            elif actionable:
                for email in actionable:
                    try:
                        client.set_member_role(report_id, f"user:{email}", str(role))
                        succeeded += 1
                    except (LookerStudioAPIError, ValueError) as error:
                        failures.append({"email": email, "message": str(error)})
            results.append({
                "report_id": report_id,
                "title": str(report_titles.get(report_id, report["title"]))[:200],
                "succeeded": succeeded,
                "unchanged": unchanged,
                "failed": len(failures) + len(protected),
                "owner_protected": protected,
                "failures": failures,
            })
        return jsonify({"results": results, "partial": any(item["failed"] for item in results)})

    @app.get("/admin")
    def admin() -> Any:
        account = getattr(g, "current_user", None)
        if not account:
            return redirect(url_for("auth_start"))
        admin_email = str(app.config["ADMIN_EMAIL"])
        if not admin_email:
            return message_page("Admin access is not configured", "Complete the installation setup and choose an admin email.", 503)
        if not hmac.compare_digest(account["email"].lower(), admin_email):
            abort(403, description="This Google account is not allowed to view the admin page.")
        return render_template("admin.html", admin_data=get_admin_data(database_path))

    @app.get("/auth/google")
    def auth_start() -> Any:
        client = app.extensions.get("google_identity_client")
        if client is None or not app.config["INSTALLATION_CONFIGURED"]:
            return redirect(url_for("installation_setup"))
        cast(SQLiteSessionInterface, app.session_interface).regenerate(cast(ServerSession, session._get_current_object()))
        callback_url = external_url("auth_callback")
        return client.authorize_redirect(callback_url, prompt="select_account")

    @app.get("/auth/callback")
    def auth_callback() -> Any:
        if request.args.get("error"):
            return message_page("Google sign-in was not completed", "Try again when you are ready.")
        client = app.extensions.get("google_identity_client")
        if client is None or not app.config["INSTALLATION_CONFIGURED"]:
            return redirect(url_for("installation_setup"))
        try:
            token = client.authorize_access_token()
            profile = token.get("userinfo") or client.userinfo(token=token)
        except MismatchingStateError:
            current_app.logger.warning("Google OAuth state mismatch; user should restart from the canonical Auvrilo URL")
            return message_page(
                "Sign-in expired or the site address changed",
                "Restart Google sign-in from the same Auvrilo URL shown in the setup wizard. For local testing, use http://localhost:5000 consistently.",
                400,
            )
        except Exception:
            current_app.logger.exception("Google identity authorization failed")
            return message_page("Google sign-in failed", "Check the OAuth setup and try again.", 502)

        google_sub = str(profile.get("sub", ""))
        email = str(profile.get("email", ""))
        if not google_sub or not email or profile.get("email_verified") is False:
            return message_page("Google account could not be verified", "Use a Google account with a verified email address.")

        save_user(database_path, google_sub, email, str(profile.get("name", "")))
        cast(SQLiteSessionInterface, app.session_interface).regenerate(cast(ServerSession, session._get_current_object()))
        session["google_sub"] = google_sub
        session["csrf_token"] = secrets.token_urlsafe(32)

        try:
            credentials_exist = has_saved_credentials(database_path, google_sub)
            tokens_exist = has_saved_tokens(database_path, google_sub)
        except Exception:
            current_app.logger.exception("Could not check saved Google authorization")
            return message_page("Auvrilo could not load your saved connection", "Try again or contact the workspace administrator.", 500)
        if not credentials_exist:
            return redirect(url_for("credentials"))
        if not tokens_exist:
            return redirect(url_for("data_authorize"))
        return redirect(url_for("index"))

    @app.route("/auth/credentials", methods=["GET", "POST"])
    @require_login
    def credentials() -> Any:
        google_sub = str(session["google_sub"])
        if request.method == "POST":
            require_csrf()
            client_id = request.form.get("client_id", "").strip()
            client_secret = request.form.get("client_secret", "").strip()
            if not re.fullmatch(r"[A-Za-z0-9._-]{8,300}\.apps\.googleusercontent\.com", client_id):
                return render_template("credentials.html", csrf_token=csrf_token(), error="That does not look like a Google OAuth client ID."), 400
            if not 8 <= len(client_secret) <= 500:
                return render_template("credentials.html", csrf_token=csrf_token(), error="Enter the client secret from your Google Cloud OAuth client."), 400
            try:
                plaintext = json.dumps({"client_id": client_id, "client_secret": client_secret}).encode("utf-8")
                nonce, ciphertext = encrypt_bytes(
                    plaintext,
                    str(app.config["ENCRYPTION_KEY"]),
                    "google-client",
                    google_sub,
                )
                save_encrypted_record(database_path, "saved_credentials", google_sub, nonce, ciphertext)
                with connect(database_path) as connection:
                    connection.execute("DELETE FROM oauth_tokens WHERE google_sub = ?", (google_sub,))
            except EncryptionKeyError as error:
                return render_template("credentials.html", csrf_token=csrf_token(), error=str(error)), 503
            return redirect(url_for("data_authorize"))
        return render_template(
            "credentials.html",
            csrf_token=csrf_token(),
            error=None,
            has_credentials=has_saved_credentials(database_path, google_sub),
            has_tokens=has_saved_tokens(database_path, google_sub),
            user=get_user(database_path, google_sub),
        )

    @app.get("/auth/data/start")
    @require_login
    def data_authorize() -> Any:
        google_sub = str(session["google_sub"])
        try:
            credentials_data = get_credentials(google_sub)
        except Exception:
            current_app.logger.exception("Could not decrypt saved Google OAuth credentials")
            return message_page("Saved credentials could not be opened", "Check that AUVRILO_ENCRYPTION_KEY matches the key used when they were saved.", 500)
        if not credentials_data:
            return redirect(url_for("credentials"))
        account = get_user(database_path, google_sub)
        if account is None:
            return redirect(url_for("auth_start"))
        callback_url = external_url("data_callback")
        oauth_session = OAuth2Session(
            credentials_data["client_id"],
            credentials_data["client_secret"],
            token_endpoint_auth_method="client_secret_post",
            scope=DATA_SCOPES,
            redirect_uri=callback_url,
        )
        authorization_url, state = oauth_session.create_authorization_url(
            GOOGLE_AUTHORIZATION_URL,
            access_type="offline",
            include_granted_scopes="true",
            login_hint=account["email"],
            prompt="consent",
        )
        session["data_oauth_state"] = state
        return redirect(authorization_url)

    @app.get("/auth/data/callback")
    @require_login
    def data_callback() -> Any:
        expected_state = session.pop("data_oauth_state", None)
        received_state = request.args.get("state", "")
        if not expected_state or not received_state or not hmac.compare_digest(expected_state.encode("utf-8"), received_state.encode("utf-8")):
            abort(400, description="OAuth state verification failed. Restart the connection flow.")
        if request.args.get("error"):
            error_code = request.args.get("error", "")
            if error_code in {"invalid_scope", "unauthorized_client"}:
                return message_page(
                    "Google did not authorize this client or scope",
                    "Verify that the Data Studio API is enabled and the OAuth client requests the required scopes. Workspace organizations may also require administrator authorization.",
                    403,
                )
            return message_page("Looker Studio access was not approved", "You can reconnect from your Google account settings.")
        google_sub = str(session["google_sub"])
        credentials_data = get_credentials(google_sub)
        if not credentials_data:
            return redirect(url_for("credentials"))
        callback_url = external_url("data_callback")
        oauth_session = OAuth2Session(
            credentials_data["client_id"],
            credentials_data["client_secret"],
            token_endpoint_auth_method="client_secret_post",
            scope=DATA_SCOPES,
            redirect_uri=callback_url,
        )
        response_url = f"{callback_url}?{request.query_string.decode('utf-8')}"
        try:
            token = oauth_session.fetch_token(
                GOOGLE_TOKEN_URL,
                authorization_response=response_url,
                state=expected_state,
            )
            granted_scopes = token.get("scope")
            if granted_scopes and LOOKER_STUDIO_SCOPE not in granted_scopes.split():
                return message_page("Looker Studio permission was not granted", "Reconnect and approve the Looker Studio access scope.")
            identity_response = requests.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {token['access_token']}"},
                timeout=10,
            )
            identity_response.raise_for_status()
            data_profile = identity_response.json()
            if str(data_profile.get("sub", "")) != google_sub:
                return message_page(
                    "Choose the same Google account",
                    "The account used for Looker Studio access must match the account you signed in with.",
                    403,
                )
            previous_tokens = get_stored_tokens(google_sub) or {}
            if not token.get("refresh_token") and previous_tokens.get("refresh_token"):
                token["refresh_token"] = previous_tokens["refresh_token"]
            nonce, ciphertext = encrypt_bytes(
                json.dumps(token).encode("utf-8"),
                str(app.config["ENCRYPTION_KEY"]),
                "google-tokens",
                google_sub,
            )
            expires_at = int(token["expires_at"]) if token.get("expires_at") else int(time.time()) + int(token.get("expires_in", 3600))
            save_encrypted_record(database_path, "oauth_tokens", google_sub, nonce, ciphertext, expires_at)
        except Exception:
            current_app.logger.exception("Google Looker Studio authorization failed")
            return message_page("Could not finish the Google connection", "Check the OAuth client configuration and try again.", 502)
        return redirect(url_for("index"))

    @app.post("/auth/credentials/forget")
    @require_login
    def forget_credentials() -> Any:
        require_csrf()
        google_sub = str(session["google_sub"])
        revoke_google_tokens(google_sub)
        delete_user_records(database_path, google_sub)
        return redirect(url_for("credentials"))

    @app.post("/auth/account/delete")
    @require_login
    def delete_account() -> Any:
        require_csrf()
        google_sub = str(session["google_sub"])
        revoke_google_tokens(google_sub)
        delete_user(database_path, google_sub)
        cast(SQLiteSessionInterface, app.session_interface).regenerate(cast(ServerSession, session._get_current_object()))
        return redirect(url_for("index"))

    @app.get("/privacy")
    def privacy() -> str:
        return render_template("privacy.html", admin_email=app.config["ADMIN_EMAIL"])

    @app.post("/auth/logout")
    @require_login
    def logout() -> Any:
        require_csrf()
        cast(SQLiteSessionInterface, app.session_interface).regenerate(cast(ServerSession, session._get_current_object()))
        return redirect(url_for("index"))

    @app.errorhandler(400)
    def bad_request(error: Any) -> tuple[str, int]:
        description = getattr(error, "description", "The request could not be completed.")
        return message_page("That request could not be completed", str(description), 400)

    @app.errorhandler(403)
    def forbidden(error: Any) -> tuple[str, int]:
        description = getattr(error, "description", "This account is not allowed to access this page.")
        return message_page("Access is restricted", str(description), 403)

    @app.cli.command("setup-code")
    def show_setup_code() -> None:
        if app.config["INSTALLATION_CONFIGURED"]:
            raise click.ClickException("Auvrilo is already configured; sign in as the installation admin to change settings.")
        if len(str(app.config["SETUP_KEY"])) < 32:
            raise click.ClickException("No setup code is available. Set AUVRILO_SETUP_KEY or check the local key file.")
        click.echo(str(app.config["SETUP_KEY"]))

    return app


app = create_app()

if __name__ == "__main__":
    app.run()
