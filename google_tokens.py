import json
import time
from typing import Any

from authlib.integrations.requests_client import OAuth2Session

from crypto_store import decrypt_bytes, encrypt_bytes
from database import get_encrypted_record, save_encrypted_record

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
REFRESH_MARGIN_SECONDS = 90


class ReconnectRequired(RuntimeError):
    pass


def get_valid_access_token(
    database_path: str,
    encryption_key: str,
    google_sub: str,
    client_id: str,
    client_secret: str,
    refresh_margin: int = REFRESH_MARGIN_SECONDS,
) -> str:
    record = get_encrypted_record(database_path, "oauth_tokens", google_sub)
    if record is None:
        raise ReconnectRequired("Connect Google to continue.")
    nonce, ciphertext, stored_expiration = record
    try:
        token = json.loads(
            decrypt_bytes(nonce, ciphertext, encryption_key, "google-tokens", google_sub)
        )
    except Exception as error:
        raise ReconnectRequired("Saved Google authorization could not be opened.") from error

    access_token = token.get("access_token")
    expires_at = int(stored_expiration or token.get("expires_at", 0))
    if access_token and expires_at > int(time.time()) + refresh_margin:
        return str(access_token)

    refresh_token = token.get("refresh_token")
    if not refresh_token:
        raise ReconnectRequired("Reconnect Google to renew your access.")

    oauth_session = OAuth2Session(
        client_id,
        client_secret,
        token_endpoint_auth_method="client_secret_post",
        scope=token.get("scope"),
        token=token,
    )
    try:
        refreshed: dict[str, Any] = oauth_session.refresh_token(
            GOOGLE_TOKEN_URL,
            refresh_token=str(refresh_token),
        )
    except Exception as error:
        raise ReconnectRequired("Google authorization needs to be renewed. Reconnect your account.") from error

    if not refreshed.get("access_token"):
        raise ReconnectRequired("Google did not return a renewed access token. Reconnect your account.")
    refreshed.setdefault("refresh_token", refresh_token)
    if not refreshed.get("scope") and token.get("scope"):
        refreshed["scope"] = token["scope"]
    refreshed_expiration = int(refreshed["expires_at"]) if refreshed.get("expires_at") else int(time.time()) + int(refreshed.get("expires_in", 3600))
    nonce, ciphertext = encrypt_bytes(
        json.dumps(refreshed).encode("utf-8"),
        encryption_key,
        "google-tokens",
        google_sub,
    )
    save_encrypted_record(
        database_path,
        "oauth_tokens",
        google_sub,
        nonce,
        ciphertext,
        refreshed_expiration,
    )
    return str(refreshed["access_token"])
