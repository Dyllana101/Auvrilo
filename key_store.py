import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any


class KeyStoreError(RuntimeError):
    pass


def load_or_create_keys(
    key_file: str,
    secret_override: str = "",
    encryption_override: str = "",
) -> dict[str, Any]:
    path = Path(key_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    created = False

    if not path.exists():
        values = {
            "version": 1,
            "secret_key": secret_override or secrets.token_urlsafe(48),
            "encryption_key": encryption_override or secrets.token_urlsafe(48),
        }
        encoded = json.dumps(values, separators=(",", ":")).encode("utf-8")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            values = _read_keys(path)
        else:
            try:
                with os.fdopen(descriptor, "wb") as key_file_handle:
                    key_file_handle.write(encoded)
                    key_file_handle.flush()
                    os.fsync(key_file_handle.fileno())
                created = True
            except Exception:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
                raise
    else:
        values = _read_keys(path)

    secret_key = secret_override or values.get("secret_key", "")
    encryption_key = encryption_override or values.get("encryption_key", "")
    if len(secret_key) < 32 or len(encryption_key) < 32:
        raise KeyStoreError("Server keys must each be at least 32 characters")
    if secret_key == encryption_key:
        raise KeyStoreError("The session and encryption keys must be different")
    if os.name != "nt":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as error:
            raise KeyStoreError("Could not restrict permissions on the local key file") from error
    return {
        "secret_key": secret_key,
        "encryption_key": encryption_key,
        "path": str(path.resolve()),
        "created": created,
    }


def _read_keys(path: Path) -> dict[str, Any]:
    last_error: Exception | None = None
    for _ in range(20):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("version") != 1:
                raise KeyStoreError("The local key file has an unsupported format")
            return data
        except (OSError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(0.025)
    raise KeyStoreError(f"Could not read the local key file: {path}") from last_error
