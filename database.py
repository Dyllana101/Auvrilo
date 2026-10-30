import sqlite3
from pathlib import Path
from typing import Any

class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    google_sub TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    visit_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS saved_credentials (
    google_sub TEXT PRIMARY KEY REFERENCES users(google_sub) ON DELETE CASCADE,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
    google_sub TEXT PRIMARY KEY REFERENCES users(google_sub) ON DELETE CASCADE,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    expires_at INTEGER,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS server_sessions (
    session_hash TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS installation_settings (
    setting_key TEXT PRIMARY KEY,
    value TEXT,
    nonce BLOB,
    ciphertext BLOB,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def connect(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, timeout=10, factory=ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def has_encrypted_records(database_path: str) -> bool:
    if database_path == ":memory:" or not Path(database_path).is_file():
        return False
    with connect(database_path) as connection:
        tables = {
            row["name"]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        checks = {
            "saved_credentials": "SELECT 1 FROM saved_credentials LIMIT 1",
            "oauth_tokens": "SELECT 1 FROM oauth_tokens LIMIT 1",
            "installation_settings": "SELECT 1 FROM installation_settings WHERE ciphertext IS NOT NULL LIMIT 1",
        }
        for table, query in checks.items():
            if table in tables and connection.execute(query).fetchone():
                return True
    return False


def initialize_database(database_path: str) -> None:
    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with connect(database_path) as connection:
        connection.executescript(SCHEMA)
        connection.execute("DROP TABLE IF EXISTS feedback")
        user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "visit_count" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN visit_count INTEGER NOT NULL DEFAULT 0")
        connection.execute("DELETE FROM server_sessions WHERE expires_at <= strftime('%s', 'now')")


def get_user(database_path: str, google_sub: str) -> dict[str, Any] | None:
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT google_sub, email, name, visit_count, created_at, last_seen_at FROM users WHERE google_sub = ?",
            (google_sub,),
        ).fetchone()
    return dict(row) if row else None


def save_user(database_path: str, google_sub: str, email: str, name: str) -> None:
    with connect(database_path) as connection:
        connection.execute(
            """INSERT INTO users (google_sub, email, name, visit_count)
               VALUES (?, ?, ?, 1)
               ON CONFLICT(google_sub) DO UPDATE SET
                 email = excluded.email,
                 name = excluded.name,
                 visit_count = users.visit_count + 1,
                 last_seen_at = CURRENT_TIMESTAMP""",
            (google_sub, email, name),
        )


def save_encrypted_record(
    database_path: str,
    table: str,
    google_sub: str,
    nonce: bytes,
    ciphertext: bytes,
    expires_at: int | None = None,
) -> None:
    if table == "saved_credentials":
        query = """INSERT INTO saved_credentials (google_sub, nonce, ciphertext)
                   VALUES (?, ?, ?)
                   ON CONFLICT(google_sub) DO UPDATE SET nonce=excluded.nonce,
                     ciphertext=excluded.ciphertext, updated_at=CURRENT_TIMESTAMP"""
        values: tuple[Any, ...] = (google_sub, nonce, ciphertext)
    elif table == "oauth_tokens":
        query = """INSERT INTO oauth_tokens (google_sub, nonce, ciphertext, expires_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(google_sub) DO UPDATE SET nonce=excluded.nonce,
                     ciphertext=excluded.ciphertext, expires_at=excluded.expires_at,
                     updated_at=CURRENT_TIMESTAMP"""
        values = (google_sub, nonce, ciphertext, expires_at)
    else:
        raise ValueError("Unsupported encrypted record table")
    with connect(database_path) as connection:
        connection.execute(query, values)


def get_encrypted_record(
    database_path: str, table: str, google_sub: str
) -> tuple[bytes, bytes, int | None] | None:
    if table not in {"saved_credentials", "oauth_tokens"}:
        raise ValueError("Unsupported encrypted record table")
    with connect(database_path) as connection:
        row = connection.execute(
            f"SELECT nonce, ciphertext, "
            f"{'expires_at' if table == 'oauth_tokens' else 'NULL'} AS expires_at "
            f"FROM {table} WHERE google_sub = ?",
            (google_sub,),
        ).fetchone()
    if not row:
        return None
    return bytes(row["nonce"]), bytes(row["ciphertext"]), row["expires_at"]


def delete_user_records(database_path: str, google_sub: str) -> None:
    with connect(database_path) as connection:
        connection.execute("DELETE FROM saved_credentials WHERE google_sub = ?", (google_sub,))
        connection.execute("DELETE FROM oauth_tokens WHERE google_sub = ?", (google_sub,))


def delete_user(database_path: str, google_sub: str) -> None:
    with connect(database_path) as connection:
        connection.execute("DELETE FROM users WHERE google_sub = ?", (google_sub,))


def has_saved_credentials(database_path: str, google_sub: str) -> bool:
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT 1 FROM saved_credentials WHERE google_sub = ?", (google_sub,)
        ).fetchone()
    return row is not None


def has_saved_tokens(database_path: str, google_sub: str) -> bool:
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT 1 FROM oauth_tokens WHERE google_sub = ?", (google_sub,)
        ).fetchone()
    return row is not None


def get_admin_data(database_path: str) -> dict[str, Any]:
    with connect(database_path) as connection:
        summary = connection.execute(
            """SELECT COUNT(*) AS total_users, COALESCE(SUM(visit_count), 0) AS total_visits
               FROM users"""
        ).fetchone()
        users = connection.execute(
            """SELECT email, name, visit_count, created_at, last_seen_at
               FROM users ORDER BY last_seen_at DESC LIMIT 500"""
        ).fetchall()
    return {
        "total_users": summary["total_users"],
        "total_visits": summary["total_visits"],
        "users": [dict(row) for row in users],
    }


def get_installation_settings(database_path: str) -> dict[str, dict[str, Any]]:
    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT setting_key, value, nonce, ciphertext FROM installation_settings"
        ).fetchall()
    return {row["setting_key"]: dict(row) for row in rows}


def save_installation_settings(
    database_path: str,
    client_id: str,
    nonce: bytes,
    ciphertext: bytes,
    admin_email: str,
) -> None:
    with connect(database_path) as connection:
        connection.executemany(
            """INSERT INTO installation_settings (setting_key, value, nonce, ciphertext)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(setting_key) DO UPDATE SET value=excluded.value,
                 nonce=excluded.nonce, ciphertext=excluded.ciphertext,
                 updated_at=CURRENT_TIMESTAMP""",
            [
                ("identity_google_client", client_id, nonce, ciphertext),
                ("admin_email", admin_email, None, None),
            ],
        )
