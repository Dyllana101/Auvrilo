import hashlib
import json
import secrets
import time
from collections.abc import Mapping
from typing import Any

from flask import Request, Response
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict

from database import connect


class ServerSession(CallbackDict[str, Any], SessionMixin):
    def __init__(self, initial: Mapping[str, Any] | None = None, sid: str | None = None):
        def on_update(_: CallbackDict[str, Any]) -> None:
            self.modified = True

        super().__init__(initial, on_update)
        self.sid = sid or secrets.token_urlsafe(32)
        self.modified = False
        self.new = initial is None


class SQLiteSessionInterface(SessionInterface):
    session_class = ServerSession

    def __init__(self, database_path: str, lifetime_seconds: int = 30 * 24 * 60 * 60):
        self.database_path = database_path
        self.lifetime_seconds = lifetime_seconds

    @staticmethod
    def _hash_sid(sid: str) -> str:
        return hashlib.sha256(sid.encode("utf-8")).hexdigest()

    def open_session(self, app: Any, request: Request) -> ServerSession:
        sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if sid:
            with connect(self.database_path) as connection:
                row = connection.execute(
                    "SELECT data, expires_at FROM server_sessions WHERE session_hash = ?",
                    (self._hash_sid(sid),),
                ).fetchone()
                if row and row["expires_at"] > int(time.time()):
                    try:
                        data = json.loads(row["data"])
                    except (TypeError, json.JSONDecodeError):
                        data = {}
                    return self.session_class(data, sid)
                connection.execute(
                    "DELETE FROM server_sessions WHERE session_hash = ?",
                    (self._hash_sid(sid),),
                )
        return self.session_class()

    def save_session(self, app: Any, session: ServerSession, response: Response) -> None:
        name = app.config["SESSION_COOKIE_NAME"]
        if not session:
            with connect(self.database_path) as connection:
                connection.execute(
                    "DELETE FROM server_sessions WHERE session_hash = ?",
                    (self._hash_sid(session.sid),),
                )
            if session.modified:
                response.delete_cookie(
                    name,
                    domain=self.get_cookie_domain(app),
                    path=self.get_cookie_path(app),
                    secure=self.get_cookie_secure(app),
                    httponly=True,
                    samesite=self.get_cookie_samesite(app),
                )
            return

        expires_at = int(time.time()) + self.lifetime_seconds
        payload = json.dumps(dict(session), separators=(",", ":"))
        with connect(self.database_path) as connection:
            connection.execute(
                """INSERT INTO server_sessions (session_hash, data, expires_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(session_hash) DO UPDATE SET data=excluded.data,
                     expires_at=excluded.expires_at, updated_at=CURRENT_TIMESTAMP""",
                (self._hash_sid(session.sid), payload, expires_at),
            )
        response.set_cookie(
            name,
            session.sid,
            max_age=self.lifetime_seconds,
            httponly=True,
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
            domain=self.get_cookie_domain(app),
            path=self.get_cookie_path(app),
        )

    def regenerate(self, session: ServerSession) -> None:
        with connect(self.database_path) as connection:
            connection.execute(
                "DELETE FROM server_sessions WHERE session_hash = ?",
                (self._hash_sid(session.sid),),
            )
        session.clear()
        session.sid = secrets.token_urlsafe(32)
        session.new = True
