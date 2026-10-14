"""Loopback-only HTTP API, SSE snapshots, and static dashboard serving."""

from __future__ import annotations

import hmac
import json
import mimetypes
import secrets
import sqlite3
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .events import FORMATS, MAX_LINE, ParseError, normalize, parse_line, timezone_for_naive, validate_source_name
from .store import Store

MAX_BODY = 65_536
MAX_SESSION_BODY = 4_096
SESSION_COOKIE = "greylog_session"
_PACKAGE_WEB = Path(__file__).resolve().parent / "web"
_CHECKOUT_WEB = Path(__file__).resolve().parent.parent / "web"
WEB_ROOT = _PACKAGE_WEB if _PACKAGE_WEB.is_dir() else _CHECKOUT_WEB


class GreyLogServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], store: Store, token: str, stop: threading.Event | None = None):
        host = address[0]
        if host not in {"127.0.0.1", "localhost"}:
            raise ValueError("GreyLog serves on loopback only (127.0.0.1 or localhost)")
        if not token:
            raise ValueError("HTTP ingest requires a nonempty bearer token")
        self.store = store
        self.token = token
        self.session_id = secrets.token_urlsafe(32)
        self.stop = stop or threading.Event()
        super().__init__(address, GreyLogHandler)


class GreyLogHandler(BaseHTTPRequestHandler):
    server: GreyLogServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, TimeoutError):
            # Browsers commonly disconnect long-lived SSE sockets on refresh/exit.
            pass
        except sqlite3.ProgrammingError:
            # A request can race the final SQLite close during Ctrl+C teardown.
            if not self.server.stop.is_set():
                raise

    def log_message(self, format: str, *args: Any) -> None:
        # Do not log request paths, which may contain sensitive data.
        pass

    def _valid_host(self) -> bool:
        values = self.headers.get_all("Host", [])
        if len(values) != 1:
            return False
        hostname, separator, port = values[0].lower().partition(":")
        return hostname in {"127.0.0.1", "localhost"} and (not separator or port == str(self.server.server_address[1]))

    def _require_local_host(self) -> bool:
        if self._valid_host():
            return True
        self.close_connection = True
        self._json(403, {"error": "local Host header required"})
        return False

    def _require_same_origin(self) -> bool:
        origins = self.headers.get_all("Origin", [])
        if not origins:
            return True
        if len(origins) != 1:
            allowed = False
        else:
            try:
                origin = urlsplit(origins[0])
                host = self.headers["Host"].lower().partition(":")[0]
                allowed = (origin.scheme == "http" and origin.hostname == host
                           and origin.port == self.server.server_address[1]
                           and not origin.path and not origin.query and not origin.fragment)
            except (TypeError, ValueError):
                allowed = False
        if allowed:
            return True
        self.close_connection = True
        self._json(403, {"error": "same-origin request required"})
        return False

    def _has_dashboard_session(self) -> bool:
        cookie_values = self.headers.get_all("Cookie", [])
        if len(cookie_values) != 1:
            return False
        try:
            cookies = SimpleCookie()
            cookies.load(cookie_values[0])
            presented = cookies[SESSION_COOKIE].value if SESSION_COOKIE in cookies else ""
        except (CookieError, ValueError):
            return False
        return hmac.compare_digest(presented, self.server.session_id)

    def _json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self._require_local_host() or not self._require_same_origin():
            return
        path = urlsplit(self.path).path
        if path == "/api/bootstrap":
            if not self._has_dashboard_session():
                self._json(401, {"error": "dashboard session required"})
                return
            self._json(200, self.server.store.bootstrap())
        elif path == "/api/stream":
            if not self._has_dashboard_session():
                self._json(401, {"error": "dashboard session required"})
                return
            self._stream()
        elif path in {"/api/export/events", "/api/export/alerts"}:
            if not self._has_dashboard_session():
                self._json(401, {"error": "dashboard session required"})
                return
            self._export(path.rsplit("/", 1)[1])
        elif path.startswith("/api/"):
            self._json(404, {"error": "not found"})
        else:
            self._static(path)

    def _stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        while not self.server.stop.is_set():
            try:
                snapshot = json.dumps(self.server.store.bootstrap(), ensure_ascii=False, separators=(",", ":"))
                self.wfile.write(f"event: snapshot\ndata: {snapshot}\n\n".encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break
            except sqlite3.ProgrammingError:
                if not self.server.stop.is_set():
                    raise
                break
            self.server.stop.wait(1)

    def _export(self, kind: str) -> None:
        filename = f"greylog-{kind}.jsonl"
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            with closing(self.server.store.iter_export(kind)) as records:
                for record in records:
                    line = (json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
                    self.wfile.write(f"{len(line):X}\r\n".encode("ascii"))
                    self.wfile.write(line)
                    self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError, sqlite3.Error, ValueError):
            self.close_connection = True

    def _static(self, path: str) -> None:
        requested = unquote(path)
        if requested == "/":
            requested = "/index.html"
        candidate = (WEB_ROOT / requested.lstrip("/")).resolve()
        try:
            candidate.relative_to(WEB_ROOT.resolve())
        except ValueError:
            self._json(404, {"error": "not found"})
            return
        if not candidate.is_file():
            self._json(404, {"error": "not found"})
            return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self._require_local_host() or not self._require_same_origin():
            return
        path = urlsplit(self.path).path
        if path == "/api/session":
            self._session()
            return
        if path != "/api/ingest":
            self._json(404, {"error": "not found"})
            return
        authorization = self.headers.get("Authorization", "")
        if not hmac.compare_digest(authorization, f"Bearer {self.server.token}"):
            self.close_connection = True
            self._json(401, {"error": "missing or invalid bearer token"})
            return
        if self.headers.get_content_type() != "application/json":
            self.close_connection = True
            self._json(415, {"error": "JSON request required"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            self.close_connection = True
            self._json(411, {"error": "one Content-Length required"})
            return
        try:
            length = int(lengths[0])
        except ValueError:
            self.close_connection = True
            self._json(411, {"error": "valid Content-Length required"})
            return
        if length <= 0 or length > MAX_BODY:
            self.close_connection = True
            self._json(413, {"error": f"request must be 1 to {MAX_BODY} bytes"})
            return
        payload: Any = None
        source_name = "http"
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ParseError("request body must be a JSON object")
            envelope_keys = {"source", "sourceId", "format", "timezone", "line", "event"}
            envelope = set(payload).issubset(envelope_keys) and (
                "line" in payload or
                ("event" in payload and isinstance(payload["event"], dict))
            )
            if envelope:
                source = validate_source_name(payload.get("source") or payload.get("sourceId") or "http")
                format = payload.get("format", "auto")
                if not isinstance(format, str) or format not in FORMATS:
                    raise ParseError(f"format must be one of: {', '.join(FORMATS)}")
                naive_timezone = payload.get("timezone", "local")
                timezone_for_naive(naive_timezone)
            else:
                source = validate_source_name(payload.get("sourceId") or payload.get("source") or "http")
                format = "json"
                naive_timezone = "local"
            source_name = source
            if envelope and "line" in payload:
                if not isinstance(payload["line"], str) or len(payload["line"]) > MAX_LINE:
                    raise ParseError(f"line must be a string up to {MAX_LINE} characters")
                event = parse_line(payload["line"], source=source, format=format, naive_timezone=naive_timezone)
            else:
                raw = payload["event"] if envelope else payload
                vendor = format if envelope and format != "auto" else str(raw.get("vendor") or "json")
                event = normalize(raw, source=source, vendor=vendor, naive_timezone=naive_timezone)
            alerts = self.server.store.add_event(event, format=format)
            self._json(201, {"event": event, "alerts": alerts})
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self.server.store.mark_error("http", "json", "invalid JSON request")
            self._json(400, {"error": "invalid JSON request"})
        except ParseError as exc:
            self.server.store.mark_error(source_name, "http", str(exc))
            self._json(400, {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            self._json(400, {"error": str(exc)})

    def _session(self) -> None:
        if self.headers.get_content_type() != "application/json":
            self.close_connection = True
            self._json(415, {"error": "JSON request required"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            self.close_connection = True
            self._json(411, {"error": "one Content-Length required"})
            return
        try:
            length = int(lengths[0])
        except ValueError:
            self.close_connection = True
            self._json(411, {"error": "valid Content-Length required"})
            return
        if length <= 0 or length > MAX_SESSION_BODY:
            self.close_connection = True
            self._json(413, {"error": f"request must be 1 to {MAX_SESSION_BODY} bytes"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self._json(400, {"error": "invalid JSON request"})
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("token"), str):
            self._json(400, {"error": "token string required"})
            return
        if not hmac.compare_digest(payload["token"], self.server.token):
            self._json(401, {"error": "invalid token"})
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={self.server.session_id}; HttpOnly; SameSite=Strict; Path=/api")
        self.end_headers()
