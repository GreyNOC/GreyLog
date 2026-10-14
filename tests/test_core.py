from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from greylog.events import ParseError, normalize, parse_line, parse_timestamp
from greylog.cli import _export, _ingest_url, _source_timezone, _watch_spec
from greylog.server import GreyLogServer
from greylog.store import RuleConfig, Store, iter_database_records
from greylog.watch import FileWatcher


BASE = "2026-10-14T12:00:00Z"


class ParsingTests(unittest.TestCase):
    def test_ingest_url_stays_on_loopback(self):
        self.assertEqual(_ingest_url("http://localhost:8765"), "http://localhost:8765/api/ingest")
        self.assertEqual(_ingest_url("http://127.0.0.1:8765/"), "http://127.0.0.1:8765/api/ingest")
        for url in ("http://example.com:8765", "https://localhost:8765", "http://localhost:8765/?x=1",
                    "http://user:pass@localhost:8765", "http://localhost:0"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                _ingest_url(url)

    def test_watch_spec_preserves_windows_and_posix_colon_paths(self):
        self.assertEqual(
            _watch_spec(r"auth:postgresql:C:\ProgramData\PostgreSQL\logs\server.log"),
            ("auth", "postgresql", r"C:\ProgramData\PostgreSQL\logs\server.log"),
        )
        self.assertEqual(
            _watch_spec("auth:postgresql:/var/log/postgresql/server.log"),
            ("auth", "postgresql", "/var/log/postgresql/server.log"),
        )
        self.assertEqual(_source_timezone("auth=-04:00"), ("auth", "-04:00"))

    def test_naive_timezone_and_syslog_year_rollover(self):
        self.assertEqual(parse_timestamp("2026-10-14 12:00:00", naive_timezone="-04:00"),
                         "2026-10-14T16:00:00.000Z")
        expected_local = datetime(2026, 10, 14, 12, 0, 0).astimezone(timezone.utc)
        self.assertEqual(parse_timestamp("2026-10-14 12:00:00"),
                         expected_local.isoformat(timespec="milliseconds").replace("+00:00", "Z"))
        event = parse_line("<34>Dec 31 23:59:59 server app: shutdown", format="syslog",
                           received_at="2027-01-01T00:00:05Z", naive_timezone="UTC")
        self.assertEqual(event["timestamp"], "2026-12-31T23:59:59.000Z")

    def test_canonical_auth_outcome_labels(self):
        event = normalize({"kind": "authentication", "outcome": "FAILED", "actor": "alice", "message": "login failed"})
        self.assertEqual((event["kind"], event["outcome"]), ("auth", "failure"))

    def test_mongodb_nested_duration_and_level(self):
        line = json.dumps({"t": {"$date": BASE}, "s": "W", "c": "COMMAND", "msg": "Slow query", "durationMs": "unknown",
                           "attr": {"durationMillis": 2300, "command": {"find": "orders"}}})
        event = parse_line(line, format="auto", source="mongo")
        self.assertEqual(event["vendor"], "mongodb")
        self.assertEqual(event["kind"], "query")
        self.assertEqual(event["severity"], "warning")
        self.assertEqual(event["attributes"]["durationMs"], 2300)
        self.assertEqual(event["timestamp"], "2026-10-14T12:00:00.000Z")

    def test_redaction_happens_before_event_is_returned(self):
        event = normalize({"message": "password=hunter2 Bearer abc.def Basic dXNlcjpwYXNz https://x/?session_id=opaque",
                           "api_key": "secret", "jwt": "header.payload.signature",
                           "nested": {"connectionString": "postgres://u:p@db"}}, source="test")
        serialized = json.dumps(event)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("abc.def", serialized)
        self.assertNotIn("dXNlcjpwYXNz", serialized)
        self.assertNotIn("postgres://u:p@db", serialized)
        self.assertNotIn("opaque", serialized)
        self.assertNotIn("header.payload.signature", serialized)
        self.assertEqual(event["attributes"]["api_key"], "[REDACTED]")

    def test_invalid_json_and_timestamp_do_not_echo_data(self):
        with self.assertRaises(ParseError) as caught:
            parse_line('{"password":"hunter2"', format="auto")
        self.assertNotIn("hunter2", str(caught.exception))
        with self.assertRaises(ParseError) as caught:
            normalize({"timestamp": "password=hunter2", "message": "x"})
        self.assertEqual(str(caught.exception), "invalid timestamp")

    def test_vendor_text_and_generic_json_fields(self):
        event = parse_line("2026-10-14 12:00:00 UTC [42] ERROR: login failed for user alice", format="auto")
        self.assertEqual(event["vendor"], "postgresql")
        self.assertEqual(event["kind"], "auth")
        self.assertEqual(event["actor"], "alice")
        other = normalize({"message": "ok", "custom": {"region": "east"}, "attributes": {"trace": "abc"}})
        self.assertEqual(other["attributes"]["custom"]["region"], "east")
        self.assertEqual(other["attributes"]["attributes"]["trace"], "abc")


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def add(self, data, source="db", timestamp=BASE):
        return self.store.add_event(normalize({"timestamp": timestamp, **data}, source=source, received_at=timestamp))

    def test_auth_threshold_dedupe_and_actor_source_negative_controls(self):
        failure = {"kind": "auth", "outcome": "failure", "actor": "alice", "message": "login failed"}
        for _ in range(4):
            self.assertEqual(self.add(failure), [])
        self.assertEqual(self.store.bootstrap(now=BASE)["metrics"]["openAlerts"], 0)
        created = self.add(failure)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["rule"], "auth_failures")
        self.assertEqual(created[0]["evidence"]["observed"], 5)
        updated = self.add(failure)
        self.assertEqual(updated[0]["id"], created[0]["id"])
        for _ in range(4):
            self.assertEqual(self.add({**failure, "actor": "bob"}), [])
            self.assertEqual(self.add(failure, source="other"), [])
        self.assertEqual(self.store.bootstrap(now=BASE)["metrics"]["openAlerts"], 1)

    def test_window_excludes_old_failures(self):
        failure = {"kind": "auth", "outcome": "failure", "actor": "alice", "message": "login failed"}
        for _ in range(4):
            self.add(failure)
        self.assertEqual(self.add(failure, timestamp="2026-10-14T12:01:01Z"), [])

    def test_slow_query_threshold_and_negative_control(self):
        query = {"kind": "query", "message": "query done"}
        for _ in range(4):
            self.assertEqual(self.add({**query, "durationMs": 1999}), [])
        for _ in range(2):
            self.assertEqual(self.add({**query, "durationMs": 2000}), [])
        alerts = self.add({**query, "durationMs": 2100})
        self.assertEqual([alert["rule"] for alert in alerts], ["slow_queries"])
        self.assertEqual(alerts[0]["evidence"]["slowQueryMs"], 2000)
        self.assertEqual(self.add({**query, "durationMs": "abc"}), [])

    def test_source_errors_excludes_auth_failures(self):
        for _ in range(5):
            self.add({"kind": "auth", "severity": "error", "actor": "a", "outcome": "failure", "message": "login failed"})
        self.assertEqual([a["rule"] for a in self.store.bootstrap(now=BASE)["alerts"]], ["auth_failures"])
        for _ in range(4):
            self.assertEqual(self.add({"kind": "error", "severity": "error", "message": "pool error"}), [])
        self.assertEqual(self.add({"kind": "error", "severity": "error", "message": "pool error"})[0]["rule"], "source_errors")

    def test_rule_config_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            path.write_text('{"authFailures":2,"slowQueryMs":500}', encoding="utf-8")
            self.assertEqual(RuleConfig.from_file(str(path)).authFailures, 2)
            path.write_text('{"authFailures":0}', encoding="utf-8")
            with self.assertRaises(ValueError):
                RuleConfig.from_file(str(path))

    def test_skewed_events_stored_but_excluded_from_alert_count(self):
        failure = {"timestamp": BASE, "kind": "auth", "outcome": "failure", "actor": "alice", "message": "login failed"}
        for _ in range(5):
            event = normalize(failure, source="db", received_at="2026-10-14T12:10:00Z")
            self.assertEqual(self.store.add_event(event), [])
            self.assertIn("_alertSuppressed", event["attributes"])
        for _ in range(4):
            self.assertEqual(self.store.add_event(normalize(failure, source="db", received_at=BASE)), [])
        alerts = self.store.add_event(normalize(failure, source="db", received_at=BASE))
        self.assertEqual(alerts[0]["evidence"]["observed"], 5)

    def test_empty_store_has_no_fabricated_sources_or_events(self):
        snapshot = self.store.bootstrap()
        self.assertEqual(snapshot["sources"], [])
        self.assertEqual(snapshot["events"], [])
        self.assertEqual(snapshot["alerts"], [])
        self.assertEqual(snapshot["metrics"]["totalSources"], 0)
        self.assertTrue(all(bucket["count"] == 0 for bucket in snapshot["traffic"]))

    @unittest.skipUnless(os.name == "posix", "POSIX file modes only")
    def test_database_file_is_private(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "logs.sqlite"
            store = Store(path)
            store.add_event(normalize({"message": "event"}, source="db"))
            for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
                with self.subTest(path=candidate):
                    self.assertTrue(candidate.is_file())
                    self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
            store.close()

    def test_alert_evidence_keeps_samples_after_event_retention(self):
        store = Store(":memory:", retention=2, rules=RuleConfig(authFailures=2))
        try:
            for _ in range(2):
                store.add_event(normalize({"timestamp": BASE, "kind": "auth", "outcome": "failure",
                                           "actor": "alice", "message": "login failed"},
                                          source="db", received_at=BASE))
            alert = list(store.iter_export("alerts"))[0]
            self.assertEqual(len(alert["evidence"]["samples"]), 2)
            self.assertEqual(alert["evidence"]["observed"], 2)
        finally:
            store.close()

    def test_alert_retention_bounds_exports(self):
        store = Store(":memory:", rules=RuleConfig(authFailures=1), alert_retention=2)
        try:
            for actor in ("alice", "bob", "carol"):
                store.add_event(normalize({"timestamp": BASE, "kind": "auth", "outcome": "failure",
                                           "actor": actor, "message": "login failed"},
                                          source="db", received_at=BASE))
            self.assertEqual(len(list(store.iter_export("alerts"))), 2)
        finally:
            store.close()


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.stop = threading.Event()
        self.server = GreyLogServer(("127.0.0.1", 0), self.store, "ingest-token", self.stop,
                                     dashboard_token="dashboard-token")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()

    def test_auth_ingest_bootstrap_and_sse_contract(self):
        body = json.dumps({"source": "vendor", "format": "json", "line": '{"message":"password=abc query completed","durationMs":10}'}).encode()
        with self.assertRaises(HTTPError) as caught:
            urlopen(Request(self.base + "/api/ingest", data=body, method="POST"), timeout=2)
        self.assertEqual(caught.exception.code, 401)
        caught.exception.close()
        request = Request(self.base + "/api/ingest", data=body, method="POST",
                          headers={"Authorization": "Bearer ingest-token", "Content-Type": "application/json"})
        with urlopen(request, timeout=2) as response:
            self.assertEqual(response.status, 201)
            obj = json.load(response)
        self.assertEqual(obj["event"]["sourceId"], "vendor")
        self.assertNotIn("password=abc", json.dumps(obj))
        session = Request(self.base + "/api/session", data=b'{"token":"dashboard-token"}', method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(session, timeout=2) as response:
            self.assertEqual(response.status, 204)
            cookie_header = response.headers["Set-Cookie"]
            self.assertIn("HttpOnly", cookie_header)
            self.assertIn("SameSite=Strict", cookie_header)
            self.assertIn("Path=/api", cookie_header)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        cookie = cookie_header.split(";", 1)[0]
        with urlopen(Request(self.base + "/api/bootstrap", headers={"Cookie": cookie}), timeout=2) as response:
            snapshot = json.load(response)
        self.assertEqual(snapshot["metrics"]["totalEvents"], 1)
        self.assertEqual(len(snapshot["traffic"]), 60)
        self.assertEqual(snapshot["sources"][0]["status"], "live")
        with urlopen(Request(self.base + "/api/stream", headers={"Cookie": cookie}), timeout=2) as response:
            self.assertEqual(response.readline().decode().strip(), "event: snapshot")
            self.assertTrue(response.readline().decode().startswith("data: {"))

    def test_read_requires_session_and_wrong_token_fails(self):
        for path in ("/api/bootstrap", "/api/stream", "/api/export/events", "/api/export/alerts"):
            with self.subTest(path=path), self.assertRaises(HTTPError) as caught:
                urlopen(self.base + path, timeout=2)
            self.assertEqual(caught.exception.code, 401)
            self.assertEqual(json.load(caught.exception)["error"], "dashboard session required")
            caught.exception.close()
        wrong = Request(self.base + "/api/session", data=b'{"token":"wrong"}', method="POST",
                        headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(wrong, timeout=2)
        self.assertEqual(caught.exception.code, 401)
        self.assertIsNone(caught.exception.headers.get("Set-Cookie"))
        caught.exception.close()

    def test_ingest_and_dashboard_tokens_are_separate(self):
        session = Request(self.base + "/api/session", data=b'{"token":"ingest-token"}', method="POST",
                          headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(session, timeout=2)
        self.assertEqual(caught.exception.code, 401)
        caught.exception.close()

    def test_connection_limit_requires_positive_value(self):
        with self.assertRaises(ValueError):
            GreyLogServer(("127.0.0.1", 0), self.store, "ingest-token", max_connections=0)
        request = Request(self.base + "/api/ingest", data=b'{"message":"ok"}', method="POST",
                          headers={"Authorization": "Bearer dashboard-token", "Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)
        self.assertEqual(caught.exception.code, 401)
        caught.exception.close()
        # The dashboard shell remains public so the analyst can enter the token.
        with urlopen(self.base + "/", timeout=2) as response:
            self.assertEqual(response.status, 200)
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])

    def test_cross_origin_session_request_is_rejected(self):
        request = Request(self.base + "/api/session", data=b'{"token":"dashboard-token"}', method="POST",
                          headers={"Content-Type": "application/json", "Origin": "http://evil.example"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()

    def test_plain_vendor_event_fields_do_not_collide_with_envelope(self):
        payload = {"source": "vendor", "event": "login", "line": 42,
                   "message": "Login failed for user alice", "kind": "auth", "outcome": "failed"}
        request = Request(self.base + "/api/ingest", data=json.dumps(payload).encode(), method="POST",
                          headers={"Authorization": "Bearer ingest-token", "Content-Type": "application/json"})
        with urlopen(request, timeout=2) as response:
            event = json.load(response)["event"]
        self.assertEqual(event["sourceId"], "vendor")
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["attributes"]["line"], 42)
        malformed = Request(self.base + "/api/ingest", data=b'{"source":"vendor","format":"json","line":42}',
                            method="POST", headers={"Authorization": "Bearer ingest-token", "Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(malformed, timeout=2)
        self.assertEqual(caught.exception.code, 400)
        caught.exception.close()
        self.assertEqual(self.store.bootstrap()["sources"][0]["errors"], 1)

    def test_deep_json_request_is_rejected_without_handler_crash(self):
        body = b'[' * 1100 + b'0' + b']' * 1100
        request = Request(self.base + "/api/ingest", data=body, method="POST",
                          headers={"Authorization": "Bearer ingest-token", "Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)
        self.assertEqual(caught.exception.code, 400)
        caught.exception.close()

    def test_exports_include_all_retained_rows_and_alert_evidence(self):
        stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        for index in range(105):
            self.store.add_event(normalize({"message": f"event {index}", "severity": "info"},
                                           source="bulk", received_at=stamp))
        for _ in range(5):
            self.store.add_event(normalize({"kind": "auth", "outcome": "failure", "actor": "alice",
                                            "message": "login failed"}, source="bulk", received_at=stamp))
        session = Request(self.base + "/api/session", data=b'{"token":"dashboard-token"}', method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(session, timeout=2) as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        for kind, expected in (("events", 110), ("alerts", 1)):
            with self.subTest(kind=kind):
                request = Request(self.base + f"/api/export/{kind}", headers={"Cookie": cookie})
                with urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertTrue(response.headers["Content-Type"].startswith("application/x-ndjson"))
                    self.assertIn(f"greylog-{kind}.jsonl", response.headers["Content-Disposition"])
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    records = [json.loads(line) for line in response.read().decode("utf-8").splitlines()]
                self.assertEqual(len(records), expected)
                if kind == "alerts":
                    self.assertEqual(records[0]["evidence"]["observed"], 5)
                    self.assertEqual(len(records[0]["evidence"]["samples"]), 5)

    def test_dns_rebinding_host_header_is_rejected(self):
        request = Request(self.base + "/api/bootstrap", headers={"Host": "logs.attacker.test"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()


class ExportTests(unittest.TestCase):
    def test_cli_export_is_complete_read_only_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "records.db"
            destination = Path(folder) / "exports"
            destination.mkdir()
            store = Store(db, retention=3)
            for index in range(5):
                store.add_event(normalize({"message": f"event {index}"}, source="db"))
            store.close()
            before = db.read_bytes()
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(_export(Namespace(db=str(db), dir=str(destination), which="both")), 0)
            files = sorted(destination.glob("*.jsonl"))
            self.assertEqual(len(files), 2)
            events = next(path for path in files if "events" in path.name)
            self.assertEqual(len(events.read_text(encoding="utf-8").splitlines()), 3)
            self.assertEqual(len(list(iter_database_records(db, "events"))), 3)
            first_content = events.read_bytes()
            with redirect_stdout(StringIO()):
                self.assertEqual(_export(Namespace(db=str(db), dir=str(destination), which="both")), 0)
            self.assertEqual(len(list(destination.glob("*.jsonl"))), 4)
            self.assertEqual(events.read_bytes(), first_content)
            self.assertEqual(db.read_bytes(), before)
            self.assertEqual(list(destination.glob("*.tmp")), [])

    def test_cli_export_without_hardlink_support(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "records.db"
            destination = Path(folder) / "exports"
            destination.mkdir()
            store = Store(db)
            store.add_event(normalize({"message": "real event"}, source="db"))
            store.close()
            with patch("greylog.cli.os.link", side_effect=OSError("hard links unavailable")):
                with redirect_stdout(StringIO()):
                    self.assertEqual(_export(Namespace(db=str(db), dir=str(destination), which="events")), 0)
            files = list(destination.glob("*.jsonl"))
            self.assertEqual(len(files), 1)
            self.assertEqual(json.loads(files[0].read_text(encoding="utf-8"))["message"], "real event")
            self.assertEqual(list(destination.glob("*.tmp")), [])

class WatchTests(unittest.TestCase):
    def test_missing_file_recovers_and_quiet_source_stays_live(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "db.log"
            store = Store(":memory:")
            stop = threading.Event()
            watcher = FileWatcher(store, "watched", "json", str(path), from_start=True, stop=stop)
            watcher.start()
            try:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline and store.bootstrap()["sources"][0]["status"] != "error":
                    time.sleep(0.05)
                self.assertEqual(store.bootstrap()["sources"][0]["status"], "error")
                path.write_text('{"message":"ready"}\n', encoding="utf-8")
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline and store.bootstrap()["metrics"]["totalEvents"] != 1:
                    time.sleep(0.05)
                snapshot = store.bootstrap()
                self.assertEqual(snapshot["metrics"]["totalEvents"], 1)
                self.assertEqual(snapshot["sources"][0]["status"], "live")
                self.assertIsNotNone(snapshot["sources"][0]["lastPoll"])
            finally:
                stop.set()
                watcher.join(timeout=2)
                store.close()


if __name__ == "__main__":
    unittest.main()
