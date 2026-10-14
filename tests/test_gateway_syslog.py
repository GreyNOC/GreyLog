"""Local UDP tests for gateway syslog collection and alert boundaries."""

from __future__ import annotations

import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from greylog.events import normalize
from greylog.store import RuleConfig, Store
from greylog.syslog import SyslogReceiver, gateway_security_signal


class GatewaySyslogTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:", rules=RuleConfig(authFailures=3))
        self.stop = threading.Event()
        self.receiver = SyslogReceiver(self.store, "192.0.2.1", "127.0.0.1", port=0,
                                      source="router", stop=self.stop)
        self.receiver.start()

    def tearDown(self):
        self.receiver.close()
        self.receiver.join(timeout=2)
        self.store.close()

    def send(self, message: str):
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        payload = f"<134>1 {stamp} router.example firewall - - - {message}".encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(payload, self.receiver.address)

    def wait_for_events(self, count: int):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            snapshot = self.store.bootstrap()
            if snapshot["metrics"]["totalEvents"] >= count:
                return snapshot
            time.sleep(0.02)
        self.fail(f"expected {count} gateway event(s)")

    def test_only_selected_sender_is_collected_and_can_switch(self):
        self.send("IDS alert: port scan detected")
        time.sleep(0.1)
        self.assertEqual(self.store.bootstrap()["metrics"]["totalEvents"], 0)
        self.receiver.set_gateway_ip("127.0.0.1")
        self.send("Firewall denied connection from host")
        snapshot = self.wait_for_events(1)
        self.assertEqual(snapshot["sources"][0]["format"], "gateway-syslog")
        self.assertEqual(snapshot["events"][0]["attributes"]["gatewaySender"], "127.0.0.1")
        self.assertEqual(snapshot["alerts"], [])
        self.receiver.set_gateway_ip(None)
        self.send("IDS alert: port scan detected")
        time.sleep(0.1)
        self.assertEqual(self.store.bootstrap()["metrics"]["totalEvents"], 1)

    def test_explicit_signal_alert_is_evidence_backed_and_redacted(self):
        self.receiver.set_gateway_ip("127.0.0.1")
        self.send("IDS alert: port scan detected password=hunter2")
        snapshot = self.wait_for_events(1)
        self.assertEqual([alert["rule"] for alert in snapshot["alerts"]], ["gateway_security_signal"])
        self.assertEqual(snapshot["alerts"][0]["evidence"]["observed"], 1)
        self.assertEqual(snapshot["alerts"][0]["evidence"]["eventIds"], [snapshot["events"][0]["id"]])
        self.assertTrue(snapshot["events"][0]["gatewaySignal"])
        self.assertNotIn("hunter2", str(snapshot))
        self.send("IPS blocked malware detected")
        snapshot = self.wait_for_events(2)
        self.assertEqual(snapshot["alerts"][0]["evidence"]["observed"], 2)
        self.assertEqual(len(snapshot["alerts"][0]["evidence"]["eventIds"]), 2)

    def test_repeated_unattributed_gateway_login_failures_alert(self):
        self.receiver.set_gateway_ip("127.0.0.1")
        for _ in range(3):
            self.send("Admin login failed")
        snapshot = self.wait_for_events(3)
        alerts = [alert for alert in snapshot["alerts"] if alert["rule"] == "gateway_auth_failures"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["observed"], 3)

    def test_gateway_auth_alert_excludes_other_feeds_with_same_source_name(self):
        for _ in range(3):
            self.store.add_event(normalize({"message": "Admin login failed"}, source="router"), format="json")
        self.receiver.set_gateway_ip("127.0.0.1")
        self.send("Admin login failed")
        snapshot = self.wait_for_events(4)
        self.assertFalse(any(alert["rule"] == "gateway_auth_failures" for alert in snapshot["alerts"]))
        for _ in range(2):
            self.send("Admin login failed")
        snapshot = self.wait_for_events(6)
        alerts = [alert for alert in snapshot["alerts"] if alert["rule"] == "gateway_auth_failures"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["observed"], 3)
        self.assertEqual(len(alerts[0]["evidence"]["eventIds"]), 3)

    def test_malformed_json_datagram_does_not_stop_gateway_collection(self):
        self.receiver.set_gateway_ip("127.0.0.1")
        malformed = '{"a":' + '[' * 2000 + '0' + ']' * 2000 + '}'
        # Decoder recursion limits differ across Python versions. Force the
        # parser failure so this checks the receiver's per-packet recovery.
        with patch("greylog.syslog.parse_line", side_effect=RecursionError("nested JSON")) as parse:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(malformed.encode("ascii"), self.receiver.address)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if self.store.bootstrap()["sources"][0]["errors"]:
                    break
                time.sleep(0.02)
            self.assertEqual(parse.call_count, 1)
        self.assertGreater(self.store.bootstrap()["sources"][0]["errors"], 0)
        self.assertTrue(self.receiver.is_alive())
        self.send("IDS alert: port scan detected")
        snapshot = self.wait_for_events(1)
        self.assertTrue(self.receiver.is_alive())
        self.assertTrue(any(alert["rule"] == "gateway_security_signal" for alert in snapshot["alerts"]))

    def test_signal_is_limited_to_gateway_feed(self):
        event = normalize({"message": "IDS alert: port scan detected"}, source="other")
        self.assertEqual(self.store.add_event(event, format="json", gateway_signal=True), [])
        self.assertEqual(self.store.bootstrap()["alerts"], [])
        self.assertFalse(self.store.bootstrap()["events"][0]["gatewaySignal"])

    def test_signal_wording_rejects_status_and_routine_denial(self):
        self.assertTrue(gateway_security_signal("IDS alert: port scan detected"))
        self.assertFalse(gateway_security_signal("No intrusion detected"))
        self.assertFalse(gateway_security_signal("Firewall denied connection"))

    def test_existing_database_adds_gateway_signal_column(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "old.db"
            with closing(sqlite3.connect(path)) as db:
                db.execute("""CREATE TABLE events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, received_at TEXT NOT NULL,
                    source_id TEXT NOT NULL, vendor TEXT NOT NULL, kind TEXT NOT NULL,
                    severity TEXT NOT NULL, actor TEXT NOT NULL, target TEXT NOT NULL,
                    action TEXT NOT NULL, outcome TEXT NOT NULL, message TEXT NOT NULL,
                    attributes TEXT NOT NULL, duration_ms REAL,
                    alert_eligible INTEGER NOT NULL DEFAULT 1)""")
            migrated = Store(path)
            try:
                migrated.add_event(normalize({"message": "router log"}, source="router"))
                self.assertFalse(list(migrated.iter_export("events"))[0]["gatewaySignal"])
                row = migrated.db.execute("SELECT gateway_source FROM events").fetchone()
                self.assertEqual(row[0], 0)
            finally:
                migrated.close()


if __name__ == "__main__":
    unittest.main()
