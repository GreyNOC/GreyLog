from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from greylog.gateway import GatewayMonitor, GatewayRoute, _linux_ip_routes, _ping_once, _windows_routes, load_saved_selection
from greylog.server import GreyLogServer
from greylog.store import Store


class GatewayDiscoveryTests(unittest.TestCase):
    def test_windows_default_routes_and_metrics_without_ipv6_default(self):
        # PowerShell returns a JSON array even when no IPv6 default exists.
        output = json.dumps([
            {"gateway": "10.64.0.1", "interface": "VPN", "metric": 1},
            {"gateway": "192.168.1.1", "interface": "Wi-Fi", "metric": 35},
        ])
        with patch("greylog.gateway.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = output
            routes = _windows_routes()
        self.assertEqual([(route.gateway, route.interface, route.metric) for route in routes],
                         [("10.64.0.1", "VPN", 1), ("192.168.1.1", "Wi-Fi", 35)])
        self.assertIn("powershell.exe", run.call_args.args[0])

    def test_linux_ipv6_lookup_failure_keeps_valid_ipv4_route(self):
        with patch("greylog.gateway.subprocess.run") as run:
            run.side_effect = [
                type("Result", (), {"returncode": 0, "stdout": '[{"gateway":"192.168.1.1","dev":"eth0"}]'})(),
                type("Result", (), {"returncode": 1, "stdout": ""})(),
            ]
            self.assertEqual(_linux_ip_routes()[0].gateway, "192.168.1.1")

    def test_windows_icmp_unreachable_is_not_a_reply(self):
        with patch("greylog.gateway.platform.system", return_value="Windows"), patch(
            "greylog.gateway.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "Reply from 192.168.1.10: Destination host unreachable."
            self.assertEqual(_ping_once("192.168.1.1")[0], "no-reply")

    def test_unlisted_gateway_can_be_selected_without_claiming_detection(self):
        store = Store(":memory:")
        monitor = GatewayMonitor(store, threading.Event(), gateway="192.168.50.1")
        try:
            with patch("greylog.gateway.discover_gateways", return_value=[
                GatewayRoute("192.168.1.1", "Wi-Fi", "IPv4", 20),
            ]):
                monitor.refresh()
            snapshot = monitor.snapshot()
            self.assertEqual(snapshot["selection"]["gateway"], "192.168.50.1")
            self.assertEqual(snapshot["status"], "not-in-routes")
            self.assertIsNone(snapshot["current"])
            with self.assertRaises(ValueError):
                monitor.select("not-an-ip")
        finally:
            store.close()

    def test_route_disappearance_and_recovery_are_logged_once_each(self):
        store = Store(":memory:")
        monitor = GatewayMonitor(store, threading.Event(), gateway="auto")
        route = GatewayRoute("192.168.1.1", "Wi-Fi", "IPv4", 20)
        try:
            with patch("greylog.gateway.discover_gateways", side_effect=[[route], [], [], [route]]):
                for _ in range(4):
                    monitor.refresh()
            events = list(store.iter_export("events"))
            self.assertEqual(len(events), 2)
            messages = [event["message"] for event in events]
            self.assertTrue(any("absent" in message for message in messages))
            self.assertTrue(any("available" in message for message in messages))
            self.assertEqual(monitor.snapshot()["status"], "detected")
        finally:
            store.close()

    def test_selected_sender_callback_tracks_manual_and_auto_routes(self):
        store = Store(":memory:")
        monitor = GatewayMonitor(store, threading.Event())
        senders = []
        try:
            monitor.set_on_change(senders.append)
            with patch("greylog.gateway.discover_gateways", return_value=[
                GatewayRoute("10.0.0.1", "Wi-Fi", "IPv4", 20),
            ]):
                monitor.refresh()
            monitor.select("192.168.50.1")
            self.assertEqual(senders, [None, "10.0.0.1", "192.168.50.1"])
            self.assertEqual(monitor.snapshot()["status"], "not-in-routes")
        finally:
            store.close()

    def test_delayed_callback_cannot_restore_an_old_gateway_sender(self):
        store = Store(":memory:")
        monitor = GatewayMonitor(store, threading.Event())
        senders = []
        monitor.set_on_change(senders.append)
        original_notify = monitor._notify_sender
        first_pending = threading.Event()
        second_notified = threading.Event()
        release_first = threading.Event()
        failures = []

        def delayed_notify():
            if threading.current_thread() is first:
                first_pending.set()
                release_first.wait(3)
            elif threading.current_thread() is second:
                second_notified.set()
            original_notify()

        def choose(address):
            try:
                monitor.select(address)
            except BaseException as exc:
                failures.append(exc)

        first = threading.Thread(target=choose, args=("192.168.1.1",))
        second = threading.Thread(target=choose, args=("192.168.1.2",))
        try:
            with patch.object(monitor, "_notify_sender", side_effect=delayed_notify):
                first.start()
                self.assertTrue(first_pending.wait(2))
                second.start()
                self.assertTrue(second_notified.wait(2))
                second.join(timeout=2)
                self.assertFalse(second.is_alive())
                release_first.set()
                first.join(timeout=2)
                self.assertFalse(first.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(monitor.snapshot()["selection"]["gateway"], "192.168.1.2")
            self.assertEqual(senders[-1], "192.168.1.2")
        finally:
            release_first.set()
            if first.is_alive():
                first.join(timeout=2)
            if second.is_alive():
                second.join(timeout=2)
            store.close()

    def test_icmp_check_is_opt_in_and_rate_limited(self):
        store = Store(":memory:")
        route = GatewayRoute("192.168.1.1", "Wi-Fi", "IPv4", 10)
        try:
            off = GatewayMonitor(store, threading.Event())
            on = GatewayMonitor(store, threading.Event(), ping_interval=30)
            with patch("greylog.gateway.discover_gateways", return_value=[route]), patch(
                "greylog.gateway._ping_once", return_value=("reply", None)
            ) as ping:
                off.refresh()
                self.assertEqual(ping.call_count, 0)
                on.refresh()
                on.refresh()
                self.assertEqual(ping.call_count, 1)
            self.assertEqual(on.snapshot()["reachability"]["status"], "reply")
            with self.assertRaises(ValueError):
                GatewayMonitor(store, threading.Event(), ping_interval=5)
        finally:
            store.close()

    def test_dashboard_choice_persists_for_restart_and_corrupt_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "greylog.db.gateway.json"
            store = Store(":memory:")
            try:
                monitor = GatewayMonitor(store, threading.Event(), selection_path=path)
                monitor.select("192.168.50.1", "Ethernet")
                self.assertEqual(load_saved_selection(path), ("192.168.50.1", "Ethernet"))
                restored = GatewayMonitor(store, threading.Event(), gateway=load_saved_selection(path)[0],
                                          interface=load_saved_selection(path)[1], selection_path=path)
                self.assertEqual(restored.snapshot()["selection"],
                                 {"gateway": "192.168.50.1", "interface": "Ethernet"})
                path.write_text('{"gateway":"not-an-ip","interface":null}', encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_saved_selection(path)
            finally:
                store.close()


class GatewayApiTests(unittest.TestCase):
    def test_selection_requires_session_and_accepts_manual_ip(self):
        store = Store(":memory:")
        stop = threading.Event()
        monitor = GatewayMonitor(store, stop)
        with patch("greylog.gateway.discover_gateways", return_value=[
            GatewayRoute("192.168.1.1", "Wi-Fi", "IPv4", 10),
        ]):
            monitor.refresh()
        server = GreyLogServer(("127.0.0.1", 0), store, "ingest", stop,
                               dashboard_token="dashboard", gateway_monitor=monitor)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with self.assertRaises(HTTPError) as caught:
                urlopen(base + "/api/gateways", timeout=2)
            self.assertEqual(caught.exception.code, 401)
            caught.exception.close()
            session = Request(base + "/api/session", data=b'{"token":"dashboard"}', method="POST",
                              headers={"Content-Type": "application/json"})
            with urlopen(session, timeout=2) as response:
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            request = Request(base + "/api/gateways", data=b'{"gateway":"192.168.50.1"}',
                              method="POST", headers={"Content-Type": "application/json", "Cookie": cookie})
            with urlopen(request, timeout=2) as response:
                data = json.load(response)
            self.assertEqual(data["selection"]["gateway"], "192.168.50.1")
            self.assertEqual(data["status"], "not-in-routes")
            with urlopen(Request(base + "/api/bootstrap", headers={"Cookie": cookie}), timeout=2) as response:
                self.assertEqual(json.load(response)["gateway"]["selection"]["gateway"], "192.168.50.1")
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            store.close()


if __name__ == "__main__":
    unittest.main()
