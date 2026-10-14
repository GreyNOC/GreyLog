from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen

from greylog.cli import _serve, build_parser
from greylog.gateway import GatewayRoute
from greylog.server import GreyLogServer


def _local_ipv4() -> str | None:
    """Choose an assigned address for a self-directed UDP test packet."""
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM)}
    except OSError:
        return None
    for address in sorted(addresses):
        if address.startswith("127."):
            continue
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind((address, 0))
            return address
        except OSError:
            pass
        finally:
            probe.close()
    return None


class CliGatewaySyslogTests(unittest.TestCase):
    def test_serve_wires_selected_gateway_sender_to_syslog_and_dashboard(self):
        local_ip = _local_ipv4()
        if local_ip is None:
            self.skipTest("host has no assigned non-loopback IPv4 address")
        with tempfile.TemporaryDirectory() as directory:
            args = build_parser().parse_args([
                "serve", "--port", "0", "--db", str(Path(directory) / "records.db"),
                "--gateway", local_ip, "--syslog-bind", local_ip, "--syslog-port", "0",
                "--token", "ingest", "--dashboard-token", "dashboard",
            ])
            holder = {}
            result = []

            def capture_server(*server_args, **server_kwargs):
                server = GreyLogServer(*server_args, **server_kwargs)
                holder["server"] = server
                return server

            def run_serve():
                result.append(_serve(args))

            with patch("greylog.cli.GreyLogServer", side_effect=capture_server), patch(
                "greylog.gateway.discover_gateways", return_value=[
                    GatewayRoute(local_ip, "test-interface", "IPv4", 1),
                ]), patch("sys.stdout", new_callable=StringIO):
                thread = threading.Thread(target=run_serve, daemon=True)
                thread.start()
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and (
                        "server" not in holder or not holder["server"].syslog_receiver.is_alive()
                    ):
                        time.sleep(0.02)
                    self.assertIn("server", holder)
                    server = holder["server"]
                    self.assertTrue(server.syslog_receiver.is_alive())
                    base = f"http://127.0.0.1:{server.server_address[1]}"
                    session = Request(base + "/api/session", data=b'{"token":"dashboard"}', method="POST",
                                      headers={"Content-Type": "application/json"})
                    with urlopen(session, timeout=2) as response:
                        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                    packet = json.dumps({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "kind": "network", "message": "IDS alert blocked port scan",
                    }).encode("utf-8")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                        sender.bind((local_ip, 0))
                        sender.sendto(packet, server.syslog_receiver.address)
                    deadline = time.monotonic() + 4
                    while time.monotonic() < deadline:
                        with urlopen(Request(base + "/api/bootstrap", headers={"Cookie": cookie}), timeout=2) as response:
                            snapshot = json.load(response)
                        if any(alert["rule"] == "gateway_security_signal" for alert in snapshot["alerts"]):
                            break
                        time.sleep(0.05)
                    self.assertEqual(snapshot["gateway"]["syslog"]["enabled"], True)
                    self.assertTrue(any(event["sourceId"] == "gateway" for event in snapshot["events"]))
                    self.assertTrue(any(alert["rule"] == "gateway_security_signal" for alert in snapshot["alerts"]))
                finally:
                    if "server" in holder:
                        holder["server"].shutdown()
                    thread.join(timeout=5)
            self.assertEqual(result, [0])


if __name__ == "__main__":
    unittest.main()
