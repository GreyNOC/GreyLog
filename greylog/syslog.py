"""Receive bounded UDP syslog from the selected local gateway.

UDP syslog has no authentication. Filtering the sender address reduces accidental
collection, but a source address alone is not proof that a message came from the
router. Alerts based on these records are signals for an analyst to investigate.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time

from .events import MAX_LINE, ParseError, parse_line, validate_source_name
from .store import Store


_SECURITY_SIGNAL = re.compile(
    r"(?i)(?:\b(?:ids|ips|suricata|snort|intrusion detection)\b.{0,80}\b(?:alert|attack|blocked|detected|dropped)\b"
    r"|\b(?:malware|ransomware|exploit|port[ -]?scan|brute[ -]?force|intrusion)\b.{0,80}\b(?:alert|blocked|detected|prevented)\b"
    r"|\b(?:alert|blocked|detected|prevented)\b.{0,80}\b(?:malware|ransomware|exploit|port[ -]?scan|brute[ -]?force|intrusion)\b)"
)


def gateway_security_signal(message: str) -> bool:
    """Match explicit router/IDS wording, not ordinary firewall denies."""
    if re.search(r"(?i)\b(?:no|not|zero)\s+(?:\w+\s+){0,2}"
                 r"(?:malware|ransomware|exploit|port[ -]?scan|brute[ -]?force|intrusion)\b", message):
        return False
    return bool(_SECURITY_SIGNAL.search(message))


class SyslogReceiver(threading.Thread):
    """Receive one syslog record per UDP datagram from one selected IPv4 gateway.

    The socket is bound before the thread starts so bind failures are reported by
    the CLI immediately. `set_gateway_ip` can disable or switch the sender filter
    when a user changes the selected gateway in the dashboard.
    """

    def __init__(self, store: Store, gateway_ip: str | None, bind_host: str, *, port: int = 5514,
                 source: str = "gateway", stop: threading.Event | None = None,
                 naive_timezone: str = "local"):
        super().__init__(name="greylog-gateway-syslog", daemon=True)
        self.store = store
        self.source_name = validate_source_name(source)
        self.naive_timezone = naive_timezone
        self.stop = stop or threading.Event()
        self._gateway_lock = threading.Lock()
        self._gateway_ip: ipaddress.IPv4Address | None = None
        self.set_gateway_ip(gateway_ip)
        try:
            bind_ip = ipaddress.IPv4Address(bind_host)
        except ipaddress.AddressValueError as exc:
            raise ValueError("syslog bind address must be an IPv4 address") from exc
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError("syslog port must be between 0 and 65535")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.settimeout(0.5)
            self.socket.bind((str(bind_ip), port))
        except BaseException:
            self.socket.close()
            raise
        self.address = self.socket.getsockname()
        self.store.register_source(self.source_name, "gateway-syslog")

    def set_gateway_ip(self, gateway_ip: str | None) -> None:
        if gateway_ip is None:
            parsed = None
        else:
            try:
                parsed = ipaddress.IPv4Address(gateway_ip)
            except ipaddress.AddressValueError as exc:
                raise ValueError("syslog gateway must be an IPv4 address") from exc
            if parsed.is_unspecified or parsed.is_multicast:
                raise ValueError("syslog gateway must be a unicast network IPv4 address")
        with self._gateway_lock:
            self._gateway_ip = parsed

    def close(self) -> None:
        self.stop.set()
        self.socket.close()

    def run(self) -> None:
        current_second = -1
        accepted_this_second = 0
        rate_error_second = -1
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(MAX_LINE + 1)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop.is_set():
                    self.store.mark_error(self.source_name, "gateway-syslog",
                                          f"syslog socket error: {exc.strerror or type(exc).__name__}")
                break
            with self._gateway_lock:
                selected = self._gateway_ip
            if selected is None or peer[0] != str(selected):
                continue
            second = int(time.monotonic())
            if second != current_second:
                current_second = second
                accepted_this_second = 0
            accepted_this_second += 1
            if accepted_this_second > 500:
                if rate_error_second != second:
                    self.store.mark_error(self.source_name, "gateway-syslog",
                                          "syslog rate exceeds 500 packets per second")
                    rate_error_second = second
                continue
            if len(packet) > MAX_LINE:
                self.store.mark_error(self.source_name, "gateway-syslog",
                                      f"syslog datagram exceeds {MAX_LINE} bytes")
                continue
            try:
                line = packet.decode("utf-8", errors="replace")
                event = parse_line(line, source=self.source_name, format="auto",
                                   naive_timezone=self.naive_timezone)
            except ParseError as exc:
                self.store.mark_error(self.source_name, "gateway-syslog", str(exc))
                continue
            except (RecursionError, ValueError):
                # The JSON decoder can raise these for deeply nested records or
                # oversized numeric literals. One malformed datagram must not
                # stop collection of later gateway logs.
                self.store.mark_error(self.source_name, "gateway-syslog", "malformed syslog record")
                continue
            event["attributes"]["gatewaySender"] = str(selected)
            signal = gateway_security_signal(event["message"])
            self.store.add_event(event, format="gateway-syslog", gateway_signal=signal)
