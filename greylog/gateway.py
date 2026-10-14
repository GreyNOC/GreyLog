"""Discover and observe this host's default gateway routes without network probes."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .events import normalize
from .store import Store


@dataclass(frozen=True)
class GatewayRoute:
    gateway: str
    interface: str
    family: str
    metric: int


def _gateway_address(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("gateway must be an IP address")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("gateway must be an IP address") from exc
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("gateway must be a unicast network address")
    return str(address)


def _selection(gateway: str, interface: str | None) -> tuple[str, str | None]:
    if gateway != "auto":
        gateway = _gateway_address(gateway)
    if interface is not None:
        if not isinstance(interface, str) or not interface.strip() or len(interface) > 128:
            raise ValueError("interface must be a nonempty name up to 128 characters")
        interface = interface.strip()
    if gateway == "auto" and interface is not None:
        raise ValueError("automatic gateway selection cannot specify an interface")
    return gateway, interface


def load_saved_selection(path: Path) -> tuple[str, str | None] | None:
    """Load a per-user route choice; caller decides how to report bad data."""
    try:
        with path.open("rb") as stream:
            data = stream.read(1_025)
    except FileNotFoundError:
        return None
    if len(data) > 1_024:
        raise ValueError("saved gateway selection is too large")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("saved gateway selection is invalid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {"gateway", "interface"}:
        raise ValueError("saved gateway selection has invalid fields")
    return _selection(payload["gateway"], payload["interface"])


def _save_selection(path: Path, gateway: str, interface: str | None) -> None:
    """Replace the small per-user selection file atomically, with no tokens."""
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent,
                                         prefix=".greylog-gateway-", suffix=".tmp", delete=False) as stream:
            temp_path = Path(stream.name)
            json.dump({"gateway": gateway, "interface": interface}, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _metric(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _route(gateway: object, interface: object, metric: object) -> GatewayRoute | None:
    try:
        address = _gateway_address(gateway)
    except ValueError:
        return None
    name = str(interface or "").strip()[:128]
    return GatewayRoute(address, name, "IPv6" if ":" in address else "IPv4", _metric(metric))


_WINDOWS_ROUTES = r"""
$ErrorActionPreference = 'Stop'
$routes = @(Get-NetRoute |
    Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') -and $_.NextHop -and
                   $_.State -eq 'Alive' -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } |
    ForEach-Object {
        [pscustomobject]@{
            gateway = [string]$_.NextHop
            interface = [string]$_.InterfaceAlias
            metric = [int]$_.RouteMetric + [int]$_.InterfaceMetric
        }
    })
ConvertTo-Json -InputObject $routes -Compress -Depth 3
"""


def _windows_routes() -> list[GatewayRoute]:
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_ROUTES],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OSError(f"Windows route lookup failed: {exc}") from exc
    if result.returncode:
        raise OSError("Windows route lookup failed")
    try:
        records = json.loads(result.stdout.lstrip("\ufeff") or "[]")
    except json.JSONDecodeError as exc:
        raise OSError("Windows route lookup returned invalid data") from exc
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise OSError("Windows route lookup returned invalid data")
    return [route for row in records if isinstance(row, dict)
            if (route := _route(row.get("gateway"), row.get("interface"), row.get("metric")))]


def _linux_ip_routes() -> list[GatewayRoute]:
    routes: list[GatewayRoute] = []
    failed_families = 0
    for family in ("-4", "-6"):
        result = subprocess.run(["ip", "-j", family, "route", "show", "default"],
                                capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=5, check=False)
        if result.returncode:
            failed_families += 1
            continue
        try:
            records = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise OSError("Linux route lookup returned invalid data") from exc
        if not isinstance(records, list):
            raise OSError("Linux route lookup returned invalid data")
        for row in records:
            if not isinstance(row, dict):
                continue
            nexthops = row.get("nexthops")
            if isinstance(nexthops, list):
                for hop in nexthops:
                    if isinstance(hop, dict):
                        route = _route(hop.get("gateway"), hop.get("dev"), row.get("metric"))
                        if route:
                            routes.append(route)
            else:
                route = _route(row.get("gateway"), row.get("dev"), row.get("metric"))
                if route:
                    routes.append(route)
    if failed_families == 2:
        raise OSError("Linux route lookup failed")
    return routes


def _linux_proc_routes() -> list[GatewayRoute]:
    """Read the kernel IPv4 table when iproute2 is absent (small containers)."""
    try:
        lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    except OSError as exc:
        raise OSError("Linux route lookup unavailable") from exc
    routes = []
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[1] != "00000000":
            continue
        try:
            if int(fields[3], 16) & 0x3 != 0x3:
                continue
            gateway = socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])
        except (ValueError, OSError):
            continue
        route = _route(gateway, fields[0], fields[6])
        if route:
            routes.append(route)
    return routes


def discover_gateways() -> list[GatewayRoute]:
    """List OS default routes. This never sends packets to a gateway."""
    system = platform.system()
    if system == "Windows":
        routes = _windows_routes()
    elif system == "Linux":
        try:
            routes = _linux_ip_routes()
        except FileNotFoundError:
            routes = _linux_proc_routes()
    else:
        raise OSError(f"gateway discovery is unsupported on {system}")
    unique = {(route.gateway, route.interface, route.family): route for route in routes}
    return sorted(unique.values(), key=lambda route: (route.metric, route.family != "IPv4", route.interface, route.gateway))


def _ping_once(gateway: str) -> tuple[str, str | None]:
    """Send one bounded ICMP echo to an explicitly monitored gateway IP."""
    if platform.system() == "Windows":
        command = ["ping.exe", "-n", "1", "-w", "1000", gateway]
    else:
        command = ["ping", "-n", "-c", "1", "-W", "1", gateway]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=3, check=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError:
        return "unknown", "ICMP ping command is unavailable"
    except subprocess.TimeoutExpired:
        return "no-reply", None
    except OSError:
        return "unknown", "ICMP ping check failed"
    if platform.system() == "Windows":
        output = result.stdout.upper()
        # Windows ping can exit successfully for an ICMP unreachable response.
        reply = (result.returncode == 0 and
                 ("TTL=" in output or ("REPLY FROM" in output and "UNREACHABLE" not in output)))
    else:
        reply = result.returncode == 0
    return ("reply" if reply else "no-reply"), None


class GatewayMonitor(threading.Thread):
    """Track selected default route changes from local OS state only."""

    def __init__(self, store: Store, stop: threading.Event, *, gateway: str = "auto",
                 interface: str | None = None, interval: float = 5.0,
                 selection_path: Path | None = None, ping_interval: int | None = None):
        super().__init__(name="greylog-gateway-routes", daemon=True)
        if ping_interval is not None and not 30 <= ping_interval <= 3600:
            raise ValueError("gateway ICMP interval must be 30 to 3600 seconds")
        self.store = store
        self.stop = stop
        self.interval = interval
        self.selection_path = selection_path
        self.ping_interval = ping_interval
        self._lock = threading.Lock()
        self._notify_lock = threading.RLock()
        self._requested = "auto"
        self._interface: str | None = None
        self._routes: list[GatewayRoute] = []
        self._selected: GatewayRoute | None = None
        self._status = "checking"
        self._error: str | None = None
        self._checked_at: str | None = None
        self._observed = False
        self._source_error = False
        self._ping_status = "disabled" if ping_interval is None else "unknown"
        self._ping_error: str | None = None
        self._ping_at: str | None = None
        self._ping_gateway: str | None = None
        self._last_ping_mono: float | None = None
        self._on_change: Callable[[str | None], None] | None = None
        self.store.register_source("local-gateway", "os-route")
        self.select(gateway, interface, persist=False)

    def _resolve(self) -> GatewayRoute | None:
        if self._requested == "auto":
            return self._routes[0] if self._routes else None
        return next((route for route in self._routes if route.gateway == self._requested
                     and (not self._interface or route.interface == self._interface)), None)

    def _sender(self) -> str | None:
        # A manually entered gateway is an intentional syslog sender choice even
        # when it is not one of the host's current default routes.
        if self._requested != "auto":
            return self._requested
        return self._selected.gateway if self._selected and self._status == "detected" else None

    def select(self, gateway: str, interface: str | None = None, *, persist: bool = True) -> None:
        gateway, interface = _selection(gateway, interface)
        with self._lock:
            if persist and self.selection_path is not None:
                _save_selection(self.selection_path, gateway, interface)
            before = self._sender()
            self._requested = gateway
            self._interface = interface
            self._selected = self._resolve()
            self._status = "detected" if self._selected else "checking" if not self._checked_at else "not-in-routes"
            self._observed = False  # A user selection establishes a new baseline.
            sender = self._sender()
            if sender != before:
                self._ping_status = "disabled" if self.ping_interval is None else "unknown"
                self._ping_error = None
                self._ping_at = None
                self._ping_gateway = sender
                self._last_ping_mono = None
            changed_sender = sender != before
        if changed_sender:
            self._notify_sender()

    def _notify_sender(self) -> None:
        # State changes and notifications can originate in the route thread or
        # an HTTP handler. Serialize callbacks and read the latest state so an
        # older callback cannot leave the syslog filter on a stale address.
        with self._notify_lock:
            with self._lock:
                callback = self._on_change
                sender = self._sender()
            if callback:
                callback(sender)

    def set_on_change(self, callback: Callable[[str | None], None]) -> None:
        """Notify a local log receiver when the selected route address changes."""
        with self._lock:
            self._on_change = callback
        self._notify_sender()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "routes": [asdict(route) for route in self._routes],
                "selection": {"gateway": self._requested, "interface": self._interface},
                "current": asdict(self._selected) if self._selected else None,
                "status": self._status,
                "error": self._error,
                "checkedAt": self._checked_at,
                "reachability": {"enabled": self.ping_interval is not None,
                                 "status": self._ping_status, "gateway": self._ping_gateway,
                                 "checkedAt": self._ping_at, "error": self._ping_error},
            }

    def refresh(self) -> None:
        try:
            routes = discover_gateways()
            error = None
        except (OSError, subprocess.TimeoutExpired) as exc:
            routes = None
            error = str(exc)[:256]
        with self._lock:
            before = self._selected
            before_status = self._status
            before_sender = self._sender()
            if routes is None:
                self._status = "unavailable"
                self._error = error
            else:
                self._routes = routes
                self._selected = self._resolve()
                self._status = "detected" if self._selected else "not-in-routes"
                self._error = None
            self._checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            changed = (self._observed and routes is not None and
                       (before != self._selected or before_status != self._status))
            if routes is not None:
                self._observed = True
            selected = self._selected
            status = self._status
            requested = self._requested
            sender = self._sender()
            if sender != before_sender:
                self._ping_status = "disabled" if self.ping_interval is None else "unknown"
                self._ping_error = None
                self._ping_at = None
                self._ping_gateway = sender
                self._last_ping_mono = None
            changed_sender = before_sender != sender
        if changed_sender:
            self._notify_sender()
        self._maybe_ping()
        if routes is None or (status != "detected" and requested == "auto"):
            if not self._source_error:
                self.store.mark_error("local-gateway", "os-route", error or "selected gateway is absent from default routes")
                self._source_error = True
        else:
            self.store.touch_source("local-gateway", recovered_io=self._source_error)
            self._source_error = False
        if changed:
            if selected is None:
                message = "Selected gateway is absent from the local default routes"
                severity = "warning"
            elif before is None:
                message = f"Selected gateway route available: {selected.gateway} via {selected.interface}"
                severity = "info"
            else:
                message = f"Selected gateway route changed to {selected.gateway} via {selected.interface}"
                severity = "info"
            self.store.add_event(normalize({"kind": "network", "severity": severity, "message": message,
                                            "target": selected.gateway if selected else before.gateway if before else "",
                                            "action": "route-change"}, source="local-gateway", vendor="os-route"))

    def run(self) -> None:
        while not self.stop.is_set():
            self.refresh()
            self.stop.wait(self.interval)

    def _maybe_ping(self) -> None:
        if self.ping_interval is None:
            return
        with self._lock:
            gateway = self._sender()
            now = time.monotonic()
            if gateway is None:
                self._ping_status = "unknown"
                self._ping_gateway = None
                return
            if self._last_ping_mono is not None and now - self._last_ping_mono < self.ping_interval:
                return
            self._last_ping_mono = now
            self._ping_gateway = gateway
        status, error = _ping_once(gateway)
        checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        with self._lock:
            if self._sender() != gateway:
                return
            self._ping_status = status
            self._ping_error = error
            self._ping_at = checked_at
