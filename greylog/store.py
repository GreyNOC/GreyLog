"""SQLite persistence and deterministic, evidence-backed alert rules."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .events import utc_now


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _record(kind: str, row: sqlite3.Row) -> dict[str, Any]:
    if kind == "events":
        return {"id": row["id"], "timestamp": row["timestamp"], "receivedAt": row["received_at"],
                "sourceId": row["source_id"], "vendor": row["vendor"], "kind": row["kind"],
                "severity": row["severity"], "actor": row["actor"], "target": row["target"],
                "action": row["action"], "outcome": row["outcome"], "message": row["message"],
                "attributes": json.loads(row["attributes"], parse_constant=lambda _: None)}
    if kind == "alerts":
        return {"id": row["id"], "rule": row["rule"], "severity": row["severity"],
                "source": row["source"], "message": row["message"], "count": row["count"],
                "firstSeen": row["first_seen"], "lastSeen": row["last_seen"],
                "evidence": json.loads(row["evidence"], parse_constant=lambda _: None),
                "status": row["status"]}
    raise ValueError("export kind must be events or alerts")


def iter_database_records(path: str | Path, kind: str):
    """Stream retained records from a read-only SQLite snapshot."""
    if kind not in {"events", "alerts"}:
        raise ValueError("export kind must be events or alerts")
    db_path = Path(path).expanduser().resolve()
    if not db_path.is_file():
        raise FileNotFoundError(f"database not found: {db_path}")
    conn = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        order = "received_at ASC, id ASC" if kind == "events" else "first_seen ASC, id ASC"
        cursor = conn.execute(f"SELECT * FROM {kind} ORDER BY {order}")
        for row in cursor:
            yield _record(kind, row)
    finally:
        conn.close()


@dataclass(frozen=True)
class RuleConfig:
    authFailures: int = 5
    sourceErrors: int = 5
    slowQueries: int = 3
    windowSeconds: int = 60
    cooldownSeconds: int = 300
    slowQueryMs: int = 2000
    maxTimestampSkewSeconds: int = 300

    @classmethod
    def from_file(cls, path: str | None) -> "RuleConfig":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as stream:
            obj = json.load(stream)
        if not isinstance(obj, dict):
            raise ValueError("rules file must contain a JSON object")
        unknown = set(obj) - set(asdict(cls()))
        if unknown:
            raise ValueError(f"unknown rule setting(s): {', '.join(sorted(unknown))}")
        for name, value in obj.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"rule setting {name} must be a positive integer")
        return cls(**obj)


class Store:
    def __init__(self, path: str | Path = "greylog.db", *, rules: RuleConfig | None = None,
                 retention: int = 50_000, alert_retention: int = 5_000):
        self.path = str(path)
        if self.path != ":memory:":
            db_path = Path(self.path).expanduser().resolve()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            if os.name == "posix":
                os.chmod(db_path, 0o600)
            self.path = str(db_path)
        self.rules = rules or RuleConfig()
        self.retention = retention
        self.alert_retention = alert_retention
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self._create_schema()

    def _create_schema(self) -> None:
        with self.lock, self.db:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, received_at TEXT NOT NULL,
                    source_id TEXT NOT NULL, vendor TEXT NOT NULL, kind TEXT NOT NULL,
                    severity TEXT NOT NULL, actor TEXT NOT NULL, target TEXT NOT NULL,
                    action TEXT NOT NULL, outcome TEXT NOT NULL, message TEXT NOT NULL,
                    attributes TEXT NOT NULL, duration_ms REAL,
                    alert_eligible INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);
                CREATE INDEX IF NOT EXISTS idx_events_window ON events(source_id, timestamp);
                CREATE TABLE IF NOT EXISTS sources (
                    name TEXT PRIMARY KEY, format TEXT NOT NULL, last_seen TEXT,
                    events INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT, has_error INTEGER NOT NULL DEFAULT 0, last_poll TEXT
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY, signature TEXT NOT NULL, rule TEXT NOT NULL,
                    severity TEXT NOT NULL, source TEXT NOT NULL, message TEXT NOT NULL,
                    count INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    evidence TEXT NOT NULL, status TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alert_signature ON alerts(signature, last_seen);
            """)
            source_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(sources)")}
            if "last_poll" not in source_columns:
                self.db.execute("ALTER TABLE sources ADD COLUMN last_poll TEXT")
            event_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(events)")}
            if "alert_eligible" not in event_columns:
                self.db.execute("ALTER TABLE events ADD COLUMN alert_eligible INTEGER NOT NULL DEFAULT 1")

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def iter_export(self, kind: str):
        if kind not in {"events", "alerts"}:
            raise ValueError("export kind must be events or alerts")
        if self.path == ":memory:":
            order = "received_at ASC, id ASC" if kind == "events" else "first_seen ASC, id ASC"
            with self.lock:
                rows = self.db.execute(f"SELECT * FROM {kind} ORDER BY {order}").fetchall()
            for row in rows:
                yield _record(kind, row)
        else:
            yield from iter_database_records(self.path, kind)

    def register_source(self, name: str, format: str) -> None:
        name = name[:128]
        with self.lock, self.db:
            self.db.execute("INSERT OR IGNORE INTO sources(name,format) VALUES (?,?)", (name, format))

    def mark_error(self, source: str, format: str, detail: str) -> None:
        source = source[:128]
        with self.lock, self.db:
            self.db.execute("INSERT OR IGNORE INTO sources(name,format) VALUES (?,?)", (source, format))
            self.db.execute("UPDATE sources SET errors=errors+1, has_error=1, last_error=? WHERE name=?", (detail[:256], source))

    def touch_source(self, name: str, *, recovered_io: bool = False) -> None:
        with self.lock, self.db:
            if recovered_io:
                self.db.execute("UPDATE sources SET last_poll=?, has_error=0, last_error=NULL WHERE name=?", (utc_now(), name))
            else:
                self.db.execute("UPDATE sources SET last_poll=? WHERE name=?", (utc_now(), name))

    def add_event(self, event: dict[str, Any], *, format: str | None = None) -> list[dict[str, Any]]:
        source = event["sourceId"]
        attributes = event["attributes"]
        skew = abs((_time(event["receivedAt"]) - _time(event["timestamp"])).total_seconds())
        alert_eligible = skew <= self.rules.maxTimestampSkewSeconds
        if not alert_eligible and isinstance(attributes, dict):
            attributes = dict(attributes)
            attributes["_alertSuppressed"] = "event timestamp outside allowed skew from receipt"
            event["attributes"] = attributes
        duration = attributes.get("durationMs") if isinstance(attributes, dict) else None
        try:
            duration = float(duration)
            if not math.isfinite(duration) or duration < 0:
                duration = None
        except (TypeError, ValueError):
            duration = None
        with self.lock, self.db:
            self.db.execute("INSERT OR IGNORE INTO sources(name,format) VALUES (?,?)", (source, format or event["vendor"]))
            self.db.execute("""INSERT INTO events
                (id,timestamp,received_at,source_id,vendor,kind,severity,actor,target,action,outcome,message,attributes,duration_ms,alert_eligible)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                event["id"], event["timestamp"], event["receivedAt"], source, event["vendor"], event["kind"],
                event["severity"], event["actor"], event["target"], event["action"], event["outcome"],
                event["message"], json.dumps(attributes, ensure_ascii=False), duration, int(alert_eligible),
            ))
            self.db.execute("UPDATE sources SET events=events+1, last_seen=?, has_error=0, last_error=NULL WHERE name=?", (event["receivedAt"], source))
            alerts = self._evaluate(event) if alert_eligible else []
            if self.alert_retention > 0:
                total_alerts = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                if total_alerts > self.alert_retention:
                    self.db.execute("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY last_seen ASC LIMIT ?)",
                                    (total_alerts - self.alert_retention,))
            if self.retention > 0:
                total = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if total > self.retention:
                    self.db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY received_at ASC LIMIT ?)", (total - self.retention,))
            return alerts

    def _evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        timestamp = _time(event["timestamp"])
        start = _iso(timestamp - timedelta(seconds=self.rules.windowSeconds))
        end = event["timestamp"]
        source = event["sourceId"]
        candidates: list[tuple[str, str, str, int, str, tuple[Any, ...]]] = []
        if event["kind"] == "auth" and event["outcome"] == "failure" and event["actor"]:
            candidates.append(("auth_failures", "high", event["actor"], self.rules.authFailures,
                               "kind='auth' AND outcome='failure' AND actor=?", (event["actor"],)))
        if event["kind"] != "auth" and event["severity"] in {"error", "critical"}:
            candidates.append(("source_errors", "medium", "", self.rules.sourceErrors,
                               "kind!='auth' AND severity IN ('error','critical')", ()))
        try:
            duration_ms = float(event["attributes"].get("durationMs") or 0) if isinstance(event["attributes"], dict) else 0
        except (ValueError, TypeError):
            duration_ms = 0
        if event["kind"] == "query" and duration_ms >= self.rules.slowQueryMs:
            candidates.append(("slow_queries", "medium", "", self.rules.slowQueries,
                               "kind='query' AND duration_ms>=?", (self.rules.slowQueryMs,)))
        result = []
        for rule, severity, actor, threshold, condition, args in candidates:
            rows = self.db.execute(
                f"SELECT id,timestamp,message FROM events WHERE alert_eligible=1 AND source_id=? AND timestamp>=? AND timestamp<=? AND {condition} ORDER BY timestamp DESC LIMIT 20",
                (source, start, end, *args),
            ).fetchall()
            count = self.db.execute(
                f"SELECT COUNT(*) FROM events WHERE alert_eligible=1 AND source_id=? AND timestamp>=? AND timestamp<=? AND {condition}",
                (source, start, end, *args),
            ).fetchone()[0]
            if count < threshold:
                continue
            signature = json.dumps([rule, source, actor], separators=(",", ":"))
            evidence = {"eventIds": [row["id"] for row in rows], "windowSeconds": self.rules.windowSeconds,
                        "threshold": threshold, "observed": count, "actor": actor or None,
                        "samples": [{"id": row["id"], "timestamp": row["timestamp"],
                                     "message": row["message"][:256]} for row in rows[:5]]}
            if rule == "slow_queries":
                evidence["slowQueryMs"] = self.rules.slowQueryMs
            if rule == "auth_failures":
                message = f"{count} authentication failures for {actor} on {source} in {self.rules.windowSeconds}s"
            elif rule == "source_errors":
                message = f"{count} errors on {source} in {self.rules.windowSeconds}s"
            else:
                message = f"{count} slow queries on {source} in {self.rules.windowSeconds}s"
            previous = self.db.execute(
                "SELECT id,first_seen,last_seen FROM alerts WHERE signature=? AND status='open' ORDER BY last_seen DESC LIMIT 1", (signature,)
            ).fetchone()
            if previous and timestamp < _time(previous["last_seen"]):
                continue
            if previous and (timestamp - _time(previous["last_seen"])).total_seconds() < self.rules.cooldownSeconds:
                self.db.execute("UPDATE alerts SET count=?,last_seen=?,message=?,evidence=? WHERE id=?",
                                (count, end, message, json.dumps(evidence), previous["id"]))
                alert_id = previous["id"]
            else:
                if previous:
                    self.db.execute("UPDATE alerts SET status='closed' WHERE id=?", (previous["id"],))
                alert_id = uuid.uuid4().hex
                self.db.execute("""INSERT INTO alerts
                    (id,signature,rule,severity,source,message,count,first_seen,last_seen,evidence,status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (alert_id, signature, rule, severity, source, message, count, end, end, json.dumps(evidence), "open"))
            result.append({"id": alert_id, "rule": rule, "severity": severity, "source": source,
                           "message": message, "count": count, "firstSeen": previous["first_seen"] if previous and alert_id == previous["id"] else end,
                           "lastSeen": end, "evidence": evidence, "status": "open"})
        return result

    def bootstrap(self, *, now: str | None = None) -> dict[str, Any]:
        current = _time(now or utc_now())
        since = _iso(current.replace(microsecond=0) - timedelta(seconds=59))
        with self.lock, self.db:
            self.db.execute("UPDATE alerts SET status='closed' WHERE status='open' AND last_seen<?",
                            (_iso(current - timedelta(seconds=self.rules.cooldownSeconds)),))
            event_rows = self.db.execute("SELECT * FROM events ORDER BY received_at DESC LIMIT 100").fetchall()
            source_rows = self.db.execute("SELECT * FROM sources ORDER BY name").fetchall()
            alert_rows = self.db.execute("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT 100").fetchall()
            open_alert_count = self.db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            traffic_rows = self.db.execute("SELECT received_at FROM events WHERE received_at>=? AND received_at<=?", (since, _iso(current))).fetchall()
        buckets = {_iso(current.replace(microsecond=0) - timedelta(seconds=59-i)): 0 for i in range(60)}
        for row in traffic_rows:
            second = _iso(_time(row["received_at"]).replace(microsecond=0))
            if second in buckets:
                buckets[second] += 1
        sources = []
        for row in source_rows:
            last_seen = row["last_seen"]
            last_poll = row["last_poll"]
            live = bool((last_seen and (current - _time(last_seen)).total_seconds() <= 60) or
                        (last_poll and (current - _time(last_poll)).total_seconds() <= 60))
            status = "error" if row["has_error"] else "live" if live else "stale"
            sources.append({"name": row["name"], "format": row["format"], "status": status,
                            "lastSeen": last_seen, "events": row["events"], "errors": row["errors"],
                            "lastError": row["last_error"], "lastPoll": last_poll})
        alerts = [_record("alerts", row) for row in alert_rows]
        events = [_record("events", row) for row in event_rows]
        return {"now": _iso(current), "metrics": {
            "totalEvents": sum(row["events"] for row in source_rows),
            "eventsPerMinute": sum(buckets.values()),
            "openAlerts": open_alert_count,
            "activeSources": sum(item["status"] == "live" for item in sources),
            "totalSources": len(sources),
        }, "traffic": [{"time": key, "count": value} for key, value in buckets.items()],
            "sources": sources, "alerts": alerts, "events": events}
