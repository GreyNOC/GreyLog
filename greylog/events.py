"""Best-effort, bounded log parsing and normalization.

The vendor labels are adapters, not claims of complete vendor format support.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

FORMATS = ("auto", "json", "postgresql", "mysql", "mongodb", "mssql", "redis", "oracle", "syslog")
MAX_LINE = 32_768
MAX_MESSAGE = 4_096
MAX_ATTRIBUTES = 16_384

_SECRET_KEY = re.compile(r"(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|auth(?:orization)?|cookie|credential|private[_-]?key|dsn|connection[_-]?string)", re.I)
_INLINE_SECRET = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie)\s*[:=]\s*([^\s,;]+)")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+")
_COOKIE = re.compile(r"(?i)\b(?:set-)?cookie\s*:\s*[^\r\n]+")
_URI_CREDS = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@", re.I)
_DURATION = re.compile(r"(?i)\b(?:duration|elapsed|query[_ ]time)\s*[:=]?\s*(\d+(?:\.\d+)?)\s*(ms|msec|milliseconds?|s|sec|seconds?)\b")
_PG = re.compile(r"^(?P<date>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:\s*(?:UTC|[+-]\d\d(?::?\d\d)?|Z))?)\s+(?:\[[^]]+\]\s*)?(?P<level>DEBUG|LOG|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC):\s*(?P<message>.*)$", re.I)
_MYSQL = re.compile(r"^(?P<date>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+.*?\[(?P<level>ERROR|WARNING|WARN|NOTE|INFO|DEBUG)\]\s*(?P<message>.*)$", re.I)
_SYSLOG = re.compile(r"^(?:<\d+>(?:1\s+)?)?(?P<date>\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<tag>[^: ]+)(?:\[\d+\])?:?\s*(?P<message>.*)$")
_MSSQL = re.compile(r"^(?P<date>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?)\s+(?P<context>[^\t]+?)\s+(?P<message>(?:Error:|Login failed|.*))$", re.I)
_REDIS = re.compile(r"^(?:\d+:\w+\s+)?(?P<date>\d\d\s+[A-Z][a-z]{2}\s+\d{4}\s+\d\d:\d\d:\d\d(?:\.\d+)?)\s+(?P<level>[#*.-])\s+(?P<message>.*)$")
_ACTOR = re.compile(r"(?i)\b(?:user|username|role|account|principal)\s*[=:\s]\s*['\"]?([A-Za-z0-9_.@-]{1,128})")
_TARGET = re.compile(r"(?i)\b(?:database|db|table|collection|host|client)\s*[=:\s]\s*['\"]?([A-Za-z0-9_.:/@-]{1,128})")
_SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,127}$")


class ParseError(ValueError):
    pass


def validate_source_name(value: Any) -> str:
    if not isinstance(value, str) or not _SOURCE_NAME.fullmatch(value):
        raise ParseError("source name must use 1-128 letters, digits, dots, underscores, slashes, or hyphens")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def timezone_for_naive(spec: str) -> timezone | None:
    """Return None for host local time, or a portable UTC/fixed-offset zone."""
    if not isinstance(spec, str):
        raise ParseError("timezone must be local, UTC, or a fixed offset such as -04:00")
    if spec.lower() == "local":
        return None
    if spec.upper() in {"UTC", "Z"}:
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d\d):(\d\d)", spec)
    if not match:
        raise ParseError("timezone must be local, UTC, or a fixed offset such as -04:00")
    hours, minutes = int(match.group(2)), int(match.group(3))
    if hours > 14 or minutes > 59 or (hours == 14 and minutes != 0):
        raise ParseError("timezone offset must be within -14:00 to +14:00")
    offset = timedelta(hours=hours, minutes=minutes)
    return timezone(offset if match.group(1) == "+" else -offset)


def _as_utc(dt: datetime, naive_zone: timezone | None) -> datetime:
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc)
    # astimezone() applies the OS local timezone for this particular date,
    # including DST, rather than freezing today's UTC offset.
    return dt.astimezone(timezone.utc) if naive_zone is None else dt.replace(tzinfo=naive_zone).astimezone(timezone.utc)


def parse_timestamp(value: Any, fallback: str | None = None, *, naive_timezone: str = "local") -> str:
    naive_zone = timezone_for_naive(naive_timezone)
    if value is None or value == "":
        return fallback or utc_now()
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            number = float(value)
            if number > 10_000_000_000:
                number /= 1000
            dt = datetime.fromtimestamp(number, timezone.utc)
        else:
            raw = str(value).strip().replace(",", ".")
            if raw.upper().endswith(" UTC"):
                raw = raw[:-4] + "Z"
            if re.fullmatch(r"\d{10}(?:\.\d+)?|\d{13}", raw):
                number = float(raw)
                if number > 10_000_000_000:
                    number /= 1000
                dt = datetime.fromtimestamp(number, timezone.utc)
            elif re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d$", raw):
                reference = datetime.fromisoformat((fallback or utc_now()).replace("Z", "+00:00"))
                candidates = []
                for year in (reference.year - 1, reference.year, reference.year + 1):
                    try:
                        candidate = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
                    except ValueError:
                        continue
                    candidates.append(_as_utc(candidate, naive_zone))
                dt = min(candidates, key=lambda item: abs((item - reference).total_seconds()))
            elif re.match(r"^\d\d\s+[A-Z][a-z]{2}\s+\d{4}", raw):
                dt = datetime.strptime(raw, "%d %b %Y %H:%M:%S.%f" if "." in raw else "%d %b %Y %H:%M:%S")
            else:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return _as_utc(dt, naive_zone).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, TypeError) as exc:
        raise ParseError("invalid timestamp") from exc


def redact_text(value: str) -> str:
    value = _COOKIE.sub("Cookie: [REDACTED]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _BASIC.sub("Basic [REDACTED]", value)
    value = _URI_CREDS.sub(r"\1[REDACTED]@", value)
    return _INLINE_SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def redact(value: Any, depth: int = 0) -> Any:
    if depth >= 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:100]:
            safe_key = str(key)[:128]
            result[safe_key] = "[REDACTED]" if _SECRET_KEY.search(safe_key) else redact(item, depth + 1)
        return result
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return redact_text(value[:MAX_LINE])
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value)[:MAX_LINE])


def _first(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _severity(value: Any, message: str) -> str:
    label = str(value or "").strip().lower()
    if label in {"fatal", "panic", "critical", "crit", "emerg", "emergency", "alert", "f"}:
        return "critical"
    if label in {"error", "err", "e", "severe"}:
        return "error"
    if label in {"warning", "warn", "w"}:
        return "warning"
    if label in {"debug", "trace", "verbose", "d"}:
        return "debug"
    if label in {"info", "information", "notice", "log", "i"}:
        return "info"
    if re.search(r"(?i)\b(?:fatal|panic|critical)\b", message):
        return "critical"
    if re.search(r"(?i)\b(?:error|exception|failed|failure|ORA-\d{5})\b", message):
        return "error"
    if re.search(r"(?i)\b(?:warn|warning)\b", message):
        return "warning"
    return "info"


def _duration_ms(data: dict[str, Any], message: str) -> float | None:
    for nested in (data, data.get("attr"), data.get("attributes")):
        if not isinstance(nested, dict):
            continue
        for key in ("durationMs", "duration_ms", "durationMillis", "queryTimeMs", "elapsedMs"):
            if key in nested:
                try:
                    value = float(nested[key])
                    if math.isfinite(value) and value >= 0:
                        return value
                except (TypeError, ValueError):
                    pass
    match = _DURATION.search(message)
    if match:
        value = float(match.group(1))
        value = value * 1000 if match.group(2).lower().startswith("s") else value
        return value if math.isfinite(value) else None
    return None


def normalize(data: dict[str, Any], *, source: str = "default", vendor: str = "json", received_at: str | None = None,
              naive_timezone: str = "local") -> dict[str, Any]:
    """Normalize a JSON event; source and vendor from the collector take precedence."""
    source = validate_source_name(source)
    if not isinstance(vendor, str) or not _SOURCE_NAME.fullmatch(vendor) or len(vendor) > 64:
        raise ParseError("vendor label must use 1-64 safe name characters")
    safe = redact(data)
    if not isinstance(safe, dict):
        raise ParseError("event must be a JSON object")
    safe.pop("_alertSuppressed", None)
    safe.pop("_truncated", None)
    received = received_at or utc_now()
    message = str(_first(safe, "message", "msg", "text", "detail", "description") or "")[:MAX_MESSAGE]
    if not message:
        message = json.dumps(safe, ensure_ascii=False, separators=(",", ":"))[:MAX_MESSAGE]
    severity = _severity(_first(safe, "severity", "level", "s", "priority"), message)
    outcome = str(_first(safe, "outcome", "result", "status") or "").lower()[:64]
    action = str(_first(safe, "action", "operation", "command", "event") or "")[:128]
    actor = str(_first(safe, "actor", "user", "username", "account", "principal") or "")[:128]
    target = str(_first(safe, "target", "database", "db", "collection", "table", "host") or "")[:128]
    if not actor:
        match = _ACTOR.search(message)
        actor = match.group(1) if match else ""
    if not target:
        match = _TARGET.search(message)
        target = match.group(1) if match else ""
    duration = _duration_ms(safe, message)
    if duration is not None:
        safe["durationMs"] = duration
    kind = str(_first(safe, "kind", "category", "type") or "").lower()[:64]
    if kind in {"authentication", "login", "logon", "auth_failure", "auth_success"}:
        kind = "auth"
    elif kind in {"sql", "slow_query", "database_query", "db_query"}:
        kind = "query"
    elif kind in {"exception", "failure"}:
        kind = "error"
    if not kind or kind in {"event", "log"}:
        if re.search(r"(?i)\b(?:login|logon|auth(?:entication)?|access denied|permission denied)\b", message + " " + action):
            kind = "auth"
        elif duration is not None or re.search(r"(?i)\b(?:query|select|insert|update|delete)\b", message + " " + action):
            kind = "query"
        elif severity in {"error", "critical"}:
            kind = "error"
        else:
            kind = "log"
    if outcome in {"fail", "failed", "failure", "denied", "reject", "rejected", "invalid", "error"}:
        outcome = "failure"
    elif outcome in {"success", "succeeded", "ok", "accepted", "allow", "allowed"}:
        outcome = "success"
    if not outcome:
        if re.search(r"(?i)\b(?:failed|failure|denied|rejected|invalid password)\b", message):
            outcome = "failure"
        elif re.search(r"(?i)\b(?:succeeded|success|accepted)\b", message):
            outcome = "success"
        else:
            outcome = "unknown"
    # Keep vendor fields and arbitrary JSON payload keys for investigation.
    attributes = safe
    attributes_json = json.dumps(attributes, ensure_ascii=False, default=str)
    if len(attributes_json) > MAX_ATTRIBUTES:
        attributes = {"_truncated": True}
        if duration is not None:
            attributes["durationMs"] = duration
    timestamp = parse_timestamp(_first(safe, "timestamp", "time", "ts", "datetime", "t"), received,
                                naive_timezone=naive_timezone)
    return {
        "id": uuid.uuid4().hex,
        "timestamp": timestamp,
        "receivedAt": received,
        "sourceId": source,
        "vendor": vendor,
        "kind": kind,
        "severity": severity,
        "actor": actor,
        "target": target,
        "action": action,
        "outcome": outcome,
        "message": message,
        "attributes": attributes,
    }


def parse_line(line: str, *, source: str = "default", format: str = "auto", received_at: str | None = None,
               naive_timezone: str = "local") -> dict[str, Any]:
    if format not in FORMATS:
        raise ParseError(f"unsupported format: {format}")
    if len(line) > MAX_LINE:
        raise ParseError(f"line exceeds {MAX_LINE} characters")
    line = line.strip("\r\n")
    if not line.strip():
        raise ParseError("empty line")
    selected = format
    if selected == "auto":
        selected = ("json" if line.lstrip().startswith("{") else
                    "postgresql" if _PG.match(line) else
                    "mysql" if _MYSQL.match(line) else
                    "mssql" if _MSSQL.match(line) and re.search(r"(?i)\b(?:spid\d+|login failed|error:\s*\d+)", line) else
                    "redis" if _REDIS.match(line) else
                    "oracle" if re.search(r"\bORA-\d{5}\b", line, re.I) else
                    "syslog" if _SYSLOG.match(line) else "generic")
    if selected in {"json", "mongodb"} and line.lstrip().startswith("{"):
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError(f"invalid JSON: {exc.msg}") from exc
        if not isinstance(raw, dict):
            raise ParseError("JSON log line must be an object")
        if selected == "json" and {"t", "s", "msg"}.issubset(raw):
            selected = "mongodb"
        if selected == "mongodb" and "t" in raw and isinstance(raw["t"], dict):
            date = raw["t"].get("$date")
            if isinstance(date, dict) and "$numberLong" in date:
                date = date["$numberLong"]
            raw["timestamp"] = date
        return normalize(raw, source=source, vendor=selected, received_at=received_at, naive_timezone=naive_timezone)
    if selected == "json":
        raise ParseError("JSON log line must be an object")
    data: dict[str, Any] = {"message": line}
    match = None
    if selected == "postgresql":
        match = _PG.match(line)
    elif selected == "mysql":
        match = _MYSQL.match(line)
    elif selected == "mssql":
        match = _MSSQL.match(line)
    elif selected == "redis":
        match = _REDIS.match(line)
    elif selected == "syslog":
        match = _SYSLOG.match(line)
    if match:
        parts = match.groupdict()
        data.update({"timestamp": parts.get("date"), "message": parts.get("message") or line})
        if parts.get("level"):
            data["severity"] = {"#": "warning", "*": "info", ".": "debug", "-": "debug"}.get(parts["level"], parts["level"])
        if parts.get("host"):
            data["target"] = parts["host"]
        if parts.get("tag"):
            data["action"] = parts["tag"]
    elif selected == "oracle":
        if not re.search(r"\bORA-\d{5}\b", line, re.I):
            raise ParseError("Oracle line lacks ORA code")
    elif selected in {"postgresql", "mysql", "mssql", "redis", "syslog"}:
        raise ParseError(f"line does not match supported {selected} format")
    return normalize(data, source=source, vendor=selected, received_at=received_at, naive_timezone=naive_timezone)
