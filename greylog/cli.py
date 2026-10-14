"""Command line entry points for serving, ingesting, and checking log records."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sqlite3
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .events import FORMATS, ParseError, parse_line, timezone_for_naive, validate_source_name
from .server import GreyLogServer
from .store import RuleConfig, Store, iter_database_records
from .watch import FileWatcher


def _watch_spec(text: str) -> tuple[str, str, str]:
    parts = text.split(":", 2)
    if len(parts) != 3 or not all(parts):
        raise argparse.ArgumentTypeError("watch must be NAME:FORMAT:PATH")
    name, format, path = parts
    if format not in FORMATS:
        raise argparse.ArgumentTypeError(f"format must be one of: {', '.join(FORMATS)}")
    try:
        validate_source_name(name)
    except ParseError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return name, format, path


def _source_timezone(text: str) -> tuple[str, str]:
    name, separator, zone = text.partition("=")
    if not separator or not name or not zone:
        raise argparse.ArgumentTypeError("source timezone must be NAME=ZONE")
    try:
        timezone_for_naive(zone)
    except ParseError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return name, zone


def _ingest_url(base: str) -> str:
    parsed = urlsplit(base)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("ingest URL has an invalid port") from exc
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or port is None or port == 0):
        raise ValueError("ingest URL must be http://127.0.0.1:PORT or http://localhost:PORT")
    return f"http://{parsed.hostname}:{port}/api/ingest"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def _serve(args: argparse.Namespace) -> int:
    store = None
    server = None
    stop = threading.Event()
    watchers = []
    try:
        rules = RuleConfig.from_file(args.rules)
        store = Store(args.db, rules=rules)
        token = args.token or os.environ.get("GREYLOG_TOKEN")
        generated_ingest = not token
        token = token or secrets.token_urlsafe(32)
        dashboard_token = args.dashboard_token or os.environ.get("GREYLOG_DASHBOARD_TOKEN")
        generated_dashboard = not dashboard_token
        dashboard_token = dashboard_token or secrets.token_urlsafe(32)
        timezone_for_naive(args.timezone)
        source_zones = dict(args.source_timezone)
        unknown_zones = set(source_zones) - {name for name, _, _ in args.watch}
        if unknown_zones:
            raise ValueError(f"source timezone refers to unwatched source(s): {', '.join(sorted(unknown_zones))}")
        server = GreyLogServer((args.host, args.port), store, token, stop,
                               dashboard_token=dashboard_token, max_connections=args.max_connections)
        watchers = [FileWatcher(store, name, format, path, from_start=args.from_start, stop=stop,
                                naive_timezone=source_zones.get(name, args.timezone))
                    for name, format, path in args.watch]
        for watcher in watchers:
            watcher.start()
        print(f"GreyLog dashboard: http://{args.host}:{server.server_address[1]}/", flush=True)
        if generated_ingest:
            print(f"Generated local ingest token: {token}", flush=True)
        if generated_dashboard:
            print(f"Generated local dashboard token: {dashboard_token}", flush=True)
        print(f"Watching {len(args.watch)} file source(s).", flush=True)
        server.serve_forever(poll_interval=0.25)
        return 0
    except KeyboardInterrupt:
        print("\nGreyLog stopped.", flush=True)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"greylog: {exc}", file=sys.stderr)
        return 2
    finally:
        stop.set()
        if server is not None:
            server.server_close()
        for watcher in watchers:
            if watcher.is_alive():
                watcher.join(timeout=2)
        if store is not None:
            store.close()


def _ingest(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("GREYLOG_TOKEN")
    if not token:
        print("greylog: ingest requires --token or GREYLOG_TOKEN", file=sys.stderr)
        return 2
    source = args.source
    try:
        validate_source_name(source)
        url = _ingest_url(args.url)
        timezone_for_naive(args.timezone)
    except (ValueError, ParseError) as exc:
        print(f"greylog: {exc}", file=sys.stderr)
        return 2
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    stream = sys.stdin if args.file == "-" else None
    try:
        if stream is None:
            stream = open(args.file, encoding="utf-8", errors="replace")
        sent = failed = 0
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            body = json.dumps({"source": source, "format": args.format, "timezone": args.timezone,
                               "line": line.rstrip("\r\n")}).encode("utf-8")
            request = Request(url, data=body, method="POST", headers={
                "Authorization": f"Bearer {token}", "Content-Type": "application/json",
            })
            try:
                with opener.open(request, timeout=10) as response:
                    response.read()
                sent += 1
            except HTTPError as exc:
                failed += 1
                try:
                    detail = json.loads(exc.read()).get("error", exc.reason)
                except (ValueError, OSError):
                    detail = exc.reason
                finally:
                    exc.close()
                print(f"line {number}: HTTP {exc.code}: {detail}", file=sys.stderr)
            except URLError as exc:
                print(f"greylog: cannot reach server: {exc.reason}", file=sys.stderr)
                return 2
        print(f"Ingested {sent} event(s); {failed} failed.")
        return 1 if failed else 0
    except OSError as exc:
        print(f"greylog: {exc}", file=sys.stderr)
        return 2
    finally:
        if stream is not None and stream is not sys.stdin:
            stream.close()


def _check(args: argparse.Namespace) -> int:
    line = sys.stdin.readline() if args.line == "-" else args.line
    try:
        event = parse_line(line, source=args.source, format=args.format, naive_timezone=args.timezone)
    except ParseError as exc:
        print(f"greylog: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(event, indent=2, ensure_ascii=False))
    return 0


def _export(args: argparse.Namespace) -> int:
    directory = Path(args.dir).expanduser().resolve()
    if not directory.is_dir():
        print(f"greylog: export directory does not exist: {directory}", file=sys.stderr)
        return 2
    kinds = ("events", "alerts") if args.which == "both" else (args.which,)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        for kind in kinds:
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=directory,
                                                 prefix=".greylog-export-", suffix=".tmp", delete=False) as output:
                    temp_path = Path(output.name)
                    count = 0
                    for record in iter_database_records(args.db, kind):
                        output.write(json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
                        output.write("\n")
                        count += 1
                    output.flush()
                    os.fsync(output.fileno())
                for _ in range(10):
                    final = directory / f"greylog-{kind}-{timestamp}-{secrets.token_hex(16)}.jsonl"
                    try:
                        # A same-directory hard link publishes the complete file
                        # atomically and fails if the destination already exists.
                        os.link(temp_path, final)
                        break
                    except FileExistsError:
                        continue
                    except OSError:
                        # Some destination filesystems lack hard links. The
                        # exclusive create guarantees that an existing file is
                        # never replaced, including across processes.
                        created = False
                        try:
                            with open(temp_path, "rb") as source, open(final, "xb") as destination:
                                created = True
                                shutil.copyfileobj(source, destination)
                                destination.flush()
                                os.fsync(destination.fileno())
                        except FileExistsError:
                            continue
                        except BaseException:
                            if created:
                                final.unlink(missing_ok=True)
                            raise
                        break
                else:
                    raise OSError("could not reserve a unique export filename")
                print(f"Exported {count} {kind} to {final}")
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
        return 0
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"greylog: export failed: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="greylog", description="Local-first log monitor and live analyst dashboard")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="start loopback API and dashboard")
    serve.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"))
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--db", default="greylog.db", help="SQLite database path")
    serve.add_argument("--watch", type=_watch_spec, action="append", default=[], metavar="NAME:FORMAT:PATH",
                       help="tail a file read-only; repeat for multiple sources")
    serve.add_argument("--from-start", action="store_true", help="read existing file contents instead of new lines only")
    serve.add_argument("--timezone", default="local", help="timezone for naive file timestamps: local, UTC, +HH:MM, or -HH:MM")
    serve.add_argument("--source-timezone", type=_source_timezone, action="append", default=[], metavar="NAME=ZONE",
                       help="override timezone for a watched source; repeat as needed")
    serve.add_argument("--token", help="HTTP ingest bearer token (or GREYLOG_TOKEN)")
    serve.add_argument("--dashboard-token", help="dashboard token (or GREYLOG_DASHBOARD_TOKEN)")
    serve.add_argument("--max-connections", type=int, default=32, help="maximum concurrent local HTTP connections")
    serve.add_argument("--rules", help="JSON rule threshold configuration")
    serve.set_defaults(func=_serve)
    ingest = sub.add_parser("ingest", help="POST file or stdin lines to a running server")
    ingest.add_argument("file", nargs="?", default="-", help="log file path or - for stdin")
    ingest.add_argument("--url", default="http://127.0.0.1:8765", help="server base URL")
    ingest.add_argument("--token", help="HTTP ingest bearer token (or GREYLOG_TOKEN)")
    ingest.add_argument("--source", default="cli", help="source name")
    ingest.add_argument("--format", choices=FORMATS, default="auto")
    ingest.add_argument("--timezone", default="local", help="timezone for naive timestamps: local, UTC, +HH:MM, or -HH:MM")
    ingest.set_defaults(func=_ingest)
    check = sub.add_parser("check", help="parse and normalize one sample line")
    check.add_argument("line", help="sample log line or - to read stdin")
    check.add_argument("--source", default="sample")
    check.add_argument("--format", choices=FORMATS, default="auto")
    check.add_argument("--timezone", default="local", help="timezone for naive timestamps: local, UTC, +HH:MM, or -HH:MM")
    check.set_defaults(func=_check)
    export = sub.add_parser("export", help="export all retained records to JSONL files")
    export.add_argument("which", nargs="?", choices=("events", "alerts", "both"), default="both")
    export.add_argument("--db", default="greylog.db", help="existing SQLite database path")
    export.add_argument("--dir", required=True, help="existing destination directory")
    export.set_defaults(func=_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ngreylog: interrupted", file=sys.stderr)
        return 130
