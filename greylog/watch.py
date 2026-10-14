"""Read-only file tailing for real log sources."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from .events import MAX_LINE, ParseError, parse_line
from .store import Store


class FileWatcher(threading.Thread):
    def __init__(self, store: Store, name: str, format: str, path: str, *, from_start: bool = False,
                 stop: threading.Event | None = None, naive_timezone: str = "local"):
        super().__init__(name=f"greylog-watch-{name}", daemon=True)
        self.store = store
        self.source_name = name
        self.format = format
        self.path = Path(path).expanduser()
        self.from_start = from_start
        self.naive_timezone = naive_timezone
        self.stop = stop or threading.Event()
        self._last_io_error: str | None = None
        self.store.register_source(name, format)

    def run(self) -> None:
        stream = None
        file_id = None
        first_open = True
        last_touch = 0.0
        while not self.stop.is_set():
            processed = 0
            try:
                stat = self.path.stat()
                identity = (stat.st_dev, stat.st_ino)
                if stream is None or identity != file_id or stat.st_size < stream.tell():
                    if stream:
                        stream.close()
                    # Binary offsets make truncation and rotation checks reliable on
                    # Windows and POSIX, including multibyte UTF-8 log content.
                    stream = self.path.open("rb")
                    file_id = identity
                    if first_open and not self.from_start:
                        stream.seek(0, 2)
                    first_open = False
                    recovered = self._last_io_error is not None
                    self._last_io_error = None
                    self.store.touch_source(self.source_name, recovered_io=recovered)
                    last_touch = time.monotonic()
                if time.monotonic() - last_touch >= 5:
                    self.store.touch_source(self.source_name)
                    last_touch = time.monotonic()
                while processed < 500 and not self.stop.is_set():
                    offset = stream.tell()
                    line = stream.readline(MAX_LINE + 2)
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        if len(line) <= MAX_LINE:
                            stream.seek(offset)
                            break
                        # Discard the rest of a line that exceeds the cap.
                        while line and not line.endswith(b"\n"):
                            line = stream.readline(MAX_LINE + 2)
                        self.store.mark_error(self.source_name, self.format, f"line exceeds {MAX_LINE} bytes")
                        processed += 1
                        continue
                    if len(line.rstrip(b"\r\n")) > MAX_LINE:
                        self.store.mark_error(self.source_name, self.format, f"line exceeds {MAX_LINE} bytes")
                        processed += 1
                        continue
                    try:
                        event = parse_line(line.decode("utf-8", errors="replace"), source=self.source_name,
                                           format=self.format, naive_timezone=self.naive_timezone)
                        self.store.add_event(event, format=self.format)
                    except ParseError as exc:
                        self.store.mark_error(self.source_name, self.format, str(exc))
                    processed += 1
            except OSError as exc:
                detail = f"file watch error: {exc.strerror or type(exc).__name__}"
                if detail != self._last_io_error:
                    self.store.mark_error(self.source_name, self.format, detail)
                    self._last_io_error = detail
                if stream:
                    stream.close()
                    stream = None
            self.stop.wait(0.25 if processed else 0.75)
        if stream:
            stream.close()
