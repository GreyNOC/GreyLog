"""Exercise the frozen dashboard, including bundled assets and session auth."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main() -> int:
    exe = Path(sys.argv[1]).resolve()
    if not exe.is_file():
        raise FileNotFoundError(exe)
    with tempfile.TemporaryDirectory(prefix="greylog-portable-smoke-") as temp:
        database = Path(temp) / "greylog.db"
        env = os.environ.copy()
        env.pop("GREYLOG_TOKEN", None)
        env.pop("GREYLOG_DASHBOARD_TOKEN", None)
        process = subprocess.Popen(
            [str(exe), "serve", "--db", str(database), "--port", "0"],
            cwd=temp, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        lines: queue.Queue[str] = queue.Queue()

        def read_output() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                lines.put(line.rstrip("\r\n"))

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + 20
            startup: dict[str, str] = {}
            required = {"GreyLog dashboard", "Generated local dashboard token", "Generated local ingest token"}
            while not required <= startup.keys():
                if time.monotonic() > deadline:
                    raise AssertionError("portable EXE did not print its dashboard URL and generated tokens")
                try:
                    line = lines.get(timeout=0.25)
                except queue.Empty:
                    if process.poll() is not None:
                        raise AssertionError(f"portable EXE exited early with code {process.returncode}")
                    continue
                if ": " in line:
                    label, value = line.split(": ", 1)
                    startup[label] = value
            base = startup["GreyLog dashboard"]
            dashboard_token = startup["Generated local dashboard token"]
            ingest_token = startup["Generated local ingest token"]
            assert dashboard_token and ingest_token and dashboard_token != ingest_token
            with urlopen(base, timeout=2) as response:
                assert response.status == 200
                assert b"GreyLog" in response.read()
            with urlopen(base + "app.js", timeout=2) as response:
                assert response.status == 200
                assert b"/api/session" in response.read()
            wrong = Request(base + "api/session", data=json.dumps({"token": ingest_token}).encode(),
                            method="POST", headers={"Content-Type": "application/json"})
            try:
                urlopen(wrong, timeout=2)
            except HTTPError as error:
                assert error.code == 401
                error.close()
            else:
                raise AssertionError("ingest token unlocked the dashboard")
            right = Request(base + "api/session", data=json.dumps({"token": dashboard_token}).encode(),
                            method="POST", headers={"Content-Type": "application/json"})
            with urlopen(right, timeout=2) as response:
                assert response.status == 204
                assert "greylog_session=" in response.headers["Set-Cookie"]
            print("Portable EXE dashboard and token smoke passed.")
            return 0
        finally:
            if os.name == "nt":
                # PyInstaller one-file mode has a parent extractor and child app.
                # Kill the tree so the child releases the temporary database.
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=2)
            if process.stdout is not None:
                process.stdout.close()
            if os.name == "nt":
                # taskkill can return before the frozen child releases SQLite
                # sidecars; wait for that child before TemporaryDirectory exits.
                deadline = time.monotonic() + 5
                while True:
                    try:
                        for path in database.parent.glob(database.name + "*"):
                            path.unlink(missing_ok=True)
                        break
                    except PermissionError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)


if __name__ == "__main__":
    raise SystemExit(main())
