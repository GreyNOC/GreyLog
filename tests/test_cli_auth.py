"""Exercise the generated credentials through the same CLI and HTTP path users run."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class GeneratedTokenTests(unittest.TestCase):
    def test_cli_dashboard_token_unlocks_and_ingest_token_does_not(self):
        with tempfile.TemporaryDirectory() as folder:
            env = os.environ.copy()
            env.pop("GREYLOG_TOKEN", None)
            env.pop("GREYLOG_DASHBOARD_TOKEN", None)
            process = subprocess.Popen(
                [sys.executable, "-m", "greylog", "serve", "--port", "0",
                 "--db", str(Path(folder) / "greylog.db")],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            lines: queue.Queue[str] = queue.Queue()

            def read_output():
                assert process.stdout is not None
                for line in process.stdout:
                    lines.put(line.rstrip("\r\n"))

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            try:
                startup = []
                for _ in range(10):
                    line = lines.get(timeout=10)
                    startup.append(line)
                    if line.startswith("Watching "):
                        break
                labels = [line.split(": ", 1)[0] for line in startup]
                self.assertIn("GreyLog dashboard", labels)
                self.assertIn("Generated local dashboard token", labels)
                self.assertIn("Generated local ingest token", labels)
                self.assertLess(labels.index("Generated local dashboard token"),
                                labels.index("Generated local ingest token"))
                values = dict(line.split(": ", 1) for line in startup if ": " in line)
                base = values["GreyLog dashboard"]
                dashboard_token = values["Generated local dashboard token"]
                ingest_token = values["Generated local ingest token"]
                self.assertNotEqual(dashboard_token, ingest_token)

                def unlock(token):
                    request = Request(
                        base + "api/session",
                        data=json.dumps({"token": token}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    return urlopen(request, timeout=5)

                with self.assertRaises(HTTPError) as caught:
                    unlock(ingest_token)
                self.assertEqual(caught.exception.code, 401)
                caught.exception.close()
                with unlock(dashboard_token) as response:
                    self.assertEqual(response.status, 204)
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                    self.assertIn("greylog_session=", cookie)
                with urlopen(Request(base + "api/bootstrap", headers={"Cookie": cookie}), timeout=5) as response:
                    self.assertEqual(response.status, 200)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                reader.join(timeout=2)
                if process.stdout is not None:
                    process.stdout.close()


if __name__ == "__main__":
    unittest.main()
