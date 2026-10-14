"""Entry point for the one-file Windows executable."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from greylog.cli import main


def portable_default_args() -> list[str]:
    data_root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "GreyLog"
    data_root.mkdir(parents=True, exist_ok=True)
    return ["serve", "--db", str(data_root / "greylog.db")]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or portable_default_args()))
