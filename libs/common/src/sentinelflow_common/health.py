"""File-based liveness heartbeat for workers that have no HTTP server.

Workers call ``Heartbeat.beat()`` from their main loop. The container
healthcheck (and the Kubernetes liveness probe) runs::

    python -m sentinelflow_common.health --max-age 60

If the loop wedges (e.g. a hung broker connection), the file goes stale, the
check fails, and the orchestrator restarts the container.
"""

import argparse
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_PATH = Path(tempfile.gettempdir()) / "sentinelflow-heartbeat"


class Heartbeat:
    def __init__(self, path: Path = DEFAULT_PATH, min_interval: float = 5.0) -> None:
        self.path = path
        self._min_interval = min_interval
        self._last = float("-inf")

    def beat(self) -> None:
        """Touch the heartbeat file (throttled; cheap to call in a tight loop)."""
        now = time.monotonic()
        if now - self._last >= self._min_interval:
            self.path.touch()
            self._last = now


def is_fresh(path: Path, max_age: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime <= max_age
    except FileNotFoundError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Exit 0 if the worker heartbeat is fresh.")
    parser.add_argument("--path", type=Path, default=DEFAULT_PATH)
    parser.add_argument("--max-age", type=float, default=60.0, help="seconds")
    args = parser.parse_args(argv)
    return 0 if is_fresh(args.path, args.max_age) else 1


if __name__ == "__main__":
    sys.exit(main())
