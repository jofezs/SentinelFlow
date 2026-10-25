import os
import time
from pathlib import Path

from sentinelflow_common.health import Heartbeat, is_fresh, main


def test_beat_creates_file_and_is_fresh(tmp_path: Path) -> None:
    path = tmp_path / "hb"
    assert not is_fresh(path, 60)
    Heartbeat(path).beat()
    assert is_fresh(path, 60)
    assert main(["--path", str(path), "--max-age", "60"]) == 0


def test_stale_heartbeat_fails(tmp_path: Path) -> None:
    path = tmp_path / "hb"
    Heartbeat(path).beat()
    old = time.time() - 120
    os.utime(path, (old, old))
    assert not is_fresh(path, 60)
    assert main(["--path", str(path), "--max-age", "60"]) == 1


def test_missing_heartbeat_fails(tmp_path: Path) -> None:
    assert main(["--path", str(tmp_path / "nope")]) == 1


def test_beats_are_throttled(tmp_path: Path) -> None:
    path = tmp_path / "hb"
    heartbeat = Heartbeat(path, min_interval=3600)
    heartbeat.beat()
    old = time.time() - 120
    os.utime(path, (old, old))
    heartbeat.beat()  # within min_interval: no touch
    assert not is_fresh(path, 60)
