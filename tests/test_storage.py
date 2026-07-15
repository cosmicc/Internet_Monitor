"""Tests for bounded ephemeral-storage capacity monitoring."""

from types import SimpleNamespace

from internet_monitor import storage


def _filesystem(*, used_percent: int) -> SimpleNamespace:
    """Build a simple 100-block filesystem result for threshold tests."""
    free_blocks = 100 - used_percent
    return SimpleNamespace(
        f_frsize=1024,
        f_bsize=1024,
        f_blocks=100,
        f_bfree=free_blocks,
        f_bavail=free_blocks,
    )


def test_storage_thresholds_are_warning_at_80_and_critical_at_95(monkeypatch):
    """The documented thresholds should classify exact boundaries correctly."""
    filesystems = iter(
        [
            _filesystem(used_percent=79),
            _filesystem(used_percent=80),
            _filesystem(used_percent=95),
        ]
    )
    monkeypatch.setattr(storage.os, "statvfs", lambda path: next(filesystems))

    assert storage.read_storage_status("/tmp/history.json").state == "up"
    warning = storage.read_storage_status("/tmp/history.json")
    critical = storage.read_storage_status("/tmp/history.json")

    assert warning.state == "warning"
    assert warning.used_percent == 80.0
    assert warning.available_bytes == 20 * 1024
    assert critical.state == "down"
    assert critical.used_percent == 95.0


def test_storage_check_uses_closest_existing_parent(tmp_path, monkeypatch):
    """A not-yet-created snapshot directory should still report its filesystem."""
    observed_paths = []

    def fake_statvfs(path):
        observed_paths.append(path)
        return _filesystem(used_percent=10)

    monkeypatch.setattr(storage.os, "statvfs", fake_statvfs)
    snapshot_path = tmp_path / "missing" / "nested" / "history.json"

    result = storage.read_storage_status(str(snapshot_path))

    assert result.state == "up"
    assert observed_paths == [tmp_path]


def test_storage_check_returns_unknown_on_filesystem_error(monkeypatch):
    """Capacity lookup failures should create an explicit web and alert state."""
    monkeypatch.setattr(
        storage.os,
        "statvfs",
        lambda path: (_ for _ in ()).throw(OSError("unavailable")),
    )

    result = storage.read_storage_status("/tmp/history.json")

    assert result.state == "unknown"
    assert result.used_percent is None
    assert result.available_bytes is None
