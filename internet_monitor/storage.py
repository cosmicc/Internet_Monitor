"""Measure the filesystem that holds ephemeral monitoring snapshots."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


STORAGE_WARNING_PERCENT = 80.0
STORAGE_CRITICAL_PERCENT = 95.0


@dataclass(frozen=True)
class StorageStatus:
    """Represent bounded tmpfs capacity information for alerts and the web UI."""

    state: str
    used_percent: float | None
    total_bytes: int | None
    available_bytes: int | None
    warning_percent: float = STORAGE_WARNING_PERCENT
    critical_percent: float = STORAGE_CRITICAL_PERCENT

    def as_dict(self) -> dict[str, str | float | int | None]:
        """Return the public status fields without exposing filesystem paths."""
        return {
            "state": self.state,
            "used_percent": self.used_percent,
            "total_bytes": self.total_bytes,
            "available_bytes": self.available_bytes,
            "warning_percent": self.warning_percent,
            "critical_percent": self.critical_percent,
        }


def _existing_parent(snapshot_path: str) -> Path:
    """Find the closest existing directory for a configured snapshot path."""
    directory = Path(snapshot_path).expanduser().parent
    while not directory.exists() and directory != directory.parent:
        directory = directory.parent
    return directory


def read_storage_status(snapshot_path: str) -> StorageStatus:
    """Read capacity with warning and critical thresholds, failing closed."""
    try:
        filesystem = os.statvfs(_existing_parent(snapshot_path))
    except OSError:
        return StorageStatus("unknown", None, None, None)

    block_size = filesystem.f_frsize or filesystem.f_bsize
    total_bytes = filesystem.f_blocks * block_size
    free_bytes = filesystem.f_bfree * block_size
    available_bytes = filesystem.f_bavail * block_size
    if total_bytes <= 0:
        return StorageStatus("unknown", None, None, None)

    used_percent = round(
        min(100.0, max(0.0, (total_bytes - free_bytes) * 100 / total_bytes)),
        2,
    )
    if used_percent >= STORAGE_CRITICAL_PERCENT:
        state = "down"
    elif used_percent >= STORAGE_WARNING_PERCENT:
        state = "warning"
    else:
        state = "up"
    return StorageStatus(
        state,
        used_percent,
        total_bytes,
        available_bytes,
    )
