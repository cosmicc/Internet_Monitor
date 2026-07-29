"""Read container-scoped CPU and memory usage from Linux control groups.

The monitor reads the cgroup files already exposed to its Docker container. It
does not mount host filesystems, access the Docker socket, or broaden container
privileges. Both cgroup v2 and the legacy v1 layout are supported.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


MEBIBYTE = 1024 * 1024
CGROUP_V1_UNLIMITED_THRESHOLD = 1 << 60


@dataclass(frozen=True)
class ContainerResources:
    """Represent one container CPU and memory observation."""

    cpu_usage_percent: float | None
    memory_usage_bytes: int | None
    memory_limit_bytes: int | None
    memory_usage_percent: float | None

    @property
    def memory_usage_mib(self) -> float | None:
        """Return current container memory usage in mebibytes."""
        if self.memory_usage_bytes is None:
            return None
        return round(self.memory_usage_bytes / MEBIBYTE, 2)

    @property
    def memory_limit_mib(self) -> float | None:
        """Return the configured container memory limit in mebibytes."""
        if self.memory_limit_bytes is None:
            return None
        return round(self.memory_limit_bytes / MEBIBYTE, 2)

    def as_dict(self) -> dict[str, float | int | None]:
        """Return the bounded values written to the status snapshot."""
        return {
            "cpu_usage_percent": self.cpu_usage_percent,
            "memory_usage_bytes": self.memory_usage_bytes,
            "memory_limit_bytes": self.memory_limit_bytes,
            "memory_usage_percent": self.memory_usage_percent,
            "memory_usage_mib": self.memory_usage_mib,
            "memory_limit_mib": self.memory_limit_mib,
        }


class ContainerResourceMonitor:
    """Calculate container usage from successive cgroup observations."""

    def __init__(
        self,
        cgroup_root: Path | str = Path("/sys/fs/cgroup"),
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Capture the initial CPU counter used by the first completed sample."""
        self.root = Path(cgroup_root)
        self._monotonic_clock = monotonic_clock
        self._is_v2 = (self.root / "cgroup.controllers").is_file()
        self._previous_cpu_seconds = self._read_cpu_usage_seconds()
        self._previous_sample_time = self._monotonic_clock()

    @staticmethod
    def _read_text(path: Path) -> str | None:
        """Read a small kernel value, returning None when it is unavailable."""
        try:
            return path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            return None

    @classmethod
    def _read_integer(cls, path: Path) -> int | None:
        """Read a non-negative integer from a cgroup control file."""
        raw_value = cls._read_text(path)
        try:
            value = int(raw_value) if raw_value is not None else None
        except ValueError:
            return None
        return value if value is not None and value >= 0 else None

    def _first_integer(self, relative_paths: tuple[str, ...]) -> int | None:
        """Return the first readable integer across equivalent v1 locations."""
        for relative_path in relative_paths:
            value = self._read_integer(self.root / relative_path)
            if value is not None:
                return value
        return None

    def _read_cpu_usage_seconds(self) -> float | None:
        """Read cumulative container CPU time in seconds."""
        if self._is_v2:
            raw_stat = self._read_text(self.root / "cpu.stat")
            if raw_stat is None:
                return None
            for line in raw_stat.splitlines():
                name, _, raw_value = line.partition(" ")
                if name == "usage_usec":
                    try:
                        return int(raw_value) / 1_000_000
                    except ValueError:
                        return None
            return None

        usage_nanoseconds = self._first_integer(
            (
                "cpuacct/cpuacct.usage",
                "cpu,cpuacct/cpuacct.usage",
                "cpuacct.usage",
            )
        )
        if usage_nanoseconds is None:
            return None
        return usage_nanoseconds / 1_000_000_000

    @staticmethod
    def _parse_cpu_set(raw_value: str | None) -> int | None:
        """Count CPUs in a Linux cpuset range such as ``0-2,5``."""
        if not raw_value:
            return None
        cpu_count = 0
        try:
            for item in raw_value.split(","):
                start_text, separator, end_text = item.partition("-")
                start = int(start_text)
                end = int(end_text) if separator else start
                if start < 0 or end < start:
                    return None
                cpu_count += end - start + 1
        except ValueError:
            return None
        return cpu_count or None

    def _cpu_capacity(self) -> float:
        """Return the CPU allocation used to normalize usage to 0–100%."""
        if self._is_v2:
            cpu_max = self._read_text(self.root / "cpu.max")
            if cpu_max:
                quota_text, _, period_text = cpu_max.partition(" ")
                if quota_text != "max":
                    try:
                        quota = int(quota_text)
                        period = int(period_text)
                        if quota > 0 and period > 0:
                            return quota / period
                    except ValueError:
                        pass
            cpuset = self._read_text(self.root / "cpuset.cpus.effective")
        else:
            quota = self._first_integer(
                (
                    "cpu/cpu.cfs_quota_us",
                    "cpu,cpuacct/cpu.cfs_quota_us",
                    "cpu.cfs_quota_us",
                )
            )
            period = self._first_integer(
                (
                    "cpu/cpu.cfs_period_us",
                    "cpu,cpuacct/cpu.cfs_period_us",
                    "cpu.cfs_period_us",
                )
            )
            if quota is not None and period and 0 < quota < CGROUP_V1_UNLIMITED_THRESHOLD:
                return quota / period
            cpuset = None
            for path in (
                "cpuset/cpuset.cpus",
                "cpuset.cpus",
            ):
                cpuset = self._read_text(self.root / path)
                if cpuset:
                    break

        cpuset_count = self._parse_cpu_set(cpuset)
        return float(cpuset_count or os.cpu_count() or 1)

    def _read_memory(self) -> tuple[int | None, int | None]:
        """Return current usage and a finite container memory limit."""
        if self._is_v2:
            usage = self._read_integer(self.root / "memory.current")
            raw_limit = self._read_text(self.root / "memory.max")
            if raw_limit == "max":
                return usage, None
            try:
                limit = int(raw_limit) if raw_limit is not None else None
            except ValueError:
                limit = None
            return usage, limit if limit and limit > 0 else None

        usage = self._first_integer(
            (
                "memory/memory.usage_in_bytes",
                "memory.usage_in_bytes",
            )
        )
        limit = self._first_integer(
            (
                "memory/memory.limit_in_bytes",
                "memory.limit_in_bytes",
            )
        )
        if limit is not None and limit >= CGROUP_V1_UNLIMITED_THRESHOLD:
            limit = None
        return usage, limit if limit and limit > 0 else None

    def sample(self) -> ContainerResources:
        """Read current memory and calculate CPU usage since the prior sample."""
        sampled_at = self._monotonic_clock()
        cpu_seconds = self._read_cpu_usage_seconds()
        elapsed_seconds = sampled_at - self._previous_sample_time
        cpu_usage_percent: float | None = None
        if (
            cpu_seconds is not None
            and self._previous_cpu_seconds is not None
            and elapsed_seconds > 0
            and cpu_seconds >= self._previous_cpu_seconds
        ):
            used_seconds = cpu_seconds - self._previous_cpu_seconds
            normalized_usage = (
                used_seconds / elapsed_seconds / self._cpu_capacity() * 100
            )
            cpu_usage_percent = round(
                min(100.0, max(0.0, normalized_usage)),
                2,
            )

        self._previous_cpu_seconds = cpu_seconds
        self._previous_sample_time = sampled_at

        memory_usage_bytes, memory_limit_bytes = self._read_memory()
        memory_usage_percent: float | None = None
        if memory_usage_bytes is not None and memory_limit_bytes:
            memory_usage_percent = round(
                min(100.0, max(0.0, memory_usage_bytes / memory_limit_bytes * 100)),
                2,
            )

        return ContainerResources(
            cpu_usage_percent=cpu_usage_percent,
            memory_usage_bytes=memory_usage_bytes,
            memory_limit_bytes=memory_limit_bytes,
            memory_usage_percent=memory_usage_percent,
        )
