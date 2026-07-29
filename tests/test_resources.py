"""Tests for container-scoped cgroup resource measurements."""

from pathlib import Path

from internet_monitor.resources import ContainerResourceMonitor


class Clock:
    """Provide deterministic monotonic timestamps for CPU calculations."""

    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_cgroup_v2_sample_calculates_allocated_cpu_and_memory(tmp_path: Path):
    """CPU should use the cgroup quota and memory should use its finite limit."""
    (tmp_path / "cgroup.controllers").write_text(
        "cpuset cpu memory\n",
        encoding="utf-8",
    )
    (tmp_path / "cpu.stat").write_text("usage_usec 1000000\n", encoding="utf-8")
    (tmp_path / "cpu.max").write_text("200000 100000\n", encoding="utf-8")
    (tmp_path / "cpuset.cpus.effective").write_text("0-7\n", encoding="utf-8")
    (tmp_path / "memory.current").write_text("52428800\n", encoding="utf-8")
    (tmp_path / "memory.max").write_text("209715200\n", encoding="utf-8")
    clock = Clock(100.0)
    resource_monitor = ContainerResourceMonitor(tmp_path, monotonic_clock=clock)

    (tmp_path / "cpu.stat").write_text("usage_usec 2000000\n", encoding="utf-8")
    clock.value = 102.0
    sample = resource_monitor.sample()

    assert sample.cpu_usage_percent == 25.0
    assert sample.memory_usage_bytes == 52_428_800
    assert sample.memory_limit_bytes == 209_715_200
    assert sample.memory_usage_mib == 50.0
    assert sample.memory_limit_mib == 200.0
    assert sample.memory_usage_percent == 25.0


def test_unlimited_cgroup_memory_still_reports_usage(tmp_path: Path):
    """An unlimited container should show MiB without inventing a percentage."""
    (tmp_path / "cgroup.controllers").write_text(
        "cpuset cpu memory\n",
        encoding="utf-8",
    )
    (tmp_path / "cpu.stat").write_text("usage_usec 1000000\n", encoding="utf-8")
    (tmp_path / "cpu.max").write_text("max 100000\n", encoding="utf-8")
    (tmp_path / "cpuset.cpus.effective").write_text("0-1\n", encoding="utf-8")
    (tmp_path / "memory.current").write_text("10485760\n", encoding="utf-8")
    (tmp_path / "memory.max").write_text("max\n", encoding="utf-8")
    clock = Clock(1.0)
    resource_monitor = ContainerResourceMonitor(tmp_path, monotonic_clock=clock)

    clock.value = 2.0
    sample = resource_monitor.sample()

    assert sample.memory_usage_mib == 10.0
    assert sample.memory_limit_bytes is None
    assert sample.memory_limit_mib is None
    assert sample.memory_usage_percent is None


def test_cgroup_v1_sample_uses_legacy_controller_files(tmp_path: Path):
    """Legacy Docker hosts should retain container-scoped resource metrics."""
    for directory in ("cpu", "cpuacct", "cpuset", "memory"):
        (tmp_path / directory).mkdir()
    (tmp_path / "cpuacct/cpuacct.usage").write_text(
        "1000000000\n",
        encoding="utf-8",
    )
    (tmp_path / "cpu/cpu.cfs_quota_us").write_text(
        "100000\n",
        encoding="utf-8",
    )
    (tmp_path / "cpu/cpu.cfs_period_us").write_text(
        "100000\n",
        encoding="utf-8",
    )
    (tmp_path / "cpuset/cpuset.cpus").write_text("0-3\n", encoding="utf-8")
    (tmp_path / "memory/memory.usage_in_bytes").write_text(
        "26214400\n",
        encoding="utf-8",
    )
    (tmp_path / "memory/memory.limit_in_bytes").write_text(
        "104857600\n",
        encoding="utf-8",
    )
    clock = Clock(10.0)
    resource_monitor = ContainerResourceMonitor(tmp_path, monotonic_clock=clock)

    (tmp_path / "cpuacct/cpuacct.usage").write_text(
        "1500000000\n",
        encoding="utf-8",
    )
    clock.value = 11.0
    sample = resource_monitor.sample()

    assert sample.cpu_usage_percent == 50.0
    assert sample.memory_usage_mib == 25.0
    assert sample.memory_limit_mib == 100.0
    assert sample.memory_usage_percent == 25.0


def test_missing_cgroup_files_fail_closed(tmp_path: Path):
    """Missing kernel counters should produce unavailable values, not host data."""
    resource_monitor = ContainerResourceMonitor(
        tmp_path,
        monotonic_clock=lambda: 1.0,
    )

    sample = resource_monitor.sample()

    assert sample.cpu_usage_percent is None
    assert sample.memory_usage_bytes is None
    assert sample.memory_usage_percent is None
