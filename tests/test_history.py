"""Tests for bounded, ephemeral monitoring history."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from internet_monitor.history import (
    HistorySeries,
    HistoryStore,
    HistoryValue,
    _downsample,
    load_history_payload,
)


def _series() -> list[HistorySeries]:
    """Return a small stable series set for history tests."""
    return [HistorySeries("internet", "Active Internet", "ping", "1.1.1.1")]


def test_history_store_resets_and_restricts_the_snapshot(tmp_path: Path):
    """A new monitor process should start fresh container-scoped history."""
    history_path = tmp_path / "history.json"
    now = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
    store = HistoryStore(str(history_path), _series(), started_at=now)
    store.record(now, {"internet": HistoryValue(12.5, 0)})

    populated = load_history_payload(str(history_path), "24h", 720)

    assert populated["available"] is True
    assert populated["point_count"] == 1
    assert history_path.stat().st_mode & 0o777 == 0o600

    HistoryStore(str(history_path), _series(), started_at=now + timedelta(minutes=1))
    reset = load_history_payload(str(history_path), "24h", 720)

    assert reset["available"] is False
    assert reset["point_count"] == 0


def test_history_retention_uses_detailed_minute_and_hourly_tiers(tmp_path: Path):
    """Each range should use its most efficient loss-preserving tier."""
    history_path = tmp_path / "history.json"
    now = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
    store = HistoryStore(str(history_path), _series(), started_at=now - timedelta(days=40))

    for timestamp, latency in (
        (now - timedelta(days=31), 10.0),
        (now - timedelta(days=29), 20.0),
        (now - timedelta(hours=23), 30.0),
        (now - timedelta(hours=5), 40.0),
        (now, 50.0),
    ):
        store.record(timestamp, {"internet": HistoryValue(latency, 0)})
    store.flush()

    six_hours = load_history_payload(str(history_path), "6h", 720)
    one_day = load_history_payload(str(history_path), "24h", 720)
    thirty_days = load_history_payload(str(history_path), "30d", 720)

    assert six_hours["resolution"] == "detailed"
    assert [point[1][0][0] for point in six_hours["points"]] == [40.0, 50.0]
    assert one_day["resolution"] == "minute"
    assert [point[1][0][0] for point in one_day["points"]] == [30.0, 40.0, 50.0]
    assert thirty_days["resolution"] == "hourly"
    assert [point[1][0][0] for point in thirty_days["points"]] == [
        20.0,
        30.0,
        40.0,
        50.0,
    ]
    assert thirty_days["retention"] == {
        "detailed_hours": 6,
        "minute_hours": 24,
        "total_days": 30,
    }


def test_history_aggregates_latency_and_preserves_maximum_loss(tmp_path: Path):
    """Downsampling must retain outage evidence instead of averaging it away."""
    history_path = tmp_path / "history.json"
    start = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
    store = HistoryStore(str(history_path), _series(), started_at=start)

    for index, (latency, loss) in enumerate(
        ((10.0, 0), (20.0, 25), (30.0, 0), (40.0, 0), (50.0, 0), (60.0, 0))
    ):
        store.record(
            start + timedelta(seconds=index * 10),
            {"internet": HistoryValue(latency, loss)},
        )
    store.flush()

    downsampled = load_history_payload(str(history_path), "1h", 2)
    minute = load_history_payload(str(history_path), "24h", 720)

    assert downsampled["point_count"] == 2
    assert downsampled["points"][0][1][0] == [20.0, 25.0, 10.0, 30.0]
    assert minute["point_count"] == 1
    assert minute["points"][0][1][0] == [35.0, 25.0, 10.0, 60.0]


def test_downsampling_uses_the_full_point_budget_and_preserves_loss():
    """A small overflow should not discard half the available chart detail."""
    records = [
        [
            timestamp,
            [[10.0, 100.0 if timestamp == 400 else 0.0, 9.0, 11.0, 1]],
        ]
        for timestamp in range(721)
    ]

    points = _downsample(records, 720)

    assert len(points) == 720
    assert points[0][0] == 0
    assert points[-1][0] == 720
    assert max(point[1][0][1] for point in points) == 100.0


def test_history_snapshot_publication_is_batched_between_probe_cycles(
    tmp_path: Path,
):
    """Growing history should not be fully serialized after every probe."""
    history_path = tmp_path / "history.json"
    start = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
    monotonic_time = [0.0]
    store = HistoryStore(
        str(history_path),
        _series(),
        started_at=start,
        monotonic_clock=lambda: monotonic_time[0],
    )

    store.record(start, {"internet": HistoryValue(10.0, 0)})
    first_snapshot = load_history_payload(str(history_path), "1h", 720)

    monotonic_time[0] = 10.0
    store.record(start + timedelta(seconds=10), {"internet": HistoryValue(20.0, 0)})
    batched_snapshot = load_history_payload(str(history_path), "1h", 720)

    monotonic_time[0] = 60.0
    store.record(start + timedelta(seconds=60), {"internet": HistoryValue(30.0, 0)})
    published_snapshot = load_history_payload(str(history_path), "1h", 720)

    assert first_snapshot["point_count"] == 1
    assert batched_snapshot["point_count"] == 1
    assert published_snapshot["point_count"] == 3


def test_history_publication_pauses_and_resumes_after_storage_pressure(
    tmp_path: Path,
):
    """Critical tmpfs pressure should not discard in-memory observations."""
    history_path = tmp_path / "history.json"
    start = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
    store = HistoryStore(str(history_path), _series(), started_at=start)

    store.record(
        start,
        {"internet": HistoryValue(10.0, 0)},
        publish_snapshot=False,
    )
    paused_snapshot = load_history_payload(str(history_path), "1h", 720)

    store.record(
        start + timedelta(seconds=10),
        {"internet": HistoryValue(20.0, 0)},
        publish_snapshot=True,
    )
    resumed_snapshot = load_history_payload(str(history_path), "1h", 720)

    assert paused_snapshot["point_count"] == 0
    assert resumed_snapshot["point_count"] == 2


def test_invalid_history_snapshot_fails_closed(tmp_path: Path):
    """Malformed state should produce a stable empty response, not unsafe data."""
    history_path = tmp_path / "history.json"
    history_path.write_text('{"version":1,"series":"invalid"}', encoding="utf-8")

    payload = load_history_payload(str(history_path), "24h", 720)

    assert payload["available"] is False
    assert payload["series"] == []
    assert payload["points"] == []
