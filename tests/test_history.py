"""Tests for bounded, ephemeral monitoring history."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from internet_monitor.history import (
    HistorySeries,
    HistoryStore,
    HistoryValue,
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
    """All history should combine non-overlapping tiers for container lifetime."""
    history_path = tmp_path / "history.json"
    now = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
    store = HistoryStore(str(history_path), _series(), started_at=now - timedelta(days=40))

    for timestamp, latency in (
        (now - timedelta(days=40), 10.0),
        (now - timedelta(days=29), 20.0),
        (now - timedelta(hours=23), 30.0),
        (now, 40.0),
    ):
        store.record(timestamp, {"internet": HistoryValue(latency, 0)})

    one_day = load_history_payload(str(history_path), "24h", 720)
    seven_days = load_history_payload(str(history_path), "7d", 720)
    all_history = load_history_payload(str(history_path), "all", 720)

    assert one_day["resolution"] == "detailed"
    assert [point[1][0][0] for point in one_day["points"]] == [30.0, 40.0]
    assert seven_days["resolution"] == "minute"
    assert [point[1][0][0] for point in seven_days["points"]] == [30.0, 40.0]
    assert all_history["resolution"] == "tiered"
    assert [point[1][0][0] for point in all_history["points"]] == [
        10.0,
        20.0,
        30.0,
        40.0,
    ]


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

    downsampled = load_history_payload(str(history_path), "1h", 2)
    minute = load_history_payload(str(history_path), "7d", 720)

    assert downsampled["point_count"] == 2
    assert downsampled["points"][0][1][0] == [20.0, 25.0, 10.0, 30.0]
    assert minute["point_count"] == 1
    assert minute["points"][0][1][0] == [35.0, 25.0, 10.0, 60.0]


def test_invalid_history_snapshot_fails_closed(tmp_path: Path):
    """Malformed state should produce a stable empty response, not unsafe data."""
    history_path = tmp_path / "history.json"
    history_path.write_text('{"version":1,"series":"invalid"}', encoding="utf-8")

    payload = load_history_payload(str(history_path), "24h", 720)

    assert payload["available"] is False
    assert payload["series"] == []
    assert payload["points"] == []
