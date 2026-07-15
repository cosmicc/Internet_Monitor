"""Collect and serve ephemeral, container-lifetime monitoring history.

The monitor batches compact atomic JSON snapshots into the container's tmpfs.
Detailed samples are retained briefly, while minute and hourly aggregates keep
longer ranges efficient. Nothing in this module writes to persistent storage.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence


LOGGER = logging.getLogger(__name__)
HISTORY_FORMAT_VERSION = 2
MAX_HISTORY_FILE_BYTES = 8 * 1024 * 1024
MAX_HISTORY_SERIES = 20
MAX_HISTORY_RECORDS = 25_000
SNAPSHOT_INTERVAL_SECONDS = 60
DETAILED_RETENTION_SECONDS = 6 * 60 * 60
MINUTE_RETENTION_SECONDS = 24 * 60 * 60
TOTAL_RETENTION_SECONDS = 30 * 24 * 60 * 60
SERIES_ID_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")
RANGE_SECONDS = {
    "1h": 60 * 60,
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "30d": TOTAL_RETENTION_SECONDS,
}
TIER_BY_RANGE = {
    "1h": "detailed",
    "6h": "detailed",
    "24h": "minute",
    "30d": "hourly",
}
VALID_HISTORY_RANGES = tuple(RANGE_SECONDS)

# Serialized metrics are [average, maximum loss, minimum, maximum, count].
SerializedMetric = list[float | int | None]
SerializedRecord = list[object]


@dataclass(frozen=True)
class HistorySeries:
    """Describe one stable time series stored for the container lifetime."""

    id: str
    label: str
    kind: str
    host: str

    def as_dict(self) -> dict[str, str]:
        """Return the compact, serializable series metadata."""
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "host": self.host,
        }


@dataclass(frozen=True)
class HistoryValue:
    """Represent one latency or DNS timing observation."""

    average: float | None
    loss: float
    minimum: float | None = None
    maximum: float | None = None


def _finite_number(value: object) -> float | None:
    """Return a finite float, rejecting booleans and malformed values."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def _rounded(value: float | None) -> float | None:
    """Round stored measurements to reduce the tmpfs history footprint."""
    return round(value, 2) if value is not None else None


def _serialize_value(value: HistoryValue | None) -> SerializedMetric:
    """Convert one observation into the compact metric representation."""
    if value is None:
        return [None, 0.0, None, None, 0]

    average = _finite_number(value.average)
    minimum = _finite_number(value.minimum)
    maximum = _finite_number(value.maximum)
    loss = _finite_number(value.loss)
    return [
        _rounded(average),
        _rounded(min(100.0, max(0.0, loss or 0.0))),
        _rounded(minimum if minimum is not None else average),
        _rounded(maximum if maximum is not None else average),
        1 if average is not None else 0,
    ]


def _merge_metric(
    existing: SerializedMetric,
    incoming: SerializedMetric,
) -> SerializedMetric:
    """Merge metrics with weighted latency and maximum-loss semantics."""
    existing_average = _finite_number(existing[0])
    incoming_average = _finite_number(incoming[0])
    existing_count = int(existing[4]) if isinstance(existing[4], int) else 0
    incoming_count = int(incoming[4]) if isinstance(incoming[4], int) else 0
    combined_count = existing_count + incoming_count

    average: float | None = None
    if combined_count > 0:
        weighted_total = (
            (existing_average or 0.0) * existing_count
            + (incoming_average or 0.0) * incoming_count
        )
        average = weighted_total / combined_count

    minimum_values = [
        value
        for value in (
            _finite_number(existing[2]),
            _finite_number(incoming[2]),
        )
        if value is not None
    ]
    maximum_values = [
        value
        for value in (
            _finite_number(existing[3]),
            _finite_number(incoming[3]),
        )
        if value is not None
    ]
    existing_loss = _finite_number(existing[1]) or 0.0
    incoming_loss = _finite_number(incoming[1]) or 0.0
    return [
        _rounded(average),
        _rounded(max(existing_loss, incoming_loss)),
        _rounded(min(minimum_values) if minimum_values else None),
        _rounded(max(maximum_values) if maximum_values else None),
        combined_count,
    ]


def _merge_metric_sets(
    existing: list[SerializedMetric],
    incoming: list[SerializedMetric],
) -> list[SerializedMetric]:
    """Merge aligned series metrics for one aggregate bucket."""
    return [
        _merge_metric(left, right)
        for left, right in zip(existing, incoming, strict=True)
    ]


class HistoryStore:
    """Maintain tiered history and atomically publish it to tmpfs."""

    def __init__(
        self,
        path: str,
        series: Sequence[HistorySeries],
        *,
        started_at: datetime | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.path = path
        self.series = tuple(series)
        self.started_at = started_at or datetime.now(timezone.utc)
        self.updated_at: datetime | None = None
        self.detailed: deque[SerializedRecord] = deque()
        self.minute: deque[SerializedRecord] = deque()
        self.hourly: deque[SerializedRecord] = deque()
        self._monotonic_clock = monotonic_clock
        self._last_snapshot_monotonic: float | None = None
        self._write_snapshot()

    def record(
        self,
        timestamp: datetime,
        values: Mapping[str, HistoryValue],
        *,
        publish_snapshot: bool = True,
    ) -> None:
        """Add one probe cycle and publish history when allowed and due."""
        normalized_timestamp = timestamp.astimezone(timezone.utc)
        epoch_seconds = int(normalized_timestamp.timestamp())
        serialized_values = [
            _serialize_value(values.get(series.id)) for series in self.series
        ]

        self.detailed.append([epoch_seconds, serialized_values])
        self._append_aggregate(
            self.minute,
            epoch_seconds // 60 * 60,
            serialized_values,
        )
        self._append_aggregate(
            self.hourly,
            epoch_seconds // 3600 * 3600,
            serialized_values,
        )
        self._prune(epoch_seconds)
        self.updated_at = normalized_timestamp
        if publish_snapshot:
            self._publish_snapshot_if_due()

    def flush(self) -> None:
        """Immediately publish all currently retained records."""
        if self._write_snapshot():
            self._last_snapshot_monotonic = self._monotonic_clock()

    def _publish_snapshot_if_due(self) -> None:
        """Publish once per minute instead of rewriting history each cycle."""
        now = self._monotonic_clock()
        if (
            self._last_snapshot_monotonic is not None
            and now - self._last_snapshot_monotonic
            < SNAPSHOT_INTERVAL_SECONDS
        ):
            return
        if self._write_snapshot():
            self._last_snapshot_monotonic = self._monotonic_clock()

    @staticmethod
    def _append_aggregate(
        records: deque[SerializedRecord],
        bucket_timestamp: int,
        values: list[SerializedMetric],
    ) -> None:
        """Append or update the current aggregate bucket."""
        if records and records[-1][0] == bucket_timestamp:
            records[-1] = [
                bucket_timestamp,
                _merge_metric_sets(records[-1][1], values),
            ]
            return
        records.append([bucket_timestamp, values])

    def _prune(self, now_epoch: int) -> None:
        """Remove records outside their fixed chart-resolution windows."""
        detailed_cutoff = now_epoch - DETAILED_RETENTION_SECONDS
        minute_cutoff = now_epoch - MINUTE_RETENTION_SECONDS
        hourly_cutoff = now_epoch - TOTAL_RETENTION_SECONDS
        while self.detailed and self.detailed[0][0] < detailed_cutoff:
            self.detailed.popleft()
        while self.minute and self.minute[0][0] < minute_cutoff:
            self.minute.popleft()
        while self.hourly and self.hourly[0][0] < hourly_cutoff:
            self.hourly.popleft()

    def _write_snapshot(self) -> bool:
        """Atomically replace the permission-restricted history snapshot."""
        history_directory = os.path.dirname(self.path) or "/"
        temporary_path = f"{self.path}.tmp.{os.getpid()}"
        data = {
            "version": HISTORY_FORMAT_VERSION,
            "started_at": self.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updated_at": (
                self.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if self.updated_at
                else None
            ),
            "retention": {
                "detailed_hours": DETAILED_RETENTION_SECONDS // 3600,
                "minute_hours": MINUTE_RETENTION_SECONDS // 3600,
                "total_days": TOTAL_RETENTION_SECONDS // 86400,
            },
            "series": [item.as_dict() for item in self.series],
            "tiers": {
                "detailed": list(self.detailed),
                "minute": list(self.minute),
                "hourly": list(self.hourly),
            },
        }
        try:
            os.makedirs(history_directory, mode=0o700, exist_ok=True)
            with open(temporary_path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, separators=(",", ":"))
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self.path)
            return True
        except OSError as exc:
            LOGGER.error("Unable to write ephemeral history snapshot: %s", exc)
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
            return False


def _read_history_file(path: str) -> dict[str, object] | None:
    """Read a bounded history snapshot without trusting its structure."""
    try:
        with Path(path).open("rb") as handle:
            raw_history = handle.read(MAX_HISTORY_FILE_BYTES + 1)
    except OSError:
        return None
    if len(raw_history) > MAX_HISTORY_FILE_BYTES:
        return None
    try:
        history = json.loads(raw_history)
    except json.JSONDecodeError:
        return None
    return history if isinstance(history, dict) else None


def _safe_text(value: object, maximum_length: int = 128) -> str:
    """Return bounded history metadata text."""
    return str(value or "").strip()[:maximum_length]


def _sanitize_series(raw_series: object) -> list[dict[str, str]]:
    """Validate series metadata before returning it to a browser."""
    if not isinstance(raw_series, list) or len(raw_series) > MAX_HISTORY_SERIES:
        return []
    series: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for item in raw_series:
        if not isinstance(item, dict):
            return []
        series_id = _safe_text(item.get("id"), 64)
        if not SERIES_ID_PATTERN.fullmatch(series_id) or series_id in seen_ids:
            return []
        seen_ids.add(series_id)
        kind = _safe_text(item.get("kind"), 16)
        if kind not in {"ping", "dns"}:
            return []
        series.append(
            {
                "id": series_id,
                "label": _safe_text(item.get("label"), 128),
                "kind": kind,
                "host": _safe_text(item.get("host"), 128),
            }
        )
    return series


def _sanitize_metric(raw_metric: object) -> SerializedMetric | None:
    """Validate one serialized history metric."""
    if not isinstance(raw_metric, list) or len(raw_metric) != 5:
        return None
    average = _finite_number(raw_metric[0])
    loss = _finite_number(raw_metric[1])
    minimum = _finite_number(raw_metric[2])
    maximum = _finite_number(raw_metric[3])
    count = raw_metric[4]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return None
    return [
        _rounded(average),
        _rounded(min(100.0, max(0.0, loss or 0.0))),
        _rounded(minimum),
        _rounded(maximum),
        count,
    ]


def _sanitize_records(
    raw_records: object,
    series_count: int,
) -> list[SerializedRecord]:
    """Validate one history tier and keep timestamps in ascending order."""
    if not isinstance(raw_records, list) or len(raw_records) > MAX_HISTORY_RECORDS:
        return []
    records: list[SerializedRecord] = []
    previous_timestamp = -1
    for raw_record in raw_records:
        if not isinstance(raw_record, list) or len(raw_record) != 2:
            return []
        timestamp, raw_values = raw_record
        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp < previous_timestamp
            or not isinstance(raw_values, list)
            or len(raw_values) != series_count
        ):
            return []
        values: list[SerializedMetric] = []
        for raw_metric in raw_values:
            metric = _sanitize_metric(raw_metric)
            if metric is None:
                return []
            values.append(metric)
        records.append([timestamp, values])
        previous_timestamp = timestamp
    return records


def _aggregate_record_group(records: Sequence[SerializedRecord]) -> SerializedRecord:
    """Combine consecutive records while preserving the maximum loss."""
    timestamp = int(records[-1][0])
    merged = [list(metric) for metric in records[0][1]]
    for record in records[1:]:
        merged = _merge_metric_sets(merged, record[1])
    return [timestamp, merged]


def _downsample(
    records: list[SerializedRecord],
    maximum_points: int,
) -> list[SerializedRecord]:
    """Reduce a range to a safe point count with loss-preserving buckets."""
    if len(records) <= maximum_points:
        return records
    return [
        _aggregate_record_group(
            records[
                index * len(records) // maximum_points :
                (index + 1) * len(records) // maximum_points
            ]
        )
        for index in range(maximum_points)
    ]


def _select_records(
    raw_tiers: Mapping[str, object],
    range_name: str,
    series_count: int,
) -> tuple[list[SerializedRecord], str]:
    """Validate only the tier needed for the requested chart resolution."""
    tier_name = TIER_BY_RANGE[range_name]
    records = _sanitize_records(raw_tiers.get(tier_name), series_count)
    if not records:
        return [], tier_name
    cutoff = int(records[-1][0]) - RANGE_SECONDS[range_name]
    return [record for record in records if record[0] >= cutoff], tier_name


def empty_history_payload(range_name: str) -> dict[str, object]:
    """Build a stable empty response for startup or invalid history files."""
    return {
        "available": False,
        "range": range_name,
        "resolution": "none",
        "started_at": None,
        "updated_at": None,
        "series": [],
        "points": [],
        "point_count": 0,
    }


def load_history_payload(
    path: str,
    range_name: str,
    maximum_points: int,
) -> dict[str, object]:
    """Load, validate, select, and downsample history for the web API."""
    if range_name not in VALID_HISTORY_RANGES:
        raise ValueError(f"Unsupported history range: {range_name}")
    raw_history = _read_history_file(path)
    if raw_history is None or raw_history.get("version") != HISTORY_FORMAT_VERSION:
        return empty_history_payload(range_name)

    series = _sanitize_series(raw_history.get("series"))
    raw_tiers = raw_history.get("tiers")
    if not series or not isinstance(raw_tiers, dict):
        return empty_history_payload(range_name)
    selected, resolution = _select_records(raw_tiers, range_name, len(series))
    if not selected:
        return {
            **empty_history_payload(range_name),
            "started_at": _safe_text(raw_history.get("started_at")) or None,
            "updated_at": _safe_text(raw_history.get("updated_at")) or None,
            "series": series,
        }

    points = _downsample(selected, maximum_points)
    browser_points = [
        [
            record[0],
            [metric[:4] for metric in record[1]],
        ]
        for record in points
    ]
    return {
        "available": bool(points),
        "range": range_name,
        "resolution": resolution,
        "started_at": _safe_text(raw_history.get("started_at")) or None,
        "updated_at": _safe_text(raw_history.get("updated_at")) or None,
        "retention": {
            "detailed_hours": DETAILED_RETENTION_SECONDS // 3600,
            "minute_hours": MINUTE_RETENTION_SECONDS // 3600,
            "total_days": TOTAL_RETENTION_SECONDS // 86400,
        },
        "series": series,
        "points": browser_points,
        "point_count": len(browser_points),
    }
