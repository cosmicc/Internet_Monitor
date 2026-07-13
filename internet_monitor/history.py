"""Collect and serve ephemeral, container-lifetime monitoring history.

The monitor writes a compact atomic JSON snapshot into the container's tmpfs.
Detailed samples are retained briefly, while minute and hourly aggregates keep
longer ranges efficient. Nothing in this module writes to persistent storage.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence


LOGGER = logging.getLogger(__name__)
HISTORY_FORMAT_VERSION = 1
MAX_HISTORY_FILE_BYTES = 56 * 1024 * 1024
MAX_HISTORY_SERIES = 128
MAX_HISTORY_RECORDS = 500_000
SERIES_ID_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")
RANGE_SECONDS = {
    "1h": 60 * 60,
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
}
VALID_HISTORY_RANGES = (*RANGE_SECONDS.keys(), "all")

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
        detailed_hours: int = 24,
        minute_days: int = 30,
        started_at: datetime | None = None,
    ) -> None:
        self.path = path
        self.series = tuple(series)
        self.detailed_hours = detailed_hours
        self.minute_days = minute_days
        self.started_at = started_at or datetime.now(timezone.utc)
        self.updated_at: datetime | None = None
        self.detailed: deque[SerializedRecord] = deque()
        self.minute: deque[SerializedRecord] = deque()
        self.hourly: deque[SerializedRecord] = deque()
        self._write_snapshot()

    def record(
        self,
        timestamp: datetime,
        values: Mapping[str, HistoryValue],
    ) -> None:
        """Add one probe cycle to every retention tier and write a snapshot."""
        normalized_timestamp = timestamp.astimezone(timezone.utc)
        epoch_seconds = int(normalized_timestamp.timestamp())
        serialized_values = [
            _serialize_value(values.get(series.id)) for series in self.series
        ]

        self.detailed.append([epoch_seconds, serialized_values])
        self._append_aggregate(self.minute, epoch_seconds // 60 * 60, serialized_values)
        self._append_aggregate(self.hourly, epoch_seconds // 3600 * 3600, serialized_values)
        self._prune(epoch_seconds)
        self.updated_at = normalized_timestamp
        self._write_snapshot()

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
        """Remove detailed and minute records outside their retention windows."""
        detailed_cutoff = now_epoch - self.detailed_hours * 3600
        minute_cutoff = now_epoch - self.minute_days * 86400
        while self.detailed and self.detailed[0][0] < detailed_cutoff:
            self.detailed.popleft()
        while self.minute and self.minute[0][0] < minute_cutoff:
            self.minute.popleft()

    def _write_snapshot(self) -> None:
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
                "detailed_hours": self.detailed_hours,
                "minute_days": self.minute_days,
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
        except OSError as exc:
            LOGGER.error("Unable to write ephemeral history snapshot: %s", exc)
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def _read_history_file(path: str) -> dict[str, object] | None:
    """Read a bounded history snapshot without trusting its structure."""
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            raw_history = handle.read(MAX_HISTORY_FILE_BYTES + 1)
    except OSError:
        return None
    if len(raw_history.encode("utf-8")) > MAX_HISTORY_FILE_BYTES:
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
    bucket_size = math.ceil(len(records) / maximum_points)
    return [
        _aggregate_record_group(records[index : index + bucket_size])
        for index in range(0, len(records), bucket_size)
    ]


def _parse_retention(raw_retention: object) -> tuple[int, int]:
    """Return validated retention settings stored with the snapshot."""
    if not isinstance(raw_retention, dict):
        return 24, 30
    detailed_hours = raw_retention.get("detailed_hours")
    minute_days = raw_retention.get("minute_days")
    if not isinstance(detailed_hours, int) or not 1 <= detailed_hours <= 168:
        detailed_hours = 24
    if not isinstance(minute_days, int) or not 1 <= minute_days <= 365:
        minute_days = 30
    return detailed_hours, minute_days


def _select_records(
    tiers: Mapping[str, list[SerializedRecord]],
    range_name: str,
    updated_epoch: int,
    detailed_hours: int,
    minute_days: int,
) -> tuple[list[SerializedRecord], str]:
    """Select non-overlapping records appropriate for one dashboard range."""
    if range_name in {"1h", "6h", "24h"}:
        cutoff = updated_epoch - RANGE_SECONDS[range_name]
        return (
            [record for record in tiers["detailed"] if record[0] >= cutoff],
            "detailed",
        )
    if range_name == "7d":
        cutoff = updated_epoch - RANGE_SECONDS[range_name]
        return (
            [record for record in tiers["minute"] if record[0] >= cutoff],
            "minute",
        )

    detailed_cutoff = updated_epoch - detailed_hours * 3600
    minute_cutoff = updated_epoch - minute_days * 86400
    records = [
        record for record in tiers["hourly"] if record[0] < minute_cutoff
    ]
    records.extend(
        record
        for record in tiers["minute"]
        if minute_cutoff <= record[0] < detailed_cutoff
    )
    records.extend(
        record for record in tiers["detailed"] if record[0] >= detailed_cutoff
    )
    return records, "tiered"


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
    tiers = {
        name: _sanitize_records(raw_tiers.get(name), len(series))
        for name in ("detailed", "minute", "hourly")
    }
    all_timestamps = [
        record[0] for records in tiers.values() for record in records
    ]
    if not all_timestamps:
        return {
            **empty_history_payload(range_name),
            "started_at": _safe_text(raw_history.get("started_at")) or None,
            "updated_at": _safe_text(raw_history.get("updated_at")) or None,
            "series": series,
        }

    detailed_hours, minute_days = _parse_retention(raw_history.get("retention"))
    updated_epoch = max(all_timestamps)
    selected, resolution = _select_records(
        tiers,
        range_name,
        updated_epoch,
        detailed_hours,
        minute_days,
    )
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
            "detailed_hours": detailed_hours,
            "minute_days": minute_days,
            "hourly_for_container_lifetime": True,
        },
        "series": series,
        "points": browser_points,
        "point_count": len(browser_points),
    }
