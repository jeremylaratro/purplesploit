"""Compatibility helpers for ISO 8601 and RFC 3339 timestamps."""

from datetime import datetime


def parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO timestamp, including RFC 3339's UTC ``Z`` suffix on Python 3.10."""
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)
