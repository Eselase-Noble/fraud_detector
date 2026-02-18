"""
utils.py
--------
Shared utilities used across the fraud detection system.
"""
from __future__ import annotations

from datetime import datetime, timezone


def to_utc(dt: datetime) -> datetime:
    """
    Normalise any datetime to UTC-aware.
    Naive datetimes (no tzinfo) are assumed to already be UTC —
    they just get the label attached.
    Aware datetimes in other zones are converted to UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utc_now() -> datetime:
    """Return the current time as a UTC-aware datetime."""
    return datetime.now(timezone.utc)