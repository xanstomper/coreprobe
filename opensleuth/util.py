"""Shared helpers: Apple epoch timestamps, plists, sizes."""

import plistlib
from datetime import datetime, timezone
from pathlib import Path

# Seconds between the Unix epoch (1970) and Apple's epoch (2001-01-01).
APPLE_EPOCH = 978307200


def apple_to_dt(value):
    """Convert an Apple-epoch timestamp (seconds since 2001-01-01) to ISO-8601 UTC."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(APPLE_EPOCH + float(value), tz=timezone.utc).isoformat(
            timespec="seconds"
        )
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def unix_to_dt(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def load_plist(path: Path):
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def fmt_size(n):
    if n is None:
        return ""
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TiB"


def iso_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")