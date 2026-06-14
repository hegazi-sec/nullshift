from datetime import datetime, timedelta
import re
from typing import Optional, Tuple


def parse_time_range(range_str: str):
    """Support formats like last_1h, last_15m, last_24h"""
    m = re.match(r"last_(\d+)([smhd])", range_str)
    if not m:
        return datetime.utcnow() - timedelta(hours=1)
    val = int(m.group(1))
    unit = m.group(2)
    if unit == 's':
        return datetime.utcnow() - timedelta(seconds=val)
    if unit == 'm':
        return datetime.utcnow() - timedelta(minutes=val)
    if unit == 'h':
        return datetime.utcnow() - timedelta(hours=val)
    if unit == 'd':
        return datetime.utcnow() - timedelta(days=val)
    return datetime.utcnow() - timedelta(hours=1)


def normalize_window(message_or_hint: Optional[str], default_hours: int = 24) -> Tuple[str, str, str]:
    """Return (gte, lte, label) where:
    - Recognizes phrases like 'last 48h', 'last 2 days', 'last_24h', 'last 15m'
    - Defaults to 24h when unspecified or unrecognized
    - gte is in 'now-<n><unit>' format; lte is 'now'
    - label is 'last_<n><unit>' normalized to hours/days/minutes as parsed
    """
    text = (message_or_hint or "").lower().strip()
    lte = "now"
    # Patterns to check in order
    # 1) last_24h-like
    m = re.search(r"\blast[_\s]?(\d+)([smhd])\b", text)
    if m:
        n = int(m.group(1))
        u = m.group(2)
        # Normalize label and gte directly
        return (f"now-{n}{u}", lte, f"last_{n}{u}")
    # 1b) shorthand like '48h' or '48 h' or '48 hours'
    m = re.search(r"\b(\d+)\s*(h|hours?)\b", text)
    if m:
        n = int(m.group(1))
        return (f"now-{n}h", lte, f"last_{n}h")
    # 2) 'last 48h' / 'last 2 days' / 'last 2 day' / 'last 120 minutes'
    m = re.search(r"\blast\s+(\d+)\s*(hours?|hrs?|h)\b", text)
    if m:
        n = int(m.group(1))
        return (f"now-{n}h", lte, f"last_{n}h")
    m = re.search(r"\blast\s+(\d+)\s*(days?|d)\b", text)
    if m:
        n = int(m.group(1))
        hours = n * 24
        return (f"now-{hours}h", lte, f"last_{hours}h")
    # '5 days ago' -> treat as last 5 days
    m = re.search(r"\b(\d+)\s*(days?|d)\s+ago\b", text)
    if m:
        n = int(m.group(1))
        hours = n * 24
        return (f"now-{hours}h", lte, f"last_{hours}h")
    m = re.search(r"\blast\s+(\d+)\s*(minutes?|mins?|m)\b", text)
    if m:
        n = int(m.group(1))
        return (f"now-{n}m", lte, f"last_{n}m")
    # bare minutes like '15m' or '15 m'
    m = re.search(r"\b(\d+)\s*(m|minutes?)\b", text)
    if m:
        n = int(m.group(1))
        return (f"now-{n}m", lte, f"last_{n}m")
    # Default when unspecified
    return (f"now-{int(default_hours)}h", lte, f"last_{int(default_hours)}h")
