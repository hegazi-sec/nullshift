import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TimeWindow:
    label: str
    gte: str
    lte: str = "now"
    time_was_specified: bool = True


# Sentinel returned when the user's message contains no time expression.
# Uses a 7-day window — wide enough to catch recent detections, short enough
# to stay within LC's and most cloud SIEM API range limits.
# The limit=200 cap ensures we only return the 200 most recent events.
NO_TIME_SPECIFIED = TimeWindow("recent_200", "now-7d", "now", time_was_specified=False)


_WORD_NUMS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}

_UNIT_MAP = {
    # minutes
    "m": "m", "min": "m", "mins": "m", "minute": "m", "minutes": "m",
    # hours
    "h": "h", "hr": "h", "hrs": "h", "hour": "h", "hours": "h",
    # days
    "d": "d", "day": "d", "days": "d",
    # weeks
    "w": "w", "wk": "w", "wks": "w", "week": "w", "weeks": "w",
    # months -> 30d approximation
    "mo": "mo", "month": "mo", "months": "mo",
}


def _normalize(text: str) -> str:
    s = (text or "").lower()
    # keep letters, digits, whitespace; replace others with space
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _clamp_duration(value: int, unit: str) -> int:
    # min 1m
    if unit == "m":
        return max(1, min(value, 365 * 24 * 60))  # 365d in minutes
    if unit == "h":
        return max(1, min(value, 365 * 24))
    if unit == "d":
        return max(1, min(value, 365))
    if unit == "w":
        return max(1, min(value, 52))
    if unit == "mo":
        return max(1, min(value, 12))
    return value


def parse_time_window(text: str) -> TimeWindow:
    """Parse an explicit time expression from the user's message.

    Returns NO_TIME_SPECIFIED when the message contains no time expression.
    The investigation service treats that sentinel as "pull most recent 200
    events with no time constraint" instead of defaulting to 24h.
    """
    s = _normalize(text)
    if not s:
        return NO_TIME_SPECIFIED

    # Prefer matches near keywords 'last' or 'past' by capturing small windows after them
    # Examples matched:
    #   last 72 hours | last 100h | past 3 days | in the last 15 minutes | last 2w | last 1 month
    patterns = [
        r"\b(?:in the\s+)?(?:(?:last)|(?:past))\s+(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|month|months)\b",
        r"\b(?:in the\s+)?(?:(?:last)|(?:past))\s+(one|two|three|four|five|six|seven|eight|nine|ten)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|month|months)\b",
        r"\b(?:last|past)\s*(\d+)(m|h|d|w|mo)\b",
    ]

    match: Optional[re.Match] = None
    for pat in patterns:
        match = re.search(pat, s)
        if match:
            break

    if not match:
        return NO_TIME_SPECIFIED

    raw_val = match.group(1)
    raw_unit = match.group(2)

    # Convert words to numbers if needed
    try:
        val = int(raw_val)
    except ValueError:
        val = _WORD_NUMS.get(raw_val, None)
        if val is None:
            return default

    unit_key = raw_unit.lower()
    unit = _UNIT_MAP.get(unit_key)
    if not unit:
        return default

    # months -> 30d approximation
    if unit == "mo":
        val = _clamp_duration(val, unit)
        days = val * 30
        days = _clamp_duration(days, "d")
        label = f"last_{days}d"
        return TimeWindow(label=label, gte=f"now-{days}d", lte="now")

    # Clamp to safe bounds
    val = _clamp_duration(val, unit)
    label = f"last_{val}{unit}"
    return TimeWindow(label=label, gte=f"now-{val}{unit}", lte="now")


def _self_test() -> dict:
    cases = {
        "sqlmap last 48h": ("now-48h", "last_48h"),
        "sqlmap last 3 days": ("now-3d", "last_3d"),
        "sqlmap last 72 hours": ("now-72h", "last_72h"),
        "sqlmap last 100 hours": ("now-100h", "last_100h"),
        "sqlmap last 15m": ("now-15m", "last_15m"),
        "sqlmap": ("now-24h", "last_24h"),
    }
    results = {}
    for text, (gte_expect, label_expect) in cases.items():
        tw = parse_time_window(text)
        results[text] = {
            "gte": tw.gte,
            "label": tw.label,
            "ok": (tw.gte == gte_expect and tw.label == label_expect),
        }
    return results
