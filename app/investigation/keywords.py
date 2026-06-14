from __future__ import annotations

import re
from typing import List


# Deterministic threat tool names — if present in the user's message, use
# them as a targeted keyword filter rather than pulling all recent events.
THREAT_TERMS = {
    "sqlmap", "mimikatz", "nmap", "powershell", "injection",
    "exploit", "malware", "brute", "scan", "cobalt", "metasploit",
    "meterpreter", "bloodhound", "sharphound", "rubeus", "kerberoast",
    "pass-the-hash", "pass-the-ticket", "whoami", "certutil", "regsvr32",
    "mshta", "wscript", "cscript", "rundll32", "schtasks", "at.exe",
    "netcat", "nc.exe", "psexec", "wmiexec", "dcsync",
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_CVE_RE = re.compile(r"\bcve-\d{4}-\d{4,}\b", re.IGNORECASE)


def _normalize_text(message: str) -> str:
    msg = (message or "").lower()
    msg = re.sub(r"[^a-z0-9\.\-\s]", " ", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg


def extract_security_keywords(message: str) -> List[str]:
    """Return only concrete IOCs and threat tool names from the user's message.

    Returns an empty list for generic natural-language queries (e.g. "show me
    detections", "any suspicious activity?"). The empty list is the signal to
    the investigation service to pull recent events broadly and let the LLM
    analyse them — rather than sending useless English words to the SIEM.

    Returns non-empty only when the message contains:
    - An IPv4 address
    - An MD5 / SHA1 / SHA256 hash
    - A CVE identifier
    - A named threat tool (mimikatz, nmap, sqlmap, …)
    """
    text = _normalize_text(message)
    original = (message or "").lower()

    # Threat tool names: single dominant keyword when found.
    # Use whole-word matching so "exploit" doesn't trigger on "exploitation".
    tokens = text.split()
    for tok in tokens:
        if tok in THREAT_TERMS:
            return [tok]
    # Hyphenated terms (pass-the-hash) won't appear as single tokens after
    # split, so check them with a word-boundary regex against the original.
    for term in THREAT_TERMS:
        if "-" in term and re.search(r"(?<![a-z])" + re.escape(term) + r"(?![a-z])", original):
            return [term]

    out: List[str] = []
    seen: set = set()

    # IPv4 addresses
    for ip in _IP_RE.findall(message or ""):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)

    # File hashes
    for h in _HASH_RE.findall(message or ""):
        if h not in seen:
            seen.add(h)
            out.append(h)

    # CVE IDs
    for cve in _CVE_RE.findall(message or ""):
        low = cve.lower()
        if low not in seen:
            seen.add(low)
            out.append(low)

    return out
