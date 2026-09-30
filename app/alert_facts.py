"""Key facts from a raw SIEM alert payload, for the alert page.

alert_facts(payload) -> [{"label": "Host", "value": "WS-FIN-042"}, ...]

Pure and stdlib-only: the alert page and the alerts endpoint call it on the
stored payload, so it must never raise, whatever a SIEM sent.
"""
from __future__ import annotations

import json
import re
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Tuple

MAX_FACTS = 15  # every label: the side panel has room, and a rich alert shouldn't lose its event time
MAX_VALUE_LEN = 300
MAX_DEPTH = 4  # generic key search and MITRE text scan stop here

_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Candidate paths per label, in display order. The first candidate that
# yields a value wins; a tuple merges its paths (both users of a logon, every
# hash algorithm). A dotted path walks dicts and the dict items of lists
# ("NETWORK_ACTIVITY.SOURCE.IP_ADDRESS" visits every activity), "*" walks
# every value of a dict, keys match case-insensitively, and flat ECS keys
# ("host.name" as one key) resolve too. "_entities" is Sentinel's Entities
# list grouped by Type (see _sentinel_entities).
_CANDIDATES: Dict[str, List[Any]] = {
    "Host": [
        "host.name", "host.hostname",                                   # Elastic ECS
        "routing.hostname",                                             # LimaCharlie
        ("agent.name", "agent.ip"),                                     # Wazuh
        "result.host", "result.dest_host", "result.ComputerName",       # Splunk
        "_entities.host.HostName", "_entities.host.NetBiosName", "CompromisedEntity",  # Sentinel
    ],
    "User": [
        "user.name",
        "detect.event.USER_NAME",
        "data.win.eventdata.user", ("data.srcuser", "data.dstuser"),
        "result.user", "result.src_user",
        "_entities.account.Name",
    ],
    "Process": [
        "process.executable", "process.name",
        "detect.event.FILE_PATH",
        "data.win.eventdata.image",
        # Splunk CIM's `process` is often the full command string, so the name fields go first
        "result.process_name", "result.process_path", "result.Image", "result.process",
        "_entities.process.ImageFile.Name",
    ],
    "Command line": [
        "process.command_line",
        "detect.event.COMMAND_LINE",
        "data.win.eventdata.commandLine",
        "result.CommandLine", "result.command_line",
        "_entities.process.CommandLine",
    ],
    "Parent process": [
        "process.parent.executable", "process.parent.name",
        "detect.event.PARENT.FILE_PATH",
        "data.win.eventdata.parentImage",
        "result.parent_process_name", "result.parent_process", "result.ParentImage",
        "_entities.process.ParentProcess.ImageFile.Name",
    ],
    "File": [
        "file.path", "file.name",
        "data.win.eventdata.targetFilename", "syscheck.path",
        "result.file_path", "result.file_name", "result.TargetFilename",
        "_entities.file.Name",
    ],
    "Hash": [
        "file.hash.*", "process.hash.*",
        "detect.event.HASH",
        "data.win.eventdata.hashes",
        ("syscheck.sha256_after", "syscheck.sha1_after", "syscheck.md5_after"),
        "result.file_hash", "result.Hashes",
        ("_entities.filehash.Value", "_entities.file.FileHashes.Value"),
    ],
    "Source IP": [
        "source.ip", "client.ip",
        "detect.event.NETWORK_ACTIVITY.SOURCE.IP_ADDRESS",
        "data.srcip", "data.win.eventdata.sourceIp",
        "result.src_ip", "result.src",
        "SourceIP", "_entities.ip.Address",
    ],
    "Destination IP": [
        "destination.ip", "server.ip",
        "detect.event.NETWORK_ACTIVITY.DESTINATION.IP_ADDRESS",
        "data.dstip", "data.win.eventdata.destinationIp",
        "result.dest_ip", "result.dest",
        "DestinationIP",
    ],
    "Domain": [
        "dns.question.name",
        "detect.event.DOMAIN_NAME",
        "data.win.eventdata.queryName", "data.win.eventdata.destinationHostname",
        "result.query", "result.domain",
        "_entities.dns.DomainName",
    ],
    "URL": [
        "url.full", "url.original",
        "detect.event.URL",
        "data.url", "data.http.url",
        "result.url",
        "_entities.url.Url",
    ],
    "Rule": [
        "kibana.alert.rule.name", "rule.name", "signal.rule.name",  # before Wazuh: ECS carries rule.description too
        "detect_mtd.description",  # not `cat`: that is the alert title, already on the page
        ("rule.description", "rule.id"),
        "search_name",
        "AlertDisplayName", "AlertName",
    ],
    # Every subtree at once; _mitre_ids keeps only technique ids.
    "MITRE": [(
        "threat", "kibana.alert.rule.threat", "signal.rule.threat",
        "detect_mtd", "tags", "routing.tags",
        "rule.mitre",
        "result.annotations.mitre_attack", "result.mitre_technique_id",
        "Techniques", "Tactics",
    )],
    "Sensor": [
        "routing.sid",
        "agent.id",
    ],
    "Event time": [
        "kibana.alert.original_time", "@timestamp",
        "routing.event_time", "ts",
        "timestamp",
        "result._time",
        "TimeGenerated", "StartTime",
    ],
}

LABELS: Tuple[str, ...] = tuple(_CANDIDATES)

# Keys looked for anywhere in the payload (case-insensitive, depth <= MAX_DEPTH)
# for labels the shape tables left empty.
_GENERIC_KEYS: Dict[str, Tuple[str, ...]] = {
    "Host": ("hostname", "host_name", "computer", "computername"),
    "User": ("username", "user_name", "account"),
    "Command line": ("command_line", "commandline", "cmdline"),
    "Hash": ("sha256", "md5", "sha1"),
    "Source IP": ("src_ip", "source_ip"),
    "Destination IP": ("dst_ip", "dest_ip", "destination_ip"),
    "URL": ("url",),
    "Event time": ("timestamp", "@timestamp", "event_time", "_time"),
}


def alert_facts(payload: Any) -> List[Dict[str, str]]:
    """Ordered, labelled facts worth showing above the raw payload.

    Returns at most MAX_FACTS `{"label", "value"}` pairs, one per label in
    LABELS order, each value a non-empty string of at most MAX_VALUE_LEN
    characters. Anything that is not a dict, or cannot be read, gives [].
    """
    if not isinstance(payload, dict):
        return []
    try:
        return _facts(payload)
    except Exception:  # every walk below is bounded; this is the never-raise guarantee
        return []


def _facts(payload: Dict[Any, Any]) -> List[Dict[str, str]]:
    root: Dict[Any, Any] = dict(payload)
    entities = _sentinel_entities(payload)
    if entities:
        root["_entities"] = entities

    found: Dict[str, List[str]] = {}
    for label, candidates in _CANDIDATES.items():
        for candidate in candidates:
            paths = candidate if isinstance(candidate, tuple) else (candidate,)
            values = [v for p in paths for v in _values(root, p, deep=label == "MITRE")]
            if values:
                found[label] = values
                break
    missing = {label: keys for label, keys in _GENERIC_KEYS.items() if label not in found}
    found.update(_generic(payload, missing))

    facts = []
    for label in LABELS:
        values = _FORMAT.get(label, list)(found.get(label, []))
        text = _join(values)
        if text:
            facts.append({"label": label, "value": text})
    return facts[:MAX_FACTS]


# --- path getter ------------------------------------------------------------

def _values(root: Any, path: str, deep: bool = False) -> List[str]:
    """Strings under a dotted path. `deep` also flattens dicts/lists at the
    leaf (MITRE ids hide in tags, descriptions and references)."""
    leaves = _leaves(root, path.split("."))
    if deep:
        return [s for leaf in leaves for s in _text(leaf)]
    return _strings(leaves)


def _leaves(node: Any, segs: List[str]) -> List[Any]:
    if not segs:
        return [node]
    if isinstance(node, list):  # only dict items, so recursion is bounded by the path length
        return [v for item in node if isinstance(item, dict) for v in _leaves(item, segs)]
    if not isinstance(node, dict):
        return []
    if segs[0] == "*":
        return [v for child in node.values() for v in _leaves(child, segs[1:])]
    lower = {str(k).lower(): k for k in node}
    # Longest dotted prefix first: Kibana webhooks flatten ECS ("host.name", "kibana.alert.rule").
    for n in range(len(segs), 0, -1):
        key = ".".join(segs[:n])
        hit = key if key in node else lower.get(key.lower())
        if hit is not None:
            return _leaves(node[hit], segs[n:])
    return []


def _scalar(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    return str(value).strip()


def _strings(leaves: Iterable[Any]) -> List[str]:
    out = []
    for leaf in leaves:
        for item in leaf if isinstance(leaf, list) else [leaf]:
            s = _scalar(item)
            if s:
                out.append(s)
    return out


def _text(node: Any, depth: int = 0) -> List[str]:
    """Every string in a subtree, MAX_DEPTH dicts down. Lists are free
    (ECS nests threat[].technique[].subtechnique[]) but never list-in-list,
    which keeps recursion bounded."""
    if isinstance(node, str):
        return [node.strip()] if node.strip() else []
    if isinstance(node, dict):
        if depth >= MAX_DEPTH:
            return []
        return [s for child in node.values() for s in _text(child, depth + 1)]
    if isinstance(node, list):
        return [s for child in node if not isinstance(child, list) for s in _text(child, depth)]
    return []


def _generic(payload: Dict[Any, Any], wanted: Dict[str, Tuple[str, ...]]) -> Dict[str, List[str]]:
    """Breadth-first key search to MAX_DEPTH (root keys are depth 1) for the
    labels no shape table filled."""
    key_to_label = {key: label for label, keys in wanted.items() for key in keys}
    found: Dict[str, List[str]] = {}
    queue = deque([(payload, 1)])
    while queue:
        node, depth = queue.popleft()
        items = node.items() if isinstance(node, dict) else enumerate(node)
        for key, child in items:
            label = key_to_label.get(str(key).lower())
            if label:
                found.setdefault(label, []).extend(_strings([child]))
            if depth < MAX_DEPTH and isinstance(child, (dict, list)):
                queue.append((child, depth + 1))
    return found


def _sentinel_entities(payload: Dict[Any, Any]) -> Dict[str, List[Dict[Any, Any]]]:
    """Sentinel's Entities grouped by lowercased Type: {"host": [...], "ip": [...]}."""
    entities = payload.get("Entities")
    if isinstance(entities, str):  # KQL exports the column as JSON text
        try:
            entities = json.loads(entities)
        except ValueError:
            return {}
    groups: Dict[str, List[Dict[Any, Any]]] = {}
    for entity in entities if isinstance(entities, list) else []:
        if isinstance(entity, dict) and isinstance(entity.get("Type"), str):
            groups.setdefault(entity["Type"].lower(), []).append(entity)
    # ponytail: "$ref" links between entities (a process's ImageFile) are not
    # resolved; the referenced file entity is in the list anyway, so File still fills
    return groups


# --- value formatting -------------------------------------------------------

def _mitre_ids(values: List[str]) -> List[str]:
    return [m.group().upper() for m in _MITRE_ID.finditer(" ".join(values))]


def _iso_utc(value: str) -> str:
    """Epoch seconds/ms/us/ns (number or numeric string) or an ISO-8601 string
    -> "YYYY-MM-DDTHH:MM:SSZ". Anything unparseable is shown as the SIEM sent it."""
    try:
        epoch = float(value)
    except ValueError:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    else:
        # Same magnitude thresholds as the LimaCharlie connector.
        for limit, per_second in ((1e16, 1e9), (1e14, 1e6), (1e11, 1e3)):
            if epoch > limit:
                epoch /= per_second
                break
        try:
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return value
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_FORMAT: Dict[str, Callable[[List[str]], List[str]]] = {
    "MITRE": _mitre_ids,
    "Event time": lambda values: [_iso_utc(v) for v in values],
}


def _join(values: List[str]) -> str:
    """Dedupe keeping order, join with ", ", cut to MAX_VALUE_LEN (ellipsis included)."""
    text = ", ".join(dict.fromkeys(v for v in values if v))
    if len(text) > MAX_VALUE_LEN:
        text = text[:MAX_VALUE_LEN - 1] + "…"
    return text
