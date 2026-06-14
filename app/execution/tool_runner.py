from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import re
import json

from app.connectors import wazuh, get_siem_connector
from app.utils.timeparse import parse_time_range
from app.execution.audit import audit_log
from app.config import settings
from app.utils.debug_trace import DebugTrace


class ToolRunner:
    """Executes approved, read-only tool queries across connectors with guardrails.

    Guardrails:
    - tool_name and query_id must be in allowlists
    - Time window maximum 24 hours
    - Max results = 200, Max samples = 5
    - Delegates to existing connectors only
    """

    # Allowlist of tools and queries
    APPROVED: Dict[str, List[str]] = {
        "wazuh": [
            "alerts_by_ip",
            "alerts_by_rule",
            # Discovery/generic
            "recent_alerts",
            "top_alerts",
            "alerts_contains",
            # Web/DVWA discovery & follow-ups
            "web_top_user_agents",
            "web_top_urls",
            "web_method_breakdown",
            "web_recent_samples",
            "web_login_post_burst",
            "web_404_spike",
            "web_unique_paths_high",
            "web_payload_hunt",
        ],
        # --- New SIEM providers (share a common query vocabulary) ---
        "splunk": [
            "alerts_by_ip",
            "alerts_by_rule",
            "recent_alerts",
            "top_alerts",
            "keyword_search",
        ],
        "elastic": [
            "alerts_by_ip",
            "alerts_by_rule",
            "recent_alerts",
            "top_alerts",
            "keyword_search",
        ],
        "limacharlie": [
            "alerts_by_ip",
            "alerts_by_rule",
            "recent_alerts",
            "top_alerts",
            "keyword_search",
        ],
        "sentinel": [
            "alerts_by_ip",
            "alerts_by_rule",
            "recent_alerts",
            "top_alerts",
            "keyword_search",
        ],
    }

    MAX_RESULTS: int = 200
    MAX_SAMPLES: int = 5

    def _enforce_time_window(self, earliest: Optional[str], latest: Optional[str]) -> Tuple[str, datetime, datetime]:
        """Return a safe time_range string and (start,end) datetimes.

        - Accepts strings like "last_15m", "last_1h", "last_24h". If absolute
          timestamps are ever passed (ISO-8601), clamps to 24h.
        - Always clamps effective window to a maximum of 24 hours.
        - Returns a best-effort time_range string compatible with existing connectors
          (e.g., "last_24h").
        """
        now = datetime.utcnow()

        def _try_parse_abs(s: str) -> Optional[datetime]:
            try:
                # Try a few common ISO-ish formats
                s2 = s.replace("Z", "+00:00").strip()
                # fromisoformat handles "+00:00"
                return datetime.fromisoformat(s2).replace(tzinfo=None)
            except Exception:
                return None

        # If relative string provided (earliest) like last_1h/min, prefer it
        start_dt: Optional[datetime] = None
        end_dt: Optional[datetime] = None

        if earliest and earliest.startswith("last_"):
            start_dt = parse_time_range(earliest)
        elif earliest:
            start_dt = _try_parse_abs(earliest)
        if latest:
            end_dt = _try_parse_abs(latest) or now
        else:
            end_dt = now

        if not start_dt:
            # Default 24h if nothing provided
            start_dt = now - timedelta(hours=24)

        # Clamp to 24h window max
        if end_dt < start_dt:
            # swap just in case
            start_dt, end_dt = end_dt, start_dt

        if (end_dt - start_dt) > timedelta(hours=24):
            start_dt = end_dt - timedelta(hours=24)

        # Build time_range string for connectors: choose nearest hour/min granularity
        delta = end_dt - start_dt
        hours = int(delta.total_seconds() // 3600)
        mins_rem = int((delta.total_seconds() % 3600) // 60)
        if hours >= 1 and mins_rem == 0:
            time_range = f"last_{hours}h"
        elif hours == 0 and mins_rem > 0:
            time_range = f"last_{mins_rem}m"
        else:
            # round up partial hours
            time_range = f"last_{min(hours + 1, 24)}h"

        return time_range, start_dt, end_dt

    @classmethod
    def approved_queries(cls) -> Dict[str, List[str]]:
        return cls.APPROVED

    def _summary_wazuh(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_rule: Dict[str, int] = {}
        by_agent: Dict[str, int] = {}
        for r in rows[: self.MAX_RESULTS]:
            # best-effort keys
            rid = None
            sig = None
            try:
                rule = r.get("rule") or {}
                rid = str(rule.get("id")) if rule.get("id") is not None else None
                sig = rule.get("description") or rule.get("name")
            except Exception:
                pass
            agent_id = None
            try:
                ag = r.get("agent") or {}
                agent_id = ag.get("id") or ag.get("name")
            except Exception:
                pass
            if rid:
                by_rule[rid] = by_rule.get(rid, 0) + 1
            if agent_id:
                by_agent[agent_id] = by_agent.get(agent_id, 0) + 1
        # format top entries
        top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10]
        top_agents = sorted(by_agent.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "by_rule": [{"rule_id": rid, "count": cnt} for rid, cnt in top_rules],
            "by_agent": [{"agent": aid, "count": cnt} for aid, cnt in top_agents],
        }

    # ------------------------------------------------------------------
    # Shared summary for normalized-alert connectors (Splunk/Elastic/Sentinel)
    # ------------------------------------------------------------------

    def _summary_normalized(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize rows produced by NormalizedAlert.to_dict()."""
        by_rule: Dict[str, int] = {}
        by_agent: Dict[str, int] = {}
        for r in rows[: self.MAX_RESULTS]:
            rule_name = r.get("_rule_name") or r.get("_rule_id") or ""
            agent = r.get("_agent") or ""
            if rule_name:
                by_rule[rule_name] = by_rule.get(rule_name, 0) + 1
            if agent:
                by_agent[agent] = by_agent.get(agent, 0) + 1
        top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10]
        top_agents = sorted(by_agent.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "by_rule": [{"rule_name": name, "count": cnt} for name, cnt in top_rules],
            "by_agent": [{"agent": agent, "count": cnt} for agent, cnt in top_agents],
        }

    # ------------------------------------------------------------------
    # Exec methods for new SIEM providers
    # ------------------------------------------------------------------

    def _exec_siem(self, provider: str, query_id: str, params: Dict[str, Any], gte: str, lte: str) -> List[Dict[str, Any]]:
        """Generic executor for Splunk / Elastic / Sentinel / LimaCharlie using the SIEMConnector ABC."""
        conn = get_siem_connector(provider)
        if not conn.is_available():
            raise RuntimeError(f"{provider} connector is not configured (missing credentials)")

        if query_id == "alerts_by_ip":
            ip = params.get("ip")
            if not ip:
                raise ValueError("Missing required param: ip")
            return [a.to_dict() for a in conn.search_by_ip(ip, gte, lte, self.MAX_RESULTS)]

        if query_id == "alerts_by_rule":
            rule_id = params.get("rule_id")
            if not rule_id:
                raise ValueError("Missing required param: rule_id")
            return [a.to_dict() for a in conn.search_by_rule(rule_id, gte, lte, self.MAX_RESULTS)]

        if query_id in ("recent_alerts", "top_alerts"):
            return [a.to_dict() for a in conn.recent_alerts(gte, lte, self.MAX_RESULTS)]

        if query_id == "keyword_search":
            kw = params.get("keywords")
            if not kw:
                one = params.get("keyword") or params.get("contains_text")
                kw = [one] if one else []
            if isinstance(kw, str):
                kw = [kw]
            if not kw:
                return [a.to_dict() for a in conn.recent_alerts(gte, lte, self.MAX_RESULTS)]
            return [a.to_dict() for a in conn.keyword_search(kw, gte, lte, self.MAX_RESULTS)]

        raise ValueError(f"Unsupported query_id for {provider}: {query_id}")

    def _exec_wazuh(self, query_id: str, params: Dict[str, Any], time_range: str, debug: Optional[DebugTrace] = None) -> List[Dict[str, Any]]:
        if query_id == "alerts_by_ip":
            ip = params.get("ip")
            if not ip:
                raise ValueError("Missing required param: ip")
            # Optional filters
            agent = params.get("agent")
            min_level = params.get("min_level")
            contains_text = params.get("contains_text")

            clauses = [
                f"data.srcip:{ip}",
                f"source.ip:{ip}",
                f"data.dstip:{ip}",
                f"destination.ip:{ip}",
            ]
            q = f"({' OR '.join(clauses)})"
            if agent:
                q += f" AND (agent.id:\"{agent}\" OR agent.name:\"{agent}\")"
            if min_level is not None:
                try:
                    lvl = int(min_level)
                    q += f" AND rule.level:[{lvl} TO *]"
                except Exception:
                    pass
            if contains_text:
                safe = str(contains_text).replace('"', '\\"')
                q += f" AND (message:*{safe}* OR full_log:*{safe}*)"
            return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

        if query_id == "alerts_by_rule":
            rule_id = params.get("rule_id")
            if not rule_id:
                raise ValueError("Missing required param: rule_id")
            agent = params.get("agent")
            min_level = params.get("min_level")
            q = f"rule.id:\"{rule_id}\""
            if agent:
                q += f" AND (agent.id:\"{agent}\" OR agent.name:\"{agent}\")"
            if min_level is not None:
                try:
                    lvl = int(min_level)
                    q += f" AND rule.level:[{lvl} TO *]"
                except Exception:
                    pass
            return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

        if query_id == "recent_alerts" or query_id == "top_alerts":
            # Generic discovery over time window
            q = ""  # allow API defaults plus time range
            return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

        if query_id == "alerts_contains":
            # Normalize inputs: keywords | keyword | contains_text | query | _subject_terms
            # If 'query' provided, pass through directly to connector
            raw_query = params.get("query")
            if isinstance(raw_query, str) and raw_query.strip():
                return wazuh.wazuh_search(raw_query, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

            kw = params.get("keywords")
            if not kw:
                one = params.get("keyword") or params.get("contains_text")
                if one:
                    kw = [one]
            if not kw:
                st = params.get("_subject_terms")
                if st:
                    kw = st if isinstance(st, list) else [st]
            # If still no keywords, run a very broad search (time-scoped) instead of failing
            if not kw:
                return wazuh.wazuh_search("", limit=self.MAX_RESULTS, time_range=time_range, debug=debug)
            if isinstance(kw, str):
                kw = [kw]

            # Generic wildcard handling for substring hunts across HTTP-related fields in Wazuh archives
            def _escape_qs(tok: str) -> str:
                # Escape Lucene/ES query_string special chars except '*' which we add deliberately
                # + - = && || > < ! ( ) { } [ ] ^ " ~ ? : \\ /
                s = str(tok)
                specials = r"[+\-=!(){}\[\]^\"~?:\\/<>]"
                s = re.sub(specials, lambda m: f"\\{m.group(0)}", s)
                return s

            # Remove filler terms and normalize
            FILLERS = {"attack", "activity", "scan", "happen"}
            orig_keywords = []
            for w in kw:
                s = str(w).strip()
                if not s:
                    continue
                if s.lower() in FILLERS:
                    continue
                orig_keywords.append(s)
            wildcards = [f"*{_escape_qs(w)}*" for w in orig_keywords]

            # Structured + fallback raw fields
            fields = [
                "data.http.http_user_agent",
                "data.http.url",
                "data.http.hostname",
                "data.http.http_method",
                # raw fallbacks
                "full_log",
                "message",
            ]
            field_terms: List[str] = []
            for f in fields:
                for wc in wildcards:
                    field_terms.append(f"{f}:{wc}")
            q_terms = "(" + " OR ".join(field_terms) + ")"

            # Base web filter (STRICT AND): HTTP event type + optional target + ensure raw field present
            base_filters = ["data.event_type:http", "full_log:*"]
            dst_ip = params.get("dst_ip") or params.get("dest_ip")
            dst_port = params.get("dst_port") or params.get("dest_port")
            if dst_ip:
                base_filters.append(f"data.dest_ip:{dst_ip}")
            if dst_port:
                try:
                    base_filters.append(f"data.dest_port:{int(dst_port)}")
                except Exception:
                    pass
            base_q = " AND ".join(base_filters)
            q = f"({base_q}) AND {q_terms}" if base_q else q_terms

            if debug:
                try:
                    debug.add({
                        "type": "request",
                        "source": "wazuh",
                        "base_filter": base_q,
                        "keyword_fields_used": fields,
                        "original_keywords": orig_keywords,
                        "wildcard_keywords": wildcards,
                        "query_preview": q[:500],
                        "time_range": time_range,
                    })
                except Exception:
                    pass

            return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

        # --- Web/DVWA discovery & follow-ups ---
        if query_id in {"web_top_user_agents", "web_top_urls", "web_method_breakdown", "web_recent_samples",
                        "web_login_post_burst", "web_404_spike", "web_unique_paths_high", "web_payload_hunt"}:
            dst_ip = params.get("dst_ip") or params.get("dest_ip")
            dst_port = params.get("dst_port") or params.get("dest_port") or 8080
            # Base filters (best-effort common fields in Wazuh archives)
            filters = []
            # Constrain to HTTP events and DVWA host/port in archives
            filters.append("data.event_type:http")
            if dst_ip:
                filters.append(f"data.dest_ip:{dst_ip}")
            if dst_port:
                try:
                    p = int(dst_port)
                    filters.append(f"data.dest_port:{p}")
                except Exception:
                    pass
            base = " AND ".join(filters) if filters else "*"

            if query_id == "web_top_user_agents":
                # Broad fetch; caller aggregates by user_agent
                q = f"{base}"
                return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

            if query_id == "web_login_post_burst":
                q = f"({base}) AND (data.http.url:\"/login.php\") AND (data.http.http_method:POST)"
                return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

            if query_id == "web_404_spike":
                q = f"({base}) AND (data.http.status:(404 OR 403))"
                return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

            if query_id == "web_unique_paths_high":
                # Broad fetch; caller will compute unique path counts
                q = f"{base}"
                return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

            if query_id == "web_payload_hunt":
                markers = [
                    "<script", "alert(", "onerror=", "%3Cscript%3E", "%3Cimg", "javascript:"
                ]
                terms = []
                for m in markers:
                    s = m.replace('"', '\\"')
                    terms.append(f"data.http.url:*{s}*")
                q = f"({base}) AND (" + " OR ".join(terms) + ")"
                return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

            # Discovery fetches (events returned; caller aggregates)
            q = f"{base}"
            return wazuh.wazuh_search(q, limit=self.MAX_RESULTS, time_range=time_range, debug=debug)

        raise ValueError(f"Unsupported Wazuh query_id: {query_id}")

    def execute(
        self,
        tool_name: str,
        query_id: str,
        params: Dict[str, Any],
        earliest: Optional[str],
        latest: Optional[str],
        user: Dict[str, Any],
        debug: Optional[DebugTrace] = None,
    ) -> Dict[str, Any]:
        # Validate tool and query allowlists
        tname = (tool_name or "").lower().strip()
        qid = (query_id or "").strip()
        if tname not in self.APPROVED:
            raise ValueError(f"Tool not allowed: {tname}")
        if qid not in self.APPROVED[tname]:
            raise ValueError(f"Query not allowed for {tname}: {qid}")

        # Enforce time window and derive connector-compatible time_range
        time_range, start_dt, end_dt = self._enforce_time_window(earliest, latest)
        # ISO strings for the new SIEM connectors (Elastic/Sentinel/Splunk expect ISO 8601)
        gte_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        lte_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Execute via connectors
        rows: List[Dict[str, Any]] = []
        summary: Dict[str, Any] = {}
        error: Optional[str] = None
        success: bool = True

        try:
            if tname == "wazuh":
                rows = self._exec_wazuh(qid, params or {}, time_range, debug=debug)
                summary = self._summary_wazuh(rows)
            elif tname in ("splunk", "elastic", "sentinel", "limacharlie"):
                rows = self._exec_siem(tname, qid, params or {}, gte_iso, lte_iso)
                summary = self._summary_normalized(rows)
            else:
                raise ValueError(f"Unsupported tool: {tname}")
        except Exception as e:
            success = False
            error = str(e)
            rows = []
            summary = {"error": error}

        result_count = len(rows)
        # Prepare return shape
        output: Dict[str, Any] = {
            "tool_name": tname,
            "query_id": qid,
            "result_count": result_count,
            "summary": summary,
            "samples": rows[: self.MAX_SAMPLES],
        }

        # Audit always
        try:
            username = (user or {}).get("username") or (user or {}).get("id") or "unknown"
            audit_log(username, tname, qid, params or {}, earliest, latest, result_count, success, error)
        except Exception:
            pass

        # If failed, surface the error to caller as exception to allow proper HTTP codes upstream
        if not success:
            raise ValueError(error or "Tool execution failed")

        return output
