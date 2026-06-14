---
title: Web Application Attack
tactics: [initial-access, discovery, exploitation]
ioc_fields: [src_ip, url, user_agent]
siem_queries:
  wazuh:
    - query_id: web_top_user_agents
    - query_id: web_404_spike
    - query_id: web_payload_hunt
    - query_id: web_login_post_burst
    - query_id: alerts_by_ip
  splunk:
    - query_id: keyword_search
      params:
        keywords: [sqlmap, nikto, "union select", "<script>", "../", "cmd=", "etc/passwd", nuclei]
    - query_id: alerts_by_ip
  elastic:
    - query_id: keyword_search
      params:
        keywords: [sqlmap, nikto, "union select", XSS, LFI, "directory traversal"]
    - query_id: alerts_by_ip
  sentinel:
    - query_id: keyword_search
      params:
        keywords: [sqlmap, nikto, "union select", injection, "web attack", SQLi]
    - query_id: alerts_by_ip
  suricata:
    - query_id: alerts_keyword
      params:
        keywords: [sqlmap, nikto, "ET WEB", "SQL Injection", XSS]
    - query_id: alerts_by_ip
---

# Web Application Attack on DVWA / Web Server — L1 Triage Playbook

> EXAMPLE — replace with your environment's actual procedure before relying on it.

## Indicators
- Burst of HTTP requests with sqlmap, nikto, Nuclei, or Wfuzz User-Agent strings
- Spike in 4xx / 5xx responses on a single host (suggests scanning)
- Suspicious URL patterns: `union select`, `..%2f`, `<script>`, `cmd=`, `etc/passwd`
- Wazuh web ruleset IDs in the 31xxx range (web attack signatures)

## Investigation Steps
1. Run `wazuh.web_top_user_agents` over the last 1h. Tool/scanner UAs almost always confirm intent.
2. Run `wazuh.web_top_urls` and look for parameter-heavy URLs that don't match normal traffic.
3. Run `wazuh.web_method_breakdown` — a sudden spike in POSTs to a login page is a credential stuffing or DVWA brute force.
4. Run `wazuh.web_404_spike` to confirm scanning behavior.
5. Run `wazuh.web_payload_hunt` for SQLi / XSS / LFI tokens. Match by source IP.
6. Cross-check with `suricata.alerts_keyword` (e.g. "sqlmap", "nikto") to confirm the IDS also saw it.

## Verdict Guidance
- **Likely Benign** — authorized internal scanner, scheduled scan window, no successful exploitation.
- **Suspicious** — external source, scanner UA, no obvious data exfil. Block source IP.
- **Malicious** — 200 OK responses on injection payloads, file uploads, or shell-like URLs (`/shell.php`, `?cmd=`). Escalate.

## Escalate to L2 if
- Any 200 OK on a URL containing SQLi / RCE / LFI patterns.
- New files written to the web root (Wazuh syscheck on the web server).
- Outbound connections from the web server to external IPs after the attack window.
