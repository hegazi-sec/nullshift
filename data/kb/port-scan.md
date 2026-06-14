---
title: Port Scan / Network Reconnaissance
tactics: [discovery, reconnaissance]
ioc_fields: [src_ip, dst_port]
siem_queries:
  wazuh:
    - query_id: alerts_by_ip
    - query_id: alerts_contains
      params:
        keywords: [scan, nmap, masscan, zmap, recon]
  splunk:
    - query_id: keyword_search
      params:
        keywords: [nmap, masscan, zmap, "port scan", "ET SCAN", "SYN scan", reconnaissance]
    - query_id: alerts_by_ip
  elastic:
    - query_id: keyword_search
      params:
        keywords: [nmap, masscan, "port scan", "SYN scan", reconnaissance, discovery]
    - query_id: alerts_by_ip
  sentinel:
    - query_id: keyword_search
      params:
        keywords: [nmap, masscan, "port scan", "network scan", reconnaissance]
    - query_id: alerts_by_ip
  suricata:
    - query_id: alerts_by_ip
    - query_id: alerts_keyword
      params:
        keywords: ["ET SCAN", nmap, masscan, zmap, "Potential", "Port Scan"]
  pfsense:
    - query_id: blocks_by_ip
    - query_id: recent_blocks
---

# Port Scan / Network Reconnaissance — L1 Triage Playbook

> EXAMPLE — replace with your environment's actual procedure before relying on it.

## Indicators
- Many distinct destination ports from a single source IP within a short window (Suricata)
- pfSense block log showing repeated drops from the same source against varying ports
- Suricata signatures: "ET SCAN Potential", "Nmap", "Masscan", "ZMap"

## Investigation Steps
1. Run `suricata.alerts_by_ip` for the source over the last 1h.
2. Run `pfsense.blocks_by_ip` for the same source — confirms the firewall already blocked the scan.
3. Run `wazuh.alerts_by_ip` to see whether the scan reached anything that logged via Wazuh.
4. Categorize: TCP SYN scan, full connect, UDP, service-version probe — the Suricata signature usually says.
5. Note which internal hosts (if any) actually answered. Scans that get TCP RST/no-response are noise; ones that get SYN/ACK on production services need a closer look.

## Verdict Guidance
- **Likely Benign** — pfSense dropped all attempts; no internal host responded; source IP is a known scanner.
- **Suspicious** — scan was partially successful (some SYN/ACK responses), but no follow-up traffic.
- **Malicious** — scan followed by targeted traffic to a discovered service (e.g. SSH brute force, web attack on a discovered port). Escalate.

## Escalate to L2 if
- Scan is sourced from an internal IP (potential pivoted host).
- Scan is followed by successful authentication or exploit attempts on a discovered service.
- The scan pattern matches your threat-intel feed for active campaigns.
