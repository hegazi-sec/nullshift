---
title: SSH Brute Force
tactics: [credential-access, brute-force]
ioc_fields: [src_ip, username]
siem_queries:
  wazuh:
    - query_id: alerts_by_rule
      params:
        rule_id: "5763"
    - query_id: alerts_by_rule
      params:
        rule_id: "5710"
    - query_id: alerts_by_rule
      params:
        rule_id: "5716"
    - query_id: alerts_by_ip
  splunk:
    - query_id: keyword_search
      params:
        keywords: [failed password, authentication failure, invalid user, sshd, "Maximum authentication"]
    - query_id: alerts_by_ip
  elastic:
    - query_id: keyword_search
      params:
        keywords: [authentication failure, invalid user, ssh brute, "failed login"]
    - query_id: alerts_by_ip
  sentinel:
    - query_id: keyword_search
      params:
        keywords: ["4625", "4776", failed logon, ssh, "invalid user"]
    - query_id: alerts_by_ip
  limacharlie:
    - query_id: keyword_search
      params:
        keywords: [ssh, sshd, "failed password", "authentication failure", "invalid user"]
    - query_id: alerts_by_ip
  suricata:
    - query_id: alerts_by_ip
    - query_id: alerts_keyword
      params:
        keywords: [SSH, "ET SCAN", "potential ssh scan"]
  pfsense:
    - query_id: blocks_by_ip
---

# SSH Brute Force — L1 Triage Playbook

> EXAMPLE — replace with your environment's actual procedure before relying on it.

## Indicators
- Repeated `authentication failure` rows in Wazuh for the same source IP within a short window
- Wazuh rule IDs commonly in 5710, 5712, 5716, 5719, 5720, 5763
- Suricata signatures referencing "SSH" or "ET SCAN potential SSH Scan"
- pfSense blocks against the same source IP

## Investigation Steps
1. Pull `wazuh.alerts_by_ip` for the source IP over the last 1h, then 24h.
2. Aggregate failures by `data.srcuser` (target username). A burst against many usernames suggests credential spraying; a burst against one suggests targeted brute force.
3. Run `suricata.alerts_by_ip` for the same source to confirm the connection attempts hit the wire.
4. Run `pfsense.blocks_by_ip` to see whether the firewall already dropped the source.
5. Check Wazuh for any *successful* login from the same IP after the failures — this is the escalation trigger.

## Verdict Guidance
- **Likely Benign** — internal scanner / monitoring host, no successful login, low volume.
- **Suspicious** — external IP, sustained failures, no success yet. Block at perimeter.
- **Malicious** — successful authentication after a burst of failures. Escalate to L2 immediately.

## Escalate to L2 if
- Any successful SSH session from the brute-force source IP.
- The source IP also appears in current Wazuh rootcheck or syscheck alerts on the same agent.
- Volume exceeds your environment's normal scan baseline.
