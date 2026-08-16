---
title: Elastic Query Reference for Security Investigation
description: KQL and EQL syntax, Elastic Common Schema (ECS) fields, indices, and 60 investigation patterns for L2 hunting in Elastic SIEM / Elasticsearch
tags:
  - elastic
  - elasticsearch
  - kql
  - eql
  - esql
  - ecs
  - hunting
  - siem
  - query
mitre_attack:
  - TA0001
  - TA0002
  - TA0003
  - TA0004
  - TA0005
  - TA0006
  - TA0007
  - TA0008
  - TA0010
  - TA0011
nist_csf:
  - DE.AE-02
  - DE.CM-01
  - RS.AN-03
  - ID.RA-01
---

# Elastic Query Reference for Security Investigation

Elastic (Elasticsearch / Elastic Security / the Kibana SIEM app) supports three
query languages. Pick by the job:

- **KQL** (Kibana Query Language) — fast field filtering in the Discover/Security
  views. Best for "find events where X". No aggregation on its own.
- **EQL** (Event Query Language) — event correlation and **sequences** (this then
  that, ordered, within a time window). Best for multi-step attack chains.
- **ES|QL** (Elasticsearch Query Language) — piped, SQL-like, with aggregation.
  Best for stats/grouping (`| STATS ... BY ...`), Elastic 8.11+.

All three read the **Elastic Common Schema (ECS)** — normalized field names like
`source.ip`, `process.command_line`, `user.name` — regardless of which beat or
integration shipped the data.

---

## KQL Syntax

```kql
field: value                     exact match
field: "value with spaces"       quoted phrase
field: value*                    wildcard (leading wildcards are slow)
field >= 100                     range on numeric/date
field: (a or b or c)             any of
not field: value                 negation
field1: v1 and field2: v2        boolean and
event.category: process and process.name: "powershell.exe"
```

- KQL has no time filter of its own — the Kibana time picker or the index query
  supplies the range. In a saved query, pair with `@timestamp >= "now-24h"`.
- `field: *` matches "field exists"; `not field: *` matches "field is missing".

---

## EQL Syntax

```eql
process where process.name == "powershell.exe" and
  process.command_line : "*-enc*"
```

Category keywords: `process`, `network`, `file`, `registry`, `authentication`,
`any`. String match `:` is case-insensitive wildcard; `==` is exact.

**Sequences** — the reason to reach for EQL:

```eql
sequence by host.name with maxspan=5m
  [process where process.name == "winword.exe"]
  [process where process.parent.name == "winword.exe" and
    process.name in ("cmd.exe", "powershell.exe")]
```

Reads: on the same host, within 5 minutes, Word ran, then Word spawned a shell.
`by host.name` correlates the two steps on a shared field.

---

## ES|QL Syntax

```esql
FROM logs-* 
| WHERE event.category == "network" and destination.port > 1024
| STATS count = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY destination.ip
| SORT count DESC
| LIMIT 20
```

Pipeline like SPL: `FROM` an index pattern, then `WHERE`, `STATS`, `EVAL`,
`SORT`, `KEEP`, `DROP`, `LIMIT`.

---

## Key Indices / Data Streams

| Pattern | Contents |
|---|---|
| `logs-*` | Catch-all for Elastic Agent integration logs (8.x data streams) |
| `winlogbeat-*` / `logs-windows.*` | Windows event logs (Security, Sysmon, PowerShell) |
| `filebeat-*` | Linux syslog, auth.log, application logs |
| `packetbeat-*` / `logs-network_traffic.*` | Network flows, DNS, HTTP, TLS |
| `auditbeat-*` | Linux auditd, file integrity, process/socket events |
| `logs-endpoint.events.*` | Elastic Defend (endpoint) process/network/file/registry |
| `.alerts-security.alerts-*` | Detection engine alerts |

Use `logs-*` when unsure which integration produced the data — ECS makes the
fields consistent across all of them.

---

## Elastic Common Schema (ECS) Field Reference

**Event classification**
```
event.category      process | network | file | authentication | registry | dns
event.type          start | end | creation | deletion | connection | info
event.action        the source's own action label (e.g. "logged-in")
event.outcome       success | failure | unknown
event.dataset       source of the event (e.g. "windows.security")
```

**Host / agent**
```
host.name           hostname
host.ip             host IP(s)
host.os.type        windows | linux | macos
agent.type          filebeat | winlogbeat | endpoint
```

**Process (Sysmon EID 1, EDR)**
```
process.name                image name (e.g. "powershell.exe")
process.executable          full path
process.command_line        full command line  ← primary hunting field
process.args                tokenized args
process.pid
process.hash.sha256 / .md5
process.parent.name         parent image
process.parent.command_line
user.name / user.domain
```

**Network**
```
source.ip / source.port
destination.ip / destination.port
network.protocol            dns | http | tls
network.transport           tcp | udp
network.bytes / source.bytes / destination.bytes
dns.question.name           queried domain  ← DNS hunting
dns.question.type           A | AAAA | TXT | CNAME
url.original / url.domain
http.request.method
tls.server.ja3s / tls.client.ja3
```

**File / Registry**
```
file.path / file.name / file.extension
file.hash.sha256
registry.path               full key path
registry.value
registry.data.strings
```

**Authentication (Windows Security, ECS)**
```
event.category: authentication
winlog.event_id             4624 | 4625 | 4672 | 4768 | 4769 ...
winlog.event_data.LogonType 3 = network, 10 = RDP
user.name / source.ip
winlog.event_data.TicketEncryptionType   0x17 = RC4 (Kerberoast signal)
```

---

## Investigation Query Patterns (60 Patterns)

Each pattern gives KQL for quick filtering; EQL or ES|QL where correlation or
aggregation matters. Replace example IPs/hosts with your indicators.

---
### COMMAND & CONTROL (TA0011)

#### 1. All traffic to/from a suspicious IP
```kql
source.ip: "1.2.3.4" or destination.ip: "1.2.3.4"
```
```esql
FROM logs-*
| WHERE source.ip == "1.2.3.4" or destination.ip == "1.2.3.4"
| STATS count = COUNT(*), first = MIN(@timestamp), last = MAX(@timestamp)
    BY source.ip, destination.ip, destination.port
| SORT count DESC
```

#### 2. Beaconing — repeated connections to one destination
```esql
FROM logs-*
| WHERE event.category == "network" and source.ip == "192.168.1.50"
| STATS hits = COUNT(*) BY destination.ip, destination.port,
    bucket = DATE_TRUNC(1 hour, @timestamp)
| SORT destination.ip, bucket
```
Even hit counts across every hour bucket = automated beacon.

#### 3. Beaconing by interval regularity (low jitter)
```eql
sequence by source.ip, destination.ip with maxspan=1h
  [network where destination.port == 443]
  [network where destination.port == 443]
  [network where destination.port == 443]
```
Three connections to the same dest inside an hour — inspect timestamps for
fixed spacing. For hard math on jitter, export to ES|QL and compute deltas.

#### 4. DNS requests for suspicious domains
```kql
dns.question.name: (*.evil.* or *c2* or *.xyz)
```

#### 5. DGA detection — many unique domains per host
```esql
FROM logs-*
| WHERE event.category == "dns"
| STATS unique_domains = COUNT_DISTINCT(dns.question.name) BY source.ip
| WHERE unique_domains > 200
| SORT unique_domains DESC
```

#### 6. DNS TXT queries from endpoints (tunneling / C2)
```kql
dns.question.type: "TXT" and not host.name: (dns-* or dc-*)
```

#### 7. Non-standard outbound ports
```kql
event.category: network and event.type: connection and
  not destination.port: (80 or 443 or 53 or 25 or 123)
```

#### 8. Long DNS labels (DNS exfiltration)
```esql
FROM logs-*
| WHERE event.category == "dns"
| EVAL qlen = LENGTH(dns.question.name)
| WHERE qlen > 50
| STATS count = COUNT(*) BY source.ip, dns.question.name, qlen
| SORT qlen DESC
```

#### 9. JA3/JA3S hash of known malware TLS fingerprint
```kql
tls.client.ja3: "a0e9f5d64349fb13191bc781f81f42e1"
```

#### 10. Rare user-agent strings on outbound HTTP
```esql
FROM logs-*
| WHERE event.category == "network" and network.protocol == "http"
| STATS count = COUNT(*) BY user_agent.original
| SORT count ASC
| LIMIT 25
```

---
### EXECUTION (TA0002)

#### 11. PowerShell encoded command
```kql
process.name: "powershell.exe" and
  process.command_line: (*-enc* or *-EncodedCommand* or *FromBase64String*)
```

#### 12. PowerShell script block with base64 payload (EID 4104)
```kql
winlog.event_id: 4104 and
  powershell.file.script_block_text: (*frombase64string* or *JAB* or *TVqQ*)
```

#### 13. Office app spawning a shell (macro execution)
```eql
process where process.parent.name in ("winword.exe","excel.exe","powerpnt.exe")
  and process.name in ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
```

#### 14. mshta / rundll32 with URL argument
```kql
process.name: (mshta.exe or rundll32.exe) and
  process.command_line: (*http* or *javascript* or *vbscript*)
```

#### 15. wscript/cscript running a script file
```kql
process.name: (wscript.exe or cscript.exe) and
  process.command_line: (*.vbs* or *.js* or *.wsf*)
```

#### 16. Suspicious parent-child: services.exe spawning cmd
```eql
process where process.parent.name == "services.exe" and
  process.name in ("cmd.exe","powershell.exe")
```

#### 17. Linux shell spawned by web server (webshell)
```eql
process where process.parent.name in ("apache2","httpd","nginx","php-fpm")
  and process.name in ("sh","bash","dash","python","perl")
```

#### 18. curl/wget piped to shell
```kql
process.command_line: ((*curl* or *wget*) and (*| sh* or *| bash* or *|sh* or *|bash*))
```

#### 19. Scheduled task creation via schtasks
```kql
process.name: "schtasks.exe" and process.command_line: *create*
```

#### 20. WMIC process call create
```kql
process.name: "wmic.exe" and process.command_line: (*process* and *call* and *create*)
```

---
### PERSISTENCE (TA0003)

#### 21. Run key registry modification
```kql
event.category: registry and
  registry.path: (*\\CurrentVersion\\Run* or *\\CurrentVersion\\RunOnce*)
```

#### 22. New service installation (EID 7045)
```kql
winlog.event_id: 7045
```
```esql
FROM logs-*
| WHERE winlog.event_id == 7045
| STATS count = COUNT(*) BY host.name, winlog.event_data.ServiceName,
    winlog.event_data.ImagePath
| SORT count ASC
```

#### 23. New scheduled task registered (EID 4698)
```kql
winlog.event_id: 4698
```

#### 24. Linux cron modification
```kql
event.category: file and file.path: (*/etc/cron* or */var/spool/cron*)
```

#### 25. Linux persistence via rc.local / systemd unit
```kql
event.category: file and
  file.path: (*/etc/rc.local or */etc/systemd/system/* or */.config/systemd/*)
```

#### 26. WMI event subscription persistence
```kql
winlog.event_id: (19 or 20 or 21) and event.dataset: "windows.sysmon_operational"
```

#### 27. New local user created (EID 4720)
```kql
winlog.event_id: 4720
```

#### 28. User added to privileged group (EID 4728, 4732)
```kql
winlog.event_id: (4728 or 4732 or 4756)
```

#### 29. Startup folder file drop
```kql
event.category: file and event.type: creation and
  file.path: *\\Start Menu\\Programs\\Startup\\*
```

#### 30. SSH authorized_keys modification (Linux)
```kql
event.category: file and file.path: *authorized_keys*
```

---
### PRIVILEGE ESCALATION (TA0004)

#### 31. Special privileges assigned at logon (EID 4672)
```kql
winlog.event_id: 4672 and not user.name: (SYSTEM or "LOCAL SERVICE" or "NETWORK SERVICE")
```

#### 32. Token manipulation / runas
```kql
process.command_line: (*runas* or *SeDebugPrivilege* or *SeImpersonatePrivilege*)
```

#### 33. Linux sudo to root
```kql
event.category: process and process.name: "sudo" and process.args: "root"
```

#### 34. setuid/setgid binary execution
```kql
event.category: process and process.thread.capabilities.effective: *
  and process.name: (pkexec or dbus-* or *)
```

#### 35. Potato-style exploit binaries
```kql
process.name: (*potato* or juicypotato.exe or printspoofer.exe or roguepotato.exe)
```

#### 36. UAC bypass via fodhelper / eventvwr
```eql
process where process.parent.name in ("fodhelper.exe","eventvwr.exe","sdclt.exe")
  and process.name in ("cmd.exe","powershell.exe")
```

---
### DEFENSE EVASION (TA0005)

#### 37. Windows event log cleared (EID 1102)
```kql
winlog.event_id: 1102
```

#### 38. Security service / Defender disabled
```kql
process.command_line: (*Set-MpPreference* and *DisableRealtimeMonitoring*) or
  process.command_line: (*sc* and *stop* and (*WinDefend* or *Sense*))
```

#### 39. Shadow copy deletion (ransomware precursor)
```kql
process.command_line: (*vssadmin* and *delete* and *shadows*) or
  process.command_line: (*wmic* and *shadowcopy* and *delete*)
```

#### 40. bcdedit recovery tampering
```kql
process.name: "bcdedit.exe" and
  process.command_line: (*recoveryenabled* or *bootstatuspolicy*)
```

#### 41. Process injection indicators (Sysmon EID 8/10)
```kql
winlog.event_id: (8 or 10) and event.dataset: "windows.sysmon_operational"
  and not process.name: (*chrome.exe or *msedge.exe)
```

#### 42. Renamed system binary (LOLBin masquerade)
```eql
process where process.name != process.pe.original_file_name
  and process.pe.original_file_name != null
```

#### 43. Timestomping (file MACE alteration)
```kql
event.category: file and event.action: "modification" and
  process.name: (powershell.exe or *timestomp*)
```

#### 44. Clear Linux bash history
```kql
process.command_line: (*history -c* or *rm* and *.bash_history* or *> ~/.bash_history*)
```

#### 45. Base64 / encoded Linux command
```kql
process.command_line: (*base64* and (*-d* or *--decode*)) and
  process.parent.name: (bash or sh)
```

---
### CREDENTIAL ACCESS (TA0006)

#### 46. LSASS memory access (credential dumping)
```kql
winlog.event_id: 10 and winlog.event_data.TargetImage: *lsass.exe*
  and not winlog.event_data.SourceImage: (*MsMpEng.exe or *wininit.exe)
```

#### 47. comsvcs.dll MiniDump of LSASS
```kql
process.command_line: (*comsvcs.dll* and *MiniDump*)
```

#### 48. Mimikatz command signatures
```kql
process.command_line: (*sekurlsa* or *logonpasswords* or *lsadump* or *kerberos::*)
```

#### 49. Kerberoasting — RC4 service ticket requests (EID 4769)
```kql
winlog.event_id: 4769 and
  winlog.event_data.TicketEncryptionType: "0x17" and
  not service.name: "krbtgt"
```
```esql
FROM logs-*
| WHERE winlog.event_id == 4769 and winlog.event_data.TicketEncryptionType == "0x17"
| STATS requests = COUNT(*) BY user.name, service.name
| WHERE requests > 5
| SORT requests DESC
```

#### 50. AS-REP roasting (EID 4768, no preauth)
```kql
winlog.event_id: 4768 and winlog.event_data.PreAuthType: "0"
```

#### 51. NTDS.dit access / intdsutil
```kql
process.command_line: (*ntdsutil* or *ntds.dit* or *"ac i ntds"*)
```

#### 52. Linux /etc/shadow read
```kql
event.category: file and file.path: */etc/shadow and event.action: (open or read)
```

#### 53. Brute force — many failed logons (EID 4625)
```esql
FROM logs-*
| WHERE winlog.event_id == 4625
| STATS failures = COUNT(*) BY source.ip, user.name
| WHERE failures > 10
| SORT failures DESC
```

#### 54. Password spray — one source, many accounts
```esql
FROM logs-*
| WHERE winlog.event_id == 4625
| STATS accounts = COUNT_DISTINCT(user.name) BY source.ip
| WHERE accounts > 10
| SORT accounts DESC
```

---
### DISCOVERY (TA0007)

#### 55. Native recon command burst
```kql
process.name: (whoami.exe or net.exe or nltest.exe or systeminfo.exe or
  ipconfig.exe or arp.exe or route.exe or tasklist.exe)
```
```eql
sequence by host.name with maxspan=2m
  [process where process.name == "whoami.exe"]
  [process where process.name in ("net.exe","nltest.exe","systeminfo.exe")]
```

#### 56. AD enumeration via net group / net user
```kql
process.name: "net.exe" and
  process.command_line: (*group* or *user* or *"domain admins"* or *localgroup*)
```

#### 57. BloodHound / SharpHound collection
```kql
process.command_line: (*sharphound* or *bloodhound* or *-CollectionMethod*)
```

#### 58. Linux enumeration burst
```kql
process.name: (uname or id or whoami or hostname or crontab or netstat or ss)
  and process.parent.name: (bash or sh or dash)
```

---
### LATERAL MOVEMENT (TA0008)

#### 59. Remote logon activity (RDP EID 4624 LogonType 10)
```kql
winlog.event_id: 4624 and winlog.event_data.LogonType: "10"
```

#### 60. PsExec / remote service execution
```eql
sequence by host.name with maxspan=1m
  [file where file.name : "PSEXESVC.exe"]
  [process where process.parent.name == "services.exe"]
```
Also match `process.name: "psexec*"` or service name `PSEXESVC` in EID 7045.

---
### EXFILTRATION (TA0010)

#### 61. Large outbound transfer to external IP
```esql
FROM logs-*
| WHERE event.category == "network" and destination.ip != null
| STATS bytes_out = SUM(source.bytes) BY source.ip, destination.ip
| WHERE bytes_out > 104857600
| SORT bytes_out DESC
```
>100 MB outbound to a single external IP — inspect the destination reputation.

#### 62. Upload to cloud storage / paste sites
```kql
url.domain: (*pastebin.com or *mega.nz or *anonfiles* or *transfer.sh or *file.io)
```

#### 63. Archive staging before exfil
```kql
process.name: (7z.exe or rar.exe or winrar.exe or tar or zip) and
  process.command_line: (*-p* or *a * or *-r*)
```

---

## Investigation Workflow for L2

1. Start in **KQL** to scope: filter on the indicator (`source.ip`, `user.name`,
   `process.command_line`) and confirm the events exist.
2. Switch to **EQL sequences** when the alert is a chain (Office → shell,
   file-drop → service-start) — correlation is where EQL beats everything else.
3. Use **ES|QL** for the counting questions: failures per source, unique domains
   per host, bytes out per destination.
4. Pivot on ECS fields, not raw source fields — `source.ip` works across
   packetbeat, endpoint, and firewall data without rewriting the query.
5. Confirm scope with `host.name` / `user.name` aggregation before escalating.

---

## Field Reference: What to Search When

| Scenario | Key ECS fields | Windows event id |
|---|---|---|
| Process execution | `process.command_line`, `process.parent.name` | 4688 / Sysmon 1 |
| PowerShell | `powershell.file.script_block_text` | 4104 |
| Failed logon / brute force | `winlog.event_id`, `source.ip`, `user.name` | 4625 |
| RDP / remote logon | `winlog.event_data.LogonType` (10) | 4624 |
| Kerberoasting | `winlog.event_data.TicketEncryptionType` (0x17) | 4769 |
| New service | `winlog.event_data.ServiceName`, `ImagePath` | 7045 |
| Scheduled task | `process.command_line` (schtasks) | 4698 |
| DNS hunting | `dns.question.name`, `dns.question.type` | — |
| Network flow | `source.ip`, `destination.ip`, `destination.port`, `source.bytes` | — |
| LSASS access | `winlog.event_id` (10), `TargetImage` | Sysmon 10 |
| Log cleared | `winlog.event_id` | 1102 |
| Registry persistence | `registry.path` | Sysmon 13 |
