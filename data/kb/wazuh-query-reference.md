---
title: Wazuh Query Reference for Security Investigation
description: OpenSearch/Lucene query syntax, Wazuh field reference, rule IDs, and 60 investigation patterns for L2 hunting in Wazuh SIEM
tags:
  - wazuh
  - opensearch
  - lucene
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

# Wazuh Query Reference for Security Investigation

## Query Engine

Wazuh stores all events in the **Wazuh Indexer** (OpenSearch). Queries use
**Lucene query string syntax** — the same syntax used in Kibana/Discover search bars
and passed directly to `wazuh_search()` in the NullShift connector.

---

## Lucene Query Syntax

### Basic operators
```
field:value                     exact match (string)
field:"exact phrase"            phrase match
field:*value*                   wildcard — contains
field:value*                    wildcard — starts with
field:*value                    wildcard — ends with
field:[10 TO *]                 numeric range — ≥ 10
field:[* TO 5]                  numeric range — ≤ 5
field:[2024-01-01 TO 2024-12-31]  date range
NOT field:value                 negation
field:(value1 OR value2)        OR within a field
field:value AND field2:value2   AND across fields
(field:a OR field:b) AND field3:c  grouped logic
```

### Wildcards and regex
```
data.srcip:192.168.*            subnet wildcard
data.win.eventdata.commandLine:*powershell*
rule.description:*brute*
data.audit.exe:/usr/bin/*
```

### Time range (passed via time_range param, not in query string)
```
last_1h    last_15m    last_24h    last_7d
```

---

## Core Field Reference

### Agent / Routing
```
agent.id                    agent numeric ID
agent.name                  hostname / agent name
agent.ip                    agent IP address
manager.name                Wazuh manager that processed the event
location                    log source path or module name
```

### Rule Fields
```
rule.id                     rule ID (integer as string)
rule.level                  severity 0–15 (12+ = critical)
rule.description            human-readable rule description
rule.groups                 array of group tags (e.g. authentication_failures)
rule.mitre.id               MITRE technique IDs (e.g. T1078)
rule.mitre.tactic           MITRE tactic names
rule.pci_dss                PCI DSS compliance tags
rule.gdpr                   GDPR compliance tags
```

### Network Fields
```
data.srcip                  source IP address
data.dstip                  destination IP address
data.srcport                source port
data.dstport                destination port
data.protocol               protocol (tcp/udp/icmp)
data.srcgeoip               source geolocation
data.dstgeoip               destination geolocation
```

### User Fields
```
data.srcuser                source / acting user
data.dstuser                destination / target user
data.user                   generic user field
```

### Windows Event Fields (data.win.*)
```
data.win.system.eventID             Windows event ID
data.win.system.computer            hostname from event
data.win.system.providerName        event source/provider
data.win.eventdata.image            process image path (Sysmon 4688/1)
data.win.eventdata.commandLine      full command line
data.win.eventdata.parentImage      parent process image
data.win.eventdata.parentCommandLine parent command line
data.win.eventdata.targetUserName   target account name
data.win.eventdata.subjectUserName  acting account name
data.win.eventdata.logonType        logon type (2=interactive, 3=network, 10=remote)
data.win.eventdata.ipAddress        source IP in logon events
data.win.eventdata.workstationName  source workstation
data.win.eventdata.serviceName      service name (7045)
data.win.eventdata.taskName         scheduled task name (4698)
data.win.eventdata.objectName       object accessed (4663/4662)
data.win.eventdata.ticketEncryptionType  Kerberos encryption (0x17=RC4)
data.win.eventdata.shareLocalPath   share path (5140)
data.win.eventdata.shareAccess      share access type
```

### Linux Audit Fields (data.audit.*)
```
data.audit.command          executed command name
data.audit.exe              full executable path
data.audit.pid              process ID
data.audit.ppid             parent process ID
data.audit.auid             audit user ID (login UID)
data.audit.uid              real user ID
data.audit.euid             effective user ID
data.audit.file.name        file accessed/modified
data.audit.key              audit rule key label
data.audit.success          syscall success (yes/no)
data.audit.execve.a0        first argument (execve syscall)
data.audit.execve.a1        second argument
data.audit.execve.a2        third argument
```

### File Integrity (syscheck.*)
```
syscheck.path               file path monitored
syscheck.event              added / modified / deleted
syscheck.md5_after          MD5 hash after change
syscheck.sha1_after         SHA1 hash after change
syscheck.sha256_after       SHA256 hash after change
syscheck.size_after         file size after change
syscheck.uname_after        owner username after change
syscheck.gname_after        owner group after change
syscheck.perm_after         permissions after change (octal)
syscheck.mtime_after        modification timestamp after change
```

### HTTP / Web Fields (data.http.* / data.*)
```
data.http.http_method       GET / POST / PUT etc.
data.http.url               request URL
data.http.hostname          Host header
data.http.http_user_agent   User-Agent header
data.http.status            HTTP response code
data.http.length            response body length
data.event_type             event type (http / dns / etc.)
data.dest_ip                destination IP (Suricata-style)
data.dest_port              destination port
```

### DNS Fields
```
data.dns.question.name      queried domain name
data.dns.rrname             resource record name
data.dns.rdata              DNS response data
data.dns.type               record type (A/AAAA/TXT/MX)
```

### Raw Log Fields
```
full_log                    original unparsed log line
message                     decoded log message
```

---

## Key Rule IDs by Category

| Category | Rule IDs |
|---|---|
| SSH brute force | 5551, 5710, 5711, 5712, 5716, 5720 |
| SSH success after failures | 5503, 5504 |
| PAM authentication | 5400–5499 |
| Windows RDP brute force | 60122, 60204 |
| Windows logon success | 60106 |
| Windows logon failure | 60109 |
| Windows account management | 62002–62011 |
| Privilege escalation | 60603, 60604 |
| New Windows service | 61614, 61615 |
| Pass-the-hash | 91165 |
| FIM — file modified | 550, 551, 552 |
| FIM — file added | 553 |
| FIM — file deleted | 554 |
| VirusTotal malware hit | 87105 |
| Web attack (SQLi/XSS) | 31103, 31104, 31151, 31152 |
| Shellcode | 40101 |
| Audit — execve | 92300, 92301 |
| Rootkit detection | 510, 511 |

---

## Key Rule Groups

```
authentication_success
authentication_failed
authentication_failures        # correlated multiple failures
attack
web                            # web attacks
pam                            # Linux PAM auth
syscheck                       # file integrity
windows                        # Windows events
audit                          # Linux auditd
malware
rootcheck
intrusion_detection
mitre_attack
```

---

## Investigation Query Patterns (60 Patterns)

---
### COMMAND & CONTROL (TA0011)

#### 1. All alerts involving a suspicious IP
```lucene
(data.srcip:"1.2.3.4" OR data.dstip:"1.2.3.4" OR data.dest_ip:"1.2.3.4")
```

#### 2. Repeated connections to same external IP (beaconing pattern)
```lucene
data.srcip:"192.168.1.50" AND data.dest_ip:"1.2.3.4"
```
Run with `last_24h`. Count results. If ≥ 4 hits with even time spacing = beaconing. Check `data.dstport` for consistency — same port each time confirms C2.

#### 3. DNS queries for suspicious domains
```lucene
data.dns.question.name:*evil* OR data.dns.rrname:*evil*
```

#### 4. DNS TXT record queries from endpoints (tunneling/C2)
```lucene
data.dns.type:"TXT" AND agent.name:"WORKSTATION-07"
```
TXT queries from workstations = DNS tunneling or C2 channel. Almost never legitimate.

#### 5. High volume DNS to single domain (DGA / beaconing)
```lucene
agent.name:"WORKSTATION-07" AND data.event_type:dns
```
Group by `data.dns.question.name`. >50 queries to one domain in an hour = DGA or beacon.

#### 6. Non-standard outbound port connections
```lucene
data.srcip:"192.168.1.50" AND data.dstport:[1024 TO 65535] AND NOT data.dstport:443 AND NOT data.dstport:80 AND NOT data.dstport:8080
```

#### 7. Outbound connection on port 4444 / 1337 / 50050 (C2 default ports)
```lucene
data.dstport:(4444 OR 1337 OR 50050 OR 8443 OR 9001)
```

#### 8. HTTP requests with suspicious URL patterns (C2 check-in)
```lucene
data.http.url:*beacon* OR data.http.url:*/api/poll* OR data.http.url:*/update*
```
Correlate with `data.http.http_user_agent` — hardcoded agents like `Mozilla/5.0 (compatible; MSIE 9.0` always the same = implant.

---
### EXECUTION (TA0002)

#### 9. PowerShell encoded command
```lucene
data.win.eventdata.commandLine:*EncodedCommand* OR data.win.eventdata.commandLine:*-enc* OR data.win.eventdata.commandLine:*FromBase64String*
```

#### 10. Base64 payload indicators in command line
```lucene
data.win.eventdata.commandLine:*JAB* OR data.win.eventdata.commandLine:*TVqQ* OR data.win.eventdata.commandLine:*SQBuAH*
```
`JAB` = `$` in base64 (PowerShell). `TVqQ` = PE MZ header in base64. Hard IOC.

#### 11. LOLBin — certutil download/decode
```lucene
data.win.eventdata.image:*certutil* AND (data.win.eventdata.commandLine:*urlcache* OR data.win.eventdata.commandLine:*decode*)
```

#### 12. LOLBin — mshta / regsvr32 / rundll32 abuse
```lucene
data.win.eventdata.image:*mshta.exe* OR (data.win.eventdata.image:*regsvr32* AND data.win.eventdata.commandLine:*http*) OR (data.win.eventdata.image:*rundll32* AND data.win.eventdata.commandLine:*javascript*)
```

#### 13. WMI spawning processes
```lucene
data.win.eventdata.parentImage:*WmiPrvSE* AND (data.win.eventdata.image:*cmd.exe* OR data.win.eventdata.image:*powershell*)
```

#### 14. Office application spawning shell (macro execution)
```lucene
data.win.eventdata.parentImage:(*WINWORD* OR *EXCEL* OR *POWERPNT* OR *OUTLOOK*) AND data.win.eventdata.image:(*cmd.exe* OR *powershell* OR *wscript* OR *mshta*)
```

#### 15. Script interpreter execution (wscript / cscript)
```lucene
data.win.eventdata.image:(*wscript.exe* OR *cscript.exe*)
```
Check `data.win.eventdata.commandLine` for `.js`, `.vbs`, `.wsf` file arguments — suspicious if outside normal admin paths.

#### 16. Linux audit — suspicious command execution
```lucene
data.audit.command:(wget OR curl OR nc OR ncat OR python3 OR perl) AND data.audit.uid:0
```
Root-level execution of download/networking tools = active attacker or malware.

---
### PERSISTENCE (TA0003)

#### 17. New Windows service installed (Event 7045)
```lucene
data.win.system.eventID:"7045"
```
Check `data.win.eventdata.serviceName` and path. Services pointing to temp/appdata = malware.

#### 18. Scheduled task created (Event 4698)
```lucene
data.win.system.eventID:"4698"
```
Check `data.win.eventdata.taskName` and task XML in `full_log` for command path.

#### 19. Registry run key modification (Event 4657)
```lucene
data.win.system.eventID:"4657" AND (full_log:*CurrentVersion\\Run* OR full_log:*Winlogon*)
```

#### 20. File written to startup folder (FIM alert)
```lucene
syscheck.path:*\\Start Menu\\Programs\\Startup\\* OR syscheck.path:*\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*
```

#### 21. FIM — new file in suspicious path
```lucene
syscheck.event:"added" AND (syscheck.path:*\\Temp\\* OR syscheck.path:*\\AppData\\* OR syscheck.path:*\\ProgramData\\*)
```

#### 22. Cron job created or modified (Linux persistence)
```lucene
syscheck.path:*/etc/cron* OR syscheck.path:*/var/spool/cron/* OR data.audit.file.name:*/etc/crontab*
```

---
### CREDENTIAL ACCESS (TA0006)

#### 23. SSH brute force (multiple failures + success)
```lucene
rule.id:(5551 OR 5712) AND agent.name:"linux-host"
```
5551 = SSH brute force. 5712 = multiple auth failures. Follow with rule.id:5503 (success after failures).

#### 24. Windows RDP brute force
```lucene
rule.id:(60122 OR 60204)
```

#### 25. Multiple Windows logon failures (Event 4625)
```lucene
data.win.system.eventID:"4625" AND agent.name:"WORKSTATION-07"
```
Group by `data.win.eventdata.targetUserName`. >5 in 5 minutes = password spray.

#### 26. Kerberoasting — RC4 TGS request (Event 4769)
```lucene
data.win.system.eventID:"4769" AND data.win.eventdata.ticketEncryptionType:"0x17"
```
`0x17` = RC4-HMAC. Modern environments use AES. RC4 TGS request from non-DC = Kerberoasting.

#### 27. Pass-the-hash — explicit credential logon (Event 4648)
```lucene
data.win.system.eventID:"4648"
```
Multiple 4648 events from same source host in sequence = PtH lateral movement chain.

#### 28. Wazuh pass-the-hash rule
```lucene
rule.id:"91165"
```
Wazuh correlates 4624 logon type 3 + NTLM auth + no password = pass-the-hash.

#### 29. LSASS access / credential dumping
```lucene
data.win.eventdata.commandLine:(*lsass* OR *sekurlsa* OR *dumpcreds* OR *mimikatz*) OR (data.win.eventdata.image:*procdump* AND data.win.eventdata.commandLine:*lsass*)
```

#### 30. DCSync — DS-Replication from non-DC (Event 4662)
```lucene
data.win.system.eventID:"4662" AND full_log:*1131f6aa*
```
GUID `1131f6aa` = DS-Replication-Get-Changes. Any non-DC account triggering this = DCSync.

#### 31. SAM / NTDS database access (FIM)
```lucene
syscheck.path:*\\SAM OR syscheck.path:*\\ntds.dit OR syscheck.path:*\\SYSTEM
```

---
### LATERAL MOVEMENT (TA0008)

#### 32. PsExec service installation on remote host
```lucene
data.win.system.eventID:"7045" AND data.win.eventdata.serviceName:"PSEXESVC"
```

#### 33. WMI remote execution
```lucene
data.win.eventdata.parentImage:*WmiPrvSE* AND data.win.eventdata.image:(*cmd.exe* OR *powershell*)
```

#### 34. RDP lateral movement (Event 4624 logon type 10)
```lucene
data.win.system.eventID:"4624" AND data.win.eventdata.logonType:"10"
```
Type 10 = RemoteInteractive (RDP). Chain of 4624/type10 across multiple hosts = RDP hopping.

#### 35. SMB admin share access (Event 5140)
```lucene
data.win.system.eventID:"5140" AND (full_log:*\\C$* OR full_log:*\\ADMIN$* OR full_log:*\\IPC$*)
```

#### 36. Remote scheduled task (Event 4698 with SYSTEM account)
```lucene
data.win.system.eventID:"4698" AND full_log:*SYSTEM*
```
Task created under NT AUTHORITY\SYSTEM by a non-local action = remote task execution.

#### 37. Network logon to multiple hosts (Event 4624 type 3 — spreading)
```lucene
data.win.system.eventID:"4624" AND data.win.eventdata.logonType:"3" AND data.win.eventdata.subjectUserName:"jsmith"
```
Multiple hosts seeing network logon from same user in short window = lateral movement.

---
### DISCOVERY (TA0007)

#### 38. Port scan from internal host
```lucene
data.srcip:"192.168.1.50" AND rule.groups:scan
```
Or check `data.srcip` across many `data.dstport` values — wide destination port range = port scan.

#### 39. Net commands — account/group enumeration
```lucene
data.win.eventdata.commandLine:(*net user* OR *net group* OR *net localgroup*)
```

#### 40. Network share enumeration
```lucene
data.win.eventdata.commandLine:(*net view* OR *net share* OR *nltest*)
```

#### 41. Process/service discovery
```lucene
data.win.eventdata.image:(*tasklist.exe* OR *sc.exe*) AND data.win.eventdata.commandLine:*query*
```

#### 42. System info gathering commands
```lucene
data.win.eventdata.image:(*systeminfo.exe* OR *whoami.exe* OR *ipconfig.exe*) OR (data.audit.command:(id OR uname OR ifconfig OR ip) AND data.audit.uid:0)
```
Cluster of discovery commands in sequence on same host = post-exploitation recon stage.

#### 43. AD enumeration via LDAP (Event 4662 — directory reads)
```lucene
data.win.system.eventID:"4662" AND full_log:*user*
```
High volume of 4662 events = BloodHound or manual AD enumeration.

---
### DEFENSE EVASION (TA0005)

#### 44. Windows event log cleared (Event 1102 / 104)
```lucene
data.win.system.eventID:("1102" OR "104")
```
1102 = Security log cleared. 104 = System log cleared. Near-certain attacker action.

#### 45. Process masquerading — svchost in wrong path
```lucene
data.win.eventdata.image:*svchost* AND NOT data.win.eventdata.image:*System32\\svchost*
```
Legitimate svchost lives only in `C:\Windows\System32\`. Anywhere else = masquerading.

#### 46. Security tools stopped / disabled
```lucene
data.win.eventdata.commandLine:(*sc stop* OR *sc delete*) AND (data.win.eventdata.commandLine:(*windefend* OR *sense* OR *mssecflt* OR *avp*))
```

#### 47. Audit log tampering / auditd stopped (Linux)
```lucene
data.audit.key:"audit-wazuh-w" AND data.audit.exe:*auditctl* OR rule.description:*audit*stopped*
```

#### 48. UAC bypass — fodhelper / eventvwr technique
```lucene
data.win.eventdata.parentImage:(*fodhelper* OR *eventvwr*) AND data.win.eventdata.image:(*cmd.exe* OR *powershell*)
```

#### 49. Timestomping — FIM mtime anomaly
```lucene
syscheck.event:"modified" AND syscheck.path:*\\Temp\\* AND rule.level:[8 TO *]
```
Follow up by comparing `syscheck.mtime_after` with event timestamp — large gap = timestomped.

---
### EXFILTRATION (TA0010)

#### 50. Large outbound HTTP POST (data staging)
```lucene
data.http.http_method:"POST" AND data.srcip:"192.168.1.50" AND data.http.length:[100000 TO *]
```
POST with large body to external IP = staged exfiltration.

#### 51. FTP outbound connections
```lucene
data.dstport:(21 OR 990) AND data.srcip:"192.168.1.50"
```

#### 52. DNS TXT exfiltration (repeated TXT queries)
```lucene
data.dns.type:"TXT" AND agent.name:"WORKSTATION-07"
```

#### 53. Cloud storage domain access
```lucene
data.dns.question.name:(*dropbox* OR *onedrive* OR *drive.google* OR *mega.nz* OR *anonfiles*)
```

#### 54. Archive tool execution before outbound transfer
```lucene
data.win.eventdata.image:(*7z.exe* OR *winrar* OR *zip.exe*) AND data.win.eventdata.commandLine:*-p*
```
Password-protected archive creation = staging for exfil. Correlate with outbound connection within next 30 min.

---
### PRIVILEGE ESCALATION (TA0004)

#### 55. Sudo privilege escalation (Linux)
```lucene
data.audit.command:sudo AND data.audit.uid:[1000 TO *]
```
Non-root user invoking sudo — check `data.audit.exe` for what was escalated to.

#### 56. SUID binary execution (Linux)
```lucene
data.audit.exe:(*passwd* OR *sudo* OR *pkexec*) AND data.audit.euid:0 AND NOT data.audit.uid:0
```
Effective UID 0 but real UID non-zero = SUID escalation.

#### 57. Windows token impersonation / privilege use (Event 4672)
```lucene
data.win.system.eventID:"4672"
```
4672 = Special privileges assigned to new logon. Unexpected accounts getting debug/backup privileges = token abuse.

#### 58. Scheduled task created with SYSTEM privileges
```lucene
data.win.system.eventID:"4698" AND full_log:*NT AUTHORITY\\SYSTEM*
```

---
### INITIAL ACCESS (TA0001)

#### 59. Phishing execution — Office macro spawning shell
```lucene
data.win.eventdata.parentImage:(*WINWORD* OR *EXCEL* OR *OUTLOOK*) AND data.win.eventdata.image:(*powershell* OR *cmd.exe* OR *wscript* OR *mshta*)
```

#### 60. First-seen binary on a host — FIM new executable
```lucene
syscheck.event:"added" AND (syscheck.path:*.exe OR syscheck.path:*.dll OR syscheck.path:*.ps1) AND agent.name:"WORKSTATION-07"
```
Cross-reference `syscheck.sha256_after` against VirusTotal immediately. New binary dropped = initial payload.

---

## Investigation Workflow for L2

1. **Start with `agent.name` + time window** — scope all activity from the affected host
2. **Check rule.level:[10 TO *]** first — critical/high alerts are the fast path
3. **Follow `data.srcip` / `data.dstip`** — trace all network connections from artifact IPs
4. **Pivot on `data.dstuser` / `data.srcuser`** — which accounts were active at the same time
5. **Check syscheck.event:"added"** around the alert time — dropper activity
6. **Look for rule.id:91165** (pass-the-hash) and rule.id:5712 (brute force) — common post-initial-access steps
7. **Check data.win.system.eventID:4698 and 7045** — persistence is usually early
8. **Query full_log:*mimikatz* OR full_log:*cobalt* OR full_log:*metasploit*** — tool name leakage in logs

---

## Field Reference: What to Search When

| Scenario | Key Fields | Wazuh Rule IDs |
|---|---|---|
| Brute force | `data.srcip`, `data.dstuser`, `rule.level` | 5551, 5712, 60122 |
| C2 beaconing | `data.srcip`, `data.dstip`, `data.dstport` | — (raw conn) |
| Credential dumping | `data.win.eventdata.commandLine` | — |
| Pass-the-hash | `data.win.system.eventID:4648` | 91165 |
| Kerberoasting | `data.win.eventdata.ticketEncryptionType:0x17` | — |
| New persistence | `data.win.system.eventID:7045/4698` | 61614, 61615 |
| File drop | `syscheck.event:added` + hash | 553 |
| Log clearing | `data.win.system.eventID:1102` | — |
| Lateral RDP | `data.win.eventdata.logonType:10` | — |
| Linux audit | `data.audit.command`, `data.audit.exe` | 92300 |
