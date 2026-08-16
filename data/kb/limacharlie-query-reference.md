---
title: LimaCharlie Query Reference for Security Investigation
description: LCQL syntax, event field paths, D&R operators, and investigation patterns for L2 hunting in LimaCharlie XDR
tags:
  - limacharlie
  - lcql
  - query
  - hunting
  - edr
  - xdr
mitre_attack:
  - TA0001
  - TA0002
  - TA0003
  - TA0007
  - TA0008
  - TA0010
  - TA0011
nist_csf:
  - DE.AE-02
  - DE.CM-01
  - RS.AN-03
---

# LimaCharlie Query Reference for Security Investigation

## LCQL Query Structure

Every LCQL query follows this pipeline:

```
<time_range> | <platform_filter> | <event_type> | <conditions> | <projection>
```

All clauses after `time_range` are optional. Build left to right — narrow first, then project.

### Time Range
```
-24h        last 24 hours
-12h        last 12 hours
-1h         last hour
-10m        last 10 minutes
```

### Platform Filter
```
plat == windows
plat == linux
plat == macos
```

### Event Type
Specify one or `*` for all:
```
DNS_REQUEST
NEW_PROCESS
NEW_TCP4_CONNECTION
NEW_UDP4_CONNECTION
NETWORK_CONNECTIONS
FILE_CREATE
FILE_MODIFIED
FILE_DELETE
USER_LOGIN
SSH_LOGIN
CODE_IDENTITY
WEL                   # Windows Event Log
MODULE_LOAD
YARA_DETECTION
```

---

## Field Path Notation

### Routing Fields (metadata on every event)
```
routing/hostname          endpoint hostname
routing/sid               sensor UUID — uniquely identifies the endpoint
routing/oid               organization ID (multi-tenant)
routing/event_type        event type string (e.g. NEW_PROCESS)
routing/event_time        Unix timestamp in milliseconds
routing/ext_ip            external IP of the sensor
routing/int_ip            internal IP of the sensor
routing/plat              platform code
routing/tags              array of applied sensor tags
```

### Network Event Fields
```
# TCP/UDP connections
event/PROCESS_ID
event/SOURCE/IP_ADDRESS
event/SOURCE/PORT
event/DESTINATION/IP_ADDRESS
event/DESTINATION/PORT
event/STATE                         # connection state

# DNS
event/DOMAIN_NAME
event/DNS_TYPE
event/DNS_FLAGS

# HTTP
event/URL
event/IP_ADDRESS
event/RESULT

# NETWORK_CONNECTIONS (process network snapshot)
event/NETWORK_ACTIVITY/SOURCE/IP_ADDRESS
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS
event/HASH
event/COMMAND_LINE
```

### Process Event Fields
```
event/PROCESS_ID
event/PARENT_PROCESS_ID
event/COMMAND_LINE
event/FILE_PATH
event/MEMORY_USAGE
event/THREADS
event/BASE_ADDRESS
event/PARENT/COMMAND_LINE
event/PARENT/FILE_PATH
event/PARENT/PROCESS_ID
```

### File Event Fields
```
event/FILE_PATH
event/HASH
event/RULE_NAME             # for FILE_TYPE_ACCESSED
```

### Authentication Event Fields
```
event/USER_NAME             # USER_LOGIN, USER_LOGOUT, SSH_LOGIN, SSH_LOGOUT
```

### Code Identity Fields
```
event/FILE_PATH
event/HASH
event/SIGNATURE             # certificate chain details
```

### Windows Event Log Fields (WEL)
```
event/EVENT_ID              # 4624=logon, 4625=failed logon, 4688=new process,
                            # 4648=explicit creds, 4768/4769=Kerberos, 7045=new service
event/PROVIDER
event/COMPUTER
event/MESSAGE
```

---

## LCQL Conditions (Filtering)

### Comparison Operators
```
field contains "value"
field == "value"
field != "value"
field > number
field starts with "prefix"
field ends with ".exe"
```

### Logical
```
condition1 and condition2
condition1 or condition2
not condition
```

### Aggregation (Projection)
```
COUNT(event) as count
COUNT_UNIQUE(field) as unique_count
GROUP BY(field1 field2)
ORDER BY(count desc)
LIMIT 50
```

---

## Security Investigation Query Patterns (60 Patterns)

---
### COMMAND & CONTROL (TA0011)

#### 1. All connections to/from a suspicious IP
```lcql
-24h | * | NEW_TCP4_CONNECTION |
  event/DESTINATION/IP_ADDRESS contains "1.2.3.4" or
  event/SOURCE/IP_ADDRESS contains "1.2.3.4" |
  routing/hostname as host
  event/DESTINATION/PORT as port
  routing/event_time as ts
  ORDER BY(ts desc)
```

#### 2. Beaconing — periodic connections to same destination
```lcql
-24h | plat == windows | NEW_TCP4_CONNECTION |
  event/DESTINATION/IP_ADDRESS == "1.2.3.4" |
  routing/hostname as host
  event/DESTINATION/PORT as port
  routing/event_time as ts
  COUNT(event) as connections
  GROUP BY(host port)
  ORDER BY(connections desc)
```
Even distribution of `ts` values at regular intervals = beaconing. Any count ≥ 4 in 24h on a non-browser port is suspicious.

#### 3. DNS tunneling — high query frequency to single domain
```lcql
-24h | * | DNS_REQUEST |
  routing/hostname == "WORKSTATION-07" |
  event/DOMAIN_NAME as domain
  COUNT(event) as count
  GROUP BY(domain)
  ORDER BY(count desc)
  LIMIT 100
```
DNS tunneling = hundreds of queries to one domain or subdomains with long random labels (e.g. `a8f3k2x.evil.com`).

#### 4. DGA detection — high unique domain count from one host
```lcql
-24h | * | DNS_REQUEST |
  routing/hostname == "WORKSTATION-07" |
  event/DOMAIN_NAME as domain
  COUNT_UNIQUE(domain) as unique_domains
  GROUP BY(host)
  ORDER BY(unique_domains desc)
```
Normal hosts query <50 unique domains/day. >200 unique domains = likely DGA malware rotating C2 addresses.

#### 5. Non-standard port C2 (outbound on unusual ports)
```lcql
-24h | * | NEW_TCP4_CONNECTION |
  routing/hostname == "WORKSTATION-07" and
  not event/DESTINATION/PORT == 80 and
  not event/DESTINATION/PORT == 443 and
  not event/DESTINATION/PORT == 53 and
  not event/DESTINATION/PORT == 25 |
  event/DESTINATION/IP_ADDRESS as dst_ip
  event/DESTINATION/PORT as dst_port
  COUNT(event) as count
  GROUP BY(dst_ip dst_port)
  ORDER BY(count desc)
```

#### 6. Cobalt Strike default ports (50050, 4444, 8080 beaconing)
```lcql
-24h | * | NEW_TCP4_CONNECTION |
  event/DESTINATION/PORT == 50050 or
  event/DESTINATION/PORT == 4444 or
  event/DESTINATION/PORT == 8080 or
  event/DESTINATION/PORT == 1337 |
  routing/hostname as host
  event/DESTINATION/IP_ADDRESS as dst_ip
  event/DESTINATION/PORT as port
  routing/event_time as ts
```

#### 7. HTTP C2 — suspicious user-agent strings
```lcql
-24h | * | HTTP_REQUEST |
  event/URL contains "beacon" or
  event/URL contains "/api/v" or
  event/URL contains "/update" |
  routing/hostname as host
  event/URL as url
  event/IP_ADDRESS as dst_ip
  routing/event_time as ts
  ORDER BY(ts desc)
```

#### 8. DNS exfiltration — long subdomain labels (data encoded in DNS)
```lcql
-24h | * | DNS_REQUEST |
  event/DOMAIN_NAME contains ".evil.com" or
  event/DNS_TYPE == "TXT" |
  routing/hostname as host
  event/DOMAIN_NAME as domain
  COUNT(event) as count
  GROUP BY(host domain)
  ORDER BY(count desc)
```
TXT record requests from endpoints = DNS exfiltration or C2. Long subdomain = encoded payload.

---
### EXECUTION (TA0002)

#### 9. PowerShell encoded command execution
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/COMMAND_LINE contains "EncodedCommand" or
  event/COMMAND_LINE contains "-enc " or
  event/COMMAND_LINE contains "-e " or
  event/COMMAND_LINE contains "FromBase64String" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  event/PARENT/FILE_PATH as parent
  routing/event_time as ts
  ORDER BY(ts desc)
```

#### 10. LOLBin — certutil download cradle
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/FILE_PATH contains "certutil" and (
  event/COMMAND_LINE contains "urlcache" or
  event/COMMAND_LINE contains "decode" or
  event/COMMAND_LINE contains "-f " ) |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 11. LOLBin — bitsadmin, mshta, regsvr32, rundll32 abuse
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/FILE_PATH contains "bitsadmin" or
  event/FILE_PATH contains "mshta.exe" or
  (event/FILE_PATH contains "regsvr32" and event/COMMAND_LINE contains "http") or
  (event/FILE_PATH contains "rundll32" and event/COMMAND_LINE contains "javascript") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  event/PARENT/FILE_PATH as parent
  routing/event_time as ts
```

#### 12. WMI execution (wmic spawning processes)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/PARENT/FILE_PATH contains "WmiPrvSE" or
  event/PARENT/FILE_PATH contains "wmic" or
  (event/FILE_PATH contains "wmic" and event/COMMAND_LINE contains "process call create") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 13. Office macro spawning shell (spearphishing execution)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/PARENT/FILE_PATH contains "WINWORD" or
  event/PARENT/FILE_PATH contains "EXCEL" or
  event/PARENT/FILE_PATH contains "POWERPNT" or
  event/PARENT/FILE_PATH contains "OUTLOOK" |
  routing/hostname as host
  event/FILE_PATH as child_proc
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```
Any shell/powershell/cmd spawned from Office = malicious macro or exploit.

#### 14. Script interpreter abuse (wscript/cscript)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/FILE_PATH contains "wscript.exe" or
  event/FILE_PATH contains "cscript.exe" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  event/PARENT/FILE_PATH as parent
  routing/event_time as ts
```

#### 15. Suspicious base64 blob in command line
```lcql
-24h | * | NEW_PROCESS |
  event/COMMAND_LINE contains "JAB" or
  event/COMMAND_LINE contains "TVqQ" or
  event/COMMAND_LINE contains "SUVY" or
  event/COMMAND_LINE contains "SQBuAH" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```
`JAB` = `$` in base64 (PowerShell variable). `TVqQ` = MZ header (PE in base64). Instant IOC.

#### 16. Browser spawning unexpected child process (drive-by download)
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/PARENT/FILE_PATH contains "chrome" or
   event/PARENT/FILE_PATH contains "firefox" or
   event/PARENT/FILE_PATH contains "msedge" or
   event/PARENT/FILE_PATH contains "iexplore") and
  (event/FILE_PATH contains "cmd.exe" or
   event/FILE_PATH contains "powershell" or
   event/FILE_PATH contains "wscript") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

---
### PERSISTENCE (TA0003)

#### 17. New Windows service installed (WEL 7045)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 7045 |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
  ORDER BY(ts desc)
```

#### 18. Scheduled task creation (WEL 4698)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4698 |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
```
4698 = task created. Look for tasks pointing to temp/appdata paths or encoded commands.

#### 19. Registry run key modification (WEL 4657)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4657 and (
  event/MESSAGE contains "CurrentVersion\\Run" or
  event/MESSAGE contains "CurrentVersion\\RunOnce" or
  event/MESSAGE contains "Winlogon") |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
```

#### 20. File written to startup folder
```lcql
-24h | plat == windows | FILE_CREATE |
  event/FILE_PATH contains "\\Start Menu\\Programs\\Startup\\" or
  event/FILE_PATH contains "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\" |
  routing/hostname as host
  event/FILE_PATH as path
  event/HASH as hash
  routing/event_time as ts
```

#### 21. DLL loaded from suspicious path (DLL hijacking / sideloading)
```lcql
-24h | plat == windows | MODULE_LOAD |
  (event/FILE_PATH contains "\\Temp\\" or
   event/FILE_PATH contains "\\AppData\\" or
   event/FILE_PATH contains "\\Downloads\\") and
  event/FILE_PATH ends with ".dll" |
  routing/hostname as host
  event/FILE_PATH as dll_path
  event/PROCESS_ID as pid
  routing/event_time as ts
```

#### 22. Logon script / GPO script persistence (WEL 4688 + path)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/PARENT/FILE_PATH contains "userinit" or
  event/COMMAND_LINE contains "\\scripts\\" or
  event/COMMAND_LINE contains "\\logon\\" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

---
### CREDENTIAL ACCESS (TA0006)

#### 23. Brute force — rapid failed logons (WEL 4625 burst)
```lcql
-1h | plat == windows | WEL |
  event/EVENT_ID == 4625 |
  routing/hostname as host
  event/USER_NAME as user
  COUNT(event) as failures
  GROUP BY(host user)
  ORDER BY(failures desc)
```
>10 failures in 1h from same host/user = brute force or password spray.

#### 24. Kerberoasting — RC4 TGS requests (WEL 4769)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4769 and
  event/MESSAGE contains "0x17" |
  routing/hostname as host
  event/USER_NAME as user
  event/MESSAGE as details
  routing/event_time as ts
```
`0x17` = RC4-HMAC encryption type in Kerberos TGS. Modern DCs use AES; RC4 request = Kerberoasting.

#### 25. Pass-the-hash — explicit credential logon (WEL 4648)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4648 |
  routing/hostname as host
  event/USER_NAME as user
  event/MESSAGE as details
  COUNT(event) as count
  GROUP BY(host user)
  ORDER BY(count desc)
```
Rare in normal operations. Multiple 4648 from same host = lateral movement with stolen hash.

#### 26. LSASS memory access (credential dumping)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/COMMAND_LINE contains "lsass" or
  (event/FILE_PATH contains "procdump" and event/COMMAND_LINE contains "lsass") or
  event/COMMAND_LINE contains "sekurlsa" or
  event/COMMAND_LINE contains "dumpcreds" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 27. DCSync — DS replication rights abuse (WEL 4662)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4662 and
  event/MESSAGE contains "1131f6aa" |
  routing/hostname as host
  event/USER_NAME as user
  event/MESSAGE as details
  routing/event_time as ts
```
GUID `1131f6aa` = DS-Replication-Get-Changes. Non-DC performing this = DCSync attack.

#### 28. Credential dumping via comsvcs.dll (MiniDump)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/COMMAND_LINE contains "comsvcs.dll" and
  event/COMMAND_LINE contains "MiniDump" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```
`rundll32 comsvcs.dll,MiniDump <lsass_pid>` = native Windows credential dump, no external tools.

#### 29. SAM / NTDS database access
```lcql
-24h | plat == windows | FILE_TYPE_ACCESSED |
  event/FILE_PATH contains "\\SAM" or
  event/FILE_PATH contains "\\NTDS\\ntds.dit" or
  event/FILE_PATH contains "\\system32\\config\\SYSTEM" |
  routing/hostname as host
  event/FILE_PATH as path
  event/PROCESS_ID as pid
  routing/event_time as ts
```

---
### LATERAL MOVEMENT (TA0008)

#### 30. PsExec usage — service creation on remote host
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 7045 and
  event/MESSAGE contains "PSEXESVC" |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
```

#### 31. WMI remote execution to lateral host
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/PARENT/FILE_PATH contains "WmiPrvSE" and
  (event/FILE_PATH contains "cmd.exe" or
   event/FILE_PATH contains "powershell") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 32. RDP lateral movement (WEL 4624 type 10)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4624 and
  event/MESSAGE contains "LogonType: 10" |
  routing/hostname as host
  event/USER_NAME as user
  event/MESSAGE as details
  COUNT(event) as count
  GROUP BY(host user)
  ORDER BY(count desc)
```
Logon type 10 = RemoteInteractive (RDP). Multiple hosts in sequence = RDP hopping.

#### 33. SMB admin share access (C$ / ADMIN$)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 5140 and (
  event/MESSAGE contains "\\C$" or
  event/MESSAGE contains "\\ADMIN$" or
  event/MESSAGE contains "\\IPC$") |
  routing/hostname as host
  event/USER_NAME as user
  event/MESSAGE as details
  routing/event_time as ts
```

#### 34. Remote scheduled task creation (lateral execution)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4698 and
  event/MESSAGE contains "S-1-5-18" |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
```
Task created running as SYSTEM on a host the analyst didn't touch = remote task (PsExec/DCOM pattern).

#### 35. Pass-the-ticket — Kerberos anomaly (4768 + unusual workstation)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4768 and
  not event/MESSAGE contains "MACHINE$" |
  routing/hostname as host
  event/USER_NAME as user
  event/MESSAGE as details
  routing/event_time as ts
```

#### 36. DCOM lateral movement (mmc.exe or excel.exe spawning shell remotely)
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/PARENT/FILE_PATH contains "mmc.exe" or
   event/PARENT/FILE_PATH contains "EXCEL") and
  (event/FILE_PATH contains "cmd.exe" or
   event/FILE_PATH contains "powershell") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

---
### DISCOVERY (TA0007)

#### 37. Internal port scanning — high unique destination count from one host
```lcql
-1h | * | NEW_TCP4_CONNECTION |
  routing/hostname == "WORKSTATION-07" |
  event/DESTINATION/IP_ADDRESS as dst_ip
  event/DESTINATION/PORT as dst_port
  COUNT_UNIQUE(dst_ip) as unique_ips
  GROUP BY(dst_port)
  ORDER BY(unique_ips desc)
```
>20 unique IPs on same port in 1h = horizontal scan. Many ports on same IP = vertical scan.

#### 38. AD/LDAP enumeration (WEL 4662 on directory objects)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4662 and
  event/MESSAGE contains "user" |
  routing/hostname as host
  event/USER_NAME as user
  COUNT(event) as count
  GROUP BY(host user)
  ORDER BY(count desc)
```

#### 39. Account/group discovery via net commands
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/FILE_PATH contains "net.exe" or event/FILE_PATH contains "net1.exe") and
  (event/COMMAND_LINE contains "user" or
   event/COMMAND_LINE contains "group" or
   event/COMMAND_LINE contains "localgroup" or
   event/COMMAND_LINE contains "domain") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 40. Network share enumeration
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/FILE_PATH contains "net.exe" and event/COMMAND_LINE contains "view") or
  (event/FILE_PATH contains "nltest" and event/COMMAND_LINE contains "dclist") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 41. Process/service discovery (tasklist, sc query)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/FILE_PATH contains "tasklist" or
  (event/FILE_PATH contains "sc.exe" and event/COMMAND_LINE contains "query") or
  event/FILE_PATH contains "qprocess" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 42. System info gathering (systeminfo, ipconfig, whoami)
```lcql
-24h | plat == windows | NEW_PROCESS |
  event/FILE_PATH contains "systeminfo" or
  event/FILE_PATH contains "whoami" or
  (event/FILE_PATH contains "ipconfig" and event/COMMAND_LINE contains "/all") or
  event/FILE_PATH contains "hostname.exe" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  event/PARENT/FILE_PATH as parent
  routing/event_time as ts
```
Legitimate admin rarely runs all of these in sequence. Cluster of discovery commands = post-exploitation recon.

---
### DEFENSE EVASION (TA0005)

#### 43. Event log clearing (WEL 1102 / 104)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 1102 or
  event/EVENT_ID == 104 |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
```
1102 = Security log cleared. 104 = System log cleared. Almost never legitimate.

#### 44. Process masquerading — svchost / lsass in wrong path
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/FILE_PATH contains "svchost" and
   not event/FILE_PATH contains "\\System32\\svchost") or
  (event/FILE_PATH contains "lsass" and
   not event/FILE_PATH contains "\\System32\\lsass") or
  (event/FILE_PATH contains "csrss" and
   not event/FILE_PATH contains "\\System32\\csrss") |
  routing/hostname as host
  event/FILE_PATH as path
  routing/event_time as ts
```

#### 45. Timestomping — file with modification time far before creation time
```lcql
-24h | plat == windows | FILE_MODIFIED |
  event/FILE_PATH contains "\\Temp\\" or
  event/FILE_PATH contains "\\AppData\\" |
  routing/hostname as host
  event/FILE_PATH as path
  routing/event_time as ts
```
Correlate creation time with modification time — attacker sets mtime to year 2010 to hide the file.

#### 46. UAC bypass — fodhelper / eventvwr technique
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/PARENT/FILE_PATH contains "fodhelper" or
   event/PARENT/FILE_PATH contains "eventvwr") and
  (event/FILE_PATH contains "cmd.exe" or
   event/FILE_PATH contains "powershell") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 47. Security tool tampering — stopping AV/EDR services
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/FILE_PATH contains "sc.exe" and (
   event/COMMAND_LINE contains "stop" or
   event/COMMAND_LINE contains "delete" or
   event/COMMAND_LINE contains "config")) and (
  event/COMMAND_LINE contains "sense" or
  event/COMMAND_LINE contains "windefend" or
  event/COMMAND_LINE contains "mssecflt" or
  event/COMMAND_LINE contains "cavp") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 48. Parent process spoofing (unusual parent-child pair)
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/FILE_PATH contains "powershell" and
   event/PARENT/FILE_PATH contains "explorer.exe") or
  (event/FILE_PATH contains "cmd.exe" and
   event/PARENT/FILE_PATH contains "winword") |
  routing/hostname as host
  event/FILE_PATH as proc
  event/PARENT/FILE_PATH as parent
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 49. Process injection — suspicious module loaded into system process
```lcql
-24h | plat == windows | MODULE_LOAD |
  (event/FILE_PATH contains "\\Temp\\" or
   event/FILE_PATH contains "\\AppData\\") and
  event/FILE_PATH ends with ".dll" |
  routing/hostname as host
  event/FILE_PATH as dll
  event/PROCESS_ID as pid
  routing/event_time as ts
```

---
### EXFILTRATION (TA0010)

#### 50. Large outbound data transfer to external IP
```lcql
-24h | * | NETWORK_CONNECTIONS |
  routing/hostname == "WORKSTATION-07" |
  event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as dst_ip
  event/NETWORK_ACTIVITY/DESTINATION/PORT as dst_port
  COUNT(event) as sessions
  GROUP BY(dst_ip dst_port)
  ORDER BY(sessions desc)
  LIMIT 20
```
Combine with connection duration from SIEM — sustained high-session-count connection to external IP = staging/exfil.

#### 51. Compressed archive creation before transfer (staging)
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/FILE_PATH contains "7z.exe" or
   event/FILE_PATH contains "winrar" or
   event/FILE_PATH contains "compress") and
  (event/COMMAND_LINE contains "-p" or
   event/COMMAND_LINE contains "password") |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```
Password-protected archive + network transfer shortly after = staged exfil.

#### 52. Cloud storage upload (Dropbox / OneDrive / Google Drive)
```lcql
-24h | * | DNS_REQUEST |
  event/DOMAIN_NAME contains "dropbox" or
  event/DOMAIN_NAME contains "onedrive" or
  event/DOMAIN_NAME contains "drive.google" or
  event/DOMAIN_NAME contains "mega.nz" or
  event/DOMAIN_NAME contains "anonfiles" |
  routing/hostname as host
  event/DOMAIN_NAME as domain
  COUNT(event) as count
  GROUP BY(host domain)
  ORDER BY(count desc)
```

#### 53. FTP / unusual protocol outbound
```lcql
-24h | * | NEW_TCP4_CONNECTION |
  event/DESTINATION/PORT == 21 or
  event/DESTINATION/PORT == 990 or
  event/DESTINATION/PORT == 69 |
  routing/hostname as host
  event/DESTINATION/IP_ADDRESS as dst_ip
  event/DESTINATION/PORT as port
  routing/event_time as ts
```
Outbound FTP from workstation = almost always exfiltration or C2.

#### 54. DNS data exfiltration (TXT query from endpoint)
```lcql
-24h | * | DNS_REQUEST |
  event/DNS_TYPE == "TXT" |
  routing/hostname as host
  event/DOMAIN_NAME as domain
  COUNT(event) as count
  GROUP BY(host domain)
  ORDER BY(count desc)
```

---
### PRIVILEGE ESCALATION (TA0004)

#### 55. Token impersonation — SYSTEM logon from service (WEL 4624 type 5)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4624 and
  event/MESSAGE contains "LogonType: 5" and
  not event/MESSAGE contains "MACHINE$" |
  routing/hostname as host
  event/USER_NAME as user
  event/MESSAGE as details
  routing/event_time as ts
```

#### 56. Privilege escalation via scheduled task (task running as SYSTEM)
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4698 and
  event/MESSAGE contains "NT AUTHORITY\\SYSTEM" |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
```

#### 57. UAC bypass via registry key manipulation
```lcql
-24h | plat == windows | WEL |
  event/EVENT_ID == 4657 and
  event/MESSAGE contains "mscfile" or
  event/MESSAGE contains "ms-settings" |
  routing/hostname as host
  event/MESSAGE as details
  routing/event_time as ts
```

#### 58. Linux sudo abuse / SUID exploitation
```lcql
-24h | plat == linux | NEW_PROCESS |
  event/COMMAND_LINE contains "sudo " or
  (event/COMMAND_LINE contains "chmod" and event/COMMAND_LINE contains "+s") or
  event/FILE_PATH contains "/etc/sudoers" |
  routing/hostname as host
  event/COMMAND_LINE as cmdline
  event/PARENT/FILE_PATH as parent
  routing/event_time as ts
```

---
### INITIAL ACCESS (TA0001)

#### 59. Suspicious document execution chain (phishing)
```lcql
-24h | plat == windows | NEW_PROCESS |
  (event/PARENT/FILE_PATH contains "WINWORD" or
   event/PARENT/FILE_PATH contains "EXCEL" or
   event/PARENT/FILE_PATH contains "OUTLOOK") and
  (event/FILE_PATH contains "powershell" or
   event/FILE_PATH contains "cmd.exe" or
   event/FILE_PATH contains "wscript" or
   event/FILE_PATH contains "mshta") |
  routing/hostname as host
  event/FILE_PATH as child
  event/COMMAND_LINE as cmdline
  routing/event_time as ts
```

#### 60. Newly executed binary with no prior CODE_IDENTITY (first seen)
```lcql
-1h | * | CODE_IDENTITY |
  event/HASH as hash
  event/FILE_PATH as path
  routing/hostname as host
  COUNT_UNIQUE(hash) as seen_on_hosts
  GROUP BY(hash path)
  ORDER BY(seen_on_hosts asc)
  LIMIT 50
```
Hashes seen on only 1 host, never before = newly dropped binary. Cross-reference with VirusTotal immediately.

---

## D&R Rule Detection: Key Operators for Hunting

### Path reference
```yaml
path: event/COMMAND_LINE
path: event/DESTINATION/IP_ADDRESS
path: routing/hostname
```

### Operators
```yaml
op: contains        value: "powershell"
op: matches         value: '(?i)mimikatz|sekurlsa|lsadump'
op: is              value: "4625"
op: starts with     value: "C:\\Windows\\Temp"
op: cidr            value: "10.0.0.0/8"
op: is public address     # no value needed — true if IP is publicly routable
op: exists          path: event/FILE_PATH
```

### Lookback — compare two fields in the same event
```yaml
op: is
path: event/DESTINATION/IP_ADDRESS
value: <<event/SOURCE/IP_ADDRESS>>    # flags if src == dst (loopback anomaly)
```

### Stateful — detect multi-hop process chains
```yaml
op: with descendant
event: NEW_PROCESS
rules:
  - op: contains
    path: event/FILE_PATH
    value: cmd.exe
```

### Threat feed lookup
```yaml
op: lookup
path: event/DESTINATION/IP_ADDRESS
resource: hive://lookup/c2_ips
```

---

## Investigation Workflow for L2

1. **Start with routing/hostname or routing/ext_ip** to scope all events from the artifact
2. **Pull NEW_TCP4_CONNECTION + DNS_REQUEST** first — network behavior is the fastest C2 indicator
3. **Check CONNECTION frequency** — COUNT + GROUP BY + ORDER BY ts reveals beaconing intervals
4. **Follow process chain** — NEW_PROCESS with parent path shows what spawned suspicious connections
5. **Check CODE_IDENTITY hash** against threat intel (VirusTotal via lookup_ioc)
6. **Look for WEL 4624/4648/4625** around the same timestamp — authentication concurrent with beaconing = active operator
7. **Check FILE_CREATE in Temp/AppData** around process spawn time — dropper activity

---

## Field Reference: What to Search When

| Scenario | Event Type | Key Fields |
|---|---|---|
| C2 beaconing | `NEW_TCP4_CONNECTION` | `DESTINATION/IP_ADDRESS`, `DESTINATION/PORT` |
| DNS tunneling | `DNS_REQUEST` | `DOMAIN_NAME` — look for long/random names |
| Process injection | `MODULE_LOAD` | `FILE_PATH` — DLL loaded into unexpected process |
| Credential theft | `WEL` event 4624/4648 | `USER_NAME`, `routing/hostname` |
| Persistence | `WEL` event 7045 | `MESSAGE` — service details |
| Lateral movement | `NEW_TCP4_CONNECTION` to port 445/135/3389 | `DESTINATION/PORT` |
| Data staging | `FILE_CREATE` in Temp | `FILE_PATH`, `HASH` |
| Living-off-the-land | `NEW_PROCESS` | `COMMAND_LINE` — look for encoded powershell, certutil, bitsadmin |
