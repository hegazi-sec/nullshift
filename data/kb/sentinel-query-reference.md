---
title: Microsoft Sentinel Query Reference for Security Investigation
description: KQL (Kusto Query Language) syntax, Sentinel / Log Analytics table schema, and 60 investigation patterns for L2 hunting in Microsoft Sentinel and Microsoft 365 Defender
tags:
  - sentinel
  - microsoft-sentinel
  - kql
  - kusto
  - log-analytics
  - defender
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

# Microsoft Sentinel Query Reference for Security Investigation

Microsoft Sentinel runs on **Log Analytics** and queries everything with
**KQL** (Kusto Query Language). Data lands in typed **tables** — you always
start a query by naming the table, then pipe through transforms.

The same KQL works in the Microsoft 365 Defender advanced-hunting portal, so
the `Device*` table patterns below are portable between Sentinel and MDE.

---

## KQL Pipeline Syntax

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize Failures = count() by Account, IpAddress
| where Failures > 10
| sort by Failures desc
```

Read top to bottom: name the table, filter early with `where`, aggregate with
`summarize`, then `sort`/`take`. Filtering before summarizing is what keeps
queries fast.

---

## Time Filtering

```kql
| where TimeGenerated > ago(24h)          last 24 hours
| where TimeGenerated > ago(1h)           last hour
| where TimeGenerated > ago(7d)           last 7 days
| where TimeGenerated between (ago(2d) .. ago(1d))   a specific window
| where TimeGenerated > startofday(now())  since midnight UTC
```

`TimeGenerated` is the ingestion timestamp present on every table. Always put
the time filter first — Log Analytics partitions on it.

---

## Core KQL Operators

| Operator | Purpose |
|---|---|
| `where` | Filter rows (`==`, `!=`, `in`, `has`, `contains`, `matches regex`) |
| `project` / `project-away` | Choose / drop columns |
| `extend` | Add a computed column |
| `summarize` | Aggregate (`count()`, `dcount()`, `sum()`, `make_set()`) by keys |
| `join kind=inner` | Correlate two tables on a shared key |
| `union` | Combine rows from multiple tables |
| `top N by Col` | Highest N rows |
| `distinct` | Unique value combinations |
| `parse` | Extract fields from a string with a pattern |
| `mv-expand` | Fan out an array column into rows |
| `bin(TimeGenerated, 1h)` | Bucket time for `summarize` (histograms/beacons) |

String match nuance: `has` is fast whole-token match (indexed); `contains` is
substring (slower); `=~` is case-insensitive equality. Prefer `has` when you
can.

---

## Key Tables

| Table | Contents |
|---|---|
| `SecurityEvent` | Windows Security event log (MMA/AMA agent) — 4624, 4625, 4688… |
| `SigninLogs` | Entra ID (Azure AD) interactive sign-ins |
| `AADNonInteractiveUserSignInLogs` | Token / non-interactive sign-ins |
| `AuditLogs` | Entra ID directory changes (users, roles, apps) |
| `OfficeActivity` | Exchange / SharePoint / Teams audit |
| `AzureActivity` | Azure Resource Manager control-plane operations |
| `DeviceProcessEvents` | MDE — process creation (portable to M365D) |
| `DeviceNetworkEvents` | MDE — network connections |
| `DeviceFileEvents` | MDE — file create/modify/delete |
| `DeviceRegistryEvents` | MDE — registry changes |
| `DeviceLogonEvents` | MDE — logon activity |
| `CommonSecurityLog` | CEF firewall / proxy / IDS logs |
| `Syslog` | Linux syslog |
| `DnsEvents` | DNS analytics logs |
| `SecurityAlert` | Alerts from Defender products / analytics rules |

When unsure which table, `search "indicator"` scans across tables — expensive,
but useful for a first pivot.

---

## Common Field Reference

**SecurityEvent (Windows)**
```
EventID              4624 logon, 4625 failed, 4688 process, 4672 priv, 4769 kerb
Account / TargetUserName / SubjectUserName
Computer             hostname
IpAddress            source IP (logon events)
LogonType            3 = network, 10 = RDP
NewProcessName       full image path (4688)
CommandLine          process command line (4688, requires audit policy)
ParentProcessName
```

**SigninLogs (Entra ID)**
```
UserPrincipalName
IPAddress
ResultType           0 = success; 50126 bad password; 50074 MFA required …
AppDisplayName
Location / LocationDetails
ConditionalAccessStatus
RiskLevelDuringSignIn
AuthenticationRequirement
```

**Device* (MDE / M365 Defender)**
```
DeviceName
AccountName / AccountDomain
FileName / FolderPath / SHA256 / SHA1 / MD5
ProcessCommandLine   ← primary hunting field
InitiatingProcessFileName / InitiatingProcessCommandLine   (parent)
RemoteIP / RemoteUrl / RemotePort   (DeviceNetworkEvents)
RegistryKey / RegistryValueName / RegistryValueData
```

---

## Investigation Query Patterns (60 Patterns)

Replace example IPs/hosts/accounts with your indicators. All patterns assume a
leading `| where TimeGenerated > ago(24h)` — add or widen as needed.

---
### COMMAND & CONTROL (TA0011)

#### 1. All connections to/from a suspicious IP
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIP == "1.2.3.4" or LocalIP == "1.2.3.4"
| summarize Connections = count(), FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated) by DeviceName, RemoteIP, RemotePort
| sort by Connections desc
```

#### 2. Beaconing — connection histogram per destination
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where DeviceName == "WS-042"
| summarize Hits = count() by RemoteIP, bin(TimeGenerated, 1h)
| sort by RemoteIP asc, TimeGenerated asc
```
Even hit counts across every hourly bucket = automated beacon.

#### 3. Beaconing by interval regularity (low jitter)
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where DeviceName == "WS-042"
| sort by RemoteIP asc, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevIP = prev(RemoteIP)
| where RemoteIP == PrevIP
| extend Interval = datetime_diff('second', TimeGenerated, PrevTime)
| summarize Jitter = stdev(Interval), Beats = count() by RemoteIP, RemotePort
| where Beats > 3 and Jitter < 60
| sort by Jitter asc
```
Low jitter (stdev < 60s) with repeat count > 3 = C2 heartbeat.

#### 4. DNS requests for suspicious domains
```kql
DnsEvents
| where TimeGenerated > ago(24h)
| where Name has_any ("evil", "c2", ".xyz", ".top")
| summarize count() by ClientIP, Name
| sort by count_ desc
```

#### 5. DGA detection — many unique domains per host
```kql
DnsEvents
| where TimeGenerated > ago(24h)
| summarize UniqueDomains = dcount(Name) by ClientIP
| where UniqueDomains > 200
| sort by UniqueDomains desc
```

#### 6. Long DNS labels (DNS tunneling / exfil)
```kql
DnsEvents
| where TimeGenerated > ago(24h)
| extend QueryLen = strlen(Name)
| where QueryLen > 50
| project TimeGenerated, ClientIP, Name, QueryLen
| sort by QueryLen desc
```

#### 7. Non-standard outbound ports
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 53, 25, 123, 3389)
| summarize count() by DeviceName, RemoteIP, RemotePort
| sort by count_ desc
```

#### 8. Firewall — allowed outbound to rare destinations (CEF)
```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceAction == "allow" and Direction == "outbound"
| summarize Bytes = sum(SentBytes) by SourceIP, DestinationIP, DestinationPort
| where Bytes > 10000000
| sort by Bytes desc
```

#### 9. Connections to known-bad IP list (threat intel join)
```kql
let badIPs = dynamic(["1.2.3.4", "5.6.7.8"]);
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIP in (badIPs)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

#### 10. Rare user agents on outbound HTTP (proxy log)
```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(RequestClientApplication)
| summarize count() by RequestClientApplication
| sort by count_ asc
| take 25
```

---
### EXECUTION (TA0002)

#### 11. PowerShell encoded command
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

#### 12. PowerShell script block with base64 payload (4104)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4104
| where EventData has_any ("frombase64string", "JAB", "TVqQ")
| project TimeGenerated, Computer, EventData
```

#### 13. Office app spawning a shell (macro execution)
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

#### 14. mshta / rundll32 with URL or script argument
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("mshta.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("http", "javascript", "vbscript")
```

#### 15. wscript/cscript running a script file
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any (".vbs", ".js", ".wsf")
```

#### 16. services.exe spawning a shell
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName =~ "services.exe"
| where FileName in~ ("cmd.exe", "powershell.exe")
```

#### 17. Linux web server spawning a shell (webshell)
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ ("apache2", "httpd", "nginx", "php-fpm")
| where FileName in~ ("sh", "bash", "dash", "python", "perl")
```

#### 18. curl/wget piped to shell (Linux)
```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("curl", "wget")
| where SyslogMessage has_any ("| sh", "| bash", "|sh", "|bash")
```

#### 19. Scheduled task creation via schtasks
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "create"
```

#### 20. WMIC process call create
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "process" and ProcessCommandLine has "call"
    and ProcessCommandLine has "create"
```

---
### PERSISTENCE (TA0003)

#### 21. Run key registry modification
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(24h)
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

#### 22. New service installation (7045)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 7045
| project TimeGenerated, Computer, ServiceName = Service, ImagePath = ServiceFileName
| summarize count() by Computer, ServiceName, ImagePath
| sort by count_ asc
```

#### 23. New scheduled task registered (4698)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4698
| project TimeGenerated, Computer, Account, TaskName = to_lower(EventData)
```

#### 24. Linux cron / systemd persistence
```kql
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where FolderPath has_any ("/etc/cron", "/var/spool/cron", "/etc/systemd/system")
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
```

#### 25. New local user created (4720)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4720
| project TimeGenerated, Computer, NewUser = TargetUserName, By = SubjectUserName
```

#### 26. User added to privileged group (4728 / 4732 / 4756)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4728, 4732, 4756)
| project TimeGenerated, Computer, Group = TargetUserName, Member = MemberName, By = SubjectUserName
```

#### 27. Startup folder file drop
```kql
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where FolderPath has @"\Start Menu\Programs\Startup"
| where ActionType == "FileCreated"
```

#### 28. WMI event subscription persistence
```kql
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType == "WmiBindEventFilterToConsumer"
| project TimeGenerated, DeviceName, AdditionalFields
```

#### 29. SSH authorized_keys modification (Linux)
```kql
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where FileName == "authorized_keys"
| project TimeGenerated, DeviceName, FolderPath, InitiatingProcessCommandLine
```

#### 30. New app registration / service principal (Entra ID)
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add application", "Add service principal",
    "Add app role assignment to service principal")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

---
### PRIVILEGE ESCALATION (TA0004)

#### 31. Special privileges assigned at logon (4672)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4672
| where Account !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| summarize count() by Account, Computer
```

#### 32. Entra ID role assignment (privileged role added)
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "Add member to role"
| extend Role = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, InitiatedBy, Role, TargetResources
```

#### 33. Linux sudo to root
```kql
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "sudo" and SyslogMessage has "COMMAND"
| project TimeGenerated, Computer, SyslogMessage
```

#### 34. UAC bypass via fodhelper / eventvwr
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ ("fodhelper.exe", "eventvwr.exe", "sdclt.exe")
| where FileName in~ ("cmd.exe", "powershell.exe")
```

#### 35. Potato-style exploit binaries
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName has_any ("potato", "printspoofer", "roguepotato", "juicypotato")
```

---
### DEFENSE EVASION (TA0005)

#### 36. Windows event log cleared (1102)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 1102
| project TimeGenerated, Computer, Account = SubjectUserName
```

#### 37. Defender disabled / tampered
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has "DisableRealtimeMonitoring"
    or (ProcessCommandLine has "sc" and ProcessCommandLine has "stop"
        and ProcessCommandLine has_any ("WinDefend", "Sense"))
```

#### 38. Shadow copy deletion (ransomware precursor)
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where (ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadows")
    or (ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

#### 39. bcdedit recovery tampering
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "bcdedit.exe"
| where ProcessCommandLine has_any ("recoveryenabled", "bootstatuspolicy")
```

#### 40. Renamed system binary (LOLBin masquerade)
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where isnotempty(ProcessVersionInfoOriginalFileName)
| where FileName !~ ProcessVersionInfoOriginalFileName
| project TimeGenerated, DeviceName, FileName, ProcessVersionInfoOriginalFileName, ProcessCommandLine
```

#### 41. Clear Linux bash history
```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("history -c", "rm .bash_history", "> ~/.bash_history")
```

#### 42. Base64-encoded Linux command
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has "base64" and ProcessCommandLine has_any ("-d", "--decode")
| where InitiatingProcessFileName in~ ("bash", "sh")
```

---
### CREDENTIAL ACCESS (TA0006)

#### 43. LSASS memory access (credential dumping)
```kql
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "wininit.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

#### 44. comsvcs.dll MiniDump of LSASS
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump"
```

#### 45. Mimikatz command signatures
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any ("sekurlsa", "logonpasswords", "lsadump", "kerberos::")
```

#### 46. Kerberoasting — RC4 service tickets (4769)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName != "krbtgt" and Account !endswith "$"
| summarize Requests = count() by Account, ServiceName
| where Requests > 5
| sort by Requests desc
```

#### 47. AS-REP roasting (4768, no preauth)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4768 and PreAuthType == "0"
| project TimeGenerated, Computer, Account, IpAddress
```

#### 48. NTDS.dit access / ntdsutil
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any ("ntdsutil", "ntds.dit", "ac i ntds")
```

#### 49. Brute force — many failed logons (4625)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize Failures = count() by Account, IpAddress, Computer
| where Failures > 10
| sort by Failures desc
```

#### 50. Entra ID password spray — one IP, many accounts
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "50126"          // invalid username or password
| summarize Accounts = dcount(UserPrincipalName), Attempts = count() by IPAddress
| where Accounts > 10
| sort by Accounts desc
```

#### 51. Impossible travel / atypical sign-in
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| summarize Countries = make_set(Location), Signins = count() by UserPrincipalName
| where array_length(Countries) > 1
```

#### 52. Successful sign-in after many failures (brute force success)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize Failures = countif(ResultType != 0), Successes = countif(ResultType == 0)
    by UserPrincipalName, IPAddress
| where Failures > 10 and Successes > 0
| sort by Failures desc
```

---
### DISCOVERY (TA0007)

#### 53. Native recon command burst
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("whoami.exe", "net.exe", "nltest.exe", "systeminfo.exe",
    "ipconfig.exe", "arp.exe", "route.exe", "tasklist.exe")
| summarize Commands = make_set(FileName), Count = count() by DeviceName, AccountName, bin(TimeGenerated, 5m)
| where Count > 3
```

#### 54. AD enumeration via net group / net user
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "net.exe"
| where ProcessCommandLine has_any ("group", "user", "domain admins", "localgroup")
```

#### 55. BloodHound / SharpHound collection
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any ("sharphound", "bloodhound", "-CollectionMethod", "Invoke-BloodHound")
```

#### 56. Linux enumeration burst
```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("uname", "whoami", "id ", "hostname", "netstat", "crontab -l")
| summarize count() by Computer, bin(TimeGenerated, 5m)
| where count_ > 4
```

---
### LATERAL MOVEMENT (TA0008)

#### 57. Remote (RDP) logon activity — LogonType 10
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624 and LogonType == 10
| project TimeGenerated, Computer, Account, IpAddress
| summarize count() by Account, IpAddress, Computer
```

#### 58. PsExec / remote service execution
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName has "psexec" or InitiatingProcessFileName =~ "PSEXESVC.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

#### 59. WMI / WinRM lateral execution
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "winrshost.exe", "wsmprovhost.exe")
| where FileName in~ ("cmd.exe", "powershell.exe")
```

---
### EXFILTRATION (TA0010)

#### 60. Large outbound transfer to external IP
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIPType == "Public"
| summarize BytesOut = sum(tolong(BytesSent)) by DeviceName, RemoteIP
| where BytesOut > 104857600
| sort by BytesOut desc
```
>100 MB outbound to one external IP — check the destination reputation. (If
`BytesSent` isn't populated in your tenant, pivot to `CommonSecurityLog` /
firewall `SentBytes`.)

#### 61. Upload to cloud storage / paste sites
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteUrl has_any ("pastebin.com", "mega.nz", "anonfiles", "transfer.sh", "file.io")
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName
```

#### 62. Archive staging before exfil
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("7z.exe", "rar.exe", "winrar.exe", "tar.exe", "zip.exe")
| where ProcessCommandLine has_any (" a ", "-r", "-p")
```

#### 63. Mass file access / potential collection
```kql
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where ActionType == "FileAccessed"
| summarize Files = dcount(FileName) by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 10m)
| where Files > 500
| sort by Files desc
```

---

## Investigation Workflow for L2

1. Name the right table first — endpoint questions go to `Device*`, identity
   questions to `SigninLogs`/`AuditLogs`, Windows host logs to `SecurityEvent`.
2. Filter on `TimeGenerated` and the indicator **before** any `summarize` —
   Log Analytics charges and slows on scanned rows.
3. Use `summarize ... by bin(TimeGenerated, 1h)` for beaconing and burst
   detection; `dcount()` for spray/DGA fan-out questions.
4. Correlate identity + endpoint with `join kind=inner` on `AccountName` /
   `UserPrincipalName` when an alert spans both planes.
5. Confirm blast radius with a `summarize by DeviceName` / `by Account` before
   escalating.

---

## Field Reference: What to Search When

| Scenario | Table | Key fields | Event id |
|---|---|---|---|
| Process execution | `DeviceProcessEvents` | `ProcessCommandLine`, `InitiatingProcessFileName` | 4688 |
| PowerShell script block | `SecurityEvent` | `EventData` | 4104 |
| Failed logon / brute force | `SecurityEvent` | `EventID`, `Account`, `IpAddress` | 4625 |
| Entra ID sign-in | `SigninLogs` | `ResultType`, `IPAddress`, `UserPrincipalName` | — |
| RDP / remote logon | `SecurityEvent` | `LogonType` (10) | 4624 |
| Kerberoasting | `SecurityEvent` | `TicketEncryptionType` (0x17) | 4769 |
| New service | `SecurityEvent` | `Service`, `ServiceFileName` | 7045 |
| Registry persistence | `DeviceRegistryEvents` | `RegistryKey`, `RegistryValueData` | — |
| DNS hunting | `DnsEvents` | `Name`, `ClientIP` | — |
| Network flow | `DeviceNetworkEvents` | `RemoteIP`, `RemotePort`, `BytesSent` | — |
| Firewall / proxy (CEF) | `CommonSecurityLog` | `SourceIP`, `DestinationIP`, `SentBytes` | — |
| LSASS access | `DeviceEvents` | `ActionType` (OpenProcessApiCall) | — |
| Directory change | `AuditLogs` | `OperationName`, `TargetResources` | — |
| Log cleared | `SecurityEvent` | `EventID` | 1102 |
