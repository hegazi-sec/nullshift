---
title: Splunk Query Reference for Security Investigation
description: SPL syntax, CIM data model fields, sourcetypes, and 60 investigation patterns for L2 hunting in Splunk SIEM
tags:
  - splunk
  - spl
  - hunting
  - siem
  - query
  - cim
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

# Splunk Query Reference for Security Investigation

## SPL Pipeline Syntax

Every SPL search is a pipeline of commands separated by `|`.

```spl
index=* sourcetype=* field=value
| command1 args
| command2 args
| table field1 field2 field3
```

The first line is the search — everything after `|` transforms results.

---

## Time Modifiers

```spl
earliest=-24h latest=now          last 24 hours
earliest=-1h latest=now           last hour
earliest=-7d latest=now           last 7 days
earliest=-15m latest=now          last 15 minutes
earliest=@d latest=now            since midnight today
earliest=-24h@h latest=@h         last 24 hours, snapped to hour
```

Time modifiers go in the initial search term or in `| where` clauses.

---

## Core SPL Commands

```spl
stats count BY field               count events grouped by field
stats count min(_time) as firstTime max(_time) as lastTime BY dest user
stats values(field) BY other_field collect distinct values
stats dc(field) as unique_count    count distinct values
eval field=if(condition, val1, val2)
eval lower_cmd=lower(CommandLine)
rex field=CommandLine "(?i)(?P<encoded>[A-Za-z0-9+/]{50,}={0,2})"
where field > 10
where like(field, "%powershell%")
where isnull(field)
table field1 field2 field3         output only these fields
rename OldField as new_field
sort -count                        sort descending by count
head 20                            first 20 results
dedup field1 field2                remove duplicate combinations
lookup threat_intel.csv ip OUTPUT threat_category
iplocation src_ip                  add geo data to IP
timechart span=1h count BY src_ip  events per hour per IP
transaction src_ip maxspan=5m      group related events
```

---

## Key Sourcetypes

```
wineventlog_security          Windows Security event log
wineventlog_system            Windows System event log
XmlWinEventLog                XML format Windows events (Sysmon etc.)
powershell                    PowerShell operational logs
WinRegistry                   Windows registry changes
syslog                        Linux syslog
linux_audit                   Linux auditd
stream:dns                    Splunk Stream DNS
stream:tcp                    Splunk Stream TCP connections
stream:http                   Splunk Stream HTTP
pan:traffic                   Palo Alto firewall
cisco:asa                     Cisco ASA firewall
suricata                      Suricata IDS
zeek:dns / zeek:conn          Zeek/Bro network logs
```

---

## CIM Data Model Field Reference

### Endpoint.Processes (Sysmon / Windows 4688)
```
Processes.dest               target host
Processes.user               executing user
Processes.process_name       executable name (e.g. powershell.exe)
Processes.process            full command line
Processes.process_path       full path to executable
Processes.process_hash       file hash
Processes.process_id         PID
Processes.process_guid       process GUID
Processes.parent_process     parent full command line
Processes.parent_process_name parent executable name
Processes.parent_process_path parent full path
Processes.parent_process_id  parent PID
Processes.original_file_name PE OriginalFileName (rename detection)
Processes.process_integrity_level  UAC integrity level
```

### Network_Traffic (firewall / netflow / proxy)
```
All_Traffic.src              source hostname or IP
All_Traffic.src_ip           source IP
All_Traffic.src_port         source port
All_Traffic.dest             destination hostname or IP
All_Traffic.dest_ip          destination IP
All_Traffic.dest_port        destination port
All_Traffic.protocol         tcp / udp / icmp
All_Traffic.transport        transport layer protocol
All_Traffic.app              application name (smb / http / dns)
All_Traffic.action           allowed / blocked / denied
All_Traffic.bytes            total bytes
All_Traffic.bytes_in         inbound bytes
All_Traffic.bytes_out        outbound bytes
All_Traffic.dvc              device that logged the event
All_Traffic.rule             firewall rule name
```

### Authentication (Windows logon / SSH / VPN)
```
Authentication.user          authenticating user
Authentication.src           source host/IP
Authentication.dest          destination host
Authentication.action        success / failure
Authentication.app           app / service
Authentication.signature     event description
Authentication.signature_id  EventCode (4624, 4625 etc.)
Authentication.logon_type    logon type (2/3/10 etc.)
```

### Endpoint.Filesystem (syscheck / FIM)
```
Filesystem.dest              host
Filesystem.file_path         full file path
Filesystem.file_hash         hash
Filesystem.user              user that modified
Filesystem.action            created / modified / deleted
```

### Windows-Native Fields (raw, non-CIM)
```
EventCode                    Windows event ID
ComputerName                 hostname from event
User                         user from event
CommandLine                  process command line (4688/Sysmon 1)
Image                        process image path (Sysmon)
ParentImage                  parent image path (Sysmon)
ParentCommandLine            parent command line
TargetUserName               target account (4624/4625/4648)
SubjectUserName              acting account
LogonType                    logon type integer
TicketEncryptionType         Kerberos encryption type (4769)
ServiceName                  service name (7045)
TaskName                     scheduled task name (4698)
ObjectName                   accessed object (4663/4662)
ShareLocalPath               SMB share path (5140)
ScriptBlockText              PS script block content (4104)
```

---

## Investigation Query Patterns (60 Patterns)

---
### COMMAND & CONTROL (TA0011)

#### 1. All traffic to/from a suspicious IP
```spl
index=* (src_ip="1.2.3.4" OR dest_ip="1.2.3.4")
| stats count min(_time) as firstTime max(_time) as lastTime BY src_ip dest_ip dest_port
| sort -count
```

#### 2. Beaconing — periodic connections to same destination
```spl
index=* sourcetype=* src_ip="192.168.1.50" dest_ip="1.2.3.4"
| timechart span=1h count
```
Even histogram bars at regular intervals = beaconing. Also check `dest_port` consistency.

#### 3. Detect beaconing by connection interval regularity
```spl
index=* src_ip="192.168.1.50"
| sort _time
| streamstats current=f last(_time) as prev_time BY dest_ip
| eval interval=_time-prev_time
| stats stdev(interval) as jitter count BY dest_ip dest_port
| where count > 3 AND jitter < 60
| sort jitter
```
Low jitter (stdev < 60s) + repeat count > 3 = automated beacon.

#### 4. DNS requests for suspicious domains
```spl
index=* sourcetype=stream:dns query="*.evil.*" OR query="*c2*"
| stats count BY query src
| sort -count
```

#### 5. High DNS query volume — DGA detection
```spl
index=* sourcetype=stream:dns
| stats dc(query) as unique_domains count BY src
| where unique_domains > 200
| sort -unique_domains
```
>200 unique domains from one host in a day = DGA malware rotating C2 addresses.

#### 6. DNS TXT record queries from endpoints
```spl
index=* sourcetype=stream:dns record_type=TXT
| stats count BY src query
| sort -count
```
TXT queries from workstations = DNS tunneling or C2 channel.

#### 7. Non-standard outbound port connections
```spl
index=* sourcetype=* action=allowed dest_port!=80 dest_port!=443 dest_port!=53 dest_port!=25
| iplocation dest_ip
| where Country!="United States"
| stats count BY src_ip dest_ip dest_port Country
| sort -count
```

#### 8. Long DNS subdomain labels (DNS exfiltration)
```spl
index=* sourcetype=stream:dns
| eval label_len=len(query)
| where label_len > 50
| stats count BY src query label_len
| sort -label_len
```
Encoded data passed in long subdomains — legitimate domains rarely exceed 30 chars.

---
### EXECUTION (TA0002)

#### 9. PowerShell encoded command
```spl
index=* (sourcetype=WinEventLog OR sourcetype=XmlWinEventLog) EventCode=4688
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*FromBase64String*")
| table _time ComputerName User CommandLine
| sort -_time
```

#### 10. PowerShell script block — base64 payload (EventCode 4104)
```spl
`powershell` EventCode=4104
  (ScriptBlockText="*frombase64string*" OR ScriptBlockText="*JAB*" OR ScriptBlockText="*TVqQ*")
| stats count min(_time) as firstTime max(_time) as lastTime BY dest user ScriptBlockText
```
`JAB` = `$` in base64. `TVqQ` = PE MZ header. Hard IOC.

#### 11. LOLBin — certutil download or decode
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name=certutil.exe
  (Processes.process="*urlcache*" OR Processes.process="*-decode*" OR Processes.process="*-f *")
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 12. LOLBin — mshta / regsvr32 / rundll32 abuse
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name=mshta.exe
  OR (Processes.process_name=regsvr32.exe AND Processes.process="*http*")
  OR (Processes.process_name=rundll32.exe AND Processes.process="*javascript*"))
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 13. WMI spawning shell (remote execution)
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.parent_process_name=WmiPrvSE.exe
  (Processes.process_name=cmd.exe OR Processes.process_name=powershell.exe)
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 14. Office macro spawning shell
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.parent_process_name IN ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE"))
  AND (Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","cscript.exe"))
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 15. Malicious PowerShell executed as a service (EventCode 7045)
```spl
`wineventlog_system` EventCode=7045
| eval l_ImagePath=lower(ImagePath)
| regex l_ImagePath="powershell[.\s]|pwsh[.\s]"
| regex l_ImagePath="-nop[rofile\s]+|-w[indowstyle]*\s+hid[den]*|-enc[odedcommand\s]+"
| stats count BY ComputerName ImagePath ServiceName AccountName
```

#### 16. Script interpreter abuse (wscript / cscript)
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name=wscript.exe OR Processes.process_name=cscript.exe)
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

---
### PERSISTENCE (TA0003)

#### 17. New service installed (EventCode 7045)
```spl
`wineventlog_system` EventCode=7045
| stats count min(_time) as firstTime max(_time) as lastTime BY ComputerName ServiceName ImagePath AccountName
| sort -_time
```

#### 18. Scheduled task created (EventCode 4698)
```spl
`wineventlog_security` EventCode=4698
| stats count BY ComputerName SubjectUserName TaskName
| sort -_time
```

#### 19. Registry run key modification
```spl
index=* sourcetype=WinRegistry
  (registry_path="*\\CurrentVersion\\Run*" OR registry_path="*\\CurrentVersion\\RunOnce*"
   OR registry_path="*Winlogon*")
| table _time dest user registry_path registry_value_data
| sort -_time
```

#### 20. Scheduled task created via XML (schtasks /create /xml)
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name=schtasks.exe
  Processes.process IN ("* /create *","* -create *")
  Processes.process IN ("* /xml *","* -xml *")
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 21. File dropped in startup folder
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Filesystem
  WHERE (Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\*"
  OR Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*")
  BY Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
```

#### 22. Cron job modification (Linux)
```spl
index=* sourcetype=linux_audit file_path IN ("/etc/cron*","/var/spool/cron/*","/etc/crontab")
| stats count BY host user file_path exe
| sort -_time
```

---
### CREDENTIAL ACCESS (TA0006)

#### 23. Brute force — rapid failed logons
```spl
`wineventlog_security` EventCode=4625
| stats count BY ComputerName TargetUserName IpAddress
| where count > 10
| sort -count
```

#### 24. Kerberoasting — RC4 TGS request (EventCode 4769)
```spl
`wineventlog_security` EventCode=4769 ServiceName!="*$"
  (TicketOptions=0x40810000 OR TicketOptions=0x40800000)
  TicketEncryptionType=0x17
| stats count min(_time) as firstTime max(_time) as lastTime BY ComputerName user ServiceName TicketEncryptionType
```
`0x17` = RC4-HMAC. Modern DCs prefer AES. RC4 TGS from non-DC = Kerberoasting.

#### 25. Password spray — many users, few failures each
```spl
`wineventlog_security` EventCode=4625
| stats dc(TargetUserName) as unique_users count BY IpAddress
| where unique_users > 10 AND count < 50
| sort -unique_users
```
Many unique users, low count each = spray (vs. brute force = one user, high count).

#### 26. Credential dumping — LSASS memory access
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process="*lsass*" OR Processes.process_name=procdump.exe
  OR Processes.process="*sekurlsa*" OR Processes.process="*dumpcreds*")
  BY Processes.dest Processes.user Processes.process Processes.process_name
| `drop_dm_object_name(Processes)`
```

#### 27. MiniDump via comsvcs.dll (native credential dump)
```spl
index=* (CommandLine="*comsvcs*" AND CommandLine="*MiniDump*")
| table _time ComputerName User CommandLine
```

#### 28. DCSync — DS-Replication event (EventCode 4662)
```spl
`wineventlog_security` EventCode=4662 ObjectType="domainDNS"
  (Properties="*1131f6aa*" OR Properties="*1131f6ad*" OR Properties="*89e95b76*")
  SubjectUserName!="*$"
| stats count BY ComputerName SubjectUserName ObjectName
```

#### 29. SAM database copy via reg save
```spl
index=* (CommandLine="*reg save*" AND (CommandLine="*sam*" OR CommandLine="*system*" OR CommandLine="*security*"))
| table _time ComputerName User CommandLine
```

---
### LATERAL MOVEMENT (TA0008)

#### 30. PsExec with accepteula flag
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name IN ("psexec.exe","psexec64.exe") OR Processes.original_file_name="psexec.c")
  Processes.process="*accepteula*"
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 31. WMI remote execution
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.parent_process_name=WmiPrvSE.exe
  (Processes.process_name=cmd.exe OR Processes.process_name=powershell.exe)
  BY Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
```

#### 32. RDP lateral movement (EventCode 4624 logon type 10)
```spl
`wineventlog_security` EventCode=4624 LogonType=10
| stats count BY ComputerName TargetUserName IpAddress WorkstationName
| sort -count
```

#### 33. SMB outbound to external hosts (ports 139/445)
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Network_Traffic
  WHERE (All_Traffic.dest_port=445 OR All_Traffic.dest_port=139)
  AND All_Traffic.action IN ("allowed","allow")
  BY All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| iplocation dest_ip
| where isnotnull(Country)
```
SMB going external = data exfil or unusual lateral movement.

#### 34. Admin share access (EventCode 5140 — C$ / ADMIN$)
```spl
`wineventlog_security` EventCode=5140 (ShareName="\\\\*\\C$" OR ShareName="\\\\*\\ADMIN$" OR ShareName="\\\\*\\IPC$")
| stats count BY ComputerName SubjectUserName ShareName IpAddress
| sort -count
```

#### 35. Pass-the-hash — explicit credential logon (EventCode 4648)
```spl
`wineventlog_security` EventCode=4648
| stats count min(_time) as firstTime max(_time) as lastTime BY ComputerName SubjectUserName TargetServerName
| where count > 2
| sort -count
```

#### 36. Remote scheduled task creation (EventCode 4698 + SYSTEM)
```spl
`wineventlog_security` EventCode=4698 SubjectUserName!="*$" SubjectUserName!="SYSTEM"
| stats count BY ComputerName SubjectUserName TaskName
```

---
### DISCOVERY (TA0007)

#### 37. Network port scan — high unique destination port count
```spl
index=* src_ip="192.168.1.50"
| stats dc(dest_port) as unique_ports count BY dest_ip
| where unique_ports > 20
| sort -unique_ports
```

#### 38. Internal host sweep — high unique destination IP count
```spl
index=* src_ip="192.168.1.50"
| stats dc(dest_ip) as unique_hosts BY dest_port
| where unique_hosts > 20
| sort -unique_hosts
```

#### 39. Account and group discovery via net commands
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name IN ("net.exe","net1.exe"))
  AND (Processes.process IN ("*user*","*group*","*localgroup*","*domain*"))
  BY Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
```

#### 40. AD enumeration — LDAP queries (ADSISearcher / ldap)
```spl
index=* (CommandLine="*ADSISearcher*" OR CommandLine="*DirectorySearcher*" OR CommandLine="*([adsisearcher]*")
| table _time ComputerName User CommandLine
```

#### 41. Process and service discovery
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name=tasklist.exe
  OR (Processes.process_name=sc.exe AND Processes.process="*query*")
  OR Processes.process_name=qprocess.exe)
  BY Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
```

#### 42. System info gathering (systeminfo / whoami / ipconfig)
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name IN ("systeminfo.exe","whoami.exe","ipconfig.exe","hostname.exe","nslookup.exe")
  BY Processes.dest Processes.user Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 43. Network share enumeration
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name=net.exe AND Processes.process="*view*")
  OR (Processes.process_name=nltest.exe AND Processes.process="*dclist*")
  BY Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
```

---
### DEFENSE EVASION (TA0005)

#### 44. Event log cleared (EventCode 1102 / 104)
```spl
(`wineventlog_security` EventCode=1102) OR (`wineventlog_system` EventCode=104)
| stats count min(_time) as firstTime max(_time) as lastTime BY ComputerName user EventCode
```

#### 45. Process masquerading — svchost in wrong directory
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name=svchost.exe
  AND Processes.process_path!="*\\Windows\\System32\\svchost.exe"
  AND Processes.process_path!="*\\Windows\\SysWOW64\\svchost.exe"
  BY Processes.dest Processes.process_path Processes.user
| `drop_dm_object_name(Processes)`
```

#### 46. Security tool stopped or disabled
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name=sc.exe
  AND (Processes.process="*stop*" OR Processes.process="*delete*")
  AND (Processes.process IN ("*windefend*","*sense*","*mssecflt*","*avp*","*cavp*"))
  BY Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
```

#### 47. UAC bypass — fodhelper / eventvwr technique
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.parent_process_name IN ("fodhelper.exe","eventvwr.exe")
  AND Processes.process_name IN ("cmd.exe","powershell.exe")
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 48. Windows Defender exclusion added
```spl
index=* (CommandLine="*Add-MpPreference*" AND CommandLine="*ExclusionPath*")
  OR (CommandLine="*Set-MpPreference*" AND CommandLine="*DisableRealtimeMonitoring*")
| table _time ComputerName User CommandLine
```

#### 49. Process injection indicator — unusual module load path
```spl
index=* sourcetype=XmlWinEventLog EventCode=7 (ImageLoaded="*\\Temp\\*" OR ImageLoaded="*\\AppData\\*")
| stats count BY ComputerName Image ImageLoaded
| sort -count
```
EventCode 7 = Sysmon image/DLL load. DLL loaded from temp/appdata into a system process = injection.

---
### EXFILTRATION (TA0010)

#### 50. Large outbound data transfer
```spl
| tstats `security_content_summariesonly` sum(All_Traffic.bytes_out) as total_bytes FROM datamodel=Network_Traffic
  WHERE All_Traffic.action IN ("allowed","allow")
  BY All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
| where total_bytes > 50000000
| sort -total_bytes
```
>50MB to external IP = potential staged exfil. Cross-reference with compression tool execution.

#### 51. Compressed archive with password (staging)
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name IN ("7z.exe","7za.exe","winrar.exe","zip.exe"))
  AND Processes.process="*-p*"
  BY Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
```

#### 52. Cloud storage upload domains
```spl
index=* sourcetype=stream:dns
  (query="*dropbox*" OR query="*onedrive*" OR query="*drive.google*" OR query="*mega.nz*" OR query="*anonfiles*")
| stats count BY src query
| sort -count
```

#### 53. FTP / unusual protocol outbound
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Network_Traffic
  WHERE (All_Traffic.dest_port=21 OR All_Traffic.dest_port=990 OR All_Traffic.dest_port=69)
  AND All_Traffic.action IN ("allowed","allow")
  BY All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
```

#### 54. Data staged before transfer — large file created then network spike
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Filesystem
  WHERE (Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\AppData\\*")
  AND (Filesystem.file_path="*.zip" OR Filesystem.file_path="*.rar" OR Filesystem.file_path="*.7z")
  BY Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
```

---
### PRIVILEGE ESCALATION (TA0004)

#### 55. Special privileges assigned (EventCode 4672)
```spl
`wineventlog_security` EventCode=4672 SubjectUserName!="*$" SubjectUserName!="SYSTEM"
| stats count BY ComputerName SubjectUserName PrivilegeList
| where like(PrivilegeList, "%SeDebugPrivilege%") OR like(PrivilegeList, "%SeImpersonatePrivilege%")
```

#### 56. Token impersonation — SYSTEM logon from unexpected source
```spl
`wineventlog_security` EventCode=4624 LogonType=5 SubjectUserName!="SYSTEM" SubjectUserName!="*$"
| stats count BY ComputerName SubjectUserName TargetUserName
```

#### 57. UAC bypass via registry key (EventCode 4657)
```spl
`wineventlog_security` EventCode=4657
  (ObjectName="*mscfile*" OR ObjectName="*ms-settings*")
| table _time ComputerName SubjectUserName ObjectName NewValue
```

#### 58. Linux sudo privilege escalation
```spl
index=* sourcetype=linux_audit syscall=execve exe="/usr/bin/sudo"
| stats count BY host auid uid exe key
| sort -count
```

---
### INITIAL ACCESS (TA0001)

#### 59. Phishing — Office document spawning shell
```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
  WHERE Processes.parent_process_name IN ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE")
  AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","cscript.exe")
  BY Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

#### 60. First-seen executable — new binary on a host
```spl
| tstats `security_content_summariesonly` dc(Processes.dest) as hosts_seen
  FROM datamodel=Endpoint.Processes
  WHERE Processes.process_hash!="unknown"
  BY Processes.process_hash Processes.process_name Processes.process_path
| where hosts_seen = 1
| sort -_time
| head 50
```
Binary seen on only 1 host ever = newly dropped payload. Cross-reference hash with VirusTotal.

---

## Investigation Workflow for L2

1. **Start with the artifact** — search by `src_ip`, `dest_ip`, `ComputerName`, or `user` across all indexes
2. **Check `stats count BY` the asset** — understand event volume and sources
3. **Look at `_time` distribution** — `timechart span=1h count` reveals patterns
4. **Follow process chain** — `parent_process_name → process_name → CommandLine`
5. **Cross-reference EventCode 4624/4625/4648** — who authenticated, from where, when
6. **Check EventCode 4698 / 7045** — persistence is usually planted early
7. **Use `iplocation`** on external IPs — geo anomaly is a quick C2 indicator
8. **Run `dedup` on hashes** — first-seen binaries surface new threats

---

## Field Reference: What to Search When

| Scenario | Key Fields | EventCodes |
|---|---|---|
| C2 beaconing | `src_ip`, `dest_ip`, `dest_port`, `bytes_out` | — |
| Credential brute force | `TargetUserName`, `IpAddress`, `LogonType` | 4625 |
| Kerberoasting | `TicketEncryptionType=0x17` | 4769 |
| PtH | `SubjectUserName`, `LogonType=3` | 4648 |
| LSASS dump | `CommandLine=*lsass*` | — |
| DCSync | `Properties=*1131f6aa*` | 4662 |
| Persistence — service | `ImagePath`, `ServiceName` | 7045 |
| Persistence — task | `TaskName` | 4698 |
| Log wiping | `EventCode=1102` or `104` | 1102, 104 |
| Lateral RDP | `LogonType=10`, `IpAddress` | 4624 |
| Macro pivot | `parent_process_name=WINWORD.EXE` | — |
| New binary | `process_hash`, `dc(dest)=1` | — |
