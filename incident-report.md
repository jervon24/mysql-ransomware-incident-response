# Incident Report: MySQL Ransom Attack on corp-retail-group

> **PDF version:** [Incident-Report-MySQL-Ransom-Attack.pdf](Incident-Report-MySQL-Ransom-Attack.pdf) · [Back to the repo](../README.md)

Times are US Eastern (UTC-4), as shown in the Defender portal. Date literals inside KQL are UTC (Oct 12 00:10 Eastern = 04:10 UTC). The MySQL audit exports contain every row twice; counts are de-duplicated.

## 1. Executive Summary

An external attacker took over the internet-exposed MySQL server on host corp-retail-group and held its data for ransom. After days of automated probing of the root, admin and sa accounts (every logged failure was a passwordless attempt), the attacker logged in as root with a credential that worked first time, left a ransom note demanding 0.0101 bitcoin within 48 hours, deleted the bby_corp database (plus the sample databases sakila and world), purged the server's binary logs and shut MySQL down at 00:11 on Oct 12, 2026. The attacker's claim that data was copied first is **not confirmed** by the logs. Root logins from attacker-linked addresses continued through Oct 17, and the same server also faced heavy Remote Desktop password guessing against its Windows administrator account.

## 2. Incident Details

| Field                            | Detail                                                                                                                                                                                                                |
|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Earliest malicious event in logs | Oct 7, 2026 20:54 – first connection attempt to the host from the 64.89.163.x range (Defender network events). First MySQL login attempt: Oct 10, 2026 20:19 from 77.90.185.30 (MySQL audit).                         |
| Destructive activity             | Oct 12, 2026 00:10:43 – 00:11:01                                                                                                                                                                                      |
| Reporter                         | Jervon Stephen, Analyst                                                                                                                                                                                               |
| Classification                   | Database extortion (ransom note + data destruction) following unauthorized remote root access; no file encryption observed                                                                                            |
| Severity                         | High (proposed)                                                                                                                                                                                                       |
| Affected assets                  | Host corp-retail-group (MySQL audit; Defender shows the name truncated as corp-retail-gro); MySQL 8.0 service; databases bby_corp, sakila, world (all deleted)                                                        |
| Environment note                 | Lab environment. The binary log name josh-mde-lab-bin and Azure guest-agent files indicate a cloud lab VM, and the database was built from a seed script with synthetic customer, order, payment and credential data. |

![lab seed script](../evidence/screenshots/01-lab-seed-script.png)

*Lab seed script: builds the database with synthetic customer, order, payment and credential data.*

**KQL – confirm Defender coverage of the MySQL host**

```kql
DeviceNetworkEvents
| where DeviceName startswith "corp-retail-gro"
| where InitiatingProcessFileName =~ "mysqld.exe"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Events=count() by DeviceName, DeviceId
```

![defender coverage mysqld](../evidence/screenshots/02-defender-coverage-mysqld.png)

*Defender recorded 323 mysqld network events from Sep 29 to Oct 17, so it covers the whole incident.*

## 3. Impact Assessment

| Area            | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Confidentiality | Attacker had full root access and surveyed all three databases before deleting them, using table-size and column-metadata queries. **No data reads were logged:** the audit log, which covers Oct 10 19:52 onward, contains no queries against business tables, so the ransom note’s claim that the data was copied is unsupported. Defender network telemetry covers the attack window and shows no outbound connection from mysqld to a public address. It records connections, not bytes, so theft over an inbound MySQL session cannot be fully excluded, and a direct copy of the data files would not appear in MySQL’s query log.                                                                                                                                                                      |
| Integrity       | DROP DATABASE on three databases; root privileges revoked and re-granted; PURGE BINARY LOGS and RESET MASTER erased binary log history.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Availability    | SHUTDOWN issued Oct 12 00:11:01. Service reachable again by Oct 12 18:23.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Scope           | One database server. Defender process, file and registry data show no ransomware binary, file encryption or new persistence.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Business impact | **Data loss and downtime.** The bby_corp database was deleted, and MySQL was down for up to about 18 hours (shut down Oct 12 00:11, next logon 18:23). Because the binary logs were purged, recovery depends entirely on the last backup, and anything written since then is lost. **Trust.** The attacker kept root access for five more days, so the server should be treated as untrusted until rebuilt and every credential is rotated. **Legal exposure.** The ransom note threatens to publish the data within 48 hours. The database held customer PII, payment records and application logins (synthetic in this lab). In production, publication would trigger breach-notification review, and the data owner would need to confirm row counts, data classification and backup age to size the loss. |

![credentials table redacted](../evidence/screenshots/03-credentials-table-redacted.png)

*Example of the exposed data: application logins stored in plaintext (synthetic lab data; password column hidden for publication).*

**KQL – MySQL data-directory file activity during the destructive session**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-10-12 04:00:00) .. datetime(2026-10-12 05:00:00))
| where DeviceName startswith "corp-retail-gro"
| where FolderPath has @"\MySQL\MySQL Server 8.0\Data"
| where ActionType in ("FileDeleted", "FileRenamed", "FileCreated")
| project Timestamp, ActionType, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp asc
```

![datadir file created](../evidence/screenshots/04-datadir-file-created.png)

*Defender records mysqld.exe creating the recover_your_data directory at 00:10:43, matching the ransom-note creation in the MySQL audit log.*

**KQL – outbound connections from the database process to non-private addresses**

```kql
DeviceNetworkEvents
| where DeviceName startswith "corp-retail-gro"
| where InitiatingProcessCommandLine has "mysqld"
| where ActionType == "ConnectionSuccess" and not(ipv4_is_private(RemoteIP))
| summarize Conns=count() by RemoteIP, RemotePort
```

![outbound loopback only](../evidence/screenshots/05-outbound-loopback-only.png)

*Only loopback (127.0.0.1, the server talking to itself) is returned, because ipv4_is_private() does not cover loopback. No connection from mysqld to any public address appears in the Sep 29 – Oct 18 telemetry.*

## 4. Indicators of Compromise

The indicators below come from the ransom note and network activity in the log exports. A second set in the same ransom-note format (BTC bc1qk9kv…, ak+28t2@…, 2no\[.\]co/2mysql, DATAID 28T2) was supplied separately but appears in none of the seven exports, so it is listed as unverified and not used in any finding.

| Type            | Value                                                                                       | Context (source table)                                                                                                                | Status                                      |
|-----------------|---------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| BTC address     | bc1qt6kstjjdatqnxd3ksdcfv0jnhdjzndcnkx8zla                                                  | Ransom note; 0.0101 BTC demand, 48-hour deadline (MySQL queries, Oct 12 00:10:44)                                                     | Observed                                    |
| Email           | ak+278hd@onionmail\[.\]org                                                                  | Ransom note contact (MySQL queries)                                                                                                   | Observed                                    |
| URL             | hxxps://cuq\[.\]in/844                                                                      | Ransom note “more information” link (MySQL queries)                                                                                   | Observed                                    |
| Data ID         | 278HD                                                                                       | Ransom note (MySQL queries)                                                                                                           | Observed                                    |
| DB / table name | RECOVER_YOUR_DATA; recover_your_data_info                                                   | Created by attacker; repeated CREATE DATABASE Oct 13–17 (MySQL queries)                                                               | Observed                                    |
| BTC address     | bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99                                                  | Second ransom-note set, supplied separately                                                                                           | Not in supplied logs                        |
| Email           | ak+28t2@onionmail\[.\]org                                                                   | Second ransom-note set, supplied separately                                                                                           | Not in supplied logs                        |
| URL             | hxxps://2no\[.\]co/2mysql                                                                   | Second ransom-note set, supplied separately                                                                                           | Not in supplied logs                        |
| Data ID         | 28T2                                                                                        | Second ransom-note set, supplied separately                                                                                           | Not in supplied logs                        |
| IP              | 77.90.185.30                                                                                | Passwordless login probing as root/admin/sa from Oct 10 20:19; root logons Oct 10 21:35 – Oct 17 10:19 (MySQL auth)                   | Observed                                    |
| IP              | 77.90.185.21                                                                                | Passwordless login probing from Oct 10 21:05; one root logon Oct 14 22:12 (MySQL auth)                                                | Observed                                    |
| IP              | 213.209.159.115                                                                             | Root logon Oct 11 23:29, 11 minutes after 77.90.185.30 logged in; logons through Oct 16 06:35 (MySQL auth)                            | Observed                                    |
| IP              | 64.89.163.169                                                                               | Failed root logons at 00:10:35 and 00:10:41, then successful root logon at 00:11:00 on Oct 12, around the ransom session (MySQL auth) | Observed                                    |
| IP range        | 64.89.163.77, .79, .80, .91, .92, .94, .154, .167, .170, .178                               | Root logons Oct 13–17; several followed by CREATE DATABASE RECOVER_YOUR_DATA (MySQL auth and queries)                                 | Observed                                    |
| IP range        | 64.89.163.130, .83, .140, .134, .144, .149, .153, .148                                      | Connection attempts and inbound connections to the host from Oct 7 (Defender network events)                                          | Observed                                    |
| IP              | 139.162.70.53; 3.129.187.38; 2.27.109.208                                                   | Inbound connections to mysqld Oct 10–16 (4, 3 and 2 connections; Defender network events)                                             | Observed, role unconfirmed                  |
| IP              | 35.205.252.77; 34.78.226.9                                                                  | Root logon Oct 14 22:09; logon as user client Oct 17 03:34 from 34.78.226.9 (MySQL auth)                                              | Observed, role unclear                      |
| IP              | 154.64.211.102; 58.56.187.158; 182.76.18.106; 38.172.56.189; 41.248.226.178; 146.19.125.182 | Successful network logons to Windows account administrator, Oct 12 20:29 – Oct 16 21:03 (DeviceLogonEvents)                           | Observed, link to DB attack not established |
| Account         | root, admin, sa (MySQL); administrator (Windows)                                            | Targeted accounts                                                                                                                     | Observed                                    |

![ransom note](../evidence/screenshots/06-ransom-note.png)

*Ransom note as stored in recover_your_data. The grid truncates the DATAID; the full value (278HD) is in the audit log.*

**KQL – IOC IPs and domains in network telemetry**

```kql
let iocDomains = dynamic(["cuq.in", "2no.co", "onionmail.org"]);
let iocIPs = dynamic(["77.90.185.30", "77.90.185.21", "213.209.159.115", "35.205.252.77", "34.78.226.9", "154.64.211.102", "58.56.187.158", "182.76.18.106", "38.172.56.189", "41.248.226.178", "146.19.125.182"]);
DeviceNetworkEvents
| where DeviceName startswith "corp-retail-gro"
| where RemoteUrl has_any (iocDomains) or RemoteIP in (iocIPs) or RemoteIP startswith "64.89.163."
| summarize Events=count(), First=min(Timestamp), Last=max(Timestamp) by DeviceName, RemoteIP, RemoteUrl, ActionType
| order by First asc
```

![ioc network results](../evidence/screenshots/07-ioc-network-results.png)

**KQL – source IPs connecting to mysqld**

```kql
DeviceNetworkEvents
| where DeviceName startswith "corp-retail-gro"
| where InitiatingProcessFileName =~ "mysqld.exe" and ActionType == "InboundConnectionAccepted"
| summarize Connections=count(), First=min(Timestamp), Last=max(Timestamp) by RemoteIP
| order by Connections desc
```

![mysqld inbound sources](../evidence/screenshots/08-mysqld-inbound-sources.png)

## 5. Timeline

| Time (2026)                 | Event                                                                                                                                                                                 | Source                        |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| Sep 29 20:58                | Defender telemetry begins. mysqld is already listening on 0.0.0.0:3306.                                                                                                               | DeviceNetworkEvents           |
| Oct 7 20:54                 | First connection attempt to the host from the 64.89.163.x range (64.89.163.130).                                                                                                      | DeviceNetworkEvents           |
| Oct 7 23:37                 | First public inbound connection accepted by mysqld on port 3306 (229 in total).                                                                                                       | DeviceNetworkEvents           |
| Oct 9 22:12                 | Windows administrator network logon failures begin (309 failures from 63 sources through Oct 17).                                                                                     | DeviceLogonEvents             |
| Oct 10 19:52                | Five failed root logons from localhost, then success at 19:52:49. Purpose not determined.                                                                                             | MySQL audit                   |
| Oct 10 20:19                | First external passwordless login attempts as root/admin/sa from 77.90.185.30; 77.90.185.21 from 21:05.                                                                               | MySQL audit                   |
| Oct 10 21:35                | **Initial access:** first external root logon (77.90.185.30).                                                                                                                         | MySQL audit                   |
| Oct 11 23:18                | New probe burst from 77.90.185.30, root logon 23:18:47; root logon from 213.209.159.115 at 23:29:28.                                                                                  | MySQL audit                   |
| Oct 12 00:10:35–41          | Two failed root logons from 64.89.163.169.                                                                                                                                            | MySQL audit                   |
| Oct 12 00:10:43–44          | **Ransom note:** CREATE DATABASE/TABLE RECOVER_YOUR_DATA, two INSERTs (0.0101 BTC, 48h, DATAID 278HD). Defender records mysqld.exe creating the recover_your_data folder at 00:10:43. | MySQL audit; DeviceFileEvents |
| Oct 12 00:10:45–55          | GRANT CREATE, DROP ON \*.\* TO root@%; schema and size queries on the three databases.                                                                                                | MySQL audit                   |
| Oct 12 00:10:56–57          | **Destruction:** DROP DATABASE on bby_corp, sakila, world, and the note database.                                                                                                     | MySQL audit                   |
| Oct 12 00:10:57–58          | Note database recreated and note inserted again.                                                                                                                                      | MySQL audit                   |
| Oct 12 00:10:59             | PURGE BINARY LOGS, RESET MASTER.                                                                                                                                                      | MySQL audit                   |
| Oct 12 00:11:00–01          | REVOKE ALL / GRANT SHUTDOWN; long-string JSON_SCHEMA_VALID call (purpose unknown); SHUTDOWN. Root logon from 64.89.163.169 logged at 00:11:00.                                        | MySQL audit                   |
| Oct 12 18:23                | MySQL reachable again: root logon from 77.90.185.30.                                                                                                                                  | MySQL audit                   |
| Oct 12 20:29                | First successful Windows administrator network logon (154.64.211.102).                                                                                                                | DeviceLogonEvents             |
| Oct 13 10:33 – Oct 17 14:38 | CREATE DATABASE RECOVER_YOUR_DATA re-run 22 times, several coinciding with root logons from 64.89.163.x.                                                                              | MySQL audit                   |
| Oct 14 11:43 – Oct 16 21:03 | Further successful Windows administrator logons from external IPs.                                                                                                                    | DeviceLogonEvents             |
| Oct 14 22:09 / Oct 17 03:34 | Logons as user client that failed the authentication-protocol handshake; role not determined.                                                                                         | MySQL audit                   |
| Oct 17 15:26                | Last MySQL audit event.                                                                                                                                                               | MySQL audit                   |

**KQL – host-side timeline (mysqld inbound connections and external logons)**

```kql
let mydevice = "corp-retail-gro";
union (DeviceNetworkEvents
| where DeviceName == mydevice
| where InitiatingProcessFileName =~ "mysqld.exe" and ActionType == "InboundConnectionAccepted"
| project Timestamp, Kind="mysqld inbound", Detail=strcat(RemoteIP, " -> port ", tostring(LocalPort))),
(DeviceLogonEvents
| where DeviceName == mydevice
| where ActionType == "LogonSuccess" and isnotempty(RemoteIP)
| project Timestamp, Kind="Windows logon", Detail=strcat(AccountName, "@", RemoteIP))
| order by Timestamp asc
```

![host side timeline](../evidence/screenshots/09-host-side-timeline.png)

*First rows of the result, sorted by time.*

**KQL – Windows logon pressure and successes**

```kql
DeviceLogonEvents
| where DeviceName == "corp-retail-gro"
| where AccountName =~ "administrator" and isnotempty(RemoteIP)
| summarize Failed=countif(ActionType=="LogonFailed"), Success=countif(ActionType=="LogonSuccess"),
            First=min(Timestamp), Last=max(Timestamp) by RemoteIP
| order by Success desc, Failed desc
```

![windows logon pressure](../evidence/screenshots/10-windows-logon-pressure.png)

*Seven successful logons come from six external addresses. The three logons from the internal address 10.0.8.4 (Oct 17 19:36) are excluded as non-external; the registry entries that follow them are OneDrive and Edge first-run settings.*

## 6. Root Cause / Attack Vector

**Most likely:** remote login to MySQL as root over the internet with a credential that worked on the first attempt. All 461 failed external attempts were passwordless (`using password: NO`) and no wrong-password attempt appears, so the credential was probably already known, reused or empty. Defender shows mysqld listening on all interfaces (0.0.0.0:3306) from Sep 29 and accepting public inbound connections from Oct 7 (229 events on port 3306), and MySQL allowed root to log in remotely. The first external root logon came 76 minutes after the first MySQL login attempt; the destructive session followed about 26.5 hours later.

| Question                         | Answer                                                                                                                                                                                                                                                                                                                                         |
|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Which credential worked?         | The root password was valid on the first attempt. All 461 failed external attempts were passwordless and no wrong-password attempt precedes the first successful logon, so the attacker already held the credential (leaked, reused or empty). The audit log does not record passwords, so the exact value is not shown.                       |
| Who ran the destructive session? | 64.89.163.169. It failed twice at 00:10:35 and 00:10:41, then logged in at 00:11:00, matching the destructive window. Connection IDs 92–122 have no logon row in the auth export, so the link rests on timing and source address.                                                                                                              |
| One actor or several?            | Consistent with one operator using several addresses (77.90.185.x, 213.209.159.115, 64.89.163.x). All followed the same root login pattern, and the ransom-note database was re-created 22 times through Oct 17. The 35.205 and 34.78 ranges are lower confidence.                                                                             |
| Was the Windows host breached?   | Yes, at account level. Windows administrator was heavily guessed over the network (309 failed attempts from 63 sources since Oct 9), and seven external logons from six addresses then succeeded from Oct 12 20:29. No malicious process, file or persistence followed in Defender data, and nothing ties these logons to the database attack. |
| Data theft?                      | No evidence of theft. The audit log shows no reads of business tables, and Defender shows no connection from mysqld to a public address across Sep 29 – Oct 18. Network events record connections, not bytes, so theft over an inbound session cannot be fully excluded (see Impact).                                                          |

**KQL – how exposed was MySQL?**

```kql
DeviceNetworkEvents
| where DeviceName == "corp-retail-gro"
| where InitiatingProcessFileName =~ "mysqld.exe"
| where ActionType in ("ListeningConnectionCreated", "InboundConnectionAccepted")
| summarize Events=count(), First=min(Timestamp) by ActionType, LocalIP, LocalPort, RemoteIPType
| order by Events desc
```

![mysqld exposure](../evidence/screenshots/11-mysqld-exposure.png)

*mysqld listens on 0.0.0.0:3306 from Sep 29 and accepted 229 inbound connections from public addresses starting Oct 7.*

**KQL – guessing pattern by account (Windows logons)**

```kql
DeviceLogonEvents
| where DeviceName =~ "corp-retail-gro"
| where ActionType == "LogonFailed"
| summarize Attempts = count(), SourceIPs = dcount(RemoteIP), First = min(Timestamp), Last = max(Timestamp) by DeviceName, AccountName, LogonType
| order by Attempts desc
| project DeviceName, AccountName, LogonType, Attempts, SourceIPs, First, Last
```

![guessing by account](../evidence/screenshots/12-guessing-by-account.png)

## 7. Response Actions

**Backup:** the data was backed up before the attack, so recovery does not depend on the attacker.

**Containment (recommended, do first)**

- Block inbound MySQL from the internet at the network security group or host firewall; allow only named application hosts.
- Block the source addresses in Section 4 and disable remote root (`root@%`).
- Reset the Windows administrator password, restrict Remote Desktop to a VPN or bastion, and review the seven external logons.
- Snapshot the VM and export all MySQL and Defender logs before any change.

**Eradication**

- Review `mysql.user`, plugins and user-defined functions for accounts or code added outside the audit window; the export shows no `CREATE USER`, `INSTALL PLUGIN` or file-write statements, but it covers only audited queries.
- Investigate the long `JSON_SCHEMA_VALID` statement and the `client` logons (Oct 14, Oct 17) as possible exploit or probe activity.
- Rotate every credential stored on or reachable from this host.

**Recovery**

- Restore bby_corp from the pre-incident backup and validate it before reconnecting applications.
- Binary logs were purged, so changes made after the backup was taken cannot be replayed from this server.
- Whether to engage with the extortion demand is a leadership and legal decision; the logs do not show that the attacker holds a copy of the data.

**KQL – mysqld child processes and account or dump tooling**

```kql
DeviceProcessEvents
| where Timestamp > datetime(2026-10-10)
| where DeviceName == "corp-retail-gro"
| where InitiatingProcessFileName =~ "mysqld.exe"
    or FileName in~ ("mysql.exe", "mysqldump.exe", "net.exe", "net1.exe")
    or ProcessCommandLine has_any ("net user", "net localgroup", "INTO OUTFILE")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

![child processes](../evidence/screenshots/13-child-processes.png)

*Results are SYSTEM-account net localgroup lookups on Oct 10, with the Defender sensor (mssense.exe) at the start of the first chain. No mysql.exe, mysqldump.exe, INTO OUTFILE or net user activity.*

**KQL – host-side persistence check**

```kql
let MyDevice = "corp-retail-gro";
DeviceRegistryEvents
| where DeviceName startswith MyDevice
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\RunOnce", @"\Services")
| where InitiatingProcessAccountName !in~ ("system")
| project TimeGenerated, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

![registry persistence](../evidence/screenshots/14-registry-persistence.png)

*Only OneDrive and Edge user-profile entries from the bby_retail and administrator accounts; no persistence entry tied to the attack.*

## 8. Evidence

| Source                          | Rows               | Coverage (Eastern)          | Used for                                                               |
|---------------------------------|--------------------|-----------------------------|------------------------------------------------------------------------|
| MySQLAudit_CL, queries (export) | 812 (406 unique)   | Oct 10 19:52 – Oct 17 15:26 | Ransom note, DROP DATABASE, grants, binary-log purge, shutdown         |
| MySQLAudit_CL, auth (export)    | 1,038 (519 unique) | Oct 10 19:52 – Oct 17 15:26 | Guessing pattern, successful root logons, source IPs                   |
| DeviceLogonEvents               | 1,211              | Sep 29 20:57 – Oct 18 12:45 | Windows administrator guessing and external logons                     |
| DeviceNetworkEvents             | 33,214             | Sep 29 20:58 – Oct 18 20:17 | mysqld listener, inbound connections from attacker IPs, outbound check |
| DeviceFileEvents                | 26,251             | Sep 29 20:58 – Oct 18 20:16 | mysqld creating the recover_your_data folder at 00:10:43               |
| DeviceRegistryEvents            | 18,150             | Sep 29 20:58 – Oct 18 20:19 | Persistence check: OneDrive and Edge entries only                      |
| DeviceProcessEvents             | 14,027             | Sep 29 20:58 – Oct 18 20:19 | Child-process check: SYSTEM net localgroup lookups only                |

Coverage gaps: the audit export has no authentication-method detail and lacks the successful logon for the destructive connections; both MySQL exports are duplicated; the Defender device name differs from the MySQL host name (truncated). All KQL in this report runs in Defender Advanced Hunting. The MySQL audit statements cited in the timeline come from the Log Analytics export and cannot be queried from Advanced Hunting.

**KQL – confirm the data coverage windows**

```kql
union withsource=Table DeviceLogonEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceProcessEvents
| where DeviceName startswith "corp-retail-gro"
| summarize Rows=count(), First=min(Timestamp), Last=max(Timestamp) by Table
```

![telemetry coverage](../evidence/screenshots/15-telemetry-coverage.png)

## 9. Lessons Learned / Recommendations

1.  **Take MySQL off the internet (immediate).** Bind it to a private address and allow only named application hosts or a VPN. This single control would have stopped the database attack.
2.  **Remove remote root and fix credentials (immediate).** Use unique, long credentials, per-application accounts without DROP, GRANT or SHUTDOWN, and enable MySQL connection-control or lockout so guessing is throttled.
3.  **Close Remote Desktop exposure (this week).** Require VPN or a bastion for the Windows administrator account, rename or disable it, and review the seven external logons already recorded.
4.  **Make backups survive an attacker with root (this week).** Keep immutable, off-host backups, test a restore of bby_corp, and ship binary logs to separate storage so PURGE BINARY LOGS cannot erase them.
5.  **Alert on the signals this attack produced (this month).** Rule one: a successful DB logon from an address with prior failures. Rule two: DROP DATABASE, PURGE BINARY LOGS, RESET MASTER, SHUTDOWN, or a privilege change on root. Root logons and note-database re-creation continued for five days after the note was written.
6.  **Close logging gaps (this month).** Onboard database hosts to Defender before an incident, log full multi-line query text and the authentication method, and stop duplicate ingestion into MySQLAudit_CL.
