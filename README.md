<div align="center">

<img width="1280" height="640" alt="social" src="https://github.com/user-attachments/assets/40984987-28de-408a-9bd6-8c8cc9138466" />


**An internet-exposed MySQL server, a remote `root` login, and a database wiped 26 hours later.**

![Microsoft Defender](https://img.shields.io/badge/Microsoft%20Defender-Advanced%20Hunting-0078D4?logo=microsoft)
![KQL](https://img.shields.io/badge/Query-KQL-5C2D91)
![MySQL](https://img.shields.io/badge/Database-MySQL%208.0-4479A1?logo=mysql&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C8102E)
![Severity](https://img.shields.io/badge/Severity-High-red)

</div>

---

## Summary

An attacker logged into MySQL on `corp-retail-group` from the internet as `root` on **Oct 10, 2026**, and on **Oct 12 at 00:10** left a ransom note (0.0101 BTC, 48 hours), dropped three databases (including `bby_corp`), purged the binary logs and shut the server down. Root logins from attacker-linked addresses continued for five more days. Every failed external MySQL logon was a passwordless probe and no wrong-password attempt is logged, so the `root` credential was most likely already known, reused or empty (source not determined).

The ransom note claims the data was copied first. **The logs do not confirm that**, and this report says so rather than guessing.

   | Field | Detail |
   |---|---|
| **Type** | Database extortion following unauthorized remote root access (no file encryption) |
| **Initial access** | Oct 10, 2026 21:35 — first external `root` logon |
| **Impact event** | Oct 12, 2026 00:10:43 – 00:11:01 |
| **Data sources** | Microsoft Defender Advanced Hunting (5 tables) + MySQL audit log |
| **Full report** | **[Read the full incident report (PDF)](Incident-Report-MySQL-Ransom-Attack.pdf)** |

## Attack chain


<img width="3136" height="1148" alt="image" src="https://github.com/user-attachments/assets/cf188bbc-7779-4ae2-b71b-4baa4dbbf449" />

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1133 External Remote Services | MySQL listening on `0.0.0.0`; inbound connections from public IPs |
| Credential Access | T1110.001 Password Guessing (Windows only) | 309 failed `administrator` network logons. The 461 failed external MySQL logons were passwordless probes, not password guesses |
| Initial Access / Persistence | T1078 Valid Accounts | Successful remote `root` logons from Oct 10 21:35, with no wrong-password attempts before them |
| Impact | T1485 Data Destruction | `DROP DATABASE` on `bby_corp`, `sakila`, `world` |
| Defense Evasion | T1070 Indicator Removal | `PURGE BINARY LOGS`, `RESET MASTER` |
| Impact | T1529 System Shutdown/Reboot | `SHUTDOWN` at 00:11:01 |
| Impact | T1657 Financial Theft (extortion) | Ransom note: 0.0101 BTC in 48 hours |
| Persistence / Privilege Escalation | T1098 Account Manipulation | `GRANT CREATE, DROP` on root, then `REVOKE ALL` / `GRANT SHUTDOWN` at 00:10:45–00:11:00 |

## What the logs could *not* tell us

Good incident reports say where the evidence stops. This one lists:

- **Whether data was copied.** The audit log shows no reads of business tables, and Defender shows no connection from `mysqld` to a public address. Network events record connections, not bytes, so theft over an inbound session can't be fully excluded.
- **Which credential worked, and where it came from.** Successful logons don't record the password, and no wrong-password attempt is logged, so it was likely already known, reused or empty.
- **Detection and response times.** No alert, ticket or responder action appears in the logs.
- **Who ran the destructive session.** The successful logon for those connections is missing from the auth export, so attribution to `64.89.163.169` rests on timing and source address.
- **Whether the Windows `administrator` logons are related.** Guessing began Oct 9, and the first successful logon came on Oct 12, about 20 hours after the destruction. Nothing links the two.



## Top recommendations

1. Take MySQL off the internet — bind to a private address, allow only named hosts or VPN.
2. Remove remote `root`, rotate its password, and use per-application accounts with connection throttling.
3. Close Remote Desktop exposure for the Windows `administrator` account.
4. Keep immutable off-host backups and ship binary logs elsewhere.
5. Alert on external `administrator` logons, public inbound connections to `mysqld`, and `DROP DATABASE` / `PURGE BINARY LOGS` / `SHUTDOWN`.
6. Onboard database hosts to Defender before an incident and log full query text.

## Skills demonstrated

  Incident response lifecycle · KQL threat hunting · log correlation across Defender and MySQL audit data · MITRE ATT&CK mapping · IOC handling and defanging

---



