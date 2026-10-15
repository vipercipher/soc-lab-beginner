# 📓 SOC Learning Log — October 2026

A 21-day, one-topic-a-day study log for **SOC / blue team** skills: reading logs,
writing detections, and responding to incidents. Each entry builds on the last,
and every entry ends with exercises answered in my own words.

> **How this log is made:** each day's lesson (concept, sample logs, detection
> logic) is drafted with help from Claude, an AI assistant, following the plan
> below. The **"My answers"** section at the bottom of every entry is mine,
> written after working through the exercises. All sample data is fictional, and
> IP addresses use the ranges reserved for documentation (`192.0.2.x`,
> `198.51.100.x`, `203.0.113.x`).

---

## How each entry is laid out

| Section | What it covers |
|---|---|
| **Why it matters** | Where this shows up in real SOC work |
| **The concept** | The idea, explained from the ground up |
| **Sample logs** | A small fictional log extract to read |
| **What to look for** | The patterns an analyst spots |
| **Detection logic** | How to turn the pattern into a rule (Sigma, KQL or SPL) |
| **Your turn** | 2–4 exercises |
| **My answers** | My own write-up of the exercises |
| **Further reading** | Official docs and references |

---

## 🗓️ The plan

| Day | Date | Topic | Entry |
|---|---|---|---|
| 01 | 11 Oct | Windows logon events: 4624, 4625 and logon types | [Read](2026-10-11-windows-logon-events.md) |
| 02 | 12 Oct | Linux `auth.log`: spotting SSH brute force | [Read](2026-10-12-linux-ssh-brute-force.md) |
| 03 | 13 Oct | Password spraying vs brute force | [Read](2026-10-13-password-spraying-vs-brute-force.md) |
| 04 | 14 Oct | Writing your first Sigma rule | [Read](2026-10-14-first-sigma-rule.md) |
| 05 | 15 Oct | Sysmon Event ID 1: process creation | [Read](2026-10-15-sysmon-process-creation.md) |
| 06 | 16 Oct | Suspicious PowerShell: encoded commands | [Read](2026-10-16-powershell-encoded-commands.md) |
| 07 | 17 Oct | Parent–child process anomalies (Office spawning shells) | |
| 08 | 18 Oct | Phishing triage: reading email headers (SPF, DKIM, DMARC) | |
| 09 | 19 Oct | IOCs vs behaviours: the Pyramid of Pain | |
| 10 | 20 Oct | Mapping detections to MITRE ATT&CK | |
| 11 | 21 Oct | Web server logs: SQL injection attempts in Nginx access logs | |
| 12 | 22 Oct | DNS logs: beaconing and random-looking domains | |
| 13 | 23 Oct | Firewall logs: recognising a port scan | |
| 14 | 24 Oct | Persistence: new accounts and admin group changes (4720, 4732) | |
| 15 | 25 Oct | Persistence: scheduled tasks and new services (4698, 7045) | |
| 16 | 26 Oct | Defence evasion: cleared audit logs (1102) | |
| 17 | 27 Oct | Alert triage: true/false positives and severity | |
| 18 | 28 Oct | The incident response lifecycle (NIST SP 800-61) | |
| 19 | 29 Oct | Writing a clear incident ticket | |
| 20 | 30 Oct | Mini case: putting it all together | |
| 21 | 31 Oct | Month recap and what to study next | |

---

## Progress

- Entries published: **6 / 21**
- Exercises answered: tracked in each entry's **My answers** section

➡️ Back to the main [Beginner SOC Lab](../README.md).
