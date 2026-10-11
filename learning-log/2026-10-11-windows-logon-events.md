# Day 01 — Windows Logon Events: 4624, 4625 and Logon Types

📅 11 October 2026 · 🏷️ Log analysis · ⏱️ ~20 min

---

## Why it matters

Almost every investigation in a Windows environment starts with one question:
**who logged in, where from, and how?** Windows answers that in the Security
event log. Scenario 01 introduced the two most important event IDs, **4624**
(success) and **4625** (failure). Today goes one level deeper: the **logon type**
and the **failure reason**, which turn "someone logged in" into a story.

---

## The concept

### The two event IDs

| Event ID | Meaning |
|---|---|
| **4624** | An account successfully logged on |
| **4625** | An account failed to log on |

### Logon type: *how* they logged in

Every 4624 and 4625 carries a **Logon Type** number. It tells you the route the
login took.

| Type | Name | Plain meaning | Typical example |
|---|---|---|---|
| 2 | Interactive | Someone at the keyboard | User signs in at their desk |
| 3 | Network | Accessing something over the network | Opening a shared folder |
| 4 | Batch | A scheduled task running | Nightly backup job |
| 5 | Service | A Windows service starting | Antivirus service at boot |
| 7 | Unlock | Unlocking a locked screen | Back from lunch |
| 8 | NetworkCleartext | Network logon with the password sent in clear text | Basic authentication to IIS |
| 10 | RemoteInteractive | Remote Desktop (RDP) | Admin connects via RDP |
| 11 | CachedInteractive | Logon using cached credentials | Laptop signs in while off the network |

> 💡 **The analyst's shortcut:** type **10** (RDP) and type **3** (network) from
> unexpected IP addresses are the ones most worth a second look. Attackers love
> RDP exposed to the internet, and they move between machines over the network.

### Failure reason: *why* a login failed

A 4625 includes a **Status** and **SubStatus** code. These are the most useful:

| Code | Meaning | What it can suggest |
|---|---|---|
| `0xC000006A` | Correct username, wrong password | Password guessing against a **real** account |
| `0xC0000064` | Username does not exist | Attacker trying a list of **guessed** usernames |
| `0xC0000234` | Account is locked out | Guessing has already triggered lockout |
| `0xC0000072` | Account is disabled | Someone trying an old or deactivated account |
| `0xC0000071` | Password has expired | Usually a harmless user issue |

The difference between `0xC000006A` and `0xC0000064` matters: the first means the
attacker already knows a valid username.

---

## Sample logs

A simplified extract from server `FS01` at the fictional company Northwind.

```
TimeCreated (UTC)     EventID  Account          LogonType  IpAddress       Status / SubStatus
2026-10-10 08:31:02   4624     priya.nair       3          203.0.113.24    -
2026-10-10 09:05:44   4624     svc_backup       4          -               -
2026-10-10 02:11:07   4625     administrator    10         198.51.100.87   0xC000006D / 0xC000006A
2026-10-10 02:11:09   4625     administrator    10         198.51.100.87   0xC000006D / 0xC000006A
2026-10-10 02:11:12   4625     admin            10         198.51.100.87   0xC000006D / 0xC0000064
2026-10-10 02:11:14   4625     test             10         198.51.100.87   0xC000006D / 0xC0000064
2026-10-10 02:11:17   4625     administrator    10         198.51.100.87   0xC000006D / 0xC000006A
2026-10-10 02:11:19   4624     administrator    10         198.51.100.87   -
2026-10-10 10:42:30   4624     sara.lund        7          -               -
```

---

## What to look for

1. **Time of day.** The burst is at **02:11 UTC**, well outside the other
   activity.
2. **Logon type 10.** All the failures are **RDP** attempts from an external IP,
   `198.51.100.87`, that no one else uses.
3. **Two kinds of failure.** `0xC0000064` for `admin` and `test` shows the
   attacker trying common usernames. `0xC000006A` for `administrator` shows they
   hit a real account and kept guessing its password.
4. **The success at the end.** A **4624 type 10** from the same IP two seconds
   after the last failure means the attacker now has an RDP session as
   `administrator`. That's a confirmed compromise of a privileged account.
5. **The normal rows** help you rule things out. `svc_backup` with type 4 is a
   scheduled job, and `sara.lund` with type 7 is just unlocking her screen.

---

## Detection logic

**In plain English:** alert when one source IP has **5 or more failed RDP
logins** followed by a **successful RDP login** within 10 minutes.

**KQL (Microsoft Sentinel, `SecurityEvent` table):**

```kql
let window = 10m;
let failures =
    SecurityEvent
    | where EventID == 4625 and LogonType == 10
    | summarize FailCount = count(), FirstFail = min(TimeGenerated),
                LastFail = max(TimeGenerated), Accounts = make_set(Account)
              by IpAddress, bin(TimeGenerated, window)
    | where FailCount >= 5;
SecurityEvent
| where EventID == 4624 and LogonType == 10
| join kind=inner failures on IpAddress
| where TimeGenerated between (LastFail .. (LastFail + window))
| project TimeGenerated, IpAddress, Account, FailCount, Accounts, Computer
```

**Tuning note:** a user mistyping their password three times isn't an attack.
Thresholds like "5 failures" and "10 minutes" are starting points you adjust to
what is normal in your environment.

---

## Your turn

1. In the sample, which rows would you **ignore** as normal, and why?
2. The attacker tried `admin` and `test` before `administrator`. What does the
   SubStatus code tell you about each of those attempts?
3. Write down the **first two actions** you'd take after seeing the 4624 at
   02:11:19. (Hint: think back to "contain first" from Scenario 01.)
4. Why would a logon type **3** success from `198.51.100.87` a few minutes later,
   on a *different* server, make this incident worse?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.
2.
3.
4.

---

## Further reading

- Microsoft Learn: [4624: An account was successfully logged on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- Microsoft Learn: [4625: An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- MITRE ATT&CK: [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) · [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

⬅️ [Learning log index](README.md) · ➡️ Day 02: Linux `auth.log` (12 Oct)
