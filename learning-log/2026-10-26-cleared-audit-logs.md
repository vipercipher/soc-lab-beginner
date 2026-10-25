# Day 16 — Defence Evasion: Cleared Audit Logs (1102)

📅 26 October 2026 · 🏷️ Log analysis · ⏱️ ~20 min

---

## Why it matters

By the end of Day 15 the attacker on `FS01` had a backdoor account
(`support_svc`), a boot-time scheduled task and an auto-start service. The
last thing a careful attacker does before leaving is **wipe the evidence**:
clear the event logs so a responder logging on to `FS01` finds nothing. Every
day so far has depended on those logs being there. The good news is that
clearing a log is **noisy in its own way**: Windows writes an event saying the
log was cleared and who did it, and that event can't be switched off. A clean
log in the middle of an incident is a clue, not a dead end.

---

## The concept

### Two events, two logs

| Event ID | Log it lands in | Meaning | Logged when |
|---|---|---|---|
| **1102** | Security | "The audit log was cleared" | **Always**. It can't be turned off by audit policy |
| **104** | System | "The *&lt;name&gt;* log file was cleared" | Always, for **any other** log (System, Application, PowerShell, Sysmon…) |

Both come from the provider **`Microsoft-Windows-Eventlog`**. Three things
to remember:

- **1102 is written *after* the clear**, so it's usually the **first** event
  in the freshly emptied Security log. Everything before it is gone from the
  machine.
- **104 always goes to the System log**, even when another log was cleared.
  Its **`Channel`** field names the log that was emptied. When the System log
  itself is cleared, the 104 is the first event in the new System log.
- Both record **who** did it, in `SubjectUserName` and `SubjectDomainName`.
  Clearing a log needs admin rights, so that account is already privileged.

Related events worth knowing:

| Event ID | Log | Meaning | Why you care |
|---|---|---|---|
| 1100 | Security | The event logging service has shut down | Stopping the service is another way to blind the log |
| 4719 | Security | System audit policy was changed | Turning auditing **off** is quieter than clearing |
| 1104 | Security | The security log is now full | Not an attack, but new events may be lost |

### How logs get cleared

The usual methods are Event Viewer's **Clear Log…** button, the built-in
command **`wevtutil cl <LogName>`**, and the PowerShell cmdlet
**`Clear-EventLog`**. All of them produce a 1102 or 104. (Day 10's exercise
asked you to map `wevtutil.exe cl Security`; today you see what it leaves
behind.)

### Why the SIEM still has the evidence

Clearing only empties the log **on that machine**. Northwind forwards events
to Microsoft Sentinel within minutes, so the 4720, 4698 and 7045 events from
Days 14 and 15 were already copied off `FS01` before the attacker cleared
anything. That's exactly why log forwarding matters: MITRE lists **Remote
Data Storage** (M1029) as the main mitigation.

> 💡 **Silence is a signal.** After a clear you may also see a host simply
> stop sending a log. A server that normally sends hundreds of Security
> events an hour and suddenly sends none deserves the same question as a
> 1102: *who made it go quiet?*

### A note on ATT&CK

In ATT&CK v19 (Day 10), the old technique *T1070.001 Indicator Removal:
Clear Windows Event Logs* was **revoked** and replaced by
**T1685.005 Disable or Modify Tools: Clear Windows Event Logs**, under the
new **Defense Impairment** tactic (TA0112). SigmaHQ's rules already use the
new tags, but plenty of blog posts and some SIEM templates still say
*T1070.001* or *Defense Evasion*. This is the mapping drift Day 10 warned
about.

### Where the logs come from

1102 is in the Security log, so it reaches Sentinel in the **`SecurityEvent`**
table. Watch out: for 1102 the **`Account`** column is usually **empty**. The
name sits inside the **`EventData`** XML, under `UserData` → `LogFileCleared`
→ `SubjectUserName`, so you have to pull it out, just as Day 15 pulled out
`TaskName`. 104 is in the System log, which lands in the **`Event`** table,
again with the details in `EventData`.

---

## Sample logs

Log-clear events from **10 October** (UTC), the same night as Days 01, 14
and 15. `FS01` is the compromised file server; `WS-TRAIN02` is a training
laptop; `WS-DEV01` is Liam Chen's developer workstation (Day 15).

**Security log, Event ID 1102 (audit log cleared):**

```
TimeCreated (UTC)    Computer    EventID  Provider                    SubjectUserName  SubjectDomainName
2026-10-10 02:21:05  FS01        1102     Microsoft-Windows-Eventlog  support_svc      FS01
2026-10-10 06:30:12  WS-TRAIN02  1102     Microsoft-Windows-Eventlog  tom.reyes        NORTHWIND
```

**System log, Event ID 104 (log file cleared):**

```
TimeCreated (UTC)    Computer  EventID  Provider                    SubjectUserName  Channel (log cleared)
2026-10-10 02:21:07  FS01      104      Microsoft-Windows-Eventlog  support_svc      System
2026-10-10 02:21:09  FS01      104      Microsoft-Windows-Eventlog  support_svc      Microsoft-Windows-PowerShell/Operational
2026-10-10 23:47:30  WS-DEV01  104      Microsoft-Windows-Eventlog  liam.chen        Application
```

The `EventData` of the 1102 on `FS01`, as Sentinel stores it (trimmed):

```xml
<UserData>
  <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
    <SubjectUserSid>S-1-5-21-[FS01]-1004</SubjectUserSid>
    <SubjectUserName>support_svc</SubjectUserName>
    <SubjectDomainName>FS01</SubjectDomainName>
    <SubjectLogonId>0x5D21A3</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

Context from the IT team: Tom Reyes resets the training laptops before each
course under standard change **CHG-2221**, and the reset includes clearing
the Security log. Liam Chen was debugging his build tools on `WS-DEV01` and
cleared the Application log to see fresh errors.

---

## What to look for

1. **Same account, again.** At 02:21:05, **`support_svc`** clears the
   Security log on `FS01`. The SID ends in **-1004**, the local account
   created at 02:13:05 on Day 14. This is 2 minutes 25 seconds after the
   service install at 02:18:40 (Day 15). The attacker is tidying up.
2. **Three logs in four seconds.** Security at 02:21:05, System at 02:21:07,
   PowerShell Operational at 02:21:09. People don't click that fast in Event
   Viewer; this is a script or three `wevtutil cl` commands back to back.
3. **What each clear was meant to hide.** Security held the 4720/4732 (Day
   14) and 4698 (Day 15). System held the **7045** for `NwHelperSvc`.
   PowerShell Operational held any **4104** script blocks (Day 06). The
   attacker picked exactly the logs that told the story.
4. **What they missed.** The 1102 and 104s themselves, which can't be
   suppressed, and every event already forwarded to Sentinel. Clearing the
   local copy didn't remove the cloud copy.
5. **The normal rows.** `tom.reyes` clears **one** log on a training laptop at
   06:30 UTC (17:30 Sydney time), matching CHG-2221. `liam.chen` clears the
   **Application** log on his own machine at 23:47 UTC (10:47 Sydney time).
   Both are single, explainable clears by the expected person on a
   non-server. Still worth a quick confirm: a 1102 is never "auto-close".
6. **Totals.** **5** clear events: **2** × 1102 and **3** × 104. **3** of the
   5 are malicious, all on `FS01` by `support_svc` within 4 seconds.

---

## Detection logic

**In plain English:** two rules. **Rule A** alerts on **every** 1102, because
clearing the Security log is rare and always worth a look. **Rule B** raises a
higher-priority alert when **one account clears two or more logs on the same
host within 5 minutes**, which is what a cover-up looks like.

**Sigma, Rule A (Security log, 1102):**

```yaml
title: Security Audit Log Cleared
id: 3d9c7e21-5b4a-4f0e-8c6d-1a2b7e9f4c58
status: experimental
description: >
  Detects the Windows Security event log being cleared (Event ID 1102),
  which attackers do to hide evidence of their activity.
references:
  - https://attack.mitre.org/techniques/T1685/005/
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
author: Jay (SOC learning log)
date: 2026-10-26
tags:
  - attack.defense-impairment
  - attack.t1685.005
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection
falsepositives:
  - Planned resets of lab, training or golden-image machines
  - Rollout of a log collection agent that resets local logs
level: high
```

On the sample it matches **2** rows: `FS01` at 02:21:05 and `WS-TRAIN02` at
06:30:12. Checking `Provider_Name` matters: some other software (AD FS, for
example) writes its own unrelated event 1102, and this keeps those out.

**KQL, Rule B (Microsoft Sentinel, `SecurityEvent` + `Event` tables):**

```kql
let window = 5m;
union
    (SecurityEvent
     | where TimeGenerated > ago(1d)
     | where EventID == 1102 and EventSourceName == "Microsoft-Windows-Eventlog"
     | extend LogCleared = "Security"),
    (Event
     | where TimeGenerated > ago(1d)
     | where EventLog == "System" and Source == "Microsoft-Windows-Eventlog" and EventID == 104
     | extend LogCleared = extract(@"<Channel>([^<]+)</Channel>", 1, EventData))
| extend ClearedBy = extract(@"<SubjectUserName>([^<]+)</SubjectUserName>", 1, EventData)
| summarize ClearCount = count(), Logs = make_set(LogCleared),
            FirstClear = min(TimeGenerated), LastClear = max(TimeGenerated)
          by Computer, ClearedBy, bin(TimeGenerated, window)
| where ClearCount >= 2
| project FirstClear, LastClear, Computer, ClearedBy, ClearCount, Logs
```

On the sample it returns **1** row: `FS01`, `support_svc`, `ClearCount` **3**,
`Logs` = `["Security", "System", "Microsoft-Windows-PowerShell/Operational"]`.
`WS-TRAIN02` and `WS-DEV01` have **1** clear each, so they stay below the
threshold (Rule A still catches the `WS-TRAIN02` 1102).

How it works:

- `union` stacks two tables into one result. The first leg takes 1102s from
  `SecurityEvent` and labels them `Security`; the second takes 104s from
  `Event` and reads the cleared log's name from `<Channel>`.
- `extract()` pulls `SubjectUserName` out of the XML in `EventData`, because
  the `Account` column is empty for these events. Both events use the same
  `<SubjectUserName>` element, so one line works for both legs.
- `bin(TimeGenerated, 5m)` groups events into 5-minute buckets, and
  `make_set()` lists the distinct logs cleared in each bucket.

**Tuning note:** keep Rule A at **every** 1102; the volume is tiny and it's
one of the few events with almost no innocent reason on a **server**. Rather
than switching it off for training laptops, lower its severity for a named
list of lab hosts (like `WS-TRAIN02`) and keep it high everywhere else. For
Rule B, `bin()` uses fixed buckets, so three clears at 02:24:58, 02:25:00 and
02:25:02 would be split 1 + 2 across two buckets; that still fires here, but
for a stricter version use a sliding window. Rule B also needs the **System
log** to be collected into the `Event` table, which isn't on by default; check
the data collection rule first. Finally, neither rule sees an attacker who
turns auditing **off** (4719) or stops the logging service (1100); add those
as companion rules.

For Day 10's mapping lookup, these become rules **NW-017** and **NW-018**:

```
NW-017,Defense Impairment,T1685.005,Disable or Modify Tools: Clear Windows Event Logs
NW-018,Defense Impairment,T1685.005,Disable or Modify Tools: Clear Windows Event Logs
```

---

## Your turn

1. For each of the **5** clear events in the sample, write one line: who
   cleared which log, on which host, and whether you'd escalate it. What one
   fact makes the `FS01` clears different from `tom.reyes` on `WS-TRAIN02`,
   even though both are 1102s?
2. The 1102 on `FS01` says `support_svc` did it. Using Day 14, explain how
   the SID **S-1-5-21-[FS01]-1004** confirms this is the same account the
   attacker created, even if the name had been changed.
3. If `FS01` runs Sysmon (Day 05), what would you expect to see as `Image`
   and `CommandLine` in the Event ID 1 records around 02:21:05–02:21:09? The
   attacker didn't clear the Sysmon log. Why was that a mistake on their
   part, and what does it teach you about collecting more than one log
   source from each server?
4. An analyst says: "The logs on `FS01` were wiped, so we can't tell what
   happened." Write a short reply listing **three** places the evidence from
   Days 14–16 still exists, and one change you'd recommend so the next
   attacker gains even less from clearing logs.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [1102: The audit log was cleared](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102) · [4719: System audit policy was changed](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719) · [wevtutil command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- Microsoft Learn: [SecurityEvent table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) · [Event table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) · [union operator (KQL)](https://learn.microsoft.com/en-us/kusto/query/union-operator)
- MITRE ATT&CK: [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) · [T1685.001 Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/) · [M1029 Remote Data Storage](https://attack.mitre.org/mitigations/M1029/)
- SigmaHQ: [Microsoft-Windows-Eventlog (System) rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/system/microsoft_windows_eventlog) · [Windows Security log rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/security)
- NIST: [SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)

⬅️ [Learning log index](README.md) · ➡️ Day 17: Alert triage: true/false positives and severity (27 Oct)
