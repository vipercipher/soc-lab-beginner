# Day 05 — Sysmon Event ID 1: Process Creation

📅 15 October 2026 · 🏷️ Endpoint telemetry · ⏱️ ~25 min

---

## Why it matters

Days 01 to 04 were all about the front door: who tried to log in, from where,
and how many times. But once an attacker is *in*, logon events go quiet. The
4624 on Day 01 tells you the attacker got an RDP session as `administrator`. It
says nothing about what they **did** in that session. That's where process
creation logs come in. Every command an attacker types, every tool they run,
starts a new process, and **Sysmon Event ID 1** records each one with its full
command line, its parent, its user and a hash of the file. If you only learn one
endpoint log, learn this one. It's the raw material for most of the next week
of this log (encoded PowerShell on Day 06, odd parent–child pairs on Day 07).

---

## The concept

### What Sysmon is

**Sysmon** (System Monitor) is a free tool from Microsoft Sysinternals. Once
installed, it runs as a service and writes detailed events to its own log:
**Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**
(channel name `Microsoft-Windows-Sysmon/Operational`). A configuration file
decides what it records. Event ID **1** is **Process Create**.

### Sysmon 1 vs. Windows 4688

Windows can log new processes on its own, as Security event **4688**. Many SOCs
collect both, so it helps to know how they differ:

| | Windows **4688** | Sysmon **1** |
|---|---|---|
| Log | Security | Microsoft-Windows-Sysmon/Operational |
| Needs | "Audit Process Creation" policy | Sysmon installed + a config |
| Command line | Only if the "Include command line in process creation events" policy is on | Always included |
| Parent process | `ParentProcessName` (Windows 10 / Server 2016 and later) | `ParentImage` **and** `ParentCommandLine` |
| File hash | No | `Hashes` (e.g. SHA256) |
| Original file name | No | `OriginalFileName` |
| Unique process ID | No (process IDs get reused) | `ProcessGuid` |

### The fields that matter most

| Field | What it holds | Why an analyst cares |
|---|---|---|
| `Image` | Full path of the program that ran | Odd locations (`C:\ProgramData\`, `C:\Users\Public\`) stand out |
| `CommandLine` | The exact command, with arguments | Tells you *what* the program was asked to do |
| `ParentImage` / `ParentCommandLine` | The program that started it | Shows the chain: who launched what |
| `User` | The account it ran as | Ties activity back to a person or service |
| `LogonId` | The logon session it belongs to | Matches `TargetLogonId` in the 4624 from Day 01 |
| `IntegrityLevel` | `Low`, `Medium`, `High` or `System` | `High` = running with admin rights |
| `OriginalFileName` | The name compiled into the file's version info | **Stays the same when the file is renamed** |
| `Hashes` | Fingerprint of the file | Look it up, or search for it on other hosts |
| `ProcessGuid` | Unique ID for this one process | Follow it across other Sysmon events, even if the PID is reused |

> 💡 **The analyst's shortcut:** `Image` is what the file is *called*.
> `OriginalFileName` is what the file *is*. When those two disagree on a Windows
> tool, someone renamed it, and legitimate software almost never does that.

Some built-in tools have a surprising `OriginalFileName`, so check before you
write a rule: `nltest.exe` is `nltestrk.exe`, `systeminfo.exe` is
`sysinfo.exe`, and `cmd.exe` is `Cmd.Exe`.

---

## Sample logs

Back to Northwind's file server `FS01`. Thirteen hours after the Day 04 brute
force (which ended in a lockout), someone is signed in over RDP as
`administrator`. Times are UTC (Sydney is
UTC+11 in October, so 14:52 UTC is **01:52 in Sydney**).

First, **one full event**, slightly trimmed, as it appears in Event Viewer's
*Details* tab:

```
Process Create:
UtcTime: 2026-10-14 14:52:40.118
ProcessGuid: {6f1d2c3a-4b5e-670d-2a01-000000001a00}
ProcessId: 5124
Image: C:\ProgramData\wu.exe
FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
Description: whoami - displays logged on user information
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: whoami.exe
CommandLine: wu.exe /all
CurrentDirectory: C:\ProgramData\
User: NORTHWIND\administrator
LogonId: 0x5A3F21
TerminalSessionId: 2
IntegrityLevel: High
Hashes: SHA256=4D1A9C…E07C (shortened)
ParentProcessGuid: {6f1d2c3a-4b2f-670d-2701-000000001a00}
ParentProcessId: 4380
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe"
```

Then **every Event ID 1** from `FS01` over the same day, as a table. Only the
key fields are shown, and `ParentImage` is shortened to the file name.

```
UtcTime (2026-10-14)  User                     ParentImage    Image                              CommandLine                                         OriginalFileName
14:52:31              NORTHWIND\administrator  explorer.exe   C:\Windows\System32\cmd.exe        "C:\Windows\system32\cmd.exe"                       Cmd.Exe
14:52:40              NORTHWIND\administrator  cmd.exe        C:\ProgramData\wu.exe              wu.exe /all                                         whoami.exe
14:53:12              NORTHWIND\administrator  cmd.exe        C:\Windows\System32\net.exe        net group "Domain Admins" /domain                   net.exe
14:53:12              NORTHWIND\administrator  net.exe        C:\Windows\System32\net1.exe       C:\Windows\system32\net1 group "Domain Admins" /domain   net1.exe
14:53:47              NORTHWIND\administrator  cmd.exe        C:\Windows\System32\nltest.exe     nltest /dclist:northwind-example.com                nltestrk.exe
14:54:20              NORTHWIND\administrator  cmd.exe        C:\Windows\System32\ipconfig.exe   ipconfig /all                                       ipconfig.exe
14:55:05              NORTHWIND\administrator  cmd.exe        C:\Windows\System32\systeminfo.exe systeminfo                                          sysinfo.exe
15:00:03              NORTHWIND\svc_backup     svchost.exe    C:\Windows\System32\Robocopy.exe   robocopy D:\Shares E:\Backup /MIR                   robocopy.exe
23:14:22              NORTHWIND\tom.reyes      cmd.exe        C:\Windows\System32\ipconfig.exe   ipconfig /all                                       ipconfig.exe
```

`tom.reyes` is on Northwind's IT helpdesk, and 23:14 UTC is 10:14 in Sydney.

---

## What to look for

1. **A renamed Windows tool.** The full event's `Image` is `wu.exe` in
   `C:\ProgramData\`, but `OriginalFileName`, `Description` and `Company` all
   say it's Microsoft's `whoami.exe`. Someone copied it and renamed it, most
   likely to slip past a rule that looks for `whoami.exe` by name. This is
   **T1036.003 Rename System Utilities**, and it's a strong signal on its own.
2. **Questions an intruder asks.** In **2 minutes 25 seconds** (14:52:40 to
   14:55:05), the same user ran **five** different discovery commands:
   *who am I* (`whoami /all`), *who are the domain admins* (`net group`),
   *where are the domain controllers* (`nltest /dclist`), *what network is
   this* (`ipconfig /all`) and *what machine is this* (`systeminfo`). Each is
   harmless alone. Together, at 01:52 in Sydney, they're someone getting their
   bearings.
3. **One command, two processes.** `net.exe` started `net1.exe` with the same
   arguments at the same second. That's normal Windows behaviour (`net` hands
   many commands to `net1`), not a second attacker action. Remember it when you
   count: those five commands produced **six** matching processes.
4. **The chain.** `explorer.exe` → `cmd.exe` → each tool. Explorer starting a
   command prompt just means someone clicked or typed it in a desktop session,
   which fits an RDP logon. The full event's `TerminalSessionId: 2` agrees: a
   remote desktop session, not the console.
5. **High integrity.** `IntegrityLevel: High` means these ran with full admin
   rights. The built-in `administrator` account gets that by default.
6. **The normal rows.** `svc_backup` running `robocopy` from `svchost.exe` (the
   Task Scheduler service) at 02:00 Sydney is the nightly backup. Tom's single
   `ipconfig /all` mid-morning is everyday troubleshooting. One discovery
   command from a helpdesk account during business hours is not a story.

---

## Detection logic

**In plain English:** match any process that is one of these discovery tools,
**by name or by original file name** (so renaming doesn't help). Then alert when
one **user on one computer** runs **4 or more different** discovery tools within
**15 minutes**.

This is a `value_count` correlation, exactly like the password-spray rule from
Day 04's exercise 3. The trick is *which field* to count: counting `Image` would
treat `wu.exe` as a new tool, but counting `OriginalFileName` counts what each
tool really is.

**Sigma (base rule + correlation rule):**

```yaml
title: Windows Discovery Tool Execution
id: d3787ce8-e314-4223-b2ff-918d07f80b5d
name: windows_discovery_tool_execution
status: experimental
description: >
  Detects execution of common built-in discovery tools, matched by image name
  or by OriginalFileName so that renamed copies are also caught. Used as the
  building block for the discovery burst correlation below.
references:
  - https://attack.mitre.org/tactics/TA0007/
  - https://attack.mitre.org/techniques/T1036/003/
author: Jay (SOC learning log)
date: 2026-10-15
tags:
  - attack.discovery
  - attack.t1033
  - attack.t1069.002
  - attack.t1018
  - attack.t1016
  - attack.t1082
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\whoami.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\nltest.exe'
      - '\ipconfig.exe'
      - '\systeminfo.exe'
  selection_original_name:
    OriginalFileName:
      - 'whoami.exe'
      - 'net.exe'
      - 'net1.exe'
      - 'nltestrk.exe'
      - 'ipconfig.exe'
      - 'sysinfo.exe'
  condition: 1 of selection_*
falsepositives:
  - IT staff troubleshooting
  - Inventory and monitoring scripts
level: informational
---
title: Burst Of Discovery Commands By One User On One Host
id: 6bad0d4a-fec6-4e1f-8256-81899984eef9
status: experimental
description: >
  Four or more different discovery tools run by the same user on the same
  computer within 15 minutes.
author: Jay (SOC learning log)
date: 2026-10-15
tags:
  - attack.discovery
correlation:
  type: value_count
  rules:
    - windows_discovery_tool_execution
  group-by:
    - Computer
    - User
  timespan: 15m
  condition:
    field: OriginalFileName
    gte: 4
falsepositives:
  - Helpdesk staff working through a troubleshooting checklist
  - Login scripts or inventory tools that run several of these at once
level: medium
```

How it works:

- `logsource: category: process_creation` is Sigma's generic name for "a new
  process started". It covers **Sysmon Event ID 1** and **Windows 4688**, and a
  processing pipeline maps it to the right log. (Some fields, like
  `OriginalFileName`, only exist in Sysmon.)
- `Image|endswith` uses the modifiers from Day 04. Starting each value with a
  backslash (`'\net.exe'`) stops it matching unrelated tools like
  `C:\Tools\magnet.exe`.
- `condition: 1 of selection_*` means "any block whose name starts with
  `selection_`". The renamed `wu.exe` fails `selection_image` but passes
  `selection_original_name`, so it's still caught.
- The base rule is `informational`: one `ipconfig` is not worth anyone's time.
  The correlation is what raises it to `medium`.

On the sample, the base rule matches **7** events: the **6** discovery
processes from `administrator` plus Tom's `ipconfig`. (`cmd.exe` and
`Robocopy.exe` aren't on the list.) Grouped by `Computer` and `User`,
`FS01` / `NORTHWIND\administrator` has **6 different** `OriginalFileName`
values (`whoami.exe`, `net.exe`, `net1.exe`, `nltestrk.exe`, `ipconfig.exe`,
`sysinfo.exe`) inside 2 minutes 25 seconds, so 6 ≥ 4 and the correlation
fires. `FS01` / `NORTHWIND\tom.reyes` has **1**, so it stays quiet.

**Turning it into a real query.** For Sysmon data in Splunk, add the `sysmon`
pipeline before the Splunk one so the rule is pointed at the Sysmon channel and
Event ID 1:

```bash
sigma check day05_discovery_burst.yml
sigma convert -t splunk -p sysmon -p splunk_windows day05_discovery_burst.yml
```

The output looks roughly like this (exact formatting depends on the backend and
pipeline versions):

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image IN ("*\\whoami.exe", "*\\net.exe", "*\\net1.exe", "*\\nltest.exe", "*\\ipconfig.exe", "*\\systeminfo.exe")
   OR OriginalFileName IN ("whoami.exe", "net.exe", "net1.exe", "nltestrk.exe", "ipconfig.exe", "sysinfo.exe"))
| bin _time span=15m
| stats dc(OriginalFileName) as value_count by _time Computer User
| search value_count >= 4
```

`dc()` is Splunk's *distinct count*: the `value_count` correlation in one
function.

**Tuning note:** because `net` launches `net1`, one `net` command counts as
**two** tools. If helpdesk checklists trip the rule, drop `net1.exe` from the
lists rather than raising the threshold, so the count reflects real commands.
Tune out *specific* accounts or scripts (a known inventory tool's parent
process, for example) instead of whole groups like "all IT staff", since admin
accounts are exactly what attackers steal. Check how Sysmon arrives in your
SIEM before deploying: many Splunk setups use
`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` as the source name. And
keep a **separate, single-event rule** for the renamed tool itself
(`OriginalFileName` is a Windows tool but `Image` doesn't end in its usual
name). That's rare enough in normal use to alert on directly.

---

## Your turn

1. In the full event, which **three** fields show that `wu.exe` is really
   `whoami.exe`? Why doesn't renaming the file change them?
2. You want to know how this `administrator` session started. Which field in
   the Sysmon event would you use to find the matching **4624**, which field in
   the 4624 would you match it against, and what **logon type** would you
   expect to see?
3. Write the **single-event** Sigma rule from the tuning note: match
   `OriginalFileName: whoami.exe` when the `Image` does **not** end in
   `\whoami.exe`. Which row(s) in today's sample would it match?
4. Tom on the helpdesk runs `whoami`, `ipconfig /all`, `hostname` and
   `net user tom.reyes /domain` while fixing a user's laptop. Would the
   correlation fire? Work out the distinct count, then suggest one way to stop
   it firing on Tom **without** hiding the same commands run from Tom's account
   by someone who stole his password.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Sysmon (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Microsoft Learn: [4688: A new process has been created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) · [Command line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- SigmaHQ: [Log sources](https://sigmahq.io/docs/basics/log-sources.html) · [Sigma correlation rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
- MITRE ATT&CK: [TA0007 Discovery](https://attack.mitre.org/tactics/TA0007/) · [T1036.003 Rename System Utilities](https://attack.mitre.org/techniques/T1036/003/) · [T1069.002 Domain Groups](https://attack.mitre.org/techniques/T1069/002/)

⬅️ [Learning log index](README.md) · ➡️ [Day 06: Suspicious PowerShell: encoded commands (16 Oct)](2026-10-16-powershell-encoded-commands.md)
