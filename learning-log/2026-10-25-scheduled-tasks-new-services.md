# Day 15 — Persistence: Scheduled Tasks and New Services (4698, 7045)

📅 25 October 2026 · 🏷️ Log analysis · ⏱️ ~25 min

---

## Why it matters

Day 14 ended with the attacker on `FS01` holding a backdoor account,
`support_svc`, and using it to log on over RDP at 02:15:44. A careful
responder disables that account. But an account is only one way back in. An
attacker with admin rights can also tell Windows itself to **run their
program automatically**: at every boot, every logon, or every hour. The two
classic ways to do that are a **scheduled task** and a **new service**.
Neither needs a password, so resetting passwords and disabling accounts
doesn't stop them. Day 10 pointed out that nothing in Northwind's rule set
would notice a new scheduled task. Today fills that gap.

---

## The concept

### Scheduled tasks and services in one sentence each

| Mechanism | What it is | Typical legitimate use |
|---|---|---|
| **Scheduled task** | A job that Task Scheduler runs on a **trigger** (a time, boot, logon, an event) | Software updaters, backups, cleanup scripts |
| **Service** | A program the Service Control Manager starts and keeps running in the background, often at boot | Antivirus, backup agents, database servers |

Both can run as **SYSTEM**, the most powerful account on the machine. That's
what makes them attractive to an attacker and why a new one deserves a look.

### The event IDs

| Event ID | Log | Meaning | Logged when |
|---|---|---|---|
| **4698** | Security | A scheduled task was created | **Audit Other Object Access Events** is set to *Success* |
| 4699 | Security | A scheduled task was deleted | Same |
| 4702 | Security | A scheduled task was updated | Same |
| **7045** | System | A service was installed in the system | Always (written by the Service Control Manager) |
| 4697 | Security | A service was installed in the system | **Audit Security System Extension** is set to *Success* |

Two things trip beginners up:

- **7045 lives in the System log**, not the Security log, and its source is
  **Service Control Manager**. It's logged by default, which makes it one of
  the most reliable persistence signals you have.
- **4698 is off by default** on many machines. If your query returns nothing,
  check the audit policy before concluding nothing happened. (Task Scheduler
  also has its own *Operational* log, where event **106** means a task was
  registered, but that log is often disabled too.)

### The fields that matter

| Event | Field | What it tells you |
|---|---|---|
| 4698 | `SubjectUserName` | Who created the task. A name ending in `$` (like `WS-FIN03$`) is the computer account, meaning something running as SYSTEM did it |
| 4698 | `TaskName` | The task's path and name, e.g. `\Microsoft\Windows\UpdateCheck` |
| 4698 | `TaskContent` | The whole task definition as XML: **trigger**, **run-as account** and **command** |
| 7045 | `ServiceName` | The service's name |
| 7045 | `ImagePath` | The program (and arguments) the service runs |
| 7045 | `StartType` | `auto start` means it runs at every boot |
| 7045 | `AccountName` | The account it runs as; `LocalSystem` is SYSTEM |

The most important field on both is **what it runs**: `TaskContent`'s
`<Command>` and `<Arguments>`, and the service's `ImagePath`. Legitimate
software almost always lives under `C:\Program Files\` or `C:\Windows\`.
Programs in **`C:\Users\Public\`**, a user's **`AppData`**, or a **`Temp`**
folder, or a hidden **PowerShell** window (Day 06), are where attackers like
to put things, because any user can write there.

> 💡 **Names lie, paths rarely do.** Attackers give tasks and services
> boring names that sound like Windows (`UpdateCheck`, `HelperSvc`), and they
> even save tasks under the `\Microsoft\Windows\` folder. Judge them by the
> command, not the name.

### Where the logs come from

4698 is in the Security log, so it reaches Microsoft Sentinel in the
**`SecurityEvent`** table, the same table as Days 01 and 14. Unlike 4720,
there's no `TaskName` column: the task's details sit inside the
**`EventData`** column as XML, so the query below pulls them out. 7045 is in
the System log, which lands in the **`Event`** table instead. Today's Sigma
rule works on 7045 and the KQL query works on 4698, so you see one of each.

---

## Sample logs

Task and service events from `FS01`, `WS-FIN03` and `WS-DEV01` on
**10 October** (UTC), the same night as Days 01 and 14. The `Command` column
is pulled out of `TaskContent` to save space.

**Security log, Event ID 4698 (scheduled task created):**

```
TimeCreated (UTC)    Computer  EventID  SubjectUserName  TaskName                                        Command + Arguments
2026-10-10 02:17:02  FS01      4698     support_svc      \Microsoft\Windows\UpdateCheck                   powershell.exe -NoP -W Hidden -File C:\Users\Public\sync.ps1
2026-10-10 03:00:15  WS-FIN03  4698     WS-FIN03$        \Microsoft\Office\Office Automatic Updates 2.0  "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /frequentupdate SCHEDULEDTASK
2026-10-10 23:40:27  WS-DEV01  4698     liam.chen        \Northwind\DevBuildCleanup                      C:\Users\liam.chen\AppData\Local\Programs\buildtools\cleanup.exe --older-than 7d
```

The full `TaskContent` of the first row, trimmed to the parts an analyst
reads:

```xml
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>FS01\support_svc</Author>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoP -W Hidden -File C:\Users\Public\sync.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
```

**System log, Event ID 7045 (service installed):**

```
TimeCreated (UTC)    Computer  EventID  ServiceName             ImagePath                                         StartType   AccountName
2026-10-10 02:18:40  FS01      7045     NwHelperSvc             C:\Users\Public\nwhelper.exe                      auto start  LocalSystem
2026-10-10 11:02:13  FS01      7045     Northwind Backup Agent  "C:\Program Files\NorthwindBackup\nwbackup.exe"   auto start  LocalSystem
```

Context from the IT team: the backup agent upgrade on `FS01` was planned
work under change ticket **CHG-2209**, and Liam Chen (local admin on
`WS-DEV01` under CHG-2217, Day 14) maintains his own build tools.

---

## What to look for

1. **Same account, same night.** At 02:17:02, **`support_svc`**, the
   backdoor account from Day 14, creates a task on `FS01`. That's 78 seconds
   after it logged on over RDP at 02:15:44. Anything that account did is
   suspect by default.
2. **A fake Microsoft name.** The task is saved as
   `\Microsoft\Windows\UpdateCheck`, a folder where real Windows tasks live.
   But Windows doesn't create its own tasks from an RDP session at 2 am, and
   the `<Author>` is `FS01\support_svc`.
3. **Read the XML.** The trigger is **`BootTrigger`** (run at every
   startup), the run-as account is **`S-1-5-18`** (SYSTEM), and the action is
   **hidden PowerShell** (`-W Hidden`, Day 06) running a script from
   **`C:\Users\Public\`**. Every one of those is a red flag; together they're
   a persistence mechanism.
4. **A second foothold.** 98 seconds later, at 02:18:40, a service
   **`NwHelperSvc`** is installed on `FS01`. It runs
   `C:\Users\Public\nwhelper.exe` as **LocalSystem** and starts automatically.
   7045 doesn't record *who* installed it in a field you'll see here, but the
   timing, the host and the `C:\Users\Public\` path tie it to the same
   attacker. Containment now means removing the task **and** the service, not
   just disabling `support_svc`.
5. **The normal rows.** The Office update task on `WS-FIN03` is created by
   `WS-FIN03$` (SYSTEM, i.e. the Office installer) and runs a signed Microsoft
   program from `C:\Program Files\`. The backup agent on `FS01` runs from
   `C:\Program Files\` at 11:02 UTC (22:02 Sydney time, the maintenance window)
   and matches CHG-2209. Liam's cleanup task on `WS-DEV01` runs from his own
   `AppData` folder, which *looks* like the attacker's pattern but is a
   developer's tool on his own machine at 23:40 UTC (10:40 Sydney time).
6. **Totals.** **5** rows: **3** task creations (4698) and **2** service
   installs (7045). **2** of the 5 are malicious, both on `FS01` within two
   minutes of each other.

---

## Detection logic

**In plain English:** two rules. **Rule A** flags a **new service** whose
`ImagePath` points somewhere programs shouldn't normally run from, or runs a
shell. **Rule B** flags a **new scheduled task** whose definition mentions
those same places or PowerShell.

**Sigma, Rule A (System log, 7045):**

```yaml
title: Service Installed From a User-Writable Path or Shell
id: 6f0b2a6e-4c1d-4f7b-9a53-2d8e1c7b5a90
status: experimental
description: >
  Detects a new Windows service whose ImagePath points to a folder that any
  user can write to, or that runs a command shell or PowerShell.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/system/service_control_manager
author: Jay (SOC learning log)
date: 2026-10-25
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1543.003
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  selection_path:
    ImagePath|contains:
      - '\Users\Public\'
      - '\AppData\'
      - '\Temp\'
      - 'cmd.exe /c'
      - 'powershell'
  condition: selection and selection_path
falsepositives:
  - Software installers that briefly run a helper service from a Temp folder
  - Per-user tools installed under AppData by developers
level: high
```

On the sample it matches **1** row: `NwHelperSvc` on `FS01` at 02:18:40.
The backup agent's `ImagePath` is under `C:\Program Files\`, so it doesn't
match. (Sigma's `contains` is case-insensitive, so `PowerShell` and
`powershell` both match.)

**KQL, Rule B (Microsoft Sentinel, `SecurityEvent` table, 4698):**

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4698
| extend TaskName = extract(@'Name="TaskName">([^<]+)<', 1, EventData)
| where EventData contains @"\Users\Public\"
     or EventData contains @"\AppData\"
     or EventData contains @"\Temp\"
     or EventData contains "powershell"
| project TimeGenerated, Computer, SubjectUserName, TaskName
```

On the sample it returns **2** rows: `\Microsoft\Windows\UpdateCheck` on
`FS01` (PowerShell and `\Users\Public\`) and `\Northwind\DevBuildCleanup` on
`WS-DEV01` (`\AppData\`). The Office task only mentions `C:\Program Files\`,
so it's not returned.

How it works:

- `EventData` holds the whole event, including `TaskContent`, as XML text.
  `extract()` uses a regular expression to copy the text between
  `Name="TaskName">` and the next `<` into a new `TaskName` column, so the
  result is readable.
- `contains` is a case-insensitive substring search over that XML, so it
  finds the paths wherever they appear in the task's command or arguments.
  The `@"..."` form is a *verbatim* string, which lets you write single
  backslashes.
- `project` keeps the columns an analyst needs to start triage. Open the
  full event to read the trigger and run-as account.

**Tuning note:** both rules will catch developers and some installers that
use `AppData` or `Temp`. Don't delete `\AppData\` from the list to silence
`WS-DEV01`: attackers use it too. Instead, allow-list a **specific** known
task name on a **specific** host (for example `\Northwind\DevBuildCleanup`
on `WS-DEV01`), and review that list every quarter. Rule B only works if
**Audit Other Object Access Events** is on; check that first, or you'll be
tuning a rule that never sees data. Neither rule catches an attacker who
drops their program into `C:\ProgramData\` or even `C:\Windows\`; a broader,
lower-severity rule that flags **every** new auto-start service running as
`LocalSystem` on servers is a good companion. And remember that an attacker
can clear the Security log to hide the 4698, which is tomorrow's topic.

For Day 10's mapping lookup, these become rules **NW-015** and **NW-016**:

```
NW-015,Persistence,T1543.003,Create or Modify System Process: Windows Service
NW-016,Persistence,T1053.005,Scheduled Task/Job: Scheduled Task
```

---

## Your turn

1. For each of the **3** scheduled tasks in the sample, write one line:
   who created it, what it runs, and whether you'd escalate it. Which one does
   Rule B wrongly flag, and what one fact convinced you it's benign?
2. Using only the `TaskContent` XML for `\Microsoft\Windows\UpdateCheck`,
   answer: *when* will it run, *as whom*, and *what* will it do? Why does the
   `BootTrigger` mean disabling `support_svc` isn't enough?
3. Day 05 taught Sysmon Event ID 1. If Sysmon were installed on `FS01`, which
   two process names would you expect to see as `Image` around 02:17 and
   02:18 if the attacker used Windows' built-in command-line tools to create
   the task and the service? Why is it useful to have **both** the Sysmon
   view and the 4698 / 7045 view?
4. Write the containment steps for `FS01` in the right order, building on
   your Day 14 answer. Include what you'd do with the task, the service, the
   two files in `C:\Users\Public\`, and the accounts. Which step would you do
   **before** deleting anything, and why?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [4698: A scheduled task was created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) · [4697: A service was installed in the system](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697) · [Audit Other Object Access Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events)
- Microsoft Learn: [Task Scheduler: Task XML schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema) · [SecurityEvent table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) · [extract() function (KQL)](https://learn.microsoft.com/en-us/kusto/query/extract-function)
- MITRE ATT&CK: [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) · [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- SigmaHQ: [Service Control Manager rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/system/service_control_manager) · [Windows Security log rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/security)

⬅️ [Learning log index](README.md) · ➡️ [Day 16: Defence evasion: cleared audit logs (1102) (26 Oct)](2026-10-26-cleared-audit-logs.md)
