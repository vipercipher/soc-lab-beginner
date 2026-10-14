# Day 04 — Writing Your First Sigma Rule

📅 14 October 2026 · 🏷️ Detection engineering · ⏱️ ~25 min

---

## Why it matters

So far this log has written every detection in a different language: KQL for
Sentinel on Day 01 and Day 03, SPL for Splunk on Day 02. Real SOCs have the same
problem. Teams change SIEMs, share rules with other companies, and borrow
detections from the community, and nobody wants to rewrite the same idea three
times. **Sigma** fixes that. It's an open, YAML-based format for describing
*what to look for in a log*, without tying it to any one product. You write the
rule once, then a converter turns it into KQL, SPL or another query language.
Thousands of community rules in the SigmaHQ repository use it, so being able to
read and write Sigma is one of the most useful skills a new analyst can pick up.

---

## The concept

### Sigma in one sentence

> A Sigma rule says: **in this kind of log** (`logsource`), **find events that
> look like this** (`detection`), and **here's how worried to be** (`level`).

### Anatomy of a rule

| Field | Required? | What it holds |
|---|---|---|
| `title` | Yes | A short, human-readable name |
| `id` | Recommended | A random UUID, so the rule can be tracked even if it's renamed |
| `status` | Recommended | `experimental`, `test` or `stable` (how much it's been proven) |
| `description` | Recommended | What the rule detects and why it matters |
| `references` | Optional | Links that explain the technique |
| `author`, `date` | Recommended | Who wrote it and when (`YYYY-MM-DD`) |
| `tags` | Optional | Usually MITRE ATT&CK, e.g. `attack.credential-access`, `attack.t1110.001` |
| `logsource` | Yes | Which log to search: `product`, `service` and/or `category` |
| `detection` | Yes | Named search blocks plus a `condition` that combines them |
| `falsepositives` | Recommended | Known harmless things that will also match |
| `level` | Recommended | `informational`, `low`, `medium`, `high` or `critical` |

### How `detection` works

The `detection` section is where beginners trip up, but there are only three
rules to learn:

| Sigma writes it as | It means | Example |
|---|---|---|
| Several fields in one block | **AND**: all must match | `EventID: 4625` and `LogonType: 10` |
| A list of values under one field | **OR**: any value matches | `SubStatus: ['0xC000006A', '0xC0000064']` |
| `condition:` | How the named blocks combine | `selection and not filter` |

Values match **whole field contents** and are **case-insensitive** by default.
To match part of a value, add a **modifier** after a pipe: `|contains`,
`|startswith`, `|endswith`. (You'll use these a lot from Day 05 onwards, when
matching command lines.)

### One event vs. many events

A plain Sigma rule looks at **one event at a time**. It can say "this is a
failed RDP logon", but not "five of them in ten minutes". For counting, Sigma 2.0
adds **correlation rules**: a second rule that points at the first and counts
its matches.

| Correlation `type` | Counts | Fits |
|---|---|---|
| `event_count` | How many matching events per group | Brute force (Day 01, Day 02) |
| `value_count` | How many **distinct values** of a field per group | Password spraying (Day 03) |
| `temporal` | Whether several different rules all fired in the window | "Failures, *then* a success" |

> 💡 **The analyst's shortcut:** write the **single-event rule first** and make
> sure it matches exactly the events you mean. Counting comes second. A
> correlation built on a sloppy base rule just counts the wrong things faster.

---

## Sample logs

Today's job is to turn Day 01's RDP brute-force idea into a Sigma rule and test
it against a new extract from Northwind's server `FS01`. Times are UTC.
`203.0.113.10` is Northwind's **admin jump host**, the one machine admins are
supposed to RDP from.

```
TimeCreated (UTC)     EventID  TargetUserName  LogonType  IpAddress       SubStatus
2026-10-13 22:40:05   4625     sara.lund       3          203.0.113.77    0xC000006A
2026-10-13 22:40:19   4624     sara.lund       3          203.0.113.77    -
2026-10-14 01:37:02   4625     administrator   10         198.51.100.29   0xC000006A
2026-10-14 01:37:04   4625     admin           10         198.51.100.29   0xC0000064
2026-10-14 01:37:07   4625     administrator   10         198.51.100.29   0xC000006A
2026-10-14 01:37:09   4625     backup          10         198.51.100.29   0xC0000064
2026-10-14 01:37:12   4625     administrator   10         198.51.100.29   0xC000006A
2026-10-14 01:37:15   4625     administrator   10         198.51.100.29   0xC0000234
2026-10-14 03:15:40   4625     svc_monitor     10         203.0.113.10    0xC000006A
2026-10-14 09:02:41   4625     priya.nair      10         203.0.113.24    0xC000006A
2026-10-14 09:02:55   4624     priya.nair      10         203.0.113.24    -
```

The column names match the real field names in the 4624/4625 event XML
(`TargetUserName`, `LogonType`, `IpAddress`, `SubStatus`), which are also the
names Sigma uses for the Windows Security log.

---

## What to look for

When you write a rule, you're deciding which **fields** separate the attack from
everything else. Work through the sample one field at a time:

1. **`EventID` 4625** narrows it to failures. That leaves **9** rows (Sara's and
   Priya's `4624` successes drop out).
2. **`LogonType` 10** narrows it to RDP. Sara's failed file-share logon (type 3)
   drops out, leaving **8**.
3. **`IpAddress` 203.0.113.10** is the jump host. `svc_monitor`'s single failure
   is a monitoring check with a stale password: worth a ticket to fix, but not
   an attack. Excluding the jump host leaves **7** rows.
4. **The source IP is what repeats.** `198.51.100.29` accounts for **6** of those
   7 rows in **13 seconds** (01:37:02 to 01:37:15). The usernames change
   (`administrator`, `admin`, `backup`) and the SubStatus changes, so neither is
   a good thing to group on. The IP is.
5. **The last attacker row is `0xC0000234`.** `administrator` is now locked out.
   Lockout stopped this one, but don't let the rule depend on it: an attacker who
   gets the password on try four never triggers lockout at all.
6. **Priya's row matches the single-event rule too.** One typo at 09:02:41,
   then a success 14 seconds later from her usual IP. That's why counting
   matters: one failure alone isn't suspicious.

---

## Detection logic

**In plain English:** match every **failed RDP logon** (4625, logon type 10)
that **isn't from the admin jump host**. Then alert when **one source IP**
produces **5 or more** of those within **10 minutes**.

**Sigma (base rule + correlation rule, in one file separated by `---`):**

```yaml
title: Failed RDP Logon From Non-Jump-Host Source
id: d03de9b1-b3e8-4ac4-99be-5d19ee5cf5d8
name: failed_rdp_logon_non_jump_host
status: experimental
description: >
  Detects a single failed Remote Desktop logon (4625, logon type 10) from any
  source other than Northwind's admin jump host. Used as the building block
  for the RDP brute-force correlation below.
references:
  - https://attack.mitre.org/techniques/T1110/001/
author: Jay (SOC learning log)
date: 2026-10-14
tags:
  - attack.credential-access
  - attack.t1110.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 10
  filter_jump_host:
    IpAddress: '203.0.113.10'
  condition: selection and not filter_jump_host
falsepositives:
  - Users mistyping their password over RDP
level: low
---
title: RDP Brute Force From One Source IP
id: 5de06b13-05c2-4499-b0e6-f3164dff93e6
status: experimental
description: >
  Five or more failed RDP logons from the same source IP within 10 minutes.
author: Jay (SOC learning log)
date: 2026-10-14
tags:
  - attack.credential-access
  - attack.t1110.001
correlation:
  type: event_count
  rules:
    - failed_rdp_logon_non_jump_host
  group-by:
    - IpAddress
  timespan: 10m
  condition:
    gte: 5
falsepositives:
  - A user's saved RDP connection retrying an old password after a reset
level: medium
```

How it works:

- The **base rule** has two named blocks. `selection` uses AND (both
  `EventID: 4625` *and* `LogonType: 10`). `filter_jump_host` names the IP to
  ignore, and the `condition` reads like a sentence: *selection and not
  filter*. Its `level` is `low` because one failed logon alone isn't worth an
  alert.
- The **`name`** field gives the base rule a handle. The correlation rule refers
  to it under `rules:` (you could use the `id` instead).
- The **correlation rule** has no `logsource` or `detection` of its own. It
  counts base-rule matches per `IpAddress` over `10m` and fires at `gte: 5`
  (greater than or equal to 5).

On the sample, the base rule matches **7** rows: the 6 from `198.51.100.29` plus
Priya's single typo. Grouped by IP, `198.51.100.29` has **6** within 13 seconds,
so 6 ≥ 5 and the correlation fires. Priya's IP has **1**, so it stays quiet.
Sara's row (type 3) and `svc_monitor`'s row (jump host) never reach the count.

**Turning it into a real query.** The `sigma-cli` tool checks and converts
rules. A *processing pipeline* maps Sigma's generic log source onto your SIEM's
index or table:

```bash
sigma check day04_rdp_bruteforce.yml
sigma convert -t splunk -p splunk_windows day04_rdp_bruteforce.yml
```

The Splunk output looks roughly like this (exact formatting depends on the
backend and pipeline versions):

```spl
source="WinEventLog:Security" EventCode=4625 LogonType=10 NOT IpAddress="203.0.113.10"
| bin _time span=10m
| stats count as event_count by _time IpAddress
| search event_count >= 5
```

Notice the pipeline renamed `EventID` to `EventCode`, the field name Splunk's
Windows add-on uses. That's exactly the kind of translation you no longer have
to remember. The first line is the base rule; the rest is the correlation,
written much like Day 02's SPL.

**Tuning note:** this rule follows Day 01's simplified sample, where failed RDP
attempts are logged as **type 10**. On real servers with **Network Level
Authentication (NLA)** turned on, which is the default on modern Windows, the
password is checked *before* the RDP session starts, so failed RDP attempts
usually show up as **type 3** instead. Before deploying, check which logon type
your own servers record for a bad RDP password. If it's type 3, change
`LogonType` to `[3, 10]` and expect more noise from file shares, then group by
`IpAddress` and `Computer` to keep it meaningful. Keep the jump host filter
narrow (one IP, not a whole subnet), and remember that correlation support
varies by converter backend. If yours can't convert the correlation, convert the
base rule and do the counting in the SIEM, as on Day 01.

---

## Your turn

1. Without looking back, explain the difference between putting `EventID: 4625`
   and `LogonType: 10` **in the same block** versus putting
   `LogonType: [3, 10]` **as a list**. Which one is AND and which is OR?
2. Write a **base Sigma rule** for Day 02's SSH failures. Use
   `logsource: product: linux, service: sshd` and a `keywords` block that
   matches `Failed password`. Which lines from Day 02's sample would your rule
   **not** catch, even though it's part of the attack?
3. Day 03's spray put **one** failure on each of many accounts. Change the
   correlation rule to catch it instead: which `type` would you use, which
   `field` would it count, and what would you `group-by`?
4. Northwind's IT team says the office and VPN range (`203.0.113.0/24`) is "trusted"
   and asks you to filter the whole range out. Write the filter, then argue
   **for or against** doing it. (Hint: look at who else uses that range in
   these samples, and think about what an attacker with a stolen VPN login
   could do.)

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1. Fields in the same block are AND. EventID: 4625 with LogonType: 10 only matches an event that is a failed logon and a Remote Desktop (RDP) logon. A list under one field is OR. LogonType: [3, 10] matches an event whose logon type is 3 or 10. One event can’t have two logon types, so the list only makes sense as “any of these values.”

2. Base rule for Day 02’s SSH failures
title: SSH Failed Password
id: 7b2e4c1a-9f3d-4e8b-a6c5-2d1f0e9b8a47
status: experimental
description: Detects a single failed SSH password attempt in sshd logs.
author: Jay (SOC learning log)
date: 2026-10-14
tags:
  - attack.credential-access
  - attack.t1110.001
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Failed password'
  condition: keywords
falsepositives:
  - Users mistyping their password
level: low
keywords searches the whole log message, so Failed password also catches Failed password for invalid user .... The rule would not catch these lines:

Invalid user admin and Invalid user test: the username checks that come before the password attempt.
maximum authentication attempts exceeded and Disconnecting ... Too many authentication failures: the MaxAuthTries cut-off.
Accepted password for deploy and session opened: this is the line that matters most. A rule that only matches failures never sees the attack succeed. You’d need a second base rule for Accepted password, joined to this one with a temporal correlation, to catch “failures, then a success.”

3. Turning the correlation into a spray detector
Type: value_count, because you’re counting distinct users, not events.
Field: the username. That’s TargetUserName in Windows logs, or UserPrincipalName for Day 03’s Entra ID sign-ins.
Group by: the source IP (IpAddress in Windows logs, IPAddress in Entra ID sign-in logs).
correlation:
  type: value_count
  rules:
    - failed_signin   # base rule matching ResultType 50126 / 50034
  group-by:
    - IPAddress
  timespan: 1h
  condition:
    field: UserPrincipalName
    gte: 5
On Day 03’s sample, 198.51.100.66 failed against 8 distinct users, so 8 ≥ 5 and the rule fires. Brute force against one account would count as 1 and stay quiet. That’s the opposite of event_count.

4. Filtering out 203.0.113.0/24
  filter_trusted_range:
    IpAddress|cidr: '203.0.113.0/24'
  condition: selection and not filter_trusted_range

Argue against it. That range is where Priya (.24), Sara (.77) and the jump host (.10) all sit, so it’s where real users and admin accounts work from. If an attacker steals a VPN login, as in Scenario 01, their traffic comes from the trusted range. Brute-forcing or password-guessing against internal servers from there would be completely invisible. That kind of lateral movement is exactly what you most need to see. Filtering a whole /24 also hides any future host in it.

Better options:
Keep filtering only the one jump host IP, as the rule already does.
Give internal sources a lower level instead of dropping them.
Tune out specific known-noisy accounts (such as svc_monitor) rather than a whole network.
---

## Further reading

- SigmaHQ: [Rules: the basics](https://sigmahq.io/docs/basics/rules.html) · [Modifiers](https://sigmahq.io/docs/basics/modifiers.html)
- SigmaHQ: [Sigma rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) · [Sigma correlation rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
- SigmaHQ: [sigma-cli](https://github.com/SigmaHQ/sigma-cli) · [Community rule repository](https://github.com/SigmaHQ/sigma)
- Microsoft Learn: [4625: An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- MITRE ATT&CK: [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

⬅️ [Learning log index](README.md) · ➡️ Day 05: Sysmon Event ID 1: process creation (15 Oct)
