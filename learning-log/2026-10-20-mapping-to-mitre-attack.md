# Day 10 — Mapping Detections to MITRE ATT&CK

📅 20 October 2026 · 🏷️ Detection engineering · ⏱️ ~25 min

---

## Why it matters

On Friday 16 October the attack on `WS-FIN03` (Day 09) didn't arrive in the
queue as one neat story. It arrived as **four separate alerts** from four
different rules, mixed in with alerts about other users. An analyst who reads
them one at a time sees "odd email", "odd Excel", "odd PowerShell" and "odd
connection". An analyst who knows **MITRE ATT&CK** sees *Initial Access →
Execution → Command and Control*: an attacker moving through the stages of an
intrusion. Mapping every detection to ATT&CK gives the SOC a shared language,
lets you **join alerts into a chain**, and shows you plainly which stages you
**can't see at all**.

---

## The concept

### What ATT&CK is

ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a free
knowledge base, maintained by MITRE, of how real attackers behave, built from
public incident reports. It sits at the **top of the Pyramid of Pain** from
Day 09: it describes behaviours (TTPs), not IPs or hashes.

| Layer | Question it answers | ID format | Northwind example |
|---|---|---|---|
| **Tactic** | *Why*: the attacker's goal at this step | `TA0002` | Execution |
| **Technique** | *How*: the general method | `T1059` | Command and Scripting Interpreter |
| **Sub-technique** | *How, more precisely* | `T1059.001` | PowerShell |
| **Procedure** | *Exactly what this attacker did* | (no ID, it's a description) | `cmd.exe /c powershell -NoP -W Hidden -enc …` started by Excel |

One technique can serve more than one tactic. Scheduled tasks (Day 15), for
example, appear under Execution, Persistence and Privilege Escalation,
because the same method can achieve different goals.

### The Enterprise tactics

The Enterprise matrix has **15 tactics**. ATT&CK v19 (April 2026) split the
old **Defense Evasion** tactic into **Stealth** and **Defense Impairment**.

| # | ID | Tactic | # | ID | Tactic |
|---|---|---|---|---|---|
| 1 | TA0043 | Reconnaissance | 9 | TA0006 | Credential Access |
| 2 | TA0042 | Resource Development | 10 | TA0007 | Discovery |
| 3 | TA0001 | Initial Access | 11 | TA0008 | Lateral Movement |
| 4 | TA0002 | Execution | 12 | TA0009 | Collection |
| 5 | TA0003 | Persistence | 13 | TA0011 | Command and Control |
| 6 | TA0004 | Privilege Escalation | 14 | TA0010 | Exfiltration |
| 7 | TA0005 | Stealth | 15 | TA0040 | Impact |
| 8 | TA0112 | Defense Impairment | | | |

> 💡 **The analyst's shortcut:** tactics are **not** a strict timeline.
> Attackers loop back (more Discovery after Lateral Movement) and skip
> stages. But seeing **several different tactics** on one user or host in a
> short time is one of the strongest signals a SOC has.

### How to map a detection

Ask three questions about the rule, in this order:

1. **What does the rule actually see?** Not what the attacker was trying to
   achieve overall, but the event it matches. Day 07's rule sees *an Office
   app starting a shell*.
2. **Which technique describes that?** Search attack.mitre.org and read the
   technique's description and detection notes. An Office app running a
   shell because a user opened a malicious document is **T1204.002 User
   Execution: Malicious File**.
3. **Which tactic does that technique serve here?** T1204.002 sits under
   **Execution**.

Map to the **most specific** sub-technique you can defend, and only to what
the rule can actually detect. Tagging a rule with ten techniques "just in
case" makes your coverage look better than it is.

### Where the mapping lives

In Sigma, it lives in the `tags` field (you've seen this since Day 04):
`attack.` followed by the tactic name in lower case with hyphens, or the
technique ID in lower case.

```yaml
tags:
  - attack.execution        # tactic
  - attack.t1204.002        # sub-technique
```

In a SIEM, it's often easier to keep the mapping in **one lookup table**
keyed by rule ID, so every alert can be enriched with its tactic, whichever
tool raised it.

### Northwind's rules so far

| Rule ID | Rule (from day) | Primary tactic | Technique |
|---|---|---|---|
| NW-001 | RDP brute force from one source IP (04) | Credential Access | T1110.001 Password Guessing |
| NW-002 | Password spraying: one source, many accounts (03) | Credential Access | T1110.003 Password Spraying |
| NW-003 | Burst of discovery commands (05) | Discovery | T1033 System Owner/User Discovery |
| NW-004 | PowerShell started with an encoded command (06) | Execution | T1059.001 PowerShell |
| NW-005 | Office application spawning a shell (07) | Execution | T1204.002 Malicious File |
| NW-006 | Macro attachment from a new sender domain (08) | Initial Access | T1566.001 Spearphishing Attachment |
| NW-007 | PowerShell outbound to a non-internal address (09, stage 3) | Command and Control | T1105 Ingress Tool Transfer |

Seven rules, **5** distinct primary tactics out of 15. Rules can carry more
than one tag (Day 06's rule also has `attack.t1027.010` Command Obfuscation,
which v19 now places under **Stealth**), but a lookup with one primary tactic
per rule keeps the counting below simple.

---

## Sample logs

All times are UTC. 03:13 UTC on **Friday 16 October** is **14:13 in Sydney**.

Northwind sends every alert, from Sentinel, Defender and Splunk, into one
Splunk index, `northwind_alerts`. This is the **mapping lookup**,
`northwind_attack_map.csv`, uploaded as a Splunk lookup table file:

```
rule_id,tactic,technique_id,technique_name
NW-001,Credential Access,T1110.001,Password Guessing
NW-002,Credential Access,T1110.003,Password Spraying
NW-003,Discovery,T1033,System Owner/User Discovery
NW-004,Execution,T1059.001,PowerShell
NW-005,Execution,T1204.002,Malicious File
NW-006,Initial Access,T1566.001,Spearphishing Attachment
NW-007,Command and Control,T1105,Ingress Tool Transfer
```

And **every alert** in `northwind_alerts` for Friday 16 October (7 alerts).
Email alerts have no host, shown as `-` (the field is empty).

```
_time (UTC)          rule_id  rule_name                                       host      user
2026-10-16 01:47:12  NW-001   RDP brute force from one source IP              FS01      administrator
2026-10-16 03:13:51  NW-006   Macro attachment from a new sender domain       -         ben.okafor
2026-10-16 03:14:37  NW-005   Office application spawning a shell             WS-FIN03  ben.okafor
2026-10-16 03:14:37  NW-004   PowerShell started with an encoded command      WS-FIN03  ben.okafor
2026-10-16 03:14:38  NW-007   PowerShell outbound to a non-internal address   WS-FIN03  ben.okafor
2026-10-16 06:30:02  NW-003   Burst of discovery commands                     WS-IT02   tom.reyes
2026-10-16 06:41:15  NW-004   PowerShell started with an encoded command      WS-IT02   tom.reyes
```

For reference, here is NW-007 written as Sigma, the rule version of Day 09's
stage 3, with its ATT&CK tags:

```yaml
title: PowerShell Outbound Connection To A Non-Internal Address
id: 4649cb6c-d36c-4e99-a894-838166a27cee
status: experimental
description: >
  Detects powershell.exe or pwsh.exe opening an outbound network connection
  to an address outside Northwind's internal range. Malicious scripts often
  use PowerShell to download a second-stage file.
references:
  - https://attack.mitre.org/techniques/T1105/
author: Jay (SOC learning log)
date: 2026-10-20
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    Initiated: 'true'
  filter_internal:
    DestinationIp|cidr: '192.0.2.0/24'
  condition: selection and not filter_internal
falsepositives:
  - Admin scripts, module installs from the PowerShell Gallery, update checks
level: low
```

It's `level: low` on purpose: on its own it's noisy. Its value is as one
link in a chain.

---

## What to look for

1. **Seven alerts, three users.** `administrator` has **1**, `ben.okafor` has
   **4** and `tom.reyes` has **2**. Sorting by time alone hides the pattern;
   grouping by user shows it.
2. **Ben's alerts read left to right across the matrix.** In **47 seconds**
   (03:13:51 to 03:14:38) his 4 alerts cover **3** tactics, Initial Access →
   Execution → Command and Control, and **4** techniques (T1566.001,
   T1204.002, T1059.001, T1105). That's the Day 09 attack, recognised from
   the alert queue alone.
3. **Two alerts, one tactic.** NW-005 and NW-004 both fired at 03:14:37 and
   both map to **Execution**. They're different techniques, but they count
   as one tactic. Counting *distinct tactics* stops a single noisy stage from
   looking like a full attack.
4. **Group by user, not host.** The email alert has no host. Grouping by
   `host` would split Ben's chain into an empty-host row and a `WS-FIN03`
   row with only 2 tactics. Choosing the right key is half of correlation.
5. **Tom's two alerts are probably work.** Discovery then Execution, 11
   minutes apart, on an IT workstation. It's **2** tactics, and nothing shows
   delivery or an outbound download. Worth a glance, not a page.
6. **The FS01 alert stands alone.** One Credential Access alert for
   `administrator`: triage it on its own merits (Days 01 and 04).
7. **The gaps.** Our 7 rules cover **5** of 15 tactics by primary tactic. If
   the attacker on `WS-FIN03` had created a scheduled task (Persistence) or
   RDP'd to `FS01` (Lateral Movement), **nothing** would have fired. Days 14
   to 16 start filling those gaps.

---

## Detection logic

**In plain English:** enrich every alert with its ATT&CK tactic from the
lookup, then raise a **new, higher-severity alert** when one user has alerts
covering **3 or more distinct tactics** within **1 hour**. This is a
"meta-detection": it doesn't read raw logs, it reads other rules' alerts.

**SPL (Splunk, `northwind_alerts` index plus the lookup above):**

```spl
index=northwind_alerts earliest=-24h
| lookup northwind_attack_map.csv rule_id OUTPUT tactic technique_id
| stats dc(tactic) AS tactic_count, values(tactic) AS tactics,
        values(technique_id) AS techniques, values(rule_name) AS rules,
        values(host) AS hosts, count AS alerts,
        min(_time) AS first_seen, max(_time) AS last_seen
        BY user
| where tactic_count >= 3 AND (last_seen - first_seen) <= 3600
| convert ctime(first_seen) ctime(last_seen)
```

How it works:

- `lookup ... rule_id OUTPUT tactic technique_id` matches each alert's
  `rule_id` against the CSV and adds the `tactic` and `technique_id` fields.
  Change the mapping in the CSV once and every search that uses it updates.
- `stats dc(tactic) ... BY user` counts **distinct** tactics per user, so the
  two Execution alerts count once. `values()` lists the tactics, techniques,
  rules and hosts for the analyst, and ignores empty values such as the email
  alert's missing host.
- The last `where` keeps users with 3 or more tactics whose first and last
  alerts are no more than 3600 seconds (1 hour) apart.

On the sample, it returns **1** row: `ben.okafor`, **3** tactics (Command and
Control, Execution, Initial Access), **4** techniques, **4** alerts, host
`WS-FIN03`, first seen 03:13:51, last seen 03:14:38. `tom.reyes` is dropped
with **2** tactics, and `administrator` with **1**.

**Tuning note:** `>= 3` tactics in 1 hour is a starting point. Lowering it to
2 would also page on Tom's routine admin work, so before you do, check how
often 2-tactic pairs happen on IT staff in a normal week. As with Day 09's
search, `stats` looks at the whole 24-hour window, so a user with alerts many
hours apart is dropped by the 3600-second check rather than alerted on;
schedule it over short, overlapping windows (for example every 15 minutes
over the last 75). Some attacks unfold over days, so a slower version
(3 tactics in 7 days, lower severity) is a useful companion. Finally, keep
the lookup **current**: rules added without a row in the CSV get no tactic and
silently fall out of this count, and ATT&CK itself changes (v19 moved
obfuscation techniques from Defense Evasion to Stealth), so review your
mappings at least whenever MITRE publishes a new version.

---

## Your turn

1. Use attack.mitre.org to map each of these to a tactic and the most
   specific technique you can defend: (a) `schtasks.exe /create` run by
   `powershell.exe` on `WS-FIN03`; (b) a 4624 **logon type 10** on `FS01`
   from `192.0.2.37` (`WS-FIN03`); (c) `wevtutil.exe cl Security`. For each,
   say whether any of NW-001 to NW-007 would fire.
2. Day 06's Sigma rule is tagged `attack.defense-evasion` and
   `attack.t1027.010`. After the v19 split, what would you change, and what
   could go wrong in a coverage report if nobody updated it?
3. Rerun the SPL in your head with `tactic_count >= 2`. Which users fire
   now? Write two sentences on whether that's a better or worse threshold
   for Northwind, and why.
4. Make a two-column list of the 15 tactics: **covered** (by at least one
   NW rule) and **not covered**. Pick the two gaps you'd close first, and
   say which day in the plan addresses each (if any).

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- MITRE ATT&CK: [Enterprise tactics](https://attack.mitre.org/tactics/enterprise/) · [Updates: April 2026 (v19)](https://attack.mitre.org/resources/updates/updates-april-2026/) · [Getting started](https://attack.mitre.org/resources/) · [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- MITRE ATT&CK techniques used today: [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) · [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002/) · [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) · [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) · [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/)
- SigmaHQ: [Sigma specification (including tags)](https://github.com/SigmaHQ/sigma-specification)
- Splunk Docs: [lookup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Lookup) · [stats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats)

⬅️ [Learning log index](README.md) · ➡️ Day 11: Web server logs: SQL injection attempts in Nginx access logs (21 Oct)
