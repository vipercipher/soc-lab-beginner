# Day 21 — Month Recap and What to Study Next

📅 31 October 2026 · 🏷️ Recap · ⏱️ ~30 min

---

## Why it matters

Twenty days ago this log started with a single question: *who logged in,
where from, and how?* (Day 01). Since then Northwind has collected **18**
detection rules, a mapping lookup, a triage helper and an incident ticket
template, and Day 20 used most of them on one real-looking morning. Before
moving on, a working SOC does two things at the end of any stretch like
this: it **looks back** at what it learned, and it **checks its own
detections are still working**. A rule that quietly stopped firing looks
exactly like a quiet month. Today does both.

---

## The concept

### The month in one table

| Day | Topic | The one thing to remember | Rule(s) |
|---|---|---|---|
| 01 | Windows logon events: 4624, 4625 and logon types | Logon **type** and **SubStatus** turn "someone logged in" into a story | NW-001 |
| 02 | Linux `auth.log`: SSH brute force | `Failed password` then `Accepted password` from one IP is the Linux version of Day 01 | — |
| 03 | Password spraying vs brute force | Many passwords, one account = brute force; one password, many accounts = spraying | NW-002 |
| 04 | Your first Sigma rule | Write the logic once in Sigma, convert it to any SIEM | — |
| 05 | Sysmon Event ID 1: process creation | Every process has a parent; the **command line** is the evidence | — |
| 06 | Suspicious PowerShell: encoded commands | `-enc` hides intent; Event ID **4104** shows what it really ran | NW-004 |
| 07 | Office spawning shells | Word or Excel starting `powershell.exe` is almost never normal | NW-005 |
| 08 | Phishing headers: SPF, DKIM, DMARC | *Pass* means "really from this domain", not "safe" | NW-006 |
| 09 | IOCs vs behaviours: the Pyramid of Pain | Hashes and IPs change in minutes; behaviours are expensive to change | NW-007 |
| 10 | Mapping detections to MITRE ATT&CK | One lookup turns alerts into tactics, and tactics into a story | (lookup) |
| 11 | SQL injection in Nginx access logs | Decode the URL before you match; status codes show what worked | NW-008 |
| 12 | DNS: beaconing and random-looking domains | Regular timing and NXDOMAIN bursts give C2 away | NW-009, NW-010 |
| 13 | Firewall logs: port scans | Many ports on one host = vertical; one port on many hosts = horizontal | NW-011, NW-012 |
| 14 | New accounts and admin groups (4720, 4732) | A brand-new account in Administrators within an hour is a red flag | NW-013, NW-014 |
| 15 | Scheduled tasks and services (4698, 7045) | Persistence pointing at a user-writable path is the tell | NW-015, NW-016 |
| 16 | Cleared audit logs (1102) | Clearing the log is itself a loud event | NW-017, NW-018 |
| 17 | Alert triage | True, benign and false positives; priority from severity × asset | (triage helper) |
| 18 | The IR lifecycle (NIST SP 800-61) | Contain before you investigate deeply; recover, then learn | — |
| 19 | Writing a clear incident ticket | Separate **confirmed**, **assessed** and **unknown** | — |
| 20 | Mini case | Join email → endpoint → DNS → persistence with one shared key | — |

> 💡 **The thread through all of it:** every day followed the same loop:
> *read the log → spot the pattern → write the rule → triage what it finds*.
> Scenario 01's `daniel.cole` case was that loop done once by hand; Day 20
> was the same loop across five data sources.

### Detection health: is the rule still working?

A detection can fail silently in three ways:

| Problem | What it looks like | Common causes |
|---|---|---|
| **Silent rule** | Zero alerts for weeks | Nothing happened (fine), **or** the log source stopped, a field was renamed, the rule was disabled |
| **Unmapped rule** | Alerts with no ATT&CK tactic | A new rule was added without a row in the lookup (Day 10's warning) |
| **Noisy rule** | Many alerts, few true positives | Logic too broad, or missing context (Day 17's precision check) |

Silent doesn't mean broken. It means **"prove it still works"**: replay a
known-bad sample, or run a safe test in a lab, and check the alert appears.

---

## Sample logs

All times are UTC. The search runs at **2026-10-31 00:00 UTC** (11:00 in
Sydney) over the last **30 days**.

**The mapping lookup**, `northwind_attack_map.csv`, as built across Days 10
to 16 (**18** rules):

```
rule_id,tactic,technique_id,technique_name
NW-001,Credential Access,T1110.001,Password Guessing
NW-002,Credential Access,T1110.003,Password Spraying
NW-003,Discovery,T1033,System Owner/User Discovery
NW-004,Execution,T1059.001,PowerShell
NW-005,Execution,T1204.002,Malicious File
NW-006,Initial Access,T1566.001,Spearphishing Attachment
NW-007,Command and Control,T1105,Ingress Tool Transfer
NW-008,Initial Access,T1190,Exploit Public-Facing Application
NW-009,Command and Control,T1071,Application Layer Protocol
NW-010,Command and Control,T1568.002,Domain Generation Algorithms
NW-011,Reconnaissance,T1595,Active Scanning
NW-012,Reconnaissance,T1595.001,Scanning IP Blocks
NW-013,Persistence,T1098.007,Additional Local or Domain Groups
NW-014,Persistence,T1136.001,Create Account: Local Account
NW-015,Persistence,T1543.003,Create or Modify System Process: Windows Service
NW-016,Persistence,T1053.005,Scheduled Task/Job: Scheduled Task
NW-017,Defense Impairment,T1685.005,Disable or Modify Tools: Clear Windows Event Logs
NW-018,Defense Impairment,T1685.005,Disable or Modify Tools: Clear Windows Event Logs
```

**Alerts per rule**, `index=northwind_alerts earliest=-30d | stats count BY
rule_id` (**16** rule IDs, **106** alerts):

```
rule_id  count
NW-001       6
NW-003       9
NW-004      31
NW-005       4
NW-006       7
NW-007       5
NW-008      14
NW-009       3
NW-010       3
NW-013       5
NW-014       2
NW-015       2
NW-016       8
NW-017       4
NW-018       1
NW-019       2
```

Context: after Day 20, `noah.kim` added **NW-019**, "rundll32 loading a
file from a user Temp folder", to close the gap in Day 20's point 8. It
went live on 29 October and has fired twice.

---

## What to look for

1. **Three rules never fired.** **18** rules are in the lookup but only
   **15** of them appear in the counts. **NW-002** (password spraying),
   **NW-011** and **NW-012** (port scans) have **0** alerts in 30 days.
2. **Not all silence is equal.** A month without a password spray is
   believable. A month without a single port scan against an
   internet-facing firewall is **not**: the internet scans everyone, all the
   time (Day 13). NW-011 and NW-012's silence is the first thing to
   investigate.
3. **One rule fires but has no tactic.** NW-019 has **2** alerts but no row
   in the lookup, so Day 10's "3 tactics in 1 hour" meta-detection can't
   count it. Had it existed on 28 October, Grace's chain would still have
   reached 4 tactics, but a smaller chain could slip under the threshold.
4. **The noisy end.** NW-004 alone is **31** of the **106** alerts (about
   29%). Most are Tom's weekly CHG-2230 script (Day 20), a **benign
   positive**: it needs an allow-list for that host and schedule, not a
   weaker rule. NW-008's **14** need Day 17's precision check.
5. **Coverage has holes.** The lookup covers **8** tactics. There's no rule
   yet for **Lateral Movement**: Day 01's exercise 4 (a type 3 logon on a
   second server) would raise nothing. That's a good place to start next.

---

## Detection logic

**In plain English:** compare the rules you **think** you have (the lookup)
with the rules that **actually fired** (the alert index). Flag every rule
with **0** alerts in 30 days as *silent*, and every rule that fired but has
no lookup row as *unmapped*. This is a health check on the detections, not
on the network.

**SPL (Splunk, `northwind_alerts` index plus the lookup):**

```spl
| inputlookup northwind_attack_map.csv
| eval alerts=0
| append
    [ search index=northwind_alerts earliest=-30d
      | stats count AS alerts, max(_time) AS last_fired BY rule_id ]
| stats sum(alerts) AS alerts, max(last_fired) AS last_fired,
        values(tactic) AS tactic BY rule_id
| eval status=case(isnull(tactic), "unmapped",
                   alerts=0, "silent",
                   true(), "ok")
| where status!="ok"
| eval last_fired=strftime(last_fired, "%Y-%m-%d %H:%M")
| table rule_id, status, tactic, alerts, last_fired
```

On the sample it returns **4** rows:

```
rule_id  status    tactic             alerts  last_fired
NW-002   silent    Credential Access  0
NW-011   silent    Reconnaissance     0
NW-012   silent    Reconnaissance     0
NW-019   unmapped                     2       2026-10-30 …
```

How it works:

- `| inputlookup` starts the search from the CSV itself, so every rule in
  the lookup becomes a row, **including** rules with no alerts. A normal
  `lookup` (Day 10) can only enrich alerts that exist, so it can never show
  a rule that didn't fire.
- `eval alerts=0` gives each lookup row a count of zero; `append` adds the
  real counts from the alert index underneath.
- The second `stats ... BY rule_id` merges the two: `sum(alerts)` is 0 for
  silent rules and the real count for the rest. `values(tactic)` is only
  filled in from the lookup rows, so a rule that exists **only** in the
  alerts (NW-019) ends up with no tactic.
- `case()` checks the conditions in order and `true()` is the catch-all
  "otherwise" (Day 17). `strftime` turns the epoch time back into a
  readable date; silent rules have no `last_fired`, so it stays empty.

**Tuning note:** run this **weekly**, not every few minutes; it is a
report for the detection owner, not a page for the on-call analyst. Thirty
days suits most rules, but rare-event rules (Day 16's NW-018, say) may go
quiet for months legitimately, so give them a longer window or a
documented "expected rare" note instead of a pass. For each silent rule,
check the **data source first**: NW-011 and NW-012 run in Sentinel on
`CommonSecurityLog` (Day 13), so
`CommonSecurityLog | where TimeGenerated > ago(1d) | summarize count() by DeviceVendor`
quickly shows whether firewall logs are still arriving. If the data is
there, replay a known-bad sample (Day 13's sample logs) or run a safe test
in a lab and confirm the alert appears. Unmapped rules are fixed by adding
the lookup row, ideally as part of the same change that adds the rule.

---

## What to study next

| Next step | Why | Builds on |
|---|---|---|
| **Lateral movement** (4624 type 3, 4648 explicit credentials, 4769 Kerberos service tickets) | Biggest gap in Northwind's coverage | Days 01, 10 |
| **Cloud and identity logs** (Entra ID sign-in and audit logs, AWS CloudTrail) | Many incidents now start with a stolen cloud login, not a laptop | Days 03, 08 |
| **Detection as code** (Sigma rules in Git, converted with `sigma-cli`) | Version control, review and testing for every rule | Days 04, 10 |
| **Testing detections** (safe, documented tests in a lab, such as Atomic Red Team) | Turns "silent" into "proven working" | Today |
| **Coverage mapping** (ATT&CK Navigator layers) | See all tactics and techniques at a glance, and the empty ones | Day 10 |
| **Scenario 02** in this repo, when it's published | Practise the full loop again on a new case | Day 20 |

---

## Your turn

1. **Silent rules.** For NW-002, NW-011 and NW-012, write the **first
   check** you'd do for each and what result would tell you the rule is
   broken rather than just quiet. Which one would you check first, and why?
2. **Fix the gap.** Write the lookup row for NW-019, choosing the tactic
   and the most specific ATT&CK technique you can defend (hint: Day 20's
   further reading). Then explain how a missing row could have hidden a
   smaller version of Grace's chain from Day 10's meta-detection.
3. **Look back.** Pick the **three** days from the table that changed how
   you read logs the most. For each, write one sentence on what you do
   differently now.
4. **Plan ahead.** Using "What to study next", write a four-week plan for
   November: one topic a week, the data source you'd practise on, and the
   rule you'd aim to write at the end of each week.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Splunk Docs: [inputlookup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Inputlookup) · [append](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Append) · [stats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats)
- MITRE ATT&CK: [Enterprise tactics](https://attack.mitre.org/tactics/enterprise/) · [TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008/) · [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- SigmaHQ: [Sigma rules repository](https://github.com/SigmaHQ/sigma) · [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
- Red Canary: [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (run only in a lab you own)
- Microsoft Learn: [Microsoft Security Operations Analyst (SC-200) learning paths](https://learn.microsoft.com/en-us/credentials/certifications/security-operations-analyst/)
- NIST: [SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) · [Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)

⬅️ [Learning log index](README.md)
