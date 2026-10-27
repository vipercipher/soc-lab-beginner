# Day 18 — The Incident Response Lifecycle (NIST SP 800-61)

📅 28 October 2026 · 🏷️ Incident response · ⏱️ ~25 min

---

## Why it matters

Day 17 ended with a decision: the seven `FS01` alerts are **one incident**,
priority **P1**. Today is what happens next. Scenario 01's solution gave a
short version (*Identify → Contain → Eradicate → Recover*); this entry gives
the version most SOCs, auditors and job interviews use, from NIST's
**SP 800-61**. A shared lifecycle means everyone knows which stage an
incident is in, what "done" looks like for that stage, and who does what.
It also stops the two classic mistakes: cleaning up before you know the full
scope, and declaring victory before checking the attacker has really gone.

---

## The concept

### The classic four phases (SP 800-61 Rev. 2, 2012)

For over a decade the standard picture was a four-phase cycle:

| Phase | Goal | Northwind example (`FS01`, 10 Oct) |
|---|---|---|
| **1. Preparation** | Be ready *before* anything happens: logging, rules, playbooks, contacts, tools | Days 01–16's rules, Sysmon, log forwarding, the asset list from Day 17 |
| **2. Detection & Analysis** | Notice it, confirm it's real, work out scope and priority | Triage the queue, confirm the RDP brute force → `support_svc` chain |
| **3. Containment, Eradication & Recovery** | Stop the spread, remove the attacker's footholds, restore normal service | Isolate `FS01`, delete the task, service and account, reconnect |
| **4. Post-Incident Activity** | Learn: what happened, what worked, what to fix | Lessons-learned meeting, new rules, updated playbook |

Phase 3 is really three steps, and the **order matters**:

| Step | Question | Typical actions |
|---|---|---|
| **Containment** | *How do I stop it getting worse, right now?* | Isolate the host, block the IP, disable the account, revoke sessions |
| **Eradication** | *What did the attacker leave behind?* | Remove persistence (Day 14's accounts, Day 15's tasks and services), malware, stolen credentials |
| **Recovery** | *How do I safely return to normal?* | Reconnect, restore from a clean backup, **watch closely** for a return |

> 💡 **The analyst's shortcut:** it's a **cycle**, not a straight line. Rev. 2
> draws an arrow from *Containment, Eradication & Recovery* back to
> *Detection & Analysis*. Any new evidence during clean-up (a second host, a
> new account) sends you back to analysis to re-scope before you carry on.

### The current model (SP 800-61 Rev. 3, April 2025)

NIST replaced Rev. 2 with **Rev. 3** in April 2025. Rev. 3 doesn't throw the
phases away; it maps them onto the six **Functions** of the NIST
Cybersecurity Framework (CSF) 2.0, because incidents are now frequent and
response is continuous rather than a separate, occasional job:

| Rev. 2 phase | CSF 2.0 Functions (Rev. 3, Table 1) |
|---|---|
| Preparation | **Govern**, **Identify** (all categories), **Protect** |
| Detection & Analysis | **Detect**, Identify (Improvement) |
| Containment, Eradication & Recovery | **Respond**, **Recover**, Identify (Improvement) |
| Post-Incident Activity | Identify (Improvement) |

Rev. 3 splits the picture into two layers: **preparation** (Govern,
Identify, Protect, which run all the time) and **incident response**
(Detect, Respond, Recover), with **lessons learned** feeding improvements
back in at every stage, not only at the end.

> ⚠️ **Word trap:** Scenario 01 used *Identify* to mean "confirm it's a real
> attack". In NIST CSF, **Identify** means understanding your assets and
> risks (and, through its Improvement category, learning lessons). Confirming
> an attack belongs to **Detect** (Rev. 2: *Detection & Analysis*). Know both
> vocabularies; interviewers use both.

### Measuring the lifecycle

Each handover between phases is a timestamp, and the gaps are the SOC's
health check:

| Measure | From → to | Why it matters |
|---|---|---|
| **Time to acknowledge** | First alert → analyst picks it up | Is anyone watching the queue? |
| **Time to contain** | First alert → first containment action | How long the attacker had a free hand |
| **Business downtime** | Containment → recovery | What the response cost the business |
| **Time to re-detect** | Attacker returns → someone notices | Did recovery include monitoring? |

---

## Sample logs

**The case log for `INC-0107`** (12 entries, UTC), as the night analyst
`ana.silva`, the on-call IR lead `raj.mehta` and the day analyst `noah.kim`
recorded it. The phase column uses Rev. 2 names, with phase 3 split into its
three steps.

```
time (UTC)           phase                   by         entry
2026-10-10 02:24:10  Detection & Analysis    ana.silva  Opened INC-0107 from alerts A-1001 to A-1007 on FS01; priority P1
2026-10-10 02:31:45  Detection & Analysis    ana.silva  Confirmed: RDP brute force, administrator logon from 198.51.100.87, backdoor account support_svc
2026-10-10 02:33:20  Containment             ana.silva  Isolated FS01 from the network (EDR host isolation)
2026-10-10 02:34:02  Containment             ana.silva  Blocked 198.51.100.87 at the perimeter firewall
2026-10-10 02:36:30  Containment             ana.silva  Disabled support_svc; reset the local administrator password
2026-10-10 02:40:12  Containment             ana.silva  Paged on-call IR lead raj.mehta; emailed the IT manager
2026-10-10 08:15:04  Eradication             raj.mehta  Removed task \Microsoft\Windows\UpdateCheck and service NwHelperSvc
2026-10-10 08:22:30  Eradication             raj.mehta  Deleted C:\Users\Public\sync.ps1, C:\Users\Public\nwhelper.exe and account support_svc
2026-10-10 10:40:05  Recovery                raj.mehta  Reconnected FS01; finance shares compared with the 9 Oct backup, no changes found
2026-10-10 13:49:30  Detection & Analysis    noah.kim   Re-entry watch fired: 2 failed logons as support_svc on FS01 from 192.0.2.52; incident reopened
2026-10-10 13:58:10  Containment             noah.kim   Isolated 192.0.2.52 (WS-OPS04); scope widened to all hosts
2026-10-14 03:00:00  Post-Incident Activity  raj.mehta  Lessons-learned meeting (14:00 Sydney time); actions logged as INC-0107-A1 to A4
```

**Security events after containment** (Day 01's format, `SecurityEvent`
column names). `192.0.2.10` is IT's admin jump host; `FS01` was offline
from 02:33 until 10:40.

```
TimeGenerated (UTC)  Computer  EventID  TargetUserName  LogonType  IpAddress   SubStatus
2026-10-10 10:41:55  FS01      4624     raj.mehta       10         192.0.2.10  -
2026-10-10 10:58:20  FS01      4624     svc_backup      4          -           -
2026-10-10 13:47:12  FS01      4625     support_svc     3          192.0.2.52  0xC0000064
2026-10-10 13:47:15  FS01      4625     support_svc     3          192.0.2.52  0xC0000064
2026-10-10 13:47:18  FS01      4625     administrator   3          192.0.2.52  0xC000006A
2026-10-10 13:52:40  WS-DEV01  4624     liam.chen       2          -           -
```

---

## What to look for

1. **Phases in the right order.** Of the **12** entries, **3** are Detection
   & Analysis, **5** Containment, **2** Eradication, **1** Recovery and **1**
   Post-Incident. `ana.silva` confirmed the chain (02:31:45) *before*
   isolating, and contained *before* deleting anything: eradicating first
   would have tipped off an attacker who still had a live RDP session.
2. **The clock.** Time to acknowledge: 02:11:17 (A-1001) → 02:24:10 =
   **12 min 53 s**. Time to contain: 02:11:17 → 02:33:20 = **22 min 3 s**.
   The attacker's RDP session (02:11:19) had **22 min 1 s** before `FS01`
   was cut off. Business downtime for the finance shares: 02:33:20 → 10:40:05
   = **8 h 6 min 45 s**.
3. **The gap is fine.** Nothing happened between 02:40 and 08:15. That's
   normal: once contained, eradication can wait for the IR lead and daylight.
   Containment buys you time; spend it on doing eradication *properly*.
4. **The attacker came back.** At 13:47 someone on `192.0.2.52`, an
   **internal** address, tried `support_svc` twice. SubStatus `0xC0000064`
   (Day 01) says the account no longer exists, because eradication worked;
   but the attacker clearly had a **second foothold** that Detection &
   Analysis never found. That's the arrow back from phase 3 to phase 2.
5. **The third attempt.** At 13:47:18 the same host tried `administrator`
   with a wrong password (`0xC000006A`): the old password was reset at
   02:36:30, so it failed. The re-entry watch below **missed this row**,
   because `administrator` wasn't on its list. `noah.kim` found it by
   looking around the alert, as in Day 17's triage routine.
6. **Time to re-detect.** First attempt 13:47:12 → watch noticed 13:49:30
   (**2 min 18 s**) → second host isolated 13:58:10 (**10 min 58 s** after
   the first attempt). Without a recovery watch, a failed logon by a
   non-existent account would never have raised an alert.
7. **The normal rows.** `raj.mehta` RDP from the jump host just after
   reconnecting (checking the recovery), `svc_backup` as a type 4 batch job
   (Day 01), and `liam.chen` at his own desk. None touch the incident.

---

## Detection logic

**In plain English:** Recovery isn't finished when the server is back
online. Run a short-lived **re-entry watch**: from the moment of
containment, alert on any logon attempt (success or failure) that uses an
account or source IP from the incident. Any hit means the attacker is still
around, and the incident goes back to Detection & Analysis.

**KQL (Microsoft Sentinel, `SecurityEvent` table):**

```kql
// INC-0107 re-entry watch: run every 5 min, delete after 30 days
let containedAt = datetime(2026-10-10 02:36:30);
let incidentAccounts = dynamic(["support_svc"]);
let incidentIPs = dynamic(["198.51.100.87"]);
SecurityEvent
| where TimeGenerated > containedAt
| where EventID in (4624, 4625)
| where TargetUserName in~ (incidentAccounts) or IpAddress in (incidentIPs)
| project TimeGenerated, Computer, EventID, TargetUserName, LogonType,
          IpAddress, SubStatus
| order by TimeGenerated asc
```

On the sample it returns **2** rows: the two `support_svc` failures from
`192.0.2.52` at 13:47:12 and 13:47:15. The jump host, backup and
`liam.chen` logons don't match, and `198.51.100.87` never appears again
because the firewall block held.

How it works:

- `containedAt` anchors the watch to the incident's own timeline, so the
  attacker's original logons from before containment don't re-fire.
- `in~` is the **case-insensitive** version of `in`. Windows account names
  aren't case-sensitive, so `Support_Svc` must match too.
- `EventID in (4624, 4625)` includes **failures** on purpose. After
  eradication the account doesn't exist, so a returning attacker can only
  ever produce a 4625 (`0xC0000064`), and that failure is the signal.

**Tuning note:** this watch is built from **IOCs** (an account name and an
IP), the bottom of Day 09's Pyramid of Pain, so it's cheap but narrow: it
missed the `administrator` attempt. Add **every** account the attacker
touched (`administrator` too, plus the new host `192.0.2.52`) as the case
grows; in Sentinel, keep the list in a **watchlist** (`_GetWatchlist()`)
so analysts update it without editing the rule. Give the watch an
**expiry** (30 days is common) so old incident rules don't pile up, and
don't let it replace the behaviour rules NW-013 to NW-018: an attacker with
a fresh account and IP would pass this watch but not those. Expect it to be
quiet: any hit is worth a look, so it can run at **high** severity with no
allow-list.

---

## Your turn

1. Put each of these actions into its Rev. 2 phase (or step of phase 3)
   **and** its CSF 2.0 Function: (a) writing the RDP brute-force rule on
   Day 01; (b) blocking `198.51.100.87`; (c) deleting `NwHelperSvc`;
   (d) comparing the finance shares with the backup; (e) adding a rule for
   logons by deleted accounts after the meeting on 14 Oct.
2. Imagine `ana.silva` had deleted the task, service and account at 02:25,
   **before** isolating `FS01`. What could the attacker, still connected
   over RDP, have done in response, and what evidence might have been
   lost?
3. Scenario 01's solution lists *Identify → Contain → Eradicate → Recover*
   for `daniel.cole`. Map each of its actions (block sign-in, revoke
   sessions, reset password, check MFA methods and mailbox rules, help
   Daniel back in) to a Rev. 2 phase. Which Rev. 2 phase is missing from
   that list, and what would you do in it?
4. Using the case log and the post-containment events, write **three**
   lessons-learned actions (INC-0107-A1 to A3) for the 14 Oct meeting:
   one for Preparation, one for Detection & Analysis, one for Recovery.
   Each should say what changes and how you'd know it worked.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- NIST: [SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final) · [Incident Response project page](https://csrc.nist.gov/projects/incident-response) · [SP 800-61 Rev. 2 (withdrawn, for the four-phase model)](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- NIST: [Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- Microsoft Learn: [SecurityEvent table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) · [The `in` and `in~` operators (KQL)](https://learn.microsoft.com/en-us/kusto/query/in-operator) · [Watchlists in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/watchlists)
- MITRE ATT&CK: [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) · [T1078.003 Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)

⬅️ [Learning log index](README.md) · ➡️ Day 19: Writing a clear incident ticket (29 Oct)
