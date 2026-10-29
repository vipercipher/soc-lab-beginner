# Day 19 — Writing a Clear Incident Ticket

📅 29 October 2026 · 🏷️ Incident response · ⏱️ ~25 min

---

## Why it matters

Day 17's triage routine ended with step 5, *write it down*, and Day 18's
case log for `INC-0107` showed what a well-kept record makes possible:
handovers between three people, timings for every phase, and a
lessons-learned meeting built on facts. None of that happens by itself. A
ticket is the only part of an investigation that outlives the analyst's
shift. The day analyst, the IR lead, the IT manager, an auditor six months
later and the person tuning tomorrow's rules all read it **without you in
the room**. A vague ticket means repeated work, wrong decisions and lost
lessons; a clear one means anyone can pick the case up in two minutes.

---

## The concept

### Who reads a ticket

| Reader | What they need from it | Northwind example |
|---|---|---|
| **The next analyst** | Where the case is, what's done, what's next | `noah.kim` taking over `INC-0107` at the morning handover |
| **The IR lead / manager** | How bad, what's affected, what decision is needed | `raj.mehta` deciding when to reconnect `FS01` |
| **Audit, legal, insurers** | What happened, when, who did what, with evidence | A review of the 10 Oct intrusion months later |
| **Rule tuning (Day 17)** | Why each alert was TP, benign positive or FP | Measuring NW-008's precision over 30 days |

### What goes in it

NIST SP 800-61 Rev. 2 (section 3.2.5) lists what an incident record should
hold: status, summary, indicators, related incidents, actions taken by
every handler, chain of custody, impact, contacts, evidence, comments and
next steps. Rev. 3 (Day 18) replaced Rev. 2 in 2025, but that list is still
the checklist most SOC ticket templates are built from. A practical
version:

| Field | Write… | Not… |
|---|---|---|
| **Title** | *What* on *which host/account*: `RDP brute force → backdoor account → logs cleared on FS01` | `FS01 alerts` |
| **Status & priority** | `Contained · P1 · owner raj.mehta` | Nothing, or "in progress" with no owner |
| **Summary** | 2–3 sentences, most important fact first (*bottom line up front*) | The story in the order you found it |
| **Scope** | Every host, account and IP involved, by exact name | "the server", "the admin account", "a weird IP" |
| **Timeline** | Date + time + **UTC**, one event per line | "around 2am" |
| **Actions taken** | Action, time, who: `02:33:20 UTC ana.silva isolated FS01 (EDR)` | "server is isolated" |
| **Evidence** | Alert IDs, log queries, file paths, hashes | "see SIEM" |
| **Impact** | What's known to be affected, and what's **not yet known** | Guesses dressed as facts |
| **Next steps** | Each with an owner and a deadline | "pls check" |

### Five writing rules

1. **Facts, assessments and unknowns are labelled.** *Confirmed* means you
   saw it in a log. *Assessed* or *likely* means it's your judgement, with
   the reason. *Unknown* means you looked and couldn't tell (Day 17's
   *Undetermined*). "Probably ransomware" with no evidence of encryption is
   a guess that sends the next reader the wrong way.
2. **Always UTC, always with a date.** Northwind's SIEM is in UTC; Sydney
   is UTC+11 in October (AEDT). "2am" could be 02:11 UTC or 2am Sydney
   (15:00 UTC the day before): eleven hours apart.
3. **Exact identifiers, copied, never retyped.** `support_svc`, not "the
   new user"; `198.51.100.87`, not "a weird IP". A reader should be able to
   paste each one straight into a search.
4. **Defang indicators** when the ticket may be emailed or pasted into
   chat: `198.51.100[.]87`, `hxxps://login.northwind-example[.]com`. That
   stops them becoming clickable links. Inside the SIEM, where you'll
   search for them, keep them exact.
5. **Never paste secrets.** No passwords, session tokens or personal data
   beyond what the case needs. Write "reset the local administrator
   password", not the new password.

> 💡 **The analyst's shortcut:** before you save, reread the ticket as if
> you've just walked in and know nothing. Can you answer *what happened,
> is it over, what has been done, and what do I do next?* If any of the
> four is missing, so is the ticket.

### Scenario 01's note, reviewed

Scenario 01's solution ended with a *tidy incident note* for `daniel.cole`.
It gets a lot right: a specific title, the alert ID (`SIG-4471`), UTC times,
the exact IP and location, and a status. Three things would stop a manager
signing it off: the action time is still a placeholder (`[time]`), "Checked
for attacker-added MFA methods and mailbox rules" doesn't say **what was
found**, and "Awaiting user re-enrolment" has **no owner** or deadline.

---

## Sample logs

**The first note on `INC-0107`**, written by the night analyst `ana.silva`
at 02:41 UTC on 10 October, just after the containment actions in Day 18's
case log:

```
INC-0107   Priority: P1   Status: Active   Owner: ana.silva
Title: FS01 alerts

FS01 got hacked around 2am. Lots of alerts (brute force, admin stuff, logs
cleared). Probably ransomware. Someone logged in as admin from a weird IP and
made a new user. I blocked the IP and turned off the account. Server is
isolated. Pls check in the morning.
```

**Northwind's incidents from the 10 October queue** (Sentinel
`SecurityIncident` table, latest version of each, as of 15 Oct 00:00 UTC;
`Owner` shows `Owner.assignedTo`, `Comments` shows
`AdditionalData.commentsCount`; `-` means empty):

```
IncidentNumber  CreatedTime (UTC)    Title                                            Severity  Status  Classification  ClassificationReason   Owner      Comments  ClassificationComment
107             2026-10-10 02:24:10  RDP brute force → backdoor → logs cleared, FS01  High      Closed  TruePositive    SuspiciousActivity     raj.mehta  12        Confirmed intrusion on FS01 via RDP from 198.51.100.87; backdoor support_svc removed; re-entry from 192.0.2.52 contained
108             2026-10-10 04:52:41  SQL injection pattern in web request             Medium    Closed  FalsePositive   IncorrectAlertLogic    ana.silva  0         -
109             2026-10-10 06:30:17  Security audit log cleared                       High      Closed  BenignPositive  SuspiciousButExpected  ana.silva  1         CHG-2221: tom.reyes reset training laptop WS-TRAIN02
110             2026-10-10 22:31:14  Account added to local Administrators            Medium    Closed  BenignPositive  SuspiciousButExpected  noah.kim   1         ok
111             2026-10-10 23:40:32  Scheduled task in user-writable path             Medium    New     -               -                      -          0         -
```

---

## What to look for

1. **The title says nothing.** `FS01 alerts` could be a full disk. The
   final title on incident 107 names the attack chain and the host; that's
   what a manager scanning a list of 50 incidents needs.
2. **"Around 2am" has no time zone.** The brute force started at 02:11:07
   UTC, which is 13:11 in Sydney. A day analyst in Sydney reading "2am"
   would search the wrong half of the day.
3. **No identifiers at all.** "A weird IP" is `198.51.100.87`, "admin" is
   `administrator`, "a new user" is `support_svc`. Without them, `noah.kim`
   has to redo `ana.silva`'s analysis before he can do anything.
4. **A guess stated as fact.** Nothing in the seven alerts shows encryption
   or ransom notes. "Probably ransomware" could push the morning team into
   restoring from backup before scoping, the mistake Day 18 warned about.
5. **Actions without times, and one ambiguous.** "Turned off the account":
   which one? The case log shows she **disabled `support_svc`** and **reset
   the `administrator` password**, two different actions on two accounts,
   at 02:36:30. Three containment steps are listed with **no** times, so
   Day 18's *time to contain* couldn't be measured from this note.
6. **Footholds missing.** The task `\Microsoft\Windows\UpdateCheck`
   (A-1004) and the service `NwHelperSvc` (A-1005) aren't mentioned at all,
   and the cleared logs (A-1006, A-1007) only as "logs cleared", with no
   host or account. The task and service are exactly what Eradication
   needs to remove.
7. **"Pls check in the morning"** names no person and no task. The case
   log shows she did page `raj.mehta` at 02:40:12; the ticket should say so.
8. **The incident queue.** Of the **5** incidents, **4** are closed and
   **1** is still `New`. Incidents **107** and **109** are good closes: a
   classification, a reason and a comment that would let anyone check the
   decision. **108** is closed with **0** comments and an empty
   `ClassificationComment`: the dropdown says *what* (incorrect alert
   logic) but not *why*, which is the part NW-008's tuning needs. **110**
   says only `ok`. **111** has had no owner for over four days.

---

## Detection logic

**In plain English:** this isn't a detection of an attacker; it's a
**ticket-quality check** for the SOC itself. Once a day, look at every
incident from the last 14 days and flag three problems: **closed** with no
real explanation (a classification comment under 20 characters), **open**
with **no owner**, or **open for 4 hours or more with no comments**.

**KQL (Microsoft Sentinel, `SecurityIncident` table):**

```kql
// Ticket-quality check: run daily, send results to the SOC lead
SecurityIncident
| where CreatedTime > ago(14d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend OwnerName = tostring(Owner.assignedTo),
         CommentCount = toint(AdditionalData.commentsCount)
| extend Problem = case(
    Status == "Closed" and strlen(ClassificationComment) < 20, "Closed without a clear reason",
    Status != "Closed" and isempty(OwnerName), "Open with no owner",
    Status != "Closed" and CommentCount == 0 and CreatedTime < ago(4h), "Open 4h+ with no notes",
    "")
| where isnotempty(Problem)
| project IncidentNumber, Title, Severity, Status, Classification, OwnerName,
          CommentCount, Problem
| order by IncidentNumber asc
```

Run on 15 Oct over the sample, it returns **3** rows:

```
IncidentNumber  Status  Classification  OwnerName  CommentCount  Problem
108             Closed  FalsePositive   ana.silva  0             Closed without a clear reason
110             Closed  BenignPositive  noah.kim   1             Closed without a clear reason
111             New                                0             Open with no owner
```

Incident 108's comment is empty (length 0) and 110's is `ok` (length 2).
107 and 109 have full comments, so they pass. 111 matches both open-incident
problems; `case()` reports only the first one that's true.

How it works:

- `SecurityIncident` gets a **new row every time an incident changes**
  (status, owner, comment). `summarize arg_max(TimeGenerated, *) by
  IncidentNumber` keeps only the latest row of each, the same pattern
  Microsoft's own incident-metrics queries use. Without it, incident 107
  alone could appear a dozen times.
- `Owner` and `AdditionalData` are **dynamic** (JSON) columns. `.assignedTo`
  and `.commentsCount` pull one field out; `tostring()` and `toint()` give
  them a type that `isempty()` and `==` can work with.
- `Status` in Sentinel is `New`, `Active` or `Closed`, so `!= "Closed"`
  covers both open states.
- `case()` checks its conditions in order and returns the first match;
  the final `""` is the "no problem" answer that `isnotempty()` then
  filters out.

**Tuning note:** this measures whether tickets are **filled in**, not
whether they're **good**: `Closed via ticket review, see notes` passes the
20-character test and explains nothing. Use the check to catch the empty
ones, and pair it with a weekly **peer review** of a few closed tickets
(could you rebuild the decision from the ticket alone?). Incidents closed
by **automation rules** (for example, auto-closing a known benign alert)
will trip the length test; give the rule a fixed comment that names it, or
exclude it by its `ModifiedBy` value. This is a **hygiene report**, not an
alert: send it to the SOC lead as a daily digest rather than into the
analyst queue, or it becomes yet another source of noise.

---

## Your turn

1. List every problem you can find in `ana.silva`'s note. For each, name
   the **reader** from the first table it would hurt most, and how.
2. Rewrite the `INC-0107` note as it should have looked at **02:41 UTC**,
   using the field table. Only use what was known **at that moment**
   (Day 17's seven alerts and the first six entries of Day 18's case log);
   the 13:47 re-entry hasn't happened yet. Label every statement in the
   impact section as confirmed, assessed or unknown.
3. Write the closing comments for incidents **108** and **110** that would
   pass the quality check **and** be useful to whoever tunes NW-008 and
   NW-013. Use Day 17's evidence (the decoded search, CHG-2217). One to
   three sentences each.
4. Label each statement as **confirmed**, **assessed** or **unknown**, and
   rewrite any that claim more than the evidence shows:
   (a) "The attacker logged on as `administrator` at 02:11:19 UTC from
   `198.51.100.87`." (b) "No data was taken from the finance shares."
   (c) "The attacker is a ransomware group." (d) "`support_svc` was
   created by the attacker."

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- NIST: [SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final) · [SP 800-61 Rev. 2 (withdrawn; section 3.2.5, Incident Documentation)](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- Microsoft Learn: [SecurityIncident table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident) · [Manage your SOC better with incident metrics](https://learn.microsoft.com/en-us/azure/sentinel/manage-soc-with-incident-metrics) · [Navigate and triage incidents in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage)
- Microsoft Learn: [Incidents REST API (`owner` and `additionalData` fields)](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/create-or-update) · [arg_max() (KQL)](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function) · [case() (KQL)](https://learn.microsoft.com/en-us/kusto/query/case-function)

⬅️ [Learning log index](README.md) · ➡️ [Day 20: Mini case: putting it all together (30 Oct)](2026-10-30-mini-case.md)
