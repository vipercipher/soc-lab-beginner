# Day 17 — Alert Triage: True/False Positives and Severity

📅 27 October 2026 · 🏷️ Incident response · ⏱️ ~25 min

---

## Why it matters

Days 01 to 16 built **18 rules** (NW-001 to NW-018). Every one of them
fires on something harmless sooner or later: a training laptop being reset,
a developer fixing their own machine, a shopper typing an odd search. A SOC
analyst's day is mostly **triage**: looking at each alert, deciding
*is this real?* and *how bad is it?*, and choosing what to work on first.
Scenario 01 was one alert (`SIG-4471`). Today is a whole queue, the night of
**10 October**, when the attack on `FS01` from Days 01 and 14–16 happened
alongside ordinary work. Get triage wrong in one direction and you miss the
attack; get it wrong in the other and you burn hours chasing noise until
you stop trusting your own rules.

---

## The concept

### Four outcomes

A rule makes a decision (*alert* or *no alert*); reality makes another
(*malicious* or *not*). That gives four combinations:

| | **Really malicious** | **Not malicious** |
|---|---|---|
| **Rule fired** | ✅ **True positive (TP)**: a real attack, caught | ⚠️ **False positive (FP)**: alert, but no attack |
| **Rule stayed quiet** | ❌ **False negative (FN)**: a real attack, missed | ✅ **True negative (TN)**: nothing happened, nothing fired |

You only ever see the top row in your queue. False negatives are invisible
until something else (a user, another rule, a hunt) finds them. That's why
Day 10's coverage gaps matter as much as the alerts you have.

### The fifth answer: "benign positive"

Real SOCs split false positives in two, because they need **different
fixes**. Microsoft Sentinel's close-incident options are a good model:

| Sentinel classification | Plain meaning | Northwind example | Fix |
|---|---|---|---|
| **True Positive – suspicious activity** | The rule saw what it was built for, and it's malicious | `support_svc` clearing logs on `FS01` (Day 16) | Respond |
| **Benign Positive – suspicious but expected** | The rule saw exactly what it was built for, but it was **authorised** | Tom clearing `WS-TRAIN02`'s log under CHG-2221 | Allow-list **narrowly**, or lower severity for that context |
| **False Positive – incorrect alert logic** | The rule matched something it **wasn't** meant to | A search box query that looks like SQL | Fix the **rule** |
| **False Positive – incorrect data** | The data fed to the rule was wrong | A parsing bug puts the wrong username in a field | Fix the **pipeline** |
| **Undetermined** | Not enough evidence either way | Logs missing, user unreachable | Record what's missing; don't guess |

> 💡 **The analyst's shortcut:** before you call something a false positive,
> ask *"did the rule describe this event correctly?"* If yes, it's a benign
> positive and the rule is working. Weakening the rule to silence it would
> also blind it to the attacker doing the same thing.

### Severity vs priority

**Severity** is a label a rule gives its alert (Sigma's `level`:
`informational`, `low`, `medium`, `high`, `critical`; Sentinel uses
Informational, Low, Medium, High). It's set **before** anyone has seen the
event, so it's a guess. **Priority** is what *you* decide after looking:
what to work on first. The common way to think about it is
**impact × likelihood**:

| Factor | Question | Raises priority when… |
|---|---|---|
| **Asset** | How important is the host? | Server, domain controller, internet-facing |
| **Account** | How powerful is the account? | Admin, service account, newly created |
| **Stage** | Where in ATT&CK (Day 10)? | Persistence, Defense Impairment, Exfiltration: the attacker is already in |
| **Corroboration** | Do other alerts agree? | Several rules, same host or user, short time |
| **Context** | Is there an innocent explanation? | No change ticket, odd hour, owner surprised |

Scenario 01's `SIG-4471` arrived as **Medium**. After triage (failures, then
a success from a new country, then MFA prompts denied twice and approved on
the third) it was a confirmed account takeover. Triage is allowed to
**raise** severity, and should.

### A simple triage routine

1. **Read the alert**: rule, host, user, time. What exactly did it match?
2. **Check context**: what is this host and account? Any change ticket?
3. **Look around**: other alerts and logs for the same host or user ±1 hour.
4. **Decide**: TP, benign positive, FP or undetermined, and set the priority.
5. **Write it down**: one or two lines of *why*, so the next analyst (and
   your rule tuning) can learn from it. That's Day 19's topic.

---

## Sample logs

Every alert in `northwind_alerts` for **10 October** (UTC), from the rules
built on earlier days, plus Northwind's asset lookup. The alert on `web01`
has no user, shown as `-` (the field is empty).

**Alert queue (11 alerts):**

```
_time (UTC)          alert_id  rule_id  rule_name                                    severity  host        user
2026-10-10 02:11:17  A-1001    NW-001   RDP brute force from one source IP           medium    FS01        administrator
2026-10-10 02:13:31  A-1002    NW-013   Account added to local Administrators        medium    FS01        administrator
2026-10-10 02:13:31  A-1003    NW-014   New account added to Administrators in 1h    high      FS01        administrator
2026-10-10 02:17:02  A-1004    NW-016   Scheduled task in user-writable path         medium    FS01        support_svc
2026-10-10 02:18:40  A-1005    NW-015   Service installed from user-writable path    high      FS01        support_svc
2026-10-10 02:21:05  A-1006    NW-017   Security audit log cleared                   high      FS01        support_svc
2026-10-10 02:21:09  A-1007    NW-018   Several logs cleared by one account in 5m    high      FS01        support_svc
2026-10-10 04:52:36  A-1008    NW-008   SQL injection pattern in web request         medium    web01       -
2026-10-10 06:30:12  A-1009    NW-017   Security audit log cleared                   high      WS-TRAIN02  tom.reyes
2026-10-10 22:31:09  A-1010    NW-013   Account added to local Administrators        medium    WS-DEV01    tom.reyes
2026-10-10 23:40:27  A-1011    NW-016   Scheduled task in user-writable path         medium    WS-DEV01    liam.chen
```

**Asset lookup, `northwind_assets.csv`:**

```
host,role,criticality
FS01,File server (finance shares),high
web01,Public web shop,high
WS-DEV01,Developer workstation,medium
WS-TRAIN02,Training laptop,low
```

**The request behind A-1008** (Nginx access log on `web01`, Day 11 format):

```
203.0.113.140 - - [10/Oct/2026:04:52:36 +0000] "GET /search?q=order%20by%20phone%20delivery HTTP/1.1" 200 2964 "https://www.northwind-example.com/" "Mozilla/5.0 (...) Version/18.0 Safari/605.1.15"
```

Context you already have: **CHG-2217** approves Liam Chen's local admin
rights on `WS-DEV01` (Day 14); Liam maintains his own build tools,
including the `\Northwind\DevBuildCleanup` task (Day 15); **CHG-2221**
covers Tom Reyes resetting training laptops, including clearing the
Security log (Day 16).

---

## What to look for

1. **One host, seven rules, ten minutes.** `FS01` has **7** alerts from **7**
   different rules between 02:11:17 and 02:21:09 (9 minutes 52 seconds):
   Credential Access → Persistence → Defense Impairment. Individually,
   **3** of those alerts are only `medium`. Together they are one incident,
   and the most urgent thing in the queue.
2. **Sorting by severity misleads.** **5** alerts are `high` and **6** are
   `medium`. Sort by severity alone and `WS-TRAIN02`'s log clear sits beside
   the `FS01` ones, while the brute force that **started** the attack
   (A-1001) drops into the medium pile.
3. **Three benign positives.** A-1009 (`WS-TRAIN02`, CHG-2221), A-1010
   (`WS-DEV01`, CHG-2217) and A-1011 (Liam's own cleanup task). Each rule
   did exactly what it was written to do; the activity was authorised.
   Close them with the ticket number as the reason, not "FP".
4. **One true false positive.** A-1008 matched NW-008 because the query
   contains `order%20by%20`, one of Day 11's patterns. Decoded, it's a
   shopper searching for *order by phone delivery*: one request, a normal
   browser, no quotes, no `union`, no follow-up probing. The rule's
   **logic** was too broad; nothing was attacked.
5. **The asset changes the answer.** The same rule (NW-017) fired on `FS01`
   and on `WS-TRAIN02`. On a low-criticality training laptop with a matching
   ticket it's routine; on a high-criticality file server, two minutes after
   a new service, it's an attacker covering their tracks.
6. **Totals.** **11** alerts on **4** hosts: **7** true positives (all
   `FS01`), **3** benign positives and **1** false positive. Only 7 of 11
   (about 64%) needed a response, and they all belong to **one** incident.

---

## Detection logic

**In plain English:** don't write another detection; write a **triage
helper**. Enrich every alert with the host's criticality, score each alert
as *severity × criticality*, then roll alerts up **by host** so that one
incident shows up as one row. Any host with **3 or more different rules**
firing, or a top score of **9** (high severity on a high-criticality host),
becomes **P1**.

**SPL (Splunk, `northwind_alerts` index plus `northwind_assets.csv`):**

```spl
index=northwind_alerts earliest=-24h
| lookup northwind_assets.csv host OUTPUT role criticality
| fillnull value="unknown" role criticality
| eval sev_score=case(severity="high",3, severity="medium",2, severity="low",1, true(),0)
| eval crit_score=case(criticality="high",3, criticality="medium",2, criticality="low",1, true(),2)
| eval score=sev_score*crit_score
| stats count AS alerts, dc(rule_id) AS rules, max(score) AS top_score,
        values(user) AS users, min(_time) AS first_seen, max(_time) AS last_seen
        BY host role criticality
| eval priority=case(rules>=3 OR top_score>=9, "P1", top_score>=6, "P2",
                     top_score>=3, "P3", true(), "P4")
| sort priority -alerts
| convert ctime(first_seen) ctime(last_seen)
```

On the sample it returns **4** rows:

```
host        criticality  alerts  rules  top_score  priority
FS01        high         7       7      9          P1
web01       high         1       1      6          P2
WS-DEV01    medium       2       2      4          P3
WS-TRAIN02  low          1       1      3          P3
```

`FS01` is P1 twice over (7 rules ≥ 3, and high × high = 9). `web01` is P2
(medium × high = 6). `WS-DEV01` scores medium × medium = 4 and
`WS-TRAIN02` high × low = 3, so both are P3, with `WS-DEV01` first because it
has more alerts.

How it works:

- `lookup ... host OUTPUT role criticality` adds the asset columns.
  `fillnull` labels hosts missing from the CSV as `unknown`; without it,
  `stats ... BY role criticality` would **silently drop** their alerts, and
  an unknown host is exactly the one you want to see.
- `case()` turns words into numbers. Unknown criticality gets **2**
  (medium), so a missing asset entry neither hides nor exaggerates an alert.
- `stats ... BY host` rolls the queue up into one row per host. `dc(rule_id)`
  counts **distinct** rules, so a single rule firing ten times doesn't count
  as broad corroboration (the same idea as Day 10's distinct tactics).
- `sort priority -alerts` sorts P1 → P4 as text, then by most alerts first.

**Tuning note:** a priority score tells you what to **look at first**, not
whether it's real: `web01` came out P2 and is a false positive. Close the
loop by recording a classification on every closed alert, then measure each
rule's **precision** (true positives ÷ all alerts) over 30 days:

```spl
index=northwind_alerts status=closed earliest=-30d
| stats count AS total, count(eval(classification="TruePositive")) AS tp BY rule_id
| eval precision=round(tp/total*100, 1)
| sort precision
```

On today's queue alone, NW-008 would sit at **0%** (0 of 1), and NW-013,
NW-016 and NW-017 at **50%** (1 of 2 each); one day is far too few to judge.
A low-precision rule whose misses are **false positives** needs its logic
fixed (NW-008: decode the URL and require two SQL patterns, or a quote plus
a keyword). A low-precision rule whose misses are **benign positives**
needs context (an allow-list of ticketed hosts, or a lower severity on lab
machines), not a weaker pattern. As with Day 10, `stats` over 24 hours
doesn't check that a host's rules fired **close together**; add
`(last_seen - first_seen) <= 3600` to the P1 test, or schedule the search
every 15 minutes over the last 75, and keep `northwind_assets.csv` current
or new servers fall into `unknown`.

---

## Your turn

1. Classify all **11** alerts as TP, benign positive, FP (logic or data) or
   undetermined. For each, write one line: the evidence you used and, for
   anything not a TP, the ticket or fact that explains it.
2. A-1008 on `web01` was scored **P2** but is a false positive. What did the
   score not know? List the **two or three** checks that let you close it in
   under a minute, and rewrite Day 11's rule (or describe the change) so it
   would no longer fire on this request but would still catch
   `?id=12%20union%20select%20...`.
3. Go back to Scenario 01's `SIG-4471` (Medium). Using the five factors in
   the severity table, argue what priority it should have **after** triage,
   and name one extra fact that would push it even higher.
4. NW-017 scored 50% precision today because of `WS-TRAIN02`. A teammate
   suggests disabling it on all workstations. Using Day 16's tuning note,
   write a short reply: what would you do instead, and what attack would the
   teammate's change let through?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Navigate and triage incidents in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage) · [Investigate incidents with Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases)
- Splunk Docs: [lookup command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Lookup) · [Conditional functions (`case`)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) · [fillnull command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fillnull)
- SigmaHQ: [Sigma rules specification (`level` and `falsepositives`)](https://github.com/SigmaHQ/sigma-specification)
- MITRE ATT&CK: [Enterprise tactics](https://attack.mitre.org/tactics/enterprise/)
- NIST: [SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

⬅️ [Learning log index](README.md) · ➡️ [Day 18: The incident response lifecycle (NIST SP 800-61) (28 Oct)](2026-10-28-incident-response-lifecycle.md)
