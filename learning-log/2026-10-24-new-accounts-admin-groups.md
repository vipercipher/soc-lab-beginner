# Day 14 — Persistence: New Accounts and Admin Group Changes (4720, 4732)

📅 24 October 2026 · 🏷️ Log analysis · ⏱️ ~25 min

---

## Why it matters

On Day 01 an attacker guessed the `administrator` password on `FS01` and got
an RDP session at 02:11:19. The containment step in that day's answers was to
**reset the password**. But what if, in the minutes before you noticed, the
attacker made **a second account of their own** and gave it admin rights?
Resetting `administrator` wouldn't touch it, and they could walk straight back
in. That's **persistence**: keeping access after the first way in is closed.
Creating an account and adding it to an admin group is one of the oldest and
simplest ways to do it, and Windows writes both steps to the Security log.

---

## The concept

### The account-management event IDs

| Event ID | Meaning | Logged on |
|---|---|---|
| **4720** | A user account was created | The machine that holds the account (a DC for domain accounts, the server itself for local ones) |
| **4722** | A user account was enabled | Same |
| **4726** | A user account was deleted | Same |
| **4732** | A member was added to a security-enabled **local** group | The machine that holds the group |
| **4733** | A member was removed from a security-enabled local group | Same |
| **4728** | A member was added to a security-enabled **global** group | Domain controller |
| **4756** | A member was added to a security-enabled **universal** group | Domain controller |

Creating one account usually produces **several** events in the same second:
4720 (created), 4722 (enabled), and, for a local account, a **4732** that puts
it in the built-in **Users** group automatically. Don't mistake that automatic
4732 for the attacker's privilege step.

### Who, whom and which group

The fields you read on these events:

| Field | On 4720 | On 4732 / 4728 |
|---|---|---|
| `SubjectUserName` | Who **created** the account | Who **added** the member |
| `TargetUserName` | The **new account's** name | The **group's** name |
| `TargetSid` | The new account's SID | The group's SID |
| `MemberName` | (not used) | The added account's distinguished name, or `-` for a **local** account |
| `MemberSid` | (not used) | The added account's SID |

A **SID** (security identifier) is the account's real ID; names can be
renamed, SIDs can't. The built-in local groups have the same **well-known
SID** on every Windows machine:

| SID | Group |
|---|---|
| `S-1-5-32-544` | Administrators |
| `S-1-5-32-545` | Users |
| `S-1-5-32-555` | Remote Desktop Users |

Matching on `S-1-5-32-544` is safer than matching the name `Administrators`,
which is translated on non-English Windows. One more twist: on a **domain
controller**, `Administrators` is a domain-wide group, so a 4732 for
`S-1-5-32-544` there means admin rights over **every** DC. The famous
**Domain Admins** group is a *global* group, so changes to it show up as
**4728**, not 4732.

> 💡 These events only appear if **Audit User Account Management** and
> **Audit Security Group Management** are set to log *Success* in the audit
> policy. Check your servers rather than assuming the defaults.

### Where the logs come from

As on Day 01, the Security log reaches Microsoft Sentinel in the
**`SecurityEvent`** table, which has columns for all the fields above
(`SubjectUserName`, `TargetUserName`, `TargetSid`, `MemberName`,
`MemberSid`) plus `Computer` and `EventID`. A new host today is **`DC01`**,
Northwind's domain controller, where domain accounts live.

---

## Sample logs

Account-management events from `FS01`, `DC01` and `WS-DEV01` on **10 October**
(UTC). SIDs are shortened: `[FS01]` and `[NW]` stand for the long machine and
domain identifiers, so `S-1-5-21-[FS01]-1004` is local account 1004 on `FS01`.

```
TimeCreated (UTC)    Computer  EventID  SubjectUserName  TargetUserName  TargetSid             MemberName                                          MemberSid
2026-10-10 02:13:05  FS01      4720     administrator    support_svc     S-1-5-21-[FS01]-1004  -                                                   -
2026-10-10 02:13:05  FS01      4722     administrator    support_svc     S-1-5-21-[FS01]-1004  -                                                   -
2026-10-10 02:13:05  FS01      4732     administrator    Users           S-1-5-32-545          -                                                   S-1-5-21-[FS01]-1004
2026-10-10 02:13:31  FS01      4732     administrator    Administrators  S-1-5-32-544          -                                                   S-1-5-21-[FS01]-1004
2026-10-10 22:04:12  DC01      4720     tom.reyes        maya.patel      S-1-5-21-[NW]-1187    -                                                   -
2026-10-10 22:04:12  DC01      4722     tom.reyes        maya.patel      S-1-5-21-[NW]-1187    -                                                   -
2026-10-10 22:05:40  DC01      4728     tom.reyes        Finance-Staff   S-1-5-21-[NW]-1120    CN=Maya Patel,OU=Finance,DC=northwind-example,DC=com  S-1-5-21-[NW]-1187
2026-10-10 22:31:09  WS-DEV01  4732     tom.reyes        Administrators  S-1-5-32-544          CN=Liam Chen,OU=Staff,DC=northwind-example,DC=com     S-1-5-21-[NW]-1093
```

And two logon events from `FS01` (Day 01's format) around the same time:

```
TimeCreated (UTC)     EventID  Account          LogonType  IpAddress
2026-10-10 02:11:19   4624     administrator    10         198.51.100.87
2026-10-10 02:15:44   4624     support_svc      10         198.51.100.87
```

Context from the IT team: Maya Patel is a new starter in Finance, and change
ticket **CHG-2217** approves local admin rights for Liam Chen on his
developer machine `WS-DEV01` for one week.

---

## What to look for

1. **Two minutes after the break-in.** Day 01's attacker got in as
   `administrator` at 02:11:19. At **02:13:05**, that same account creates a
   new local account, `support_svc`, on `FS01`. A name that sounds like a
   service account is a classic way to blend in.
2. **The automatic rows.** The 4722 (enabled) and the 4732 into **Users**
   (`S-1-5-32-545`) at the same second are Windows doing its normal
   housekeeping for a new local account. They aren't the dangerous part.
3. **The privilege step.** **26 seconds** later, at 02:13:31, a 4732 adds the
   same SID, `S-1-5-21-[FS01]-1004`, to **Administrators** (`S-1-5-32-544`).
   `MemberName` is `-` because it's a local account, so the **SID** is the
   only way to tie this row back to the 4720.
4. **The backdoor is used.** At 02:15:44, `support_svc` logs on over RDP
   (type 10) from **`198.51.100.87`**, the same IP as Day 01's brute force.
   Even if `administrator`'s password is reset now, the attacker still has a
   working admin account. Containment has to include **disabling
   `support_svc`**, then checking every host for other accounts created by
   the attacker.
5. **The normal rows.** On `DC01`, `tom.reyes` from the helpdesk creates
   `maya.patel` in business hours (22:04 UTC is 09:04 in Sydney) and adds her
   to `Finance-Staff`, a global group (4728) that grants no admin rights. On
   `WS-DEV01`, Tom adds `liam.chen` to Administrators. That one *is* an admin
   grant, but it matches change ticket CHG-2217 and Liam's account isn't new.
6. **Totals.** **8** account-management rows: **2** account creations (4720),
   **2** enables (4722), **3** local group adds (4732), **1** global group
   add (4728). **2** of the 4732s are to Administrators: `FS01` (malicious)
   and `WS-DEV01` (approved).

---

## Detection logic

**In plain English:** two rules. **Rule A** flags *any* member added to a
local Administrators group (4732 with `TargetSid` `S-1-5-32-544`), because
admin grants should always be explainable. **Rule B** is the high-confidence
pattern: an account is **created (4720)** and the **same SID** is added to
Administrators **within 60 minutes**.

**Sigma, Rule A (single event):**

```yaml
title: Member Added to Local Administrators Group
id: bf7d9990-3b32-4697-93dc-010c608db943
status: experimental
description: >
  Detects an account being added to the built-in Administrators group
  (well-known SID S-1-5-32-544), on a member machine or a domain controller.
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732
  - https://attack.mitre.org/techniques/T1098/007/
author: Jay (SOC learning log)
date: 2026-10-24
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.007
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4732
    TargetSid: 'S-1-5-32-544'
  condition: selection
falsepositives:
  - Admin rights granted by IT under an approved change ticket
  - Build or provisioning scripts that add a support group to new machines
level: medium
```

On the sample it matches **2** rows: `FS01` at 02:13:31 and `WS-DEV01` at
22:31:09. The 4732 into **Users** has a different `TargetSid`, so it doesn't
match.

**KQL, Rule B (Microsoft Sentinel, `SecurityEvent` table):**

```kql
let window = 60m;
let newAccounts =
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4720
    | project CreatedTime = TimeGenerated, CreatedOn = Computer,
              NewAccount = TargetUserName, NewAccountSid = TargetSid,
              CreatedBy = SubjectUserName;
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4732 and TargetSid == "S-1-5-32-544"
| project AddedTime = TimeGenerated, AddedOn = Computer,
          MemberSid, AddedBy = SubjectUserName
| join kind=inner newAccounts on $left.MemberSid == $right.NewAccountSid
| where AddedTime between (CreatedTime .. (CreatedTime + window))
| project CreatedTime, AddedTime, CreatedOn, AddedOn, NewAccount,
          NewAccountSid, CreatedBy, AddedBy
```

On the sample it returns **1** row: `support_svc`, created on `FS01` at
02:13:05 and added to Administrators on `FS01` at 02:13:31, both by
`administrator`. Liam's add on `WS-DEV01` has no 4720 for SID
`S-1-5-21-[NW]-1093` (his account is years old), and Maya's new account was
never added to Administrators, so neither appears.

How it works:

- The `let newAccounts` block collects every 4720 and keeps the new
  account's SID. The main query collects every 4732 into `S-1-5-32-544`.
- `join ... on $left.MemberSid == $right.NewAccountSid` pairs them by
  **SID**, not name. That works for local accounts (where `MemberName` is
  `-`) and for a domain account created on `DC01` and then added to a local
  group on another server, which is why `CreatedOn` and `AddedOn` are kept
  separately.
- `between (CreatedTime .. (CreatedTime + window))` keeps only adds that
  happen within 60 minutes after the creation, the same trick as Day 01.

**Tuning note:** Rule A will fire on legitimate IT work, so give it a
**medium** severity and a simple triage step: look for a matching change
ticket and confirm with the person named in `SubjectUserName`. Rule B is
rarer and deserves **high** severity, but your onboarding process may create
IT staff accounts and grant admin rights in one go; allow-list that process
by its service account (`SubjectUserName`) rather than turning the rule off.
Neither rule catches an attacker who adds an **existing** account to
**Domain Admins**; that's a 4728 on `DC01`, so watch it with its own rule.
And an attacker with admin rights can clear the Security log to hide all of
this, which is Day 16's topic.

For Day 10's mapping lookup, these become rules **NW-013** and **NW-014**:

```
NW-013,Persistence,T1098.007,Additional Local or Domain Groups
NW-014,Persistence,T1136.001,Create Account: Local Account
```

---

## Your turn

1. In the sample, four rows have `EventID` 4732 or 4728. For each, say which
   group was changed, whether it grants admin rights, and whether you'd
   escalate it. Which one would a careless rule that matched "any 4732"
   wrongly flag?
2. Rule A fires on `WS-DEV01` at 22:31:09. Write the two or three checks you'd
   do before closing it as a benign true positive. What answer to those
   checks would make you escalate instead?
3. Why does Rule B join on `MemberSid` and not on the account **name**? What
   would happen to the join if you used `MemberName`, given what `FS01`
   logged?
4. Imagine that at 02:20 the attacker uses `support_svc` to add the existing
   account `svc_backup` to **Domain Admins**. Which event ID would appear, on
   which computer, and would Rule A or Rule B catch it? Sketch the KQL
   `where` line for a rule that would. (Hint: Domain Admins' SID always ends
   in `-512`.)

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [4720: A user account was created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) · [4732: A member was added to a security-enabled local group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732) · [4728: A member was added to a security-enabled global group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4728)
- Microsoft Learn: [Audit User Account Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management) · [Audit Security Group Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management) · [Security identifiers (well-known SIDs)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
- MITRE ATT&CK: [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) · [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
- SigmaHQ: [Windows Security log rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/security)

⬅️ [Learning log index](README.md) · ➡️ Day 15: Persistence: scheduled tasks and new services (4698, 7045) (25 Oct)
