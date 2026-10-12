# Day 03 — Password Spraying vs Brute Force

📅 13 October 2026 · 🏷️ Log analysis · ⏱️ ~20 min

---

## Why it matters

On Day 01 and Day 02 the attacker hammered **one account at a time** with
password after password. That's loud, and it trips account lockout. A smarter
attacker flips it around: try **one common password against many accounts**,
once each, and move on. No single account sees enough failures to lock or to
look odd, so account lockout and any alert that counts failures per user stay
quiet. This is **password
spraying**, and it's one of the most common ways cloud accounts like the one in
Scenario 01 get broken into. The trick for the analyst is to stop counting per
*account* and start counting per *source*.

---

## The concept

### Same goal, different shape

| | Brute force | Password spraying |
|---|---|---|
| Accounts targeted | One (or a few) | Many, often every name the attacker can find |
| Passwords tried | Many per account | One or two per account (`Spring2026!`, `Welcome1`) |
| Speed | Fast bursts, seconds apart | Often slow: one round, then wait an hour or a day |
| Account lockout | Trips it quickly | Designed to stay **under** the threshold |
| What stands out in the logs | Lots of failures for **one user** | Lots of **different users** failing from **one IP** |
| Where we saw it | Day 01 (RDP), Day 02 (SSH) | Today |
| MITRE ATT&CK | T1110.001 Password Guessing | T1110.003 Password Spraying |

> 💡 **The analyst's shortcut:** brute force is *many passwords, one door*.
> Spraying is *one password, many doors*. So for brute force you group failures
> **by user**; for spraying you group them **by source IP** and count how many
> **distinct users** failed.

### Reading Microsoft Entra ID sign-ins

Northwind's staff sign in to Microsoft 365, so the evidence lives in the
**Microsoft Entra ID sign-in logs** (the `SigninLogs` table in Microsoft
Sentinel). Each row is one sign-in attempt, and the `ResultType` field holds an
error code. `0` means success; anything else is a reason it didn't (fully)
succeed.

| `ResultType` | Meaning | What it tells you | Day 01 cousin |
|---|---|---|---|
| `0` | Success | They're in | 4624 |
| `50126` | Invalid username or password | Wrong password (for a real account) | 4625 `0xC000006A` |
| `50034` | User account doesn't exist in the directory | Attacker guessed a username that isn't real | 4625 `0xC0000064` |
| `50053` | Account locked (Smart Lockout), or sign-in from a known bad IP blocked | Guessing has hit the limit | 4625 `0xC0000234` |
| `50074` | Strong authentication (MFA) is required | **The password was correct.** Only MFA stopped them | No direct equivalent |

> ⚠️ **`50074` is not a "failure" to shrug off.** The user's password passed;
> the sign-in only paused for MFA. If it comes from an attacker's IP, the
> password is **known to the attacker** and must be reset, even though no one
> got in. (Remember Scenario 01: Daniel's attacker had the password and then
> pushed MFA prompts until one was approved.)

Entra ID's **Smart Lockout** locks an account for a minute after **10** failed
attempts by default. One spray round puts just **one** failure on each account,
far below that, which is exactly the point.

---

## Sample logs

A simplified extract from Northwind's Entra ID sign-in logs. Times are UTC.

```
TimeGenerated (UTC)   UserPrincipalName                    IPAddress       AppDisplayName                ResultType
2026-10-13 03:02:10   aaron.blake@northwind-example.com    198.51.100.66   Office 365 Exchange Online    50126
2026-10-13 03:02:41   daniel.cole@northwind-example.com    198.51.100.66   Office 365 Exchange Online    50126
2026-10-13 03:03:09   emma.walsh@northwind-example.com     198.51.100.66   Office 365 Exchange Online    50126
2026-10-13 03:03:37   j.smith@northwind-example.com        198.51.100.66   Office 365 Exchange Online    50034
2026-10-13 03:04:02   liam.chen@northwind-example.com      198.51.100.66   Office 365 Exchange Online    50126
2026-10-13 03:04:30   marco.rossi@northwind-example.com    198.51.100.66   Office 365 Exchange Online    50074
2026-10-13 03:04:58   noah.patel@northwind-example.com     198.51.100.66   Office 365 Exchange Online    50126
2026-10-13 03:05:26   priya.nair@northwind-example.com     198.51.100.66   Office 365 Exchange Online    50126
2026-10-13 03:05:51   sara.lund@northwind-example.com      198.51.100.66   Office 365 Exchange Online    50126
2026-10-13 07:58:41   priya.nair@northwind-example.com     203.0.113.24    Office 365 Exchange Online    0
2026-10-13 08:12:05   sara.lund@northwind-example.com      203.0.113.77    Microsoft Teams               50126
2026-10-13 08:12:31   sara.lund@northwind-example.com      203.0.113.77    Microsoft Teams               0
```

---

## What to look for

1. **One IP, many different users.** `198.51.100.66` tries **9 different
   usernames** in under 4 minutes (03:02:10 to 03:05:51), **once each**. No
   user would ever sign in as nine colleagues.
2. **No account gets more than one try.** Group by user and nothing looks wrong:
   each account has a single failure, nowhere near Smart Lockout's 10. That's
   why lockout and any per-user failure alert would miss this.
3. **A username that doesn't exist.** `j.smith` returns `50034`. The attacker's
   list was built by guessing the `first.last` pattern, and one guess missed.
4. **The `50074` row.** `marco.rossi` didn't fail on the password; Entra asked
   for MFA. The sprayed password is **Marco's real password**. MFA saved the
   day this time, but the password is compromised.
5. **Rule out the normal rows.** Priya's success from her usual IP
   (`203.0.113.24`) at 07:58, and Sara's one typo followed by a success 26
   seconds later from her usual IP (`203.0.113.77`), are everyday activity. Note
   that Priya and Sara were also sprayed at 03:05; their later normal sign-ins
   don't change that.

> 🔎 **Quick pivot:** once you have the spraying IP, list every result it got.
> Anything other than `50126` and `50034` deserves a closer look.
>
> ```kql
> SigninLogs
> | where IPAddress == "198.51.100.66"
> | summarize Attempts = count() by UserPrincipalName, ResultType
> ```

---

## Detection logic

**In plain English:** alert when one source IP has failed sign-ins for **5 or
more different users** within an hour, with only a **few attempts per user**.
Raise the severity if that IP **got past the password** for any user (`0` or
`50074`).

**KQL (Microsoft Sentinel, `SigninLogs` table; run over the last 24 hours):**

```kql
let window = 1h;
let sprayers =
    SigninLogs
    | where ResultType in ("50126", "50034", "50053")
    | summarize FailedUsers = dcount(UserPrincipalName),
                FailedAttempts = count(),
                TargetedUsers = make_set(UserPrincipalName, 100),
                FirstSeen = min(TimeGenerated),
                LastSeen = max(TimeGenerated)
              by IPAddress, bin(TimeGenerated, window)
    | where FailedUsers >= 5 and FailedAttempts < FailedUsers * 3;
sprayers
| join kind=leftouter (
    SigninLogs
    | where ResultType in ("0", "50074")
    | summarize PasswordAccepted = make_set(UserPrincipalName, 100) by IPAddress
  ) on IPAddress
| extend Severity = iff(array_length(PasswordAccepted) > 0, "High", "Medium")
| project FirstSeen, LastSeen, IPAddress, FailedUsers, FailedAttempts,
          TargetedUsers, PasswordAccepted, Severity
```

How it works: the first block counts failures **per IP per hour** and keeps IPs
that failed against at least 5 distinct users, averaging fewer than 3 tries each
(the "many doors, few tries" shape; brute force would fail the second check).
`ResultType` is a **string** in `SigninLogs`, so the codes are in quotes. The
`leftouter` join then looks for any user that same IP got past the password for.

On the sample, `198.51.100.66` has **8 failures** (seven `50126` and one
`50034`) against **8 distinct users** in the 03:00 bucket, so 8 ≥ 5 and 8 < 24
and the rule fires. Marco's `50074` lands in `PasswordAccepted`, so the alert is
**High**. Sara's 08:12 typo is one user from one IP and never comes close.

**Tuning note:** real sprays are often **slower** than this sample (one round a
day) or spread across **many IPs** to dodge exactly this rule. Widen the window
to 24 hours as you gain confidence, and add a second view that groups failures
by `ResultType == "50126"` across *all* IPs to catch a tenant-wide jump in
failures. Expect false positives from shared egress IPs (a VPN, a corporate
proxy, a hotel or conference Wi-Fi) where many real users sit behind one
address; list your own known egress IPs and exclude or downgrade them. As on
Day 01, `bin` uses fixed buckets, so a spray that straddles the hour can be
split in two.

---

## Your turn

1. In your own words, explain why Smart Lockout and an alert on "5 or more
   failures for one user" would **both** miss this spray. Then describe one way
   an attacker could also slip past **today's** rule.
2. The spray hit 9 usernames but the rule counts only **8** failed users. Which
   row isn't counted as a failure, and why should it still worry you **more**
   than the others?
3. You confirm this is a spray. List the **first three things** you'd do,
   covering Marco, the other targeted users and the attacking IP. (Think
   "contain, then scope" from Scenario 01.)
4. Sketch what a password spray against **on-premises Active Directory** would
   look like in Windows Security events from Day 01. Which event ID and SubStatus
   code would you expect, and which field would show many different values?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.
2.
3.
4.

---

## Further reading

- Microsoft Learn: [Password spray investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray)
- Microsoft Learn: [Protect user accounts from attacks with Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- Microsoft Learn: [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes) · [`SigninLogs` table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- MITRE ATT&CK: [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) · [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

⬅️ [Learning log index](README.md) · ➡️ Day 04: Writing your first Sigma rule (14 Oct)
