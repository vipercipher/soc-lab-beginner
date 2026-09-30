# Scenario 01 — Solution & Analyst Walkthrough

Read this **after** you've tried the questions. It shows how a SOC analyst reads
the logs, and, most importantly, the correct **first response**.

---

## The short version

**This is a real account takeover.** An attacker brute-forced daniel.cole's
password from Ukraine, then tricked or wore down the user into approving an MFA
prompt (**"MFA fatigue"**), and is now logged in. The account is compromised.

**Correct first action: disable the account / force a sign-out and password
reset right now, before doing anything else.** Contain first, investigate second.

---

## How to read it, question by question

**Q1 — Normal location.** Almost every row is from **Sydney, AU**, on IPs
starting `203.0.113.x`. That's Northwind's baseline. Anything far from Sydney
deserves a second look.

**Q2 — Daniel's normal pattern.** During the day he's on **Windows 11 – Edge**,
from Sydney, using **Password + MFA**. Remember this — it's what "good" looks
like for him.

**Q3 — The brute force.** From **22:14:06 to 22:16:01**, there are **8 failed
password attempts in a row**, about **15 seconds apart**. That steady,
machine-like spacing is a classic sign of an automated **brute-force / password-
guessing** attack, not a human mistyping.

**Q4 — The location.** All of it comes from **Kyiv, UA** on IP
`198.51.100.212`. Daniel has never signed in from there. 🚩

**Q5 — Impossible travel.** He was in **Sydney at 12:41 UTC**, then "in Kyiv" at
**22:14 UTC** — about 9.5 hours later. Sydney to Kyiv is a ~20+ hour trip. A
person cannot be in both places that close together, so the two sessions can't
both be the real Daniel. This is called **"impossible travel"**, and it's one of
the strongest signals that an account is compromised.

**Q6 — The password falls.** At **22:16:01** a password attempt finally shows
**Success**. The attacker has guessed the password. But notice — there's still
MFA to get past.

**Q7 — The MFA fatigue attack.** At **22:19:10** and **22:19:52** the MFA
challenge is **denied** (`MFA denied by user`) — good, Daniel tapped "No" twice.
But at **22:21:33** the MFA challenge shows **Success**. The attacker kept
sending prompts until Daniel, confused or annoyed, finally tapped "Yes". This is
an **MFA fatigue** (or "MFA bombing") attack.

**Q8 — What that means.** MFA `Success` here is **bad news**, not good. It means
the attacker got past the second factor too. From **22:24 onwards** they have
**full `Password + MFA` sessions** — they're inside the account.

**Q9 — Real or false alarm?** **Real attack.** Brute force + impossible travel +
a bypassed MFA + repeated successful logins from a foreign IP is not a
coincidence.

**Q10 — Your first action (the whole point of the lab).**

> **Contain the account immediately.** In Microsoft Entra ID (or your identity
> platform): **disable the user / block sign-in and revoke their active
> sessions**, which kicks the attacker out, then force a password reset.

Do that **before** you write the report or call anyone. An attacker who's logged
in right now can be reading email or stealing data every extra minute. Stopping
the bleeding comes first.

---

## The order a SOC analyst actually works in

Security teams use a simple order of operations, often summarised as
**Identify → Contain → Eradicate → Recover**:

1. **Identify** ✅ — you did this: confirmed it's a real compromise, not noise.
2. **Contain** 🚨 — block sign-in, **revoke/kill active sessions**, reset the
   password. Stop it spreading.
3. **Eradicate** — remove what the attacker left behind: check for new **MFA
   methods** they registered, mailbox forwarding rules, new app permissions or
   consent grants, and any changes they made.
4. **Recover** — help Daniel back in safely with a fresh password and re-enrolled
   MFA, and confirm normal activity resumes.
5. **Document & learn** — write it up (see below) and ask what would have stopped
   it (e.g. blocking logins from unexpected countries, phishing-resistant MFA).

> Note: revoking sessions and resetting the password are both part of Contain —
> a reset alone doesn't log out a session the attacker already has, so you do
> both.

---

## What a tidy incident note looks like

> **Incident:** Account takeover — daniel.cole@northwind-example.com
> **Detected:** Alert SIG-4471, 2026-03-11 22:16 UTC
> **Summary:** 8 failed password sign-ins from 198.51.100.212 (Kyiv, UA) between
> 22:14–22:16 UTC, followed by a successful password sign-in, then an MFA-fatigue
> bypass at 22:21 UTC. Impossible travel vs. Sydney session at 12:41 UTC.
> Multiple full sessions from the foreign IP through 23:02 UTC and again 08:49
> UTC on 12 March.
> **Action taken:** Disabled account, revoked all sessions, forced password
> reset at [time]. Checked for attacker-added MFA methods and mailbox rules.
> **Status:** Contained. Awaiting user re-enrolment.

---

## What you just practised

- Reading real-world **sign-in logs** and spotting the baseline
- Recognising a **brute-force** pattern by timing
- Spotting **impossible travel**
- Understanding an **MFA fatigue** attack (and why an MFA "Success" can be bad)
- Knowing the **correct first response: contain before you investigate**

That "contain first" instinct is exactly what separates a trained analyst from
someone who freezes. Nice work. 🎯

➡️ More scenarios will be added over time. See the main
[README](../../README.md).
