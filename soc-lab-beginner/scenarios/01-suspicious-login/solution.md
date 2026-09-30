# Scenario 01 — Solution & Analyst Walkthrough

Read this **after** you've tried the questions. It shows how a SOC analyst reads
the logs, and, most importantly, the correct **first response**.

---

## The short version

**This is a real account takeover.** An attacker brute-forced daniel.cole's
password from Ukraine (a burst of `event.code` 4625 failures, then a 4624
success), then wore the user down into approving an MFA prompt (**"MFA
fatigue"**), and is now logged in. The account is compromised.

**Correct first action: disable the account / block sign-in and revoke active
sessions, then force a password reset — right now, before anything else.**
Contain first, investigate second.

---

## How to read it, question by question

**Q1 — Normal country.** Almost every row is from **Australia**, on IPs starting
`203.0.113.x`. That's Northwind's baseline. Anything else deserves a look.

**Q2 — Daniel's normal pattern.** During the day he signs in with **Password +
MFA** from **WIN-FIN02**, from Australia. Remember this — it's what "good" looks
like for him.

**Q3 — The brute force.** From **22:14:06 to 22:16:01** there are **8 rows with
`event.code` 4625** (failed logon) for daniel.cole, about **15 seconds apart**.
That steady, machine-like spacing is a classic **brute-force / password-guessing**
attack, not a human mistyping. `event.code` 4625 = a failed Windows logon.

**Q4 — The location.** All of it is from **`source.ip` 198.51.100.212**, which
maps to **Ukraine**. Daniel has never signed in from there. 🚩

**Q5 — Impossible travel.** A 4624 success from Australia at **12:41 UTC**, then
activity "from Ukraine" at **22:14 UTC** — about 9.5 hours later. Australia to
Ukraine is a 20+ hour trip. A person can't be in both places that close together,
so both sessions can't be the real Daniel. This is **"impossible travel"**, one
of the strongest signals an account is compromised.

**Q6 — The password falls.** At **22:16:20** there's an `event.code` **4624**
(success) from the attacker's IP. The attacker has guessed the password — but
there's still MFA to get past.

**Q7 — The MFA fatigue attack.** The `mfa_challenge` rows at **22:19:10** and
**22:19:52** have `event.outcome` = **failure** (`MFA denied by user`) — good,
Daniel tapped "No" twice. But at **22:21:33** the `event.outcome` is **success**
(`MFA approved`). The attacker kept sending prompts until Daniel, confused or
annoyed, finally tapped "Yes". This is an **MFA fatigue** (or "MFA bombing")
attack.

**Q8 — What that means.** MFA `success` here is **bad news**, not good. The
attacker got past the second factor too. From **22:24 onward** there are full
**Password + MFA** sessions (4624) — they're inside the account.

**Q9 — Real or false alarm?** **Real attack.** Brute force + impossible travel +
a bypassed MFA + repeated successful logins from a foreign IP is not coincidence.

**Q10 — Your first action (the whole point of the lab).**

> **Contain the account immediately.** In Microsoft Entra ID (or your identity
> platform): **disable the user / block sign-in and revoke their active
> sessions** to kick the attacker out, then force a password reset.

Do that **before** writing the report or calling anyone. An attacker who's logged
in right now can read email or steal data every extra minute. Stop the bleeding
first.

**Q11 — The detection-engineer view (bonus).** You'd write a **threshold rule**:
count `event.code : 4625`, **group by `user.name`**, and fire when the count
reaches, say, **5** in a short window. That's precisely **Rule 2 (Threshold)** on
day 8 of the Elastic SIEM lab. This paper scenario is you doing by hand what that
rule automates.

---

## The order a SOC analyst actually works in

Security teams use a simple order, often summarised as
**Identify → Contain → Eradicate → Recover**:

1. **Identify** ✅ — you did this: confirmed it's a real compromise, not noise.
2. **Contain** 🚨 — block sign-in, **revoke/kill active sessions**, reset the
   password. Stop it spreading.
3. **Eradicate** — remove what the attacker left: check for new **MFA methods**
   they registered, mailbox forwarding rules, new app permissions, and any
   changes they made.
4. **Recover** — help Daniel back in with a fresh password and re-enrolled MFA,
   and confirm normal activity resumes.
5. **Document & learn** — write it up (below) and ask what would have stopped it
   (blocking logins from unexpected countries, phishing-resistant MFA).

> Note: revoking sessions and resetting the password are both part of Contain —
> a reset alone doesn't log out a session the attacker already holds, so do both.

---

## What a tidy incident note looks like

> **Incident:** Account takeover — user.name `daniel.cole`, host `WIN-FIN02`
> **Detected:** Alert SIG-4471, 2026-03-11 22:16 UTC
> **Summary:** 8 × `event.code` 4625 from `source.ip` 198.51.100.212 (Ukraine)
> between 22:14–22:16 UTC, followed by a 4624 success, then an MFA-fatigue bypass
> at 22:21 UTC. Impossible travel vs. Australia session at 12:41 UTC. Multiple
> full sessions from the foreign IP through 23:02 UTC and again 08:49 UTC on
> 12 March.
> **Action taken:** Disabled account, revoked all sessions, forced password reset
> at [time]. Checked for attacker-added MFA methods and mailbox rules.
> **Status:** Contained. Awaiting user re-enrolment.

---

## What you just practised

- Reading real-world **sign-in logs in ECS fields** and spotting the baseline
- Recognising a **brute-force** pattern by `event.code` 4625 and timing
- Spotting **impossible travel**
- Understanding an **MFA fatigue** attack (why an MFA "success" can be bad)
- Knowing the correct first response: **contain before you investigate**
- Seeing how the same logic becomes a **threshold detection rule**

That "contain first" instinct is exactly what separates a trained analyst from
someone who freezes. Nice work. 🎯

➡️ **Ready for the real tool?** This scenario is the paper version of what you'll
do live in the **14-day Elastic SIEM lab** — see the main
[README](../../README.md) for how they fit together.
