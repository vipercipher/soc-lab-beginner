# Scenario 01 — Questions

Answer these from `logs.csv`. Jot your answers on paper or in a notes file, then
check `solution.md`. Don't peek until you've had a real go. 🙂

## Part A — Get your bearings

1. On a normal working day, which **country** (`source.geo.country_name`) do
   Northwind staff sign in from?
2. What `auth.method` does daniel.cole normally use during the day, and which
   host (`host.name`) is he on?

## Part B — Investigate the alert

3. Between **22:14 and 22:16 UTC on 11 March**, how many rows have
   `event.code` **4625** for daniel.cole, and how many seconds apart are they?
   What does `event.code` 4625 mean?
4. What `source.ip` and `source.geo.country_name` are those failed attempts
   coming from? Is that normal for this user?
5. Daniel had a successful sign-in (`event.code` 4624) from Australia at
   **12:41 UTC**, and the suspicious activity is from another country at
   **22:14 UTC**. Why is that combination suspicious? (Think about travel time.)
6. After the failed attempts, is there an `event.code` **4624** (logon success)
   from the attacker's IP? At what time?

## Part C — The critical moment

7. Look at the `mfa_challenge` rows around **22:19–22:21 UTC**. What is the
   `event.outcome` on the first two, and on the third?
8. In your own words: what does an MFA `event.outcome` of `success` here mean?
   Is the account now protected, or not?

## Part D — Your decision

9. Based on everything above, is this a **real attack** or a **false alarm**?
10. **What is the very first thing you should do?** Write your single most
    important first action, then the next steps. This is the most important
    question in the lab.

## Part E — Think like a detection engineer (bonus)

11. If you had to write a rule to catch this automatically, what would it count?
    (Hint: how many `event.code` 4625 events, grouped by which field, before it
    fires?) This is exactly the **threshold rule** you'd build on day 8 of the
    Elastic SIEM lab.

---

➡️ When you're ready, open **`solution.md`**.
