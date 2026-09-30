# Scenario 01 — Questions

Answer these from `logs.csv`. Jot your answers on paper or in a notes file, then
check `solution.md`. Don't peek until you've had a real go. 🙂

## Part A — Get your bearings

1. On a normal working day, which **city** do Northwind staff usually sign in
   from?
2. What **device** and **auth method** does daniel.cole normally use during the
   day?

## Part B — Investigate the alert

3. At around **22:14–22:16 UTC on 11 March**, what happens to daniel.cole's
   account? How many failed attempts are there in a row, and how close together
   are they?
4. What **location** are those attempts coming from? Is that normal for this
   user?
5. Daniel signed in from Sydney at **12:41 UTC** and the suspicious activity is
   from another country at **22:14 UTC**. Why is that combination suspicious?
   (Think about how long it takes to travel between the two places.)
6. After all those failed attempts, does the attacker eventually get a
   **Success**? At what time?

## Part C — The critical moment

7. Look at the rows around **22:19–22:21 UTC**. The attacker now has the password
   and hits an **MFA challenge**. What happens on the first two tries, and what
   happens on the third?
8. In your own words: what does it mean that the MFA challenge was eventually a
   `Success`? Is the account now protected, or not?

## Part D — Your decision

9. Based on everything above, is this a **real attack** or a **false alarm**?
10. **What is the very first thing you should do?** Write down your single most
    important first action, then a short list of the next steps. This is the most
    important question in the lab.

---

➡️ When you're ready, open **`solution.md`**.
