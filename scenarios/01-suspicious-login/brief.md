# Scenario 01 — Suspicious Login Alert

## Your role

You've just started a shift as a **SOC (Security Operations Center) analyst** at
a company called **Northwind** (a made-up company for this lab). Your job is to
watch for signs that someone's account has been broken into, and decide what to
do about it.

An automated alert has just landed in your queue. 👇

---

## 🚨 The alert

```
ALERT ID:     SIG-4471
SEVERITY:     Medium
RULE:         Multiple failed sign-ins followed by a success
USER:         daniel.cole@northwind-example.com
TIME:         2026-03-11 22:16 UTC
STATUS:       New — awaiting analyst review
```

The security system noticed something about Daniel Cole's account and flagged it
for a human (you) to look at. The alert on its own doesn't tell you whether this
is a real attack or a false alarm. That's what you need to work out.

---

## What you have

In this folder there's a file called **`logs.csv`**. It's a record of sign-in
activity for a few staff accounts over two days. Each row is one login attempt,
with:

| Column | What it means |
|---|---|
| `timestamp_utc` | When the attempt happened (in UTC time) |
| `user` | Whose account was used |
| `ip_address` | The internet address the attempt came from |
| `location` | Roughly where that address is |
| `device` | The operating system and browser used |
| `auth_method` | How they tried to prove who they are (password, MFA…) |
| `result` | Whether it worked (`Success`) or not (`Failed`) |
| `failure_reason` | Why it failed, if it did |

> 💡 **MFA** = Multi-Factor Authentication: the second step after a password,
> like a code from an app or a phone prompt. See `../../GLOSSARY.md` for any
> term you don't recognise.

---

## What to do

1. Open `logs.csv`. You can open it in **Excel**, **Google Sheets**, or even a
   plain text editor. (In Excel/Sheets it will line up into neat columns.)
2. Focus on the flagged user, **daniel.cole**, but glance at the others too so
   you know what *normal* looks like.
3. Work through the questions in **`questions.md`**.
4. When you're done, or if you get stuck, check **`solution.md`** to see how a
   SOC analyst would read it, and what the correct **first response** is.

Take your time. The goal isn't speed, it's noticing what's out of place and
knowing the safe first move. Good luck. 🕵️
