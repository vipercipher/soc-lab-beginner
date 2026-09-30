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
RULE:         Multiple failed sign-ins followed by a success (event.code 4625 → 4624)
USER:         daniel.cole
HOST:         WIN-FIN02
TIME:         2026-03-11 22:16 UTC
STATUS:       New — awaiting analyst review
```

The security system noticed something about Daniel Cole's account and flagged it
for a human (you) to look at. The alert on its own doesn't tell you whether this
is a real attack or a false alarm. That's what you need to work out.

---

## What you have

In this folder there's a file called **`logs.csv`**. It's a record of Windows
sign-in activity for a few staff accounts over two days. The columns use **ECS
(Elastic Common Schema)** field names — the same names a real Elastic SIEM uses,
so what you learn here transfers straight to the tool:

| Column | What it means |
|---|---|
| `@timestamp` | When the attempt happened (UTC) |
| `event.category` | The kind of event — here, `authentication` |
| `event.action` | The specific action: `logged_in`, `logon_failed`, `mfa_challenge` |
| `event.code` | The Windows event ID — **4624** = logon success, **4625** = logon failed |
| `event.outcome` | `success` or `failure` |
| `user.name` | Whose account was used |
| `source.ip` | The internet address the attempt came from |
| `source.geo.country_name` | The country that IP maps to |
| `host.name` | Which computer was signed into |
| `auth.method` | How they proved who they are (Password, MFA…) |
| `message` | A short human-readable note |

> 💡 **event.code 4625** is the Windows event ID for a **failed logon**, and
> **4624** is a **successful logon**. You'll use these exact codes again if you
> go on to the 14-day Elastic SIEM lab. See `../../GLOSSARY.md` for any term.

---

## What to do

1. Open `logs.csv` in **Excel**, **Google Sheets**, or a text editor. In a
   spreadsheet app it lines up into neat columns.
2. Focus on the flagged user, **daniel.cole**, but glance at the others so you
   know what *normal* looks like.
3. Work through the questions in **`questions.md`**.
4. When you're done, or stuck, check **`solution.md`** for how a SOC analyst
   reads it, and the correct **first response**.

Take your time. The goal isn't speed, it's noticing what's out of place and
knowing the safe first move. Good luck. 🕵️
