# 🛡️ Beginner SOC Lab

**Learn to think like a security analyst by investigating real-looking logs — no
setup, no risk, no experience required.**

This is a hands-on lab for people who are curious about cybersecurity but have
never done it. Each scenario drops you into the seat of a **SOC analyst** (the
person who watches for and responds to cyber attacks). You're given an alert and
some log data, and your job is to work out what happened and what to do first.

There's nothing to install and nothing dangerous here — just data files to read
and questions to answer. If you can open a spreadsheet, you can do this lab.

> **The paper version of a real SIEM.** The logs here use the same **ECS
> (Elastic Common Schema)** field names and **Windows event codes** (4624, 4625)
> that a real Elastic Security SIEM uses. So this lab doubles as **"day 0"** — it
> teaches you to *read* alerts and decide what to do, before you stand up the live
> tool in a full [14-day Elastic SIEM lab](#-where-this-leads).

---

## 🎯 What you'll learn

- How to read **sign-in logs in ECS fields** and spot what's normal vs. suspicious
- How real attacks like **brute force**, **impossible travel** and **MFA
  fatigue** actually show up in the data
- The single most important habit of a good analyst: knowing the **correct first
  response** when an account is under attack
- A first taste of **detection engineering** — turning what you spotted into a rule

---

## 🚀 How to start (2 minutes)

1. **Download this lab:** click the green **Code** button at the top of this
   page → **Download ZIP**, then unzip it. (Or `git clone` it if you know how.)
2. Open the **`scenarios/`** folder and pick a scenario, starting with
   **`01-suspicious-login`**.
3. Inside each scenario, read the files **in this order**:

   | File | What it's for |
   |---|---|
   | `brief.md` | Sets the scene and explains the alert |
   | `logs.csv` | The data you investigate (open in Excel, Google Sheets, or a text editor) |
   | `questions.md` | The questions to work through |
   | `solution.md` | The full walkthrough and correct response — **open this last** |

4. Try the questions **before** reading the solution. Struggling a bit is where
   the learning happens.
5. Stuck on a word? The **[GLOSSARY](GLOSSARY.md)** explains every term in plain
   English.

---

## 📚 Scenarios

| # | Scenario | Skills | Level |
|---|---|---|---|
| 01 | [Suspicious Login](scenarios/01-suspicious-login/brief.md) | Brute force (4625), impossible travel, MFA fatigue, containment, threshold rules | 🟢 Beginner |
| 02 | *Coming soon* | | |

More scenarios (phishing emails, suspicious PowerShell, new admin accounts…) will
be added over time.

---

## 🚀 Where this leads

Once you're comfortable reading these logs on paper, the next step is doing it
live. The concepts map one-to-one onto a real SIEM:

| You learned here | You'll do it live in Elastic |
|---|---|
| Reading ECS fields in a CSV | Reading the same fields in **Discover** |
| Spotting 8× `event.code` 4625 | Writing a **Threshold rule** (day 8) |
| Deciding "contain first" | Working the **alert queue** and writing a **Case** |
| Following the attacker's steps | The **process analyzer** and **timelines** |

A companion **14-day Elastic SIEM lab** walks you through standing up a free
Elastic trial, shipping Windows logs, firing real alerts, and writing your own
detections. This paper lab is the gentlest possible on-ramp to it.

---

## ❓ FAQ

**Do I need any tools or a special computer?**
No. Everything opens in a spreadsheet app or a plain text editor.

**Is any of this dangerous? Is there malware?**
No. There are no programs to run and no real malware — only text and CSV files
with **made-up** data. Every name, company, and IP address is fictional.

**Are these real IP addresses / companies?**
No. The IP ranges used (`203.0.113.x`, `198.51.100.x`) are reserved for
documentation and examples, and the company and people are invented.

**I'm a complete beginner. Is this for me?**
Yes — that's exactly who it's for. Start with scenario 01 and take your time.

---

## 🤝 Contributing

Ideas for new scenarios, or spotted a mistake? Open an issue or a pull request.

---

## ⚠️ Note

These labs use fictional data for **education only**. The techniques shown are for
understanding and defending against attacks. Always act ethically and only test
systems you're authorised to.

## 📄 License

[MIT](LICENSE) © Jay Shrestha
