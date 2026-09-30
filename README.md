# 🛡️ Beginner SOC Lab

**Learn how a cybersecurity analyst catches hackers — by reading real-looking
computer logs and deciding what to do. No experience, no software, no risk.**

If you've ever wondered what people in cybersecurity actually *do* all day, this
lab lets you try it. You'll play the role of the person whose job is to spot when
someone's account has been hacked and stop it. Everything is a safe, made-up
practice file. If you can open a spreadsheet, you can do this.

---

## 🧭 First, some plain-English background

Before you start, here are the only ideas you need. Don't worry about memorising
them — you'll pick them up as you go, and there's a full
**[GLOSSARY](GLOSSARY.md)** for every term.

**What is a SOC?**
A **SOC** (say "sock") stands for **Security Operations Center**. It's the team at
a company whose job is to watch all the computers and accounts for signs of a
hacker, and respond when they find one. Think of them as the security guards
watching the cameras.

**What is a SOC analyst?**
That's the person doing the watching — the role *you* play in this lab. When the
computer systems notice something odd, they send the analyst an **alert**, and the
analyst investigates to decide: is this a real attack, or a false alarm?

**What is a log?**
A **log** is just a record of things that happened on a computer, one line at a
time. Every time someone logs in, the computer writes a line: who, when, from
where, and whether it worked. A "sign-in log" is a list of all those login
attempts. Reading logs is the main thing you'll do here.

**What is an alert?**
An **alert** is an automatic message saying "something here might be wrong, a
human should check." An alert is a *starting point*, not proof. Your job is to
look at the logs behind the alert and figure out what really happened.

That's it. Now you know enough to start. 🎉

---

## 🎯 What you'll learn

By the end of the first scenario you'll be able to:

- Read a **sign-in log** and tell what "normal" looks like
- Spot the fingerprints of three common attacks:
  - **Brute force** — a hacker guessing a password over and over
  - **Impossible travel** — the same account logging in from two far-apart places
  - **MFA fatigue** — a hacker spamming approval prompts until the victim taps "yes"
- Know the **single most important first action** when an account is hacked
- Get a first taste of **detection engineering** — turning what you spotted into
  an automatic rule

---

## 💡 Why the files look "technical" (and why that's good for you)

The log file in this lab uses the same **column names** that professional security
tools use. This standard set of names is called **ECS (Elastic Common Schema)**.
For example, instead of a column called "what happened," you'll see one called
`event.action`.

Don't be put off by this — it's on purpose, and it's a head start. It means that
after this paper lab, if you move on to a **real** security tool (like Elastic
Security), the columns will already look familiar. You're learning the real
vocabulary from day one.

Here's a translation table so nothing is a mystery:

| Column name in the file | In plain English |
|---|---|
| `@timestamp` | When it happened (the date and time, in UTC) |
| `event.category` | The *type* of event — here it's always `authentication` (a login) |
| `event.action` | What happened: `logged_in`, `logon_failed`, or `mfa_challenge` |
| `event.code` | A Windows number for the event: **4624** = login worked, **4625** = login failed |
| `event.outcome` | Did it work? `success` or `failure` |
| `user.name` | Whose account was used |
| `source.ip` | The internet address the login came from (like a return address) |
| `source.geo.country_name` | Which country that address is in |
| `host.name` | Which computer was being logged into |
| `auth.method` | How they proved who they are — `Password`, `Password + MFA`, etc. |
| `message` | A short human note about the event |

> 💡 **The two numbers to remember:** `event.code` **4625** = a *failed* login, and
> **4624** = a *successful* login. Lots of 4625s in a row, then a 4624, means
> someone kept guessing a password until they got in.

---

## 🚀 How to do the lab, step by step

### Step 1 — Download it
At the top of this page, click the green **Code** button, then **Download ZIP**.
Unzip the file. (If you know Git, you can `git clone` it instead.)

### Step 2 — Open the first scenario
Inside, open the `scenarios` folder, then `01-suspicious-login`. You'll see four
files. **Read them in this exact order:**

| Order | File | What it is |
|---|---|---|
| 1️⃣ | `brief.md` | Sets the scene. "You're a SOC analyst, here's your alert." |
| 2️⃣ | `logs.csv` | The evidence. The login records you investigate. |
| 3️⃣ | `questions.md` | The questions that guide your investigation. |
| 4️⃣ | `solution.md` | The answers and the correct response. **Open this LAST.** |

### Step 3 — Open the log file
Open `logs.csv` in **Excel** or **Google Sheets** (it will line up into tidy
columns), or even Notepad. A `.csv` is just a simple table saved as text.

### Step 4 — Investigate
Read `questions.md` and try to answer each question by looking at `logs.csv`.
Write your answers on paper or in a notes file. Take your time. Compare the
suspicious account against the normal ones to see what stands out.

### Step 5 — Check your work
Only now, open `solution.md`. It walks through every question the way a real
analyst would, and explains the correct **first thing to do**. It's fine if you
didn't get everything — reading the walkthrough *is* the learning.

> 🧠 **The golden rule you'll discover:** when an account is genuinely hacked, the
> first move is always to **contain it** — lock the account and log the hacker out
> — *before* you write reports or tell anyone. Stop the bleeding first.

---

## 📚 Scenarios

| # | Scenario | What you practise | Difficulty |
|---|---|---|---|
| 01 | [Suspicious Login](scenarios/01-suspicious-login/brief.md) | Brute force, impossible travel, MFA fatigue, containment | 🟢 Beginner |
| 02 | *Coming soon* | | |

More scenarios (suspicious emails, odd PowerShell commands, surprise admin
accounts…) will be added over time. ⭐ Star this repo to find it again.

---

## 🚀 Where this leads (your next step after the lab)

This lab is deliberately the *paper* version of real security work. Everything you
do here has a direct equivalent in a live security tool called **Elastic
Security**:

| What you did here (on paper) | What it becomes in the real tool |
|---|---|
| Read the columns in `logs.csv` | Read the same fields in Elastic's **Discover** |
| Counted 8 failed logins (`4625`) | Wrote a **Threshold rule** that counts them for you |
| Decided "contain first" | Worked a live **alert queue** and wrote a **Case** |
| Followed the hacker's steps | Used the **process analyzer** and **timelines** |

So when you're ready for the real thing, none of it will feel foreign — you'll
already know what you're looking at.

---

## ❓ Frequently asked questions

**Do I need to install anything or be good with computers?**
No. If you can open a spreadsheet and read, you're ready.

**Is anything here dangerous? Could I catch a virus?**
No. There are **no programs to run** and **no real malware** — only plain text and
table files with completely made-up data.

**Are the names, companies and addresses real?**
No, all invented. The internet addresses used (`203.0.113.x` and `198.51.100.x`)
are special ranges reserved just for examples and documentation.

**I'm a total beginner and nervous. Is this really for me?**
Yes — this is built for exactly you. Start with scenario 01, read slowly, and use
the glossary whenever a word is unfamiliar.

**How long does one scenario take?**
About 20–40 minutes if you actually try the questions before peeking.

---

## 🤝 Contributing

Got an idea for a new scenario, or spotted a mistake? Open an **issue** or a
**pull request** — beginners' feedback is especially welcome, because it keeps this
lab easy to follow.

---

## ⚠️ A note on ethics

These labs use fictional data for **learning only**. Understanding how attacks work
is what lets defenders stop them. Always act ethically and only ever test systems
you own or have clear permission to test.

## 📄 License

[MIT](LICENSE) © Jay Shrestha — free to use, share, and build on.