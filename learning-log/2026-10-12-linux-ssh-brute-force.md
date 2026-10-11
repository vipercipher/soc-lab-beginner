# Day 02 — Linux `auth.log`: Spotting SSH Brute Force

📅 12 October 2026 · 🏷️ Log analysis · ⏱️ ~20 min

---

## Why it matters

Yesterday's attacker went after **RDP** on a Windows server. On Linux, the
equivalent front door is **SSH**, and any server with port 22 open to the
internet gets a steady stream of password-guessing attempts, often within
minutes of going online. Most of it is automated noise. The analyst's job is to
spot the one burst that **worked**. On Linux, the place to look is the
authentication log.

---

## The concept

### Where the log lives

| Distribution | File | Notes |
|---|---|---|
| Debian, Ubuntu | `/var/log/auth.log` | Written by `rsyslog` |
| RHEL, CentOS, Fedora, Rocky | `/var/log/secure` | Same messages, different file name |
| Any systemd system | the journal | `journalctl -u ssh` (Debian/Ubuntu) or `journalctl -u sshd` (RHEL family) |

Each line follows the classic **syslog** layout:

```
Oct 12 02:14:07 web01 sshd[4182]: Failed password for root from 198.51.100.143 port 50322 ssh2
└─ timestamp ─┘ └host┘ └process[PID]┘ └──────────────────── message ────────────────────┘
```

> 💡 Classic syslog timestamps have **no year and no time zone**. Newer releases
> (Ubuntu 24.04, for example) write ISO 8601 timestamps like
> `2026-10-12T02:14:07.512345+00:00` instead. Always check which one you have
> before you line Linux events up with Windows events in UTC.

### The SSH messages that matter

The good news: if you understood 4624 and 4625, you already understand these.

| `sshd` message | Meaning | Windows cousin (Day 01) |
|---|---|---|
| `Invalid user admin from <ip> port <n>` | Username does not exist on this server | 4625 with `0xC0000064` |
| `Failed password for invalid user admin from <ip> ...` | Password tried for a non-existent user | 4625 with `0xC0000064` |
| `Failed password for root from <ip> ...` | **Real** account, wrong password | 4625 with `0xC000006A` |
| `Accepted password for deploy from <ip> ...` | Successful login with a password | 4624 |
| `Accepted publickey for priya.nair from <ip> ...` | Successful login with an SSH key | 4624 |
| `Disconnecting authenticating user root <ip> port <n>: Too many authentication failures [preauth]` | Hit the `MaxAuthTries` limit for one connection | No direct equivalent |
| `pam_unix(sshd:session): session opened for user deploy(uid=1001) ...` | A shell session actually started | The session that follows a 4624 |

Two details to remember:

- **`[preauth]`** at the end of a line means the connection ended **before**
  anyone logged in.
- **`publickey` vs `password`** matters. If a server normally only sees key
  logins, an `Accepted password` line is unusual all by itself.

---

## Sample logs

A simplified extract from `/var/log/auth.log` on `web01`, a public-facing Ubuntu
web server at the fictional company Northwind. Times are UTC.

```
Oct 12 01:58:12 web01 sshd[3990]: Accepted publickey for priya.nair from 203.0.113.24 port 61544 ssh2: ED25519 SHA256:Xq3k...
Oct 12 02:14:01 web01 sshd[4171]: Invalid user admin from 198.51.100.143 port 50310
Oct 12 02:14:03 web01 sshd[4171]: Failed password for invalid user admin from 198.51.100.143 port 50310 ssh2
Oct 12 02:14:04 web01 sshd[4175]: Invalid user test from 198.51.100.143 port 50316
Oct 12 02:14:06 web01 sshd[4175]: Failed password for invalid user test from 198.51.100.143 port 50316 ssh2
Oct 12 02:14:07 web01 sshd[4182]: Failed password for root from 198.51.100.143 port 50322 ssh2
Oct 12 02:14:10 web01 sshd[4182]: Failed password for root from 198.51.100.143 port 50322 ssh2
Oct 12 02:14:13 web01 sshd[4182]: Failed password for root from 198.51.100.143 port 50322 ssh2
Oct 12 02:14:13 web01 sshd[4182]: error: maximum authentication attempts exceeded for root from 198.51.100.143 port 50322 ssh2 [preauth]
Oct 12 02:14:14 web01 sshd[4182]: Disconnecting authenticating user root 198.51.100.143 port 50322: Too many authentication failures [preauth]
Oct 12 02:14:18 web01 sshd[4190]: Failed password for deploy from 198.51.100.143 port 50330 ssh2
Oct 12 02:14:21 web01 sshd[4190]: Failed password for deploy from 198.51.100.143 port 50330 ssh2
Oct 12 02:14:24 web01 sshd[4190]: Accepted password for deploy from 198.51.100.143 port 50330 ssh2
Oct 12 02:14:24 web01 sshd[4190]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)
Oct 12 03:00:01 web01 CRON[4301]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
```

---

## What to look for

1. **One IP, many attempts, seconds apart.** `198.51.100.143` makes ten
   attempts in about 20 seconds. No person types that fast.
2. **Guessed usernames first.** `Invalid user admin` and `test` show the
   attacker working through a list of common names, just like `admin` and
   `test` against RDP yesterday.
3. **Then real accounts.** `root` and `deploy` exist on this server (no
   "invalid user"). The attacker is now guessing passwords for real accounts.
4. **The `Accepted password` line.** At 02:14:24 `deploy` logs in from the
   attacker's IP, and the `session opened` line confirms a shell started. That's
   a **confirmed compromise**. Note it's a **password** login, while Priya's
   normal login uses a **key**.
5. **Rule out the normal rows.** Priya's key login from her usual IP and the
   `CRON` session (a scheduled job, the Linux cousin of logon type 4) are
   expected activity.

> 🔎 **Quick check on the server itself:** count failed attempts per source IP.
>
> ```bash
> grep "Failed password" /var/log/auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn
> ```

---

## Detection logic

**In plain English:** alert when one source IP has **10 or more failed SSH
logins** on a host within 10 minutes. Raise the severity if the **same IP also
gets an `Accepted`** login in that window.

**SPL (Splunk, Linux auth logs indexed as `sourcetype=linux_secure`):**

```spl
index=linux sourcetype=linux_secure process=sshd ("Failed password" OR "Accepted")
| rex "(?<action>Failed|Accepted) (?<auth_method>password|publickey) for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port"
| bin _time span=10m
| stats count(eval(action="Failed")) AS failures,
        count(eval(action="Accepted")) AS successes,
        dc(user) AS distinct_users,
        values(user) AS users
        by _time, host, src_ip
| where failures >= 10
| eval severity=if(successes > 0, "high", "medium")
| sort - failures
```

How it works: `rex` pulls the result, method, username and IP out of each line
(the `(invalid user )?` part handles both message styles). `bin` groups events
into 10-minute buckets, and `stats` counts failures and successes per IP per
host in each bucket.

**Tuning note:** an internet-facing SSH server will trip this rule many times a
day, so it's most useful when you **only escalate the `high` results** (failures
plus a success) and treat the rest as background noise. Also exclude your own
vulnerability scanners and admin jump hosts by IP. Because `bin` uses fixed
buckets, a burst that straddles 02:10 and 02:20 can be split in two, so a
sliding window (such as `streamstats` with `time_window`) is more reliable once
you're comfortable with SPL. Field names depend on your add-on and parsing, so
check what your environment extracts before relying on `process` or `host`.

---

## Your turn

1. In the sample, the attacker tries `root` three times and is then
   disconnected. Which `sshd` setting caused that, and why doesn't it stop the
   attack overall?
2. Map each attacker line to the closest Windows event and status code from
   Day 01. Which `sshd` message has no neat Windows equivalent?
3. The `deploy` account logged in at 02:14:24. List the **first three things**
   you'd check or do next. (Think about Scenario 01: contain, then scope.)
4. Name **two configuration changes** to `web01` that would make this attack
   fail, and explain how each one would show up differently in `auth.log`.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.
2.
3.
4.

---

## Further reading

- OpenBSD manual: [sshd(8)](https://man.openbsd.org/sshd) · [sshd_config(5)](https://man.openbsd.org/sshd_config) (see `MaxAuthTries`, `PasswordAuthentication`, `PermitRootLogin`)
- MITRE ATT&CK: [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) · [T1021.004 SSH](https://attack.mitre.org/techniques/T1021/004/)
- SigmaHQ: [Linux detection rules](https://github.com/SigmaHQ/sigma/tree/master/rules/linux)

⬅️ [Learning log index](README.md) · ➡️ Day 03: Password spraying vs brute force (13 Oct)
