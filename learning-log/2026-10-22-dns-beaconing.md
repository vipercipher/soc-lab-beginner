# Day 12 — DNS Logs: Beaconing and Random-Looking Domains

📅 22 October 2026 · 🏷️ Log analysis · ⏱️ ~25 min

---

## Why it matters

Day 09 ended with `remit.dat` landing in Ben Okafor's `%TEMP%` folder on
`WS-FIN03`. Downloading a file is only stage one for most attackers: the
malware then needs to **phone home** to get instructions. To do that it
almost always has to look up a domain name first, so **DNS logs** are often
the first place the second stage shows up. Two patterns give it away:
**beaconing** (the same lookup on a steady clock) and **random-looking
domains** (names no human would type). In ATT&CK terms (Day 10) both sit
under **Command and Control**.

---

## The concept

### DNS in one minute

Before a program can connect to `www.northwind-example.com`, it asks a DNS
resolver "what IP is this name?" The resolver answers with a record, or says
the name doesn't exist.

| Record type | What it returns | Example |
|---|---|---|
| **A** | An IPv4 address | `intranet.northwind-example.com → 192.0.2.20` |
| **AAAA** | An IPv6 address | Same idea, for IPv6 |
| **CNAME** | An alias pointing at another name | `www → web01.northwind-example.com` |
| **MX** | The mail server for a domain | Used on Day 08's email path |
| **TXT** | Free text | Where SPF and DMARC live (Day 08) |

| Response | Meaning | Why an analyst cares |
|---|---|---|
| **NOERROR** | The name exists, here's the answer | Normal |
| **NXDOMAIN** | The name **does not exist** | A few are typos; **bursts** are suspicious |
| **SERVFAIL** | The resolver couldn't get an answer | Usually a DNS problem, not an attack |

### Where DNS logs come from

| Source | Where it's collected | Sees the **process**? |
|---|---|---|
| **Sysmon Event ID 22** (`DNSEvent`) | Each Windows endpoint | **Yes**: `Image` names the program that asked |
| **Windows DNS Server** analytic log | The DNS server (often a domain controller) | No, only the client IP |
| **Network sensor** (for example Zeek `dns.log`) | A network tap or span port | No, only the client IP |

Today uses **Sysmon Event ID 22**, because it answers the question the other
two can't: *which program* made the lookup. It builds on Day 05, and
the key fields are:

| Field | What it holds |
|---|---|
| `UtcTime` | When the query was made (UTC) |
| `Image` | Full path of the process that made the query |
| `QueryName` | The name being looked up |
| `QueryStatus` | Result as a Windows code: `0` = success, `9003` = name does not exist (NXDOMAIN), `9501` = no records of that type |
| `QueryResults` | The answers; IPv4 addresses show as `::ffff:203.0.113.5;` |

> 💡 Sysmon sees lookups made through the Windows DNS client. A program
> that uses its own resolver or DNS-over-HTTPS (some browsers do) may not
> appear, which is one reason to keep network-side DNS logs too.

### Beaconing

Once malware is running, it checks in with its **command-and-control (C2)**
server on a timer: "any orders for me?" That regular check-in is a
**beacon**. Most beacons add a little **jitter** (a random wobble of a few
seconds) so the timing isn't perfectly even, but over a few minutes the
rhythm is still obvious.

| | Human browsing | Malware beacon |
|---|---|---|
| Timing | Bursty, irregular, follows the working day | Steady interval (60 s, 5 min, 1 h), day and night |
| Process | Browser, Outlook, Teams | Something unexpected: `rundll32.exe`, a binary in `%TEMP%` |
| Domain | Many different names | The **same** name, over and over |

### Random-looking domains (DGA)

Blocking one C2 domain is easy (Day 09: domains are "Simple" on the Pyramid
of Pain). So some malware uses a **domain generation algorithm (DGA)**: it
computes a long list of random-looking names each day, and the attacker
registers just one or two of them. The malware tries each name until one
resolves. In DNS logs that looks like:

| Signal | Normal name | DGA-style name |
|---|---|---|
| Looks like words? | `intranet`, `mail`, `inventory` | `q8vzk2mxw7tj` |
| Letters and digits mixed? | Rarely | Often |
| Vowels? | Plenty | Few or none |
| Result | Mostly NOERROR | **Mostly NXDOMAIN**, then one that works |

Analysts often measure "randomness" with **Shannon entropy**: a score that
is higher when the characters are more evenly mixed. It's a useful hint,
but CDNs and cloud services also use long random-looking labels, so never
alert on entropy alone.

---

## Sample logs

Back on `WS-FIN03` (`192.0.2.37`) on **16 October**, right after Day 09's
download. Times are UTC (03:15 UTC is **14:15 in Sydney**). First, one
extra Sysmon **Event ID 1** recorded a second after `remit.dat` was written:

```
UtcTime (2026-10-16)  EventID  PID   PPID  ParentImage     Image          CommandLine
03:15:01              1        6544  6420  powershell.exe  rundll32.exe   rundll32.exe C:\Users\ben.okafor\AppData\Local\Temp\remit.dat,Start
```

Then **every Sysmon Event ID 22** from `WS-FIN03` between 03:00 and 03:22.
`Image` is shortened to the file name. `invagent.exe` is Northwind's
IT asset inventory agent.

```
UtcTime (2026-10-16)  Image          QueryName                          QueryStatus  QueryResults
03:00:00              invagent.exe   inventory.northwind-example.com    0            ::ffff:192.0.2.15;
03:02:15              OUTLOOK.EXE    mail.northwind-example.com         0            ::ffff:192.0.2.10;
03:09:41              msedge.exe     intranet.northwind-example.com     0            ::ffff:192.0.2.20;
03:10:12              msedge.exe     intarnet.northwind-example.com     9003         -
03:15:00              invagent.exe   inventory.northwind-example.com    0            ::ffff:192.0.2.15;
03:15:02              rundll32.exe   q8vzk2mxw7tj.example               9003         -
03:15:02              rundll32.exe   zt4pwq9lkx2v.example               9003         -
03:15:02              rundll32.exe   m2xq7vbk9rzd.example               9003         -
03:15:03              rundll32.exe   wk9fz3tqpx7l.example               9003         -
03:15:03              rundll32.exe   r3bn8xkq2wfy.example               9003         -
03:15:03              rundll32.exe   c9tq4zmk7vxp.example               9003         -
03:15:04              rundll32.exe   h7kd2vxq8mzp.example               0            ::ffff:203.0.113.140;
03:16:05              rundll32.exe   h7kd2vxq8mzp.example               0            ::ffff:203.0.113.140;
03:17:06              rundll32.exe   h7kd2vxq8mzp.example               0            ::ffff:203.0.113.140;
03:18:04              rundll32.exe   h7kd2vxq8mzp.example               0            ::ffff:203.0.113.140;
03:19:07              rundll32.exe   h7kd2vxq8mzp.example               0            ::ffff:203.0.113.140;
03:20:05              rundll32.exe   h7kd2vxq8mzp.example               0            ::ffff:203.0.113.140;
03:21:06              rundll32.exe   h7kd2vxq8mzp.example               0            ::ffff:203.0.113.140;
```

---

## What to look for

1. **The wrong process is doing DNS.** `rundll32.exe` is a Windows tool for
   running code inside DLLs. Here PowerShell (PID 6420, Day 09's download)
   started it to run a `.dat` file from `%TEMP%`. That's a strong signal on
   its own, and it means every lookup by PID 6544 belongs to the
   downloaded file, not to Windows.
2. **Six misses in two seconds.** Between 03:15:02 and 03:15:03,
   `rundll32.exe` looks up **6** different names and gets **6** NXDOMAINs
   (`9003`). Every one is 12 characters, letters and digits mixed, **no
   vowels**, under the same parent domain. That's the DGA pattern: trying
   names until one exists.
3. **The seventh name works.** `h7kd2vxq8mzp.example` looks just as random
   but resolves to `203.0.113.140`. The attacker registered that one. It's
   the C2 domain, and `203.0.113.140` is a new IOC for Day 09's list.
4. **Then the clock starts.** `rundll32.exe` asks for `h7kd2vxq8mzp.example`
   **7** times between 03:15:04 and 03:21:06. The gaps are **61, 61, 58,
   63, 58 and 61** seconds: an average of about **60 seconds** with a
   jitter of about **±3 seconds**. Nobody clicks a link every minute on the
   minute. That's a beacon.
5. **The typo is not a DGA.** Edge's `intarnet.northwind-example.com` also
   got a `9003`, but it's **1** miss, by a browser, on Northwind's own
   domain, with a readable name, and the next lookup was the right
   spelling. Everyday noise.
6. **The other "beacon" is legitimate.** `invagent.exe` queries
   `inventory.northwind-example.com` at exactly 03:00:00 and 03:15:00: a
   perfect **15-minute** timer to an internal IP. Software you own beacons
   too. The difference is the **process, the destination and the
   reputation**, not the timing alone.
7. **Totals.** Of **18** DNS events, **13** come from `rundll32.exe`
   (6 NXDOMAIN + 7 successful), **7** NXDOMAINs in all (6 + Ben's typo), and
   only **1** external IP is returned: `203.0.113.140`.

---

## Detection logic

**In plain English:** two checks on Sysmon DNS events, each grouped by host
and process. **Beaconing:** the same process asks for the same name **6 or
more** times, and the gap between lookups barely changes (standard
deviation **5 seconds or less**). **DGA-style misses:** one process gets
NXDOMAIN for **5 or more different names** within 5 minutes.

**SPL, beaconing (Splunk, Sysmon data via the Splunk Add-on for Sysmon):**

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 QueryStatus=0
| sort 0 _time
| streamstats current=f last(_time) AS prev_time BY host, Image, QueryName
| eval interval=_time-prev_time
| stats count AS queries, avg(interval) AS avg_interval, stdev(interval) AS jitter,
        min(_time) AS first_seen, max(_time) AS last_seen, values(QueryResults) AS answers
        BY host, Image, QueryName
| where queries >= 6 AND jitter <= 5
| eval avg_interval=round(avg_interval, 1), jitter=round(jitter, 1)
| convert ctime(first_seen) ctime(last_seen)
```

How it works:

- `sort 0 _time` puts events oldest first (the `0` removes Splunk's default
  10,000-row limit), so `streamstats ... last(_time)` with `current=f`
  gives each event the time of the **previous** lookup of the same name by
  the same process on the same host.
- `interval` is the gap in seconds. The first lookup in each group has no
  previous one, so its interval is empty and `avg` and `stdev` skip it.
- `stats` counts lookups and measures the average gap and its standard
  deviation (Splunk's `stdev` is the sample standard deviation). A small
  `jitter` means a steady clock.

On the sample, it returns **1** row: `WS-FIN03`, `rundll32.exe`,
`h7kd2vxq8mzp.example`, **7** queries, `avg_interval` **60.3**, `jitter`
**2.0**, answer `::ffff:203.0.113.140;`. `invagent.exe` is dropped with only
**2** lookups, and every other name appears once.

**SPL, DGA-style NXDOMAIN burst:**

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 QueryStatus=9003
| bin _time span=5m
| stats count AS nxdomain, dc(QueryName) AS unique_names, values(QueryName) AS names
        BY _time, host, Image
| where unique_names >= 5
```

On the sample, it returns **1** row: the 03:15 bucket, `WS-FIN03`,
`rundll32.exe`, **6** NXDOMAINs for **6** unique names. Edge's typo is
**1** name in the 03:10 bucket, so it's dropped.

**Tuning note:** run the beacon search over a window long enough to see the
rhythm (for example the last 4 hours, every hour); a 1-hour beacon needs
many hours to reach 6 lookups. Over a full day, `invagent.exe` would make
**96** lookups with a jitter near **0** and fire, so keep an allow-list of
**known agents and internal destinations** (by `Image` and domain), and
review it, rather than raising the threshold. Some beacons use large
jitter (±30% or more), so a companion search on "same name, more than 20
lookups a day, from a non-browser process" catches what the `jitter <= 5`
check misses. For DGAs, real malware often tries dozens or hundreds of
names, so `>= 5` is deliberately low for this lab; check how many NXDOMAINs
your noisiest legitimate processes produce before you settle on a number.
As on Day 02, fixed 5-minute buckets can split a burst in two. Finally, the
Windows DNS client caches answers, and many long-lived programs only look a
name up when its TTL (time to live) runs out, so a quiet DNS log doesn't
prove there was no beacon: pair it with network connection events (Sysmon
Event ID 3, Day 09) and firewall logs (Day 13).

For Day 10's mapping lookup, these become rules **NW-009** and **NW-010**:

```
NW-009,Command and Control,T1071,Application Layer Protocol
NW-010,Command and Control,T1568.002,Domain Generation Algorithms
```

---

## Your turn

1. Work out the 6 gaps between `rundll32.exe`'s lookups of
   `h7kd2vxq8mzp.example` yourself and check the average. Why do you think
   malware authors add jitter instead of using an exact 60 seconds? Does it
   help them against the beacon search above?
2. Ben's typo and the DGA burst both returned `9003`. List three
   differences between them that an analyst can see in the log, and say
   which of those the NXDOMAIN search actually uses.
3. Place `h7kd2vxq8mzp.example`, `203.0.113.140` and "a non-browser
   process making 6+ NXDOMAIN lookups in 5 minutes" on the Pyramid of Pain
   (Day 09). If the attacker's DGA picks a new name tomorrow, which of your
   detections still work?
4. You've confirmed the beacon. Write your next three steps, in order
   (think contain, then scope, as in Scenario 01). Which other hosts would
   you search for lookups of the DGA's parent domain, and which logs would
   show whether `WS-FIN03` actually **connected** to `203.0.113.140`?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (Event ID 22: DNSEvent) · [DNS logging and diagnostics](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics)
- MITRE ATT&CK: [T1568.002 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/) · [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) · [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/)
- SigmaHQ: [Windows DNS query rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/dns_query)
- Splunk Docs: [Splunk Add-on for Sysmon](https://docs.splunk.com/Documentation/AddOns/released/MSSysmon/About) · [streamstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Streamstats)
- NIST: [SP 800-81-2, Secure Domain Name System (DNS) Deployment Guide](https://csrc.nist.gov/pubs/sp/800/81/2/final)

⬅️ [Learning log index](README.md) · ➡️ [Day 13: Firewall logs: recognising a port scan (23 Oct)](2026-10-23-firewall-port-scan.md)
