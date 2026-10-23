# Day 13 — Firewall Logs: Recognising a Port Scan

📅 23 October 2026 · 🏷️ Log analysis · ⏱️ ~25 min

---

## Why it matters

Before an attacker breaks in, they usually **look around** first: which of
Northwind's addresses are alive, and which doors (ports) are open on them?
The tool for that is a **port scan**, and the place it shows up most clearly
is the **firewall log**, because every probe has to pass the firewall to
reach anything. On Day 02 `web01`'s SSH port was guessed at, and on Day 11
its website was attacked with SQL injection. Both attackers had to find
those open ports first. In ATT&CK terms (Day 10), a scan from the internet
is **Reconnaissance**; the same scan from *inside* the network is
**Discovery**, and a much bigger worry.

---

## The concept

### What a firewall log line says

Every connection attempt is described by the **5-tuple** plus the decision
the firewall made:

| Field | What it holds | Example |
|---|---|---|
| **Source IP** | Who started the connection | `198.51.100.150` |
| **Source port** | A temporary port on the sender's side | `40001` |
| **Destination IP** | Who they tried to reach | `203.0.113.10` |
| **Destination port** | The service they wanted | `443` (HTTPS) |
| **Protocol** | TCP, UDP or ICMP | `TCP` |
| **Action** | What the firewall did | `allow` or `deny` |

The **destination port** tells you which service was being knocked on. The
ones you'll see most often:

| Port | Service | Port | Service |
|---|---|---|---|
| 21 | FTP | 143 | IMAP (mail) |
| 22 | SSH (Day 02) | 443 | HTTPS |
| 23 | Telnet | 445 | SMB (Windows file sharing) |
| 25 | SMTP (mail) | 3306 | MySQL |
| 53 | DNS (Day 12) | 3389 | RDP (Day 01) |
| 80 | HTTP | 5432 | PostgreSQL |
| 110 | POP3 (mail) | 8080 | Alternative HTTP |
| 135, 139 | Windows RPC and NetBIOS | | |

### How a TCP port scan works

A TCP connection starts with a three-step **handshake**: SYN →
SYN/ACK → ACK. A scanner such as Nmap sends just the first **SYN** to a
port and watches what comes back:

| Reply | Nmap calls the port | What it means |
|---|---|---|
| **SYN/ACK** | `open` | A service is listening |
| **RST** (reset) | `closed` | Reachable, but nothing listening |
| **Nothing** (or ICMP unreachable) | `filtered` | A firewall dropped the probe |

A **SYN scan** never finishes the handshake, so the target service may not
log anything. The firewall still sees every probe, which is why it's the
best place to catch one. (UDP scans exist too, but they're slower and less
common; today sticks to TCP.)

### The shapes of a scan

| Shape | Pattern in the log | What the attacker wants |
|---|---|---|
| **Vertical** | One source → **one** host → **many** ports | "What's running on this server?" |
| **Horizontal (sweep)** | One source → **many** hosts → **one** port | "Who has RDP open?" |
| **Block** | One source → many hosts → many ports | Both at once (noisy) |

Two more giveaways: scanners are **fast** (dozens of ports a second) and a
raw SYN scan often reuses the **same source port** for every probe, while a
normal program picks a new one for each connection.

> 💡 Internet-facing addresses are scanned **all day, every day** by
> research projects, search engines for devices, and attackers alike. An
> external scan on its own is background noise. It becomes interesting when
> the same source **comes back** to the ports it found open, or when the
> scan comes from **inside** your network.

### Where the logs come from

Northwind's perimeter firewall `NW-FW01` sends its logs in **CEF** (Common
Event Format) to Microsoft Sentinel, where they land in the
**`CommonSecurityLog`** table. The columns used today are `TimeGenerated`,
`DeviceName`, `DeviceAction`, `Protocol`, `SourceIP`, `SourcePort`,
`DestinationIP` and `DestinationPort`. Each vendor chooses its own
`DeviceAction` words; `NW-FW01` writes `allow` and `deny`, and a `deny`
here is a silent drop, so a scanner sees those ports as `filtered`.

In this lab, Northwind's public addresses are `203.0.113.1` to
`203.0.113.14`, and `web01`'s public address is `203.0.113.10`. The
firewall allows ports **80** and **443** to `web01` from anywhere, and
port **22** only from admin addresses such as Priya's `203.0.113.24` (the
fix suggested in Day 02's answers). Everything else inbound is denied.

---

## Sample logs

`CommonSecurityLog` rows from `NW-FW01` on **22 October**, every inbound
connection to Northwind's public addresses between 00:38 and 00:53 UTC
(11:38 to 11:53 in Sydney). All rows are `Protocol: TCP`.

```
TimeGenerated (2026-10-22)  DeviceAction  SourceIP         SourcePort  DestinationIP   DestinationPort
00:38:12                    allow         203.0.113.24     61802       203.0.113.10    443
00:39:40                    allow         203.0.113.24     61810       203.0.113.10    22
00:41:07                    allow         198.51.100.150   40001       203.0.113.10    443
00:41:07                    deny          198.51.100.150   40001       203.0.113.10    21
00:41:07                    deny          198.51.100.150   40001       203.0.113.10    3389
00:41:07                    allow         198.51.100.150   40001       203.0.113.10    80
00:41:07                    deny          198.51.100.150   40001       203.0.113.10    22
00:41:07                    deny          198.51.100.150   40001       203.0.113.10    445
00:41:08                    deny          198.51.100.150   40001       203.0.113.10    25
00:41:08                    deny          198.51.100.150   40001       203.0.113.10    3306
00:41:08                    deny          198.51.100.150   40001       203.0.113.10    8080
00:41:08                    deny          198.51.100.150   40001       203.0.113.10    135
00:41:08                    deny          198.51.100.150   40001       203.0.113.10    23
00:41:08                    deny          198.51.100.150   40001       203.0.113.10    110
00:41:09                    deny          198.51.100.150   40001       203.0.113.10    5432
00:41:09                    deny          198.51.100.150   40001       203.0.113.10    139
00:41:09                    deny          198.51.100.150   40001       203.0.113.10    143
00:41:09                    deny          198.51.100.150   40001       203.0.113.10    53
00:43:55                    allow         203.0.113.77     52144       203.0.113.10    443
00:47:31                    allow         198.51.100.150   51230       203.0.113.10    443
00:47:33                    allow         198.51.100.150   51236       203.0.113.10    443
00:52:10                    deny          198.51.100.200   33012       203.0.113.1     3389
00:52:15                    deny          198.51.100.200   33019       203.0.113.2     3389
00:52:20                    deny          198.51.100.200   33025       203.0.113.3     3389
00:52:25                    deny          198.51.100.200   33031       203.0.113.4     3389
00:52:30                    deny          198.51.100.200   33038       203.0.113.5     3389
00:52:35                    deny          198.51.100.200   33044       203.0.113.6     3389
00:52:40                    deny          198.51.100.200   33050       203.0.113.7     3389
00:52:45                    deny          198.51.100.200   33057       203.0.113.8     3389
```

---

## What to look for

1. **One source, one host, sixteen ports.** Between 00:41:07 and 00:41:09,
   `198.51.100.150` knocks on **16** different ports of `web01`
   (`203.0.113.10`) in about **2 seconds**. No person types that fast.
   It's a **vertical scan**.
2. **The same source port every time.** All 16 probes come from source
   port `40001`. A browser or SSH client picks a fresh port for each
   connection (compare Priya's `61802` and `61810`). A fixed source port
   is typical of a raw SYN scanner.
3. **The scan found two open doors.** The firewall **allowed** ports **80**
   and **443** and **denied** the other **14**, including **22** (SSH is
   allow-listed to admin IPs only) and **3389** (RDP). From the outside,
   the scanner now knows `web01` runs a website and that everything else is
   filtered. The firewall log can't show whether `web01` answered, only
   that the probe was let through.
4. **Then it came back.** Six minutes later, at 00:47:31 and 00:47:33,
   `198.51.100.150` makes **2** normal connections to port **443**, each
   from a new source port. That's the shift from "what's open?" to "let's
   look at what's open". The next place to check is `web01`'s Nginx access
   log (Day 11) for requests from `198.51.100.150` after 00:47.
5. **A sweep for RDP.** From 00:52:10 to 00:52:45, `198.51.100.200` tries
   port **3389** on **8** consecutive addresses (`203.0.113.1` to `.8`),
   one every **5 seconds**. One port, many hosts: a **horizontal scan**.
   It's the same internet scanner that probed `/wp-login.php` and `/.env`
   on Day 11, hunting for exposed RDP like the one attacked on Day 01.
   All 8 were denied, so it learned nothing useful.
6. **The normal rows.** Priya (`203.0.113.24`) uses HTTPS and then SSH,
   both allowed because she's on the admin list. Sara (`203.0.113.77`)
   opens the website once. Different source ports, ordinary pace, ports
   that match what they use.
7. **Totals.** **29** rows: **7** allowed (Priya 2, Sara 1, and
   `198.51.100.150` 4: ports 80 and 443 in the scan plus 2 return visits)
   and **22** denied (14 from the vertical scan, 8 from the sweep).

---

## Detection logic

**In plain English:** two checks on the firewall log, each over 5-minute
windows. **Vertical scan:** one source IP reaches **10 or more different
ports** on the same destination. **Horizontal scan:** one source IP tries
the same port on **5 or more different hosts**. Count both allowed and
denied attempts, because a scan is about how many doors were tried, not how
many were blocked.

**KQL, vertical scan (Microsoft Sentinel, `CommonSecurityLog` table):**

```kql
let window = 5m;
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceName == "NW-FW01" and Protocol == "TCP"
| summarize Ports = dcount(DestinationPort),
            Allowed = countif(DeviceAction == "allow"),
            Denied = countif(DeviceAction == "deny"),
            OpenPorts = make_set_if(DestinationPort, DeviceAction == "allow", 50),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
          by SourceIP, DestinationIP, bin(TimeGenerated, window)
| where Ports >= 10
| order by Ports desc
```

On the sample, it returns **1** row: `198.51.100.150` → `203.0.113.10`,
**16** ports, **2** allowed, **14** denied, `OpenPorts` holding 443 and 80, first
seen 00:41:07, last seen 00:41:09. The return visits at 00:47 fall in the
next window with only **1** port (443), and Priya's **2** ports stay well
under the threshold.

**KQL, horizontal scan (sweep):**

```kql
let window = 5m;
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceName == "NW-FW01" and Protocol == "TCP"
| summarize Hosts = dcount(DestinationIP),
            Targets = make_set(DestinationIP, 50),
            Denied = countif(DeviceAction == "deny")
          by SourceIP, DestinationPort, bin(TimeGenerated, window)
| where Hosts >= 5
```

On the sample, it returns **1** row: `198.51.100.200`, port **3389**,
**8** hosts, **8** denied. `198.51.100.150` only ever touches **1** host,
so it doesn't appear here.

How they work:

- `summarize ... by ..., bin(TimeGenerated, window)` groups rows into
  5-minute buckets, as on Day 01. `dcount()` counts **distinct** values,
  so 16 different ports score 16, but 16 visits to port 443 score 1.
- `countif()` and `make_set_if()` only count or collect rows that match a
  condition, which is how the vertical query lists the ports that were let
  through. (`dcount()` is an estimate on very large numbers, but exact
  enough at the small counts used here.)

**Tuning note:** external scans are constant, so treat these as
**low-severity** signals to aggregate, not alerts that page someone at
night. Raise the priority when the same source later gets **allowed**
connections to a port it found open (as `198.51.100.150` did), or when the
source is **internal**. Allow-list Northwind's own authorised vulnerability
scanner by IP so its weekly run doesn't fire. A patient scanner that sends
one probe every few minutes will never reach 10 ports in one 5-minute
bucket, and as on Day 02, fixed buckets can split a fast scan in two; a
companion search over **24 hours** with a higher bar (for example 50
distinct ports) catches the slow ones. Finally, check what your firewall
actually logs: some only log denies by default, some rate-limit logging,
and a scan the firewall never logged can't be detected here.

For Day 10's mapping lookup, these become rules **NW-011** and **NW-012**:

```
NW-011,Reconnaissance,T1595,Active Scanning
NW-012,Reconnaissance,T1595.001,Scanning IP Blocks
```

---

## Your turn

1. List the 16 ports `198.51.100.150` tried and name the service on each
   (use the table above). Which two were let through, and what would an
   Nmap report against `web01` show as `open` and as `filtered`?
2. The sweep from `198.51.100.200` sends one probe every 5 seconds. How
   slow would it have to go to slip under the horizontal search (5 hosts in
   one 5-minute bucket)? Write a KQL change that would still catch it.
3. Priya's SSH connection at 00:39:40 was allowed, but the scanner's probe
   of port 22 was denied. Which firewall rule explains that, and how does
   it change what you'd expect to see in `web01`'s `auth.log` (Day 02)
   compared with 12 October?
4. Imagine the vertical-scan query fires with `SourceIP` `192.0.2.37`
   (`WS-FIN03`, Days 09–12) and destinations inside `192.0.2.0/24`. Why is
   this far more serious than the external scan, which ATT&CK tactic and
   technique would you use instead of Reconnaissance, and what are your
   first two steps? (Hint: a perimeter firewall never sees traffic that
   stays inside one subnet, so where would these logs come from?)

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [CommonSecurityLog table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog) · [Ingest Syslog and CEF messages to Microsoft Sentinel with the Azure Monitor Agent](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama) · [summarize operator](https://learn.microsoft.com/en-us/kusto/query/summarize-operator)
- MITRE ATT&CK: [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) · [T1595.001 Scanning IP Blocks](https://attack.mitre.org/techniques/T1595/001/) · [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- Nmap Reference Guide: [Port scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html) · [Port states](https://nmap.org/book/man-port-scanning-basics.html)
- NIST: [SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/pubs/sp/800/41/r1/final)

⬅️ [Learning log index](README.md) · ➡️ [Day 14: Persistence: new accounts and admin group changes (4720, 4732) (24 Oct)](2026-10-24-new-accounts-admin-groups.md)
