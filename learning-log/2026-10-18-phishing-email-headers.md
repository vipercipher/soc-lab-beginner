# Day 08 — Phishing Triage: Reading Email Headers (SPF, DKIM, DMARC)

📅 18 October 2026 · 🏷️ Email security · ⏱️ ~25 min

---

## Why it matters

Day 07 ended on `WS-FIN07` with a question: Word opened `Invoice_88214.docm`
from Outlook's attachment cache, so **which email delivered it?** Today you go
back up the chain to the message itself. Phishing is still one of the most
common ways attackers get in, and "user reported a suspicious email" is one of
the most common tickets in a SOC queue. The body of an email is written by the
attacker and says whatever they want. The **headers** are partly written by
the mail servers it passed through, and they hold the evidence: where the
message really came from, and whether the sender's domain vouches for it.

---

## The concept

### Two "from" addresses

Every email has **two** sender addresses, and they don't have to match:

| Name | Where you see it | Who checks it |
|---|---|---|
| **Envelope sender** (`MAIL FROM`, shown afterwards as `Return-Path`) | Hidden; used by servers for bounces | **SPF** |
| **Header `From`** | What the user sees in Outlook | **DMARC** |

An attacker can type anything into the header `From`, just like writing any
return address on a paper envelope. That gap is what the three checks below
try to close.

### Reading `Received` headers: bottom to top

Each mail server that handles a message adds a `Received:` line **at the
top**. So the **lowest** `Received:` line is the first hop, and the most
trustworthy one is the line **your own** server added, because the attacker
can't fake it. It records the IP address that actually connected to you.

### SPF, DKIM and DMARC

| Check | Question it answers | How | Published in DNS as |
|---|---|---|---|
| **SPF** (RFC 7208) | Is this IP allowed to send for the **envelope** domain? | Receiver looks up the `MAIL FROM` domain's list of allowed senders | TXT record at the domain: `v=spf1 ip4:198.51.100.14 -all` |
| **DKIM** (RFC 6376) | Was this message signed by domain `d=`, and is it unchanged? | Sender signs chosen headers and the body; receiver checks the signature with the public key | TXT record at `selector._domainkey.domain` |
| **DMARC** (RFC 7489) | Does the **visible `From`** domain line up with a domain that passed SPF or DKIM? | Requires SPF **or** DKIM to pass **and** be *aligned* with the `From` domain | TXT record at `_dmarc.domain`: `v=DMARC1; p=quarantine; ...` |

**Alignment** is the key idea. SPF can pass for `quick-send.example` while the
`From` header says `fabrikam-supplies.example`. On its own, SPF doesn't care.
DMARC does: it asks whether the domain that passed is the **same** as the
`From` domain. By default alignment is *relaxed*, so a subdomain counts:
`bounce.fabrikam-supplies.example` aligns with `fabrikam-supplies.example`.

The DMARC **policy** (`p=`) tells receivers what the domain owner wants done
with mail that fails:

| Policy | Meaning |
|---|---|
| `p=none` | Monitor only; deliver as normal and send reports |
| `p=quarantine` | Treat as suspicious (junk folder or quarantine) |
| `p=reject` | Refuse the message |

### `Authentication-Results`: the verdict in one header

The receiving server writes its verdicts into an `Authentication-Results`
header (RFC 8601), so you rarely need to check DNS yourself. Microsoft 365
writes it like this:

```
Authentication-Results: spf=pass (sender IP is 198.51.100.14)
 smtp.mailfrom=bounce.fabrikam-supplies.example; dkim=pass (signature was verified)
 header.d=fabrikam-supplies.example;dmarc=pass action=none
 header.from=fabrikam-supplies.example;compauth=pass reason=100
```

`smtp.mailfrom` is the envelope domain SPF checked, `header.d` is the DKIM
signing domain, and `header.from` is the visible `From` domain that DMARC
compared them against. `compauth` is Microsoft's own **composite** verdict,
which combines these with other signals.

> 💡 **The analyst's shortcut:** SPF, DKIM and DMARC prove which **domain**
> sent a message, not that the domain is **trustworthy**. An attacker who
> registers their own lookalike domain can pass all three. A `pass` answers
> "is this really from `X`?", and you still have to ask "should we trust `X`?"

---

## Sample logs

Northwind's mail runs on Microsoft 365. Server names in the headers are
simplified. Times are UTC (00:36 UTC on Thursday 15 October is **11:36 in
Sydney**).

First, the DNS records for the supplier Priya deals with, and for the domain
that sent her the invoice (all fictional):

```
fabrikam-supplies.example         TXT  "v=spf1 ip4:198.51.100.14 -all"
_dmarc.fabrikam-supplies.example  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@fabrikam-supplies.example"

fabrikam-suppl1es.example         TXT  "v=spf1 ip4:203.0.113.62 -all"
_dmarc.fabrikam-suppl1es.example  TXT  "v=DMARC1; p=none"
  (registered 2026-10-14, one day before the email)
```

Then the **message trace** for finance mailboxes between 00:15 and 00:40 UTC
that morning (5 messages). `MailFrom domain` is the envelope domain;
`From` is what the user saw.

```
Received  Recipient   From (header)                        MailFrom domain                   SenderIP        Attachment          SPF   DKIM  DMARC  Action
00:18:40  priya.nair  billing@fabrikam-supplies.example    bounce.fabrikam-supplies.example  198.51.100.14   Statement_Sep.pdf   pass  pass  pass   Delivered
00:22:03  priya.nair  billing@fabrikam-supplies.example    quick-send.example                203.0.113.61    Invoice_88214.docm  pass  none  fail   Quarantined
00:29:17  ben.okafor  news@payroll-weekly.example          payroll-weekly.example            198.51.100.120  -                   pass  pass  pass   Delivered
00:35:10  priya.nair  tom.reyes@northwind-example.com      northwind-example.com             (internal)      Budget_Q4.xlsx      -     -     -      Delivered
00:36:48  priya.nair  accounts@fabrikam-suppl1es.example   fabrikam-suppl1es.example         203.0.113.62    Invoice_88214.docm  pass  pass  pass   Delivered
```

The **headers of the 00:36:48 message**, the one Priya opened, trimmed:

```
Received: from mx1.northwind-example.com (192.0.2.25) by mbx02.northwind-example.com;
 Thu, 15 Oct 2026 00:36:49 +0000
Received: from mail.fabrikam-suppl1es.example (203.0.113.62) by mx1.northwind-example.com;
 Thu, 15 Oct 2026 00:36:48 +0000
Authentication-Results: spf=pass (sender IP is 203.0.113.62)
 smtp.mailfrom=fabrikam-suppl1es.example; dkim=pass (signature was verified)
 header.d=fabrikam-suppl1es.example;dmarc=pass action=none
 header.from=fabrikam-suppl1es.example;compauth=pass reason=100
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=fabrikam-suppl1es.example;
 s=s1; h=from:to:subject:date:message-id; bh=…; b=…
Return-Path: <accounts@fabrikam-suppl1es.example>
From: "Fabrikam Supplies Accounts" <accounts@fabrikam-suppl1es.example>
Reply-To: <fabrikam.accounts@mailbox-free.example>
To: <priya.nair@northwind-example.com>
Subject: RE: Overdue invoice 88214
Date: Thu, 15 Oct 2026 00:36:41 +0000
Message-ID: <a71c09e2f3@mail.fabrikam-suppl1es.example>
Content-Type: multipart/mixed; boundary="…"
  (attachment: Invoice_88214.docm)
```

And the `Authentication-Results` of the **00:22:03** message, the one that
was quarantined:

```
Authentication-Results: spf=pass (sender IP is 203.0.113.61)
 smtp.mailfrom=quick-send.example; dkim=none (message not signed)
 header.d=none;dmarc=fail action=quarantine
 header.from=fabrikam-supplies.example;compauth=fail reason=000
```

---

## What to look for

1. **Two attempts, same bait.** Both `Invoice_88214.docm` messages carry the
   same file name and a near-identical subject, **14 minutes 45 seconds**
   apart (00:22:03 and 00:36:48), from two neighbouring IPs, `203.0.113.61`
   and `203.0.113.62`. That reads like one attacker trying twice.
2. **Why the first one failed.** At 00:22:03 the `From` said
   `fabrikam-supplies.example`, the real supplier. SPF **passed**, but for
   `quick-send.example`, which isn't the `From` domain. There was **no** DKIM
   signature. With nothing aligned, DMARC **failed**, and Fabrikam's
   `p=quarantine` policy did its job: `action=quarantine`.
3. **Why the second one got through.** At 00:36:48 the attacker stopped
   pretending to be `fabrikam-supplies.example` and used **their own** domain,
   `fabrikam-suppl1es.example` (a digit `1` instead of the letter `i`). SPF,
   DKIM and DMARC all **pass**, because the attacker controls that domain's
   DNS. This is the shortcut above in action: authentication passed, trust
   was never earned.
4. **A brand-new domain.** The lookalike was registered on 14 October, one
   day before the email. Northwind had never received mail from it. Newly
   registered domains are a classic phishing signal (MITRE **T1583.001
   Acquire Infrastructure: Domains**).
5. **`Reply-To` points somewhere else.** Replies would go to
   `mailbox-free.example`, not to the sender's domain. If Priya answers to
   "check the invoice", she talks to the attacker.
6. **"RE:" with no thread.** The subject starts with `RE:`, but there's no
   `In-Reply-To` or `References` header. It's dressed up as a reply to make it
   look like an ongoing conversation. It isn't one.
7. **The normal rows.** Of the **5** messages, **3** are routine: the real
   Fabrikam statement (aligned via the `bounce.` subdomain and DKIM), a
   payroll newsletter to `ben.okafor`, and Tom's internal budget file, the
   `Budget_Q4.xlsx` that Excel opened on Day 07. Only **2** carry the
   `.docm`, and only **1** of those was delivered.
8. **Joining the dots.** Delivered at 00:36:48, opened in Word at 00:41:02
   (Day 07): about **4 minutes** from inbox to macro. Together, the two days
   map to **T1566.001 Spearphishing Attachment** followed by **T1204.002
   Malicious File**, with the lookalike sender as **T1656 Impersonation**.

---

## Detection logic

**In plain English:** alert when an inbound email carrying a
**macro-enabled Office attachment** is **delivered** to a mailbox, and the
sender's `From` domain has **never** delivered mail to Northwind in the
previous 30 days. This catches the lookalike even though it passed SPF, DKIM
and DMARC, because it doesn't rely on authentication at all.

Like Days 06 and 07, there's no count threshold: **one** matching email is
enough. The "time window" here is the 30-day history used to decide what
counts as a known sender.

**KQL (Microsoft Defender XDR advanced hunting, `EmailEvents` and
`EmailAttachmentInfo` tables):**

```kql
let lookback = 30d;
let knownDomains =
    EmailEvents
    | where Timestamp between (ago(lookback) .. ago(1d))
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | distinct SenderFromDomain;
EmailAttachmentInfo
| where Timestamp > ago(1d)
| where FileName matches regex @"(?i)\.(docm|dotm|xlsm|xltm|xlam|pptm|potm)$"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(1d)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
  ) on NetworkMessageId, RecipientEmailAddress
| where SenderFromDomain !in (knownDomains)
| extend Auth = parse_json(AuthenticationDetails)
| project Timestamp, RecipientEmailAddress, SenderFromAddress,
          SenderMailFromDomain, SenderIPv4, Subject, FileName,
          SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM),
          DMARC = tostring(Auth.DMARC)
```

How it works:

- `knownDomains` is every `From` domain that delivered mail to Northwind
  between 30 days ago and yesterday. It's a **baseline** of normal senders.
- `EmailAttachmentInfo` has one row per attachment. The regex keeps only
  macro-enabled Office types (the `m` at the end means *macro*). `(?i)` makes
  it case-insensitive, so `Invoice.DOCM` still matches.
- The `join` on `NetworkMessageId` (the message's unique ID) and
  `RecipientEmailAddress` attaches the email's details to each attachment,
  keeping only messages that were actually **delivered**.
- `!in (knownDomains)` drops senders seen before.
- `AuthenticationDetails` is a JSON string such as
  `{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}`.
  `parse_json` turns it into fields so the verdicts sit next to the alert.
  They're shown for context, not used to filter.

On the sample, the query returns **1** row: the 00:36:48 message to Priya.
The 00:22:03 `.docm` is excluded because it was quarantined (in
`EmailEvents`, quarantine shows as `DeliveryAction == "Blocked"`), the
statement's attachment is a `.pdf`, and the budget file is an `.xlsx` sent
internally. `fabrikam-suppl1es.example` is not in `knownDomains`, so the row
survives the last filter.

**A second view: spoofing that was stopped.** A quarantined spoof isn't a
breach, but it tells you who is being **targeted**. This lists DMARC failures
over the last day:

```kql
EmailEvents
| where Timestamp > ago(1d) and EmailDirection == "Inbound"
| extend Auth = parse_json(AuthenticationDetails)
| where tostring(Auth.DMARC) == "fail"
| summarize Messages = count(), Recipients = make_set(RecipientEmailAddress)
          by SenderFromDomain, SenderMailFromDomain, SenderIPv4, DeliveryAction
```

On the sample it returns **1** row: `fabrikam-supplies.example` sent via
`quick-send.example` from `203.0.113.61`, `Blocked`, to `priya.nair`. On its
own that's "the controls worked". Seen next to the first query's hit, it's the
attacker's first attempt.

**Tuning note:** a genuinely new supplier sending a macro-enabled
spreadsheet will fire the first query. That's rare enough to be worth a look,
not to exclude. If you must exclude one, exclude the **exact** domain after
verifying it with the business, never a pattern like `*fabrikam*`, because
that's exactly what the lookalike matches. The 30-day baseline is a trade-off:
longer catches more "new" domains but needs more history (advanced hunting
keeps 30 days). Patient attackers register a domain and send harmless mail
for weeks first, so pair this with other signals: a `Reply-To` on a different
domain, newly registered domains, and lookalikes of your top suppliers. And
fix your own side: if `_dmarc.northwind-example.com` is `p=none`, anyone can
spoof Northwind to your customers.

---

## Your turn

1. For the 00:22:03 message, SPF says `pass` but DMARC says `fail`. In your
   own words, explain how both can be true. What would the attacker have
   needed to make DMARC **pass** while keeping
   `From: billing@fabrikam-supplies.example`?
2. The 00:36:48 message passed SPF, DKIM and DMARC. List **four** clues in the
   headers and message trace that it's still a phish, ordered from strongest
   to weakest, and say why you ranked them that way.
3. Write a KQL query against `EmailEvents` that finds **every** Northwind
   mailbox that received mail from `203.0.113.61`, `203.0.113.62` or any
   address at `fabrikam-suppl1es.example` in the last 7 days. For anyone who
   got a delivered copy, which Day 07 query would you run next, and on which
   host?
4. Northwind's own DMARC record is `v=DMARC1; p=none`. Explain what moving to
   `p=reject` would protect against, and why it would **not** have stopped the
   email Priya opened.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Email authentication in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about) · [Anti-spam message headers in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo) · [EmailEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table) · [EmailAttachmentInfo table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table)
- IETF RFCs: [RFC 7208 SPF](https://www.rfc-editor.org/rfc/rfc7208) · [RFC 6376 DKIM](https://www.rfc-editor.org/rfc/rfc6376) · [RFC 7489 DMARC](https://www.rfc-editor.org/rfc/rfc7489) · [RFC 8601 Authentication-Results](https://www.rfc-editor.org/rfc/rfc8601)
- NIST: [SP 800-177 Rev. 1, Trustworthy Email](https://csrc.nist.gov/pubs/sp/800/177/r1/final)
- MITRE ATT&CK: [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) · [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/) · [T1656 Impersonation](https://attack.mitre.org/techniques/T1656/)

⬅️ [Learning log index](README.md) · ➡️ Day 09: IOCs vs behaviours: the Pyramid of Pain (19 Oct)
