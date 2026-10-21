# Day 11 — Web Server Logs: SQL Injection Attempts in Nginx Access Logs

📅 21 October 2026 · 🏷️ Log analysis · ⏱️ ~25 min

---

## Why it matters

On Day 02, `web01`, Northwind's public-facing Ubuntu server, was attacked
through its **SSH** door. But the reason `web01` is on the internet at all is
the **website** it serves, and anyone in the world can send it a request.
**SQL injection (SQLi)** is one of the oldest and most damaging web attacks:
if the site pastes user input straight into a database query, an attacker
can make the database hand over data it should never show. In ATT&CK terms
(Day 10) it's **T1190 Exploit Public-Facing Application**, under **Initial
Access**. The first place a SOC analyst usually sees it is the web server's
**access log**.

---

## The concept

### What SQL injection is

Northwind's shop shows a product with a URL like `/products?id=12`. Behind
the scenes, a badly written app builds a database query by gluing the `id`
value into a string:

```
SELECT name, price, description, image FROM products WHERE id = 12
```

If the app doesn't check or safely handle `id`, an attacker can send
`12 AND 1=2` instead of `12`. The database now runs
`... WHERE id = 12 AND 1=2`, which is never true, so the page comes back
empty. The attacker has just proved they can **change the query's logic**.
From there they can extend the query to read other tables.

The fix is in the code, not the SOC: **parameterised queries** (prepared
statements) keep user input as data, never as part of the SQL. The SOC's job
is to spot attempts, and above all to spot the ones that **worked**.

### The Nginx access log

On Ubuntu, Nginx writes one line per request to
`/var/log/nginx/access.log` (problems go to `/var/log/nginx/error.log`). The
default format is called **combined**:

```
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

which produces lines like:

```
203.0.113.24 - - [21/Oct/2026:01:02:11 +0000] "GET /products?id=12 HTTP/1.1" 200 5120 "https://www.northwind-example.com/" "Mozilla/5.0 (...)"
```

The two `-` after the IP are a fixed dash and `$remote_user` (empty unless
the site uses HTTP login).

| Nginx variable | What it holds | Why an analyst cares |
|---|---|---|
| `$remote_addr` | Client IP | Who sent it (or the proxy in front of them) |
| `$time_local` | Time, with the server's UTC offset | Line up with other logs (Day 02 time zone warning) |
| `$request` | Method, path **and query string**, protocol | Where the injection payload shows up |
| `$status` | HTTP status code | Did the request error, succeed, or hit nothing? |
| `$body_bytes_sent` | Size of the response body | **Big jumps can mean data was returned** |
| `$http_referer` | Page the request came from | Real browsers usually send one; tools often don't |
| `$http_user_agent` | Client software | Tools often name themselves (but it's easy to fake) |

> 💡 Two blind spots: the combined format logs the **query string** of a
> `GET`, but **not the body of a `POST`** (login forms, search forms that
> post). And it doesn't record how long a request took unless you add
> `$request_time` to the format.

### Reading URL encoding

Browsers and tools **URL-encode** special characters, and Nginx logs the
request line as it was received. So you have to decode before you can read
the payload.

| Encoded | Character | Encoded | Character |
|---|---|---|---|
| `%27` | `'` (single quote) | `%2C` | `,` |
| `%20` or `+` | space | `%28` `%29` | `(` `)` |
| `%3D` | `=` | `%23` | `#` |
| `%22` | `"` (double quote) | `--` | SQL comment (not encoded) |

### The common SQLi families

| Family | What the attacker sends | What it looks like in the access log |
|---|---|---|
| **Error-based** | A stray `'` to break the query | A **500** (server error) where the normal page is 200 |
| **Boolean-based** | `AND 1=1` then `AND 1=2` | Two 200s with **different response sizes** |
| **UNION-based** | `ORDER BY n` to count columns, then `UNION SELECT ...` | 500s while counting, then a 200 with a **much bigger** response |
| **Time-based** | `SLEEP(5)` (MySQL) or `WAITFOR DELAY` (SQL Server) | Slow responses; only visible with `$request_time` |

---

## Sample logs

A simplified extract from `/var/log/nginx/access.log` on `web01`, which
serves `www.northwind-example.com`. The server runs on UTC, so `+0000`.
Long browser user agents are shortened to `Mozilla/5.0 (...)`.

```
203.0.113.24 - - [21/Oct/2026:01:02:11 +0000] "GET /products?id=12 HTTP/1.1" 200 5120 "https://www.northwind-example.com/" "Mozilla/5.0 (...) Chrome/130.0.0.0 Safari/537.36"
203.0.113.77 - - [21/Oct/2026:01:04:36 +0000] "GET /search?q=o%27brien+green+tea HTTP/1.1" 200 2871 "https://www.northwind-example.com/" "Mozilla/5.0 (...) Version/18.0 Safari/605.1.15"
198.51.100.200 - - [21/Oct/2026:01:15:02 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x"
198.51.100.200 - - [21/Oct/2026:01:15:03 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x"
198.51.100.61 - - [21/Oct/2026:01:22:40 +0000] "GET /products?id=12%27 HTTP/1.1" 500 177 "-" "sqlmap/1.8.3#stable (https://sqlmap.org)"
198.51.100.61 - - [21/Oct/2026:01:22:41 +0000] "GET /products?id=12%20AND%201%3D1 HTTP/1.1" 200 5120 "-" "sqlmap/1.8.3#stable (https://sqlmap.org)"
198.51.100.61 - - [21/Oct/2026:01:22:41 +0000] "GET /products?id=12%20AND%201%3D2 HTTP/1.1" 200 312 "-" "sqlmap/1.8.3#stable (https://sqlmap.org)"
198.51.100.61 - - [21/Oct/2026:01:22:43 +0000] "GET /products?id=12%20ORDER%20BY%205--%20- HTTP/1.1" 500 177 "-" "sqlmap/1.8.3#stable (https://sqlmap.org)"
198.51.100.61 - - [21/Oct/2026:01:22:44 +0000] "GET /products?id=12%20ORDER%20BY%204--%20- HTTP/1.1" 200 5120 "-" "sqlmap/1.8.3#stable (https://sqlmap.org)"
198.51.100.61 - - [21/Oct/2026:01:22:46 +0000] "GET /products?id=-1%20UNION%20SELECT%201%2C2%2C3%2C4--%20- HTTP/1.1" 200 5233 "-" "sqlmap/1.8.3#stable (https://sqlmap.org)"
198.51.100.61 - - [21/Oct/2026:01:22:49 +0000] "GET /products?id=-1%20UNION%20SELECT%201%2Cusername%2Cpassword_hash%2C4%20FROM%20users--%20- HTTP/1.1" 200 48210 "-" "sqlmap/1.8.3#stable (https://sqlmap.org)"
203.0.113.24 - - [21/Oct/2026:01:30:05 +0000] "GET /products?id=31 HTTP/1.1" 200 4980 "https://www.northwind-example.com/products?id=12" "Mozilla/5.0 (...) Chrome/130.0.0.0 Safari/537.36"
```

---

## What to look for

1. **Decode first.** `id=12%20AND%201%3D2` is `id=12 AND 1=2`, and the last
   request is `id=-1 UNION SELECT 1,username,password_hash,4 FROM users-- -`.
   You can't judge a request you haven't read in plain text.
2. **One IP, seven requests, nine seconds.** `198.51.100.61` sends **7**
   requests to `/products` between 01:22:40 and 01:22:49, with no referer.
   No shopper browses like that.
3. **The probe and the error.** The first request adds just a `'` and gets a
   **500**. A quote breaking the page is the classic sign that input reaches
   the SQL unescaped. (Compare Sara at `203.0.113.77`: her search for
   `o'brien green tea` also contains `%27`, but it's a normal page from a
   real browser with a referer. A quote alone is not an attack.)
4. **The boolean pair.** `AND 1=1` returns **5120** bytes, exactly the normal
   page for `id=12`. `AND 1=2` returns **312**, an empty page. The attacker's
   logic is changing the database's answer: the site is injectable.
5. **Counting columns.** `ORDER BY 5` fails (**500**), `ORDER BY 4` works
   (**200**), so the query has **4** columns. That's why the `UNION SELECT`
   that follows lists exactly four values.
6. **The response that matters.** `UNION SELECT 1,2,3,4` returns 5233 bytes,
   barely more than normal. The final request, naming `username` and
   `password_hash` from a `users` table, returns **48210** bytes, more than
   **9 times** the normal 5120. A `200` here is **bad news**, not good: it
   strongly suggests data came back. Of the 7 requests, **2** returned 500
   and **5** returned 200.
7. **The user agent.** `sqlmap` is a well-known automated SQLi testing tool
   that names itself by default. Useful, but remember the Pyramid of Pain
   (Day 09): a user agent is trivial to change. The **behaviour** above is
   what you should detect.
8. **The background noise.** `198.51.100.200` asks for `/wp-login.php` and
   `/.env` and gets **404s**. That's an internet-wide scanner checking for
   WordPress and leaked config files. Northwind doesn't run WordPress, so
   this is low priority (ATT&CK calls it Reconnaissance), not SQLi.
9. **The normal rows.** Priya (`203.0.113.24`) views products 12 and 31 with
   a browser and referers, 5 KB pages, minutes apart. Everyday browsing.

---

## Detection logic

**In plain English:** flag any request whose query string contains common
SQL injection keywords, in plain or URL-encoded form, unless the page didn't
exist (404). Then, per source IP, raise an alert at **3 or more** such
requests in 10 minutes, and make it **high** severity if any of them got an
unusually large response.

**Sigma (single request, `webserver` category):**

```yaml
title: SQL Injection Keywords In Web Request Query String
id: b3975cd0-a843-4c8b-8239-e2255567d55f
status: experimental
description: >
  Detects common SQL injection keywords (UNION SELECT, ORDER BY, boolean
  tests such as AND 1=1) in the query string of requests to a web server,
  in plain or URL-encoded form. Requests that returned 404 are excluded.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://owasp.org/www-community/attacks/SQL_Injection
author: Jay (SOC learning log)
date: 2026-10-21
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - 'union select'
      - 'union%20select'
      - 'union all select'
      - 'union%20all%20select'
      - 'order by '
      - 'order%20by%20'
      - 'and 1='
      - 'and%201%3D'
      - 'information_schema'
      - 'sleep('
      - 'sleep%28'
      - "'1'='1"
      - '%271%27%3D%271'
  filter_not_found:
    sc-status: 404
  condition: selection and not filter_not_found
falsepositives:
  - Search boxes or forums where people type SQL-like phrases ("order by")
  - Authorised vulnerability scans of the website
level: medium
```

How it works: `cs-uri-query` and `sc-status` are Sigma's standard field
names for web server logs; your Sigma backend or pipeline maps them to
whatever your Nginx parser produces. Sigma's `contains` is case-insensitive
by default, so `UNION%20SELECT` matches `union%20select`. On the sample it
matches **6** of the attacker's 7 requests: everything except the lone
`12%27`, which on purpose isn't in the list (it would also match Sara's
search). The 404 filter drops payloads aimed at pages that don't exist,
which can't have reached a database.

**SPL (Splunk, Nginx combined logs indexed as `sourcetype=access_combined`):**

```spl
index=web sourcetype=access_combined host=web01
| eval q=lower(urldecode(uri_query))
| where status!=404 AND match(q, "union(\s+all)?\s+select|order\s+by\s+\d+|\band\s+\d+\s*=\s*\d+|information_schema|sleep\s*\(|'1'\s*=\s*'1")
| bin _time span=10m
| stats count AS sqli_requests,
        count(eval(status>=500)) AS server_errors,
        count(eval(status==200)) AS ok_responses,
        max(bytes) AS max_bytes,
        values(uri_path) AS paths, values(useragent) AS user_agents
        BY _time, clientip
| where sqli_requests >= 3
| eval severity=if(max_bytes > 20000, "high", "medium")
```

How it works: Splunk's pre-trained `access_combined` sourcetype extracts
`clientip`, `uri_path`, `uri_query`, `status`, `bytes` and `useragent` from
each combined-format line. `urldecode()` turns `%20` into a space so one
regular expression covers encoded and plain payloads, and `lower()` makes it
case-insensitive. `stats` then counts matching requests per IP in each
10-minute bucket and keeps the largest response size.

On the sample, it returns **1** row: `198.51.100.61`, **6** SQLi requests,
**1** server error (`ORDER BY 5`), **5** 200 responses, `max_bytes` **48210**,
so severity **high**. Sara's quote, Priya's browsing and the 404 scanner
don't match at all.

**Tuning note:** the `20000`-byte line works because Northwind's product
pages are about 5 KB; base yours on your own pages' normal sizes per path.
Keyword lists are easy to dodge (`UNION/**/SELECT`, double encoding such as
`%2527`), so treat this as a first net, and give extra weight to the
**behaviour**: bursts of 500s from one IP, and size swings on the same path.
Exclude your own authorised scanner by IP, and expect a few false positives
from search terms like "order by phone". As on Day 02, fixed 10-minute
buckets can split a burst in two. Finally, if the site sits behind a load
balancer or CDN, `$remote_addr` is the proxy's IP, so log the real client IP
(for example from `X-Forwarded-For`, set by a proxy you trust) or every
attacker will look the same.

For Day 10's mapping lookup, this becomes rule **NW-008**:
`NW-008,Initial Access,T1190,Exploit Public-Facing Application`.

---

## Your turn

1. Decode all 7 requests from `198.51.100.61` into plain text, and label each
   one error-based, boolean-based or UNION-based. Which one does the Sigma
   rule miss, and does that matter for catching this attack?
2. Sara's search (`q=o%27brien+green+tea`) contains `%27`. Why doesn't
   either rule fire on it? What would happen to the SOC queue if you added
   `%27` to the Sigma selection list?
3. The last request returned 48210 bytes with a 200. Write down the **first
   three things** you'd do. (Contain, then scope, as in Scenario 01. Which
   logs other than `access.log` would tell you what data actually left?)
4. Add `198.51.100.200`'s two requests to your ATT&CK thinking from Day 10:
   which tactic and technique fit them? Would you write a rule for them,
   and why or why not?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Nginx docs: [Module ngx_http_log_module](https://nginx.org/en/docs/http/ngx_http_log_module.html) (the `combined` format and `log_format`)
- OWASP: [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) · [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) · [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
- SigmaHQ: [Web server detection rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web)
- Splunk Docs: [List of pretrained source types](https://docs.splunk.com/Documentation/Splunk/latest/Data/Listofpretrainedsourcetypes) · [Text functions (`urldecode`)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions)

⬅️ [Learning log index](README.md) · ➡️ [Day 12: DNS logs: beaconing and random-looking domains (22 Oct)](2026-10-22-dns-beaconing.md)
