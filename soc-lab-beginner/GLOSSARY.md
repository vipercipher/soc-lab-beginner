# Glossary — plain-English security terms

New to security? Here are the terms used in these labs, explained simply.

**SOC (Security Operations Center)**
The team that watches an organisation's systems for signs of attack and responds
when something looks wrong. A "SOC analyst" is a person on that team.

**Alert**
An automatic notification from a security system saying "something here might be
wrong, a human should look." An alert is a starting point, not a verdict.

**Log**
A record of things that happened on a system, one line per event. Sign-in logs
record every login attempt.

**IP address**
A number that identifies a device on the internet, a bit like a return address on
an envelope. It can often be traced to a rough location.

**Authentication (auth)**
Proving you are who you say you are, usually with a password.

**MFA (Multi-Factor Authentication)**
A second proof on top of your password, like a code from an app or a "Yes/No"
prompt on your phone. It means a stolen password alone isn't enough to get in.

**Brute-force attack**
An attacker guessing a password over and over, very fast, until one works. In
logs it looks like many failed attempts, evenly spaced, in a short time.

**Impossible travel**
When the same account signs in from two places so far apart that a person
couldn't physically travel between them in the time available (e.g. Sydney at
lunch, then Europe an hour later). A strong sign the account is shared or stolen.

**MFA fatigue (MFA bombing)**
An attacker who already has the password spams the victim with MFA prompts,
hoping they'll tap "Yes" just to make it stop. If they do, the attacker gets in.

**Account takeover / compromise**
When an attacker gains control of someone's account.

**Contain / containment**
Stopping an attack from spreading or continuing, e.g. disabling the account and
logging the attacker out. Usually the first thing you do once you're sure it's
real.

**Revoke sessions**
Force-log-out of all active logins for an account. Important because resetting a
password does **not** automatically kick out someone already signed in.

**Least privilege**
Giving each account only the access it truly needs, so a compromised account can
reach as little as possible.

**Baseline / "normal"**
What ordinary, safe activity looks like for a user or system. You compare
suspicious activity against the baseline to see what's out of place.

**Identify → Contain → Eradicate → Recover**
A common order of steps for handling an incident: work out what's happening, stop
it, clean up what the attacker left, then get things back to normal.
