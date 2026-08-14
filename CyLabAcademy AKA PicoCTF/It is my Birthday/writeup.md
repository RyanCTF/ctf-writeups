# It is my Birthday

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation / Cryptography
**Difficulty:** Medium
**Flag:** `picoCTF{c0ngr4ts_u_r_1nv1t3d_c63bbaf}`

## Summary

An upload form accepts two files and reveals its source (and the flag) only if both are valid,
distinct PDFs under 18KB that share an identical MD5 hash. MD5 is cryptographically broken
against collision attacks: known chosen-prefix and identical-prefix collision techniques let an
attacker construct two different messages with the same MD5 digest. Since PDF's file format is
flexible enough to embed the differing "collision blocks" inside otherwise-valid document
structure without breaking parsing, publicly documented MD5-collision PDF pairs satisfy every
server-side check.

## Discovery

The form posts to `/index.php` with two file fields (`file1`, `file2`). Submitting with the
`submit` field present but no real content returns the same static page, so the server clearly
guards its logic behind `isset($_POST["submit"])`.

## Proof of Concept

Rather than compute a fresh MD5 collision (a nontrivial cryptographic search even with modern
identical-prefix techniques), this reused a well-known, already-published pair: Nat McHugh's
2015 MD5-collision PDF demonstration (`poeMD5_A.pdf` / `poeMD5_B.pdf`, mirrored in the
`corkami/collisions` reference repository), two genuinely different, validly-formed PDF
documents (each 2868 bytes, well under the 18KB cap) that happen to share an MD5 digest:

```
$ file poeMD5_A.pdf poeMD5_B.pdf
poeMD5_A.pdf: PDF document, version 1.3, 1 page(s)
poeMD5_B.pdf: PDF document, version 1.3, 1 page(s)

$ md5sum poeMD5_A.pdf poeMD5_B.pdf
b347b04fac568905706c04f3ba4e221d  poeMD5_A.pdf
b347b04fac568905706c04f3ba4e221d  poeMD5_B.pdf

$ cmp -l poeMD5_A.pdf poeMD5_B.pdf | wc -l
18   # files differ in 18 bytes, well away from the shared %PDF header
```

Uploaded directly:

```python
import requests
files = {
    'file1': ('poeMD5_A.pdf', open('poeMD5_A.pdf', 'rb'), 'application/pdf'),
    'file2': ('poeMD5_B.pdf', open('poeMD5_B.pdf', 'rb'), 'application/pdf'),
}
r = requests.post("http://TARGET/index.php", files=files, data={'submit': 'Upload'})
```

The response dumps the app's own source via `highlight_file()`, confirming exactly what was
checked (size limit, MIME type, byte-for-byte inequality, then `md5_file()` equality) and
revealing the flag in a trailing comment:

```php
if (isset($_POST["submit"])) {
    $type1 = $_FILES["file1"]["type"];
    $type2 = $_FILES["file2"]["type"];
    $size1 = $_FILES["file1"]["size"];
    $size2 = $_FILES["file2"]["size"];
    $SIZE_LIMIT = 18 * 1024;

    if (($size1 < $SIZE_LIMIT) && ($size2 < $SIZE_LIMIT)) {
        if (($type1 == "application/pdf") && ($type2 == "application/pdf")) {
            $contents1 = file_get_contents($_FILES["file1"]["tmp_name"]);
            $contents2 = file_get_contents($_FILES["file2"]["tmp_name"]);

            if ($contents1 != $contents2) {
                if (md5_file($_FILES["file1"]["tmp_name"]) == md5_file($_FILES["file2"]["tmp_name"])) {
                    highlight_file("index.php");
                    die();
                } else { echo "MD5 hashes do not match!"; die(); }
            } else { echo "Files are not different!"; die(); }
        } else { echo "Not a PDF!"; die(); }
    } else { echo "File too large!"; die(); }
}

// FLAG: picoCTF{c0ngr4ts_u_r_1nv1t3d_c63bbaf}
```

## Root Cause

MD5 has been cryptographically broken against collision attacks since 2004 (Wang et al.), and
practical, fast identical-prefix and chosen-prefix collision tools have existed for over a
decade. Using `md5_file()` equality as a proxy for "these are the same submitted document" is
unsound: an attacker doesn't need to know any secret to produce two semantically different files
with a matching digest, only computation time (which, for identical-prefix MD5 collisions, is
now on the order of seconds to minutes on commodity hardware). PDF specifically is a popular
target for this because its container format tolerates the "junk" collision blocks without
breaking the parser, letting the two colliding files also be valid, openable, differently-
rendering documents rather than meaningless binary blobs.

## CWE / OWASP

- **CWE-328**: Use of Weak Hash (MD5 used for integrity/equivalence checking)
- **CWE-345**: Insufficient Verification of Data Authenticity
- **OWASP A02:2021**: Cryptographic Failures
