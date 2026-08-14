# Apriti Seamo

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{w3Ll_d3sErV3d_Ch4mp_471fee75}`

## Summary

A PHP login page leaks its own source through a leftover editor backup file
(`impossibleLogin.php~`, a vim-style swap/backup suffix that Apache serves as plain text instead
of executing as PHP). The revealed logic checks whether the submitted username and password are
loosely unequal (`!=`, via a negated `==` branch) but then strictly identical once hashed with
`sha1()` (`===`). Passing arrays instead of strings for both fields makes `sha1()` fail with a
type warning and return `NULL` for both calls, so `NULL === NULL` is true and the check passes
without ever knowing a real username or password.

## Discovery

The login form itself gives nothing away, and basic SQL injection probing produces no error
differential. Checking for common backup/leftover files finds one still being served:

```
GET /impossibleLogin.php~  -> 200
```

The `.php~` extension isn't mapped to the PHP handler, so Apache returns the raw source instead
of executing it. Decoding the file's base64/octal-obfuscated strings gives the real logic:

```php
if (isset($_POST['username']) && isset($_POST['pwd'])) {
    $u = $_POST['username'];
    $p = $_POST['pwd'];
    if ($u == $p) {
        echo "<br/>Failed! No flag for you";
    } else {
        if (sha1($u) === sha1($p)) {
            echo file_get_contents("../flag.txt");
        } else {
            echo "<br/>Failed! No flag for you";
        }
    }
}
```

Sending the same value for both fields as arrays (`username[]=x&pwd[]=x`) fails, because two
identical arrays are loosely equal (`==`) to each other, hitting the first `Failed` branch before
the `sha1()` check is ever reached. The values need to be array-typed *and* different from each
other so the first check is false and execution falls through to the vulnerable `===` comparison.

## Proof of Concept

```
curl -s -X POST http://TARGET/impossibleLogin.php -d "username[]=1&pwd[]=2"
```

```
Warning: sha1() expects parameter 1 to be string, array given ...
Warning: sha1() expects parameter 1 to be string, array given ...
picoCTF{w3Ll_d3sErV3d_Ch4mp_471fee75}
```

`sha1()` on an array argument in PHP 7.x raises a warning (not a fatal error) and returns `NULL`.
Since both calls fail identically, `NULL === NULL` evaluates true, and the code that reads the
flag file executes.

## Root Cause

Two independent issues combine here: a leftover editor backup file exposed the full application
source, and the authentication check relied on hashing user-controlled input without first
validating its type. PHP's permissive type coercion means a function that "fails" on unexpected
input (returning `NULL` with a warning instead of raising a hard error) can silently make an
identity comparison pass for two values that were never actually compared meaningfully.

## CWE / OWASP

- **CWE-697**: Incorrect Comparison (type-juggling via unvalidated array input to `sha1()`)
- **CWE-530**: Exposure of Backup File to an Unauthorized Control Sphere
- **OWASP A02:2021**: Cryptographic Failures
- **OWASP A05:2021**: Security Misconfiguration
