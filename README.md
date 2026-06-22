# Writeups

Security CTF and lab writeups covering web application vulnerabilities, privilege escalation, cloud security, and more. Sourced from various platforms and competitions.

---

## Format

Each writeup follows a tutorial and technical deep dive structure:

- **Summary** - the full attack chain in plain language before any technical detail
- **Recon** - what was found and how, including tools and key output
- **Exploitation** - step by step with commands, payloads, and explanation of why each step works
- **Privilege Escalation** (where applicable) - each hop from foothold to root or flag
- **Key Takeaways** - the vulnerability class, why it exists, and what to look for on real targets

---

## Structure

```
Platform/
  Lab-Name/
    writeup.md
```

---

## BugForge Labs

| Lab | Difficulty | Vulnerability |
|-----|-----------|---------------|
| [blackmesa-001](BugForge/blackmesa-001/writeup.md) | Hard | SQLi in message field → dump config → OTP → flag |
| [cafeclub-002](BugForge/cafeclub-002/writeup.md) | Medium | UNION SQLi + business logic (negative loyalty points) |
| [cheesy-002](BugForge/cheesy-002/writeup.md) | Easy | SQLi auth bypass |
| [cheesy-005](BugForge/cheesy-005/writeup.md) | Easy | Parameter type confusion (array discount stacking) |
| [cheesy-does-it-003](BugForge/cheesy-does-it-003/writeup.md) | Easy | Business logic / client-side amount manipulation |
| [copypasta-003](BugForge/copypasta-003/writeup.md) | Easy | IDOR / broken access control |
| [copypasta-008](BugForge/copypasta-008/writeup.md) | Easy | API token name collision - no user_id scope |
| [furhire-003](BugForge/furhire-003/writeup.md) | Medium | IDOR / access control |
| [furhire-008](BugForge/furhire-008/writeup.md) | Medium | Stored SSRF to localhost /reporting |
| [furhire-010](BugForge/furhire-010/writeup.md) | Hard | CSPT → email hijack → password reset → 2FA proto bypass → ATO |
| [galaxydash-011](BugForge/galaxydash-011/writeup.md) | Medium | Handlebars SSTI via invoice_template → context dump → flag |
| [ottergram-011](BugForge/ottergram-011/writeup.md) | Easy | Client-side privacy filter bypass → IDOR on post detail |
| [shadyoaks-financial](BugForge/shadyoaks-financial/writeup.md) | Easy | Business logic (negative shares → balance inflation) |
| [sokudo-005](BugForge/sokudo-005/writeup.md) | Easy | GraphQL IDOR - user(id:1) returns admin password to any authenticated user |
| [tanuki-004](BugForge/tanuki-004/writeup.md) | Easy | IDOR on /api/stats/:user_id - no ownership check |
| [tanuki-006](BugForge/tanuki-006/writeup.md) | Easy | IDOR on PUT /api/profile/:username - no ownership check |
| [vaultly-004](BugForge/vaultly-004/writeup.md) | Medium | Prototype pollution via PATCH metadata __proto__ → published data room projection bypass → hidden vault disclosure |
