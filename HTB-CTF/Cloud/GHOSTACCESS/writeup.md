GHOSTACCESS - HTB Cloud Challenge Notes
=========================================

## Overview

This is a GCP cloud forensics challenge that follows on from EXPOSEDSUPPLY. The
attacker already has the leaked `buildops-ci-runner` service account key. In this
challenge, they escalate privileges through an IAM impersonation chain, plant a
persistent backdoor on a dormant service account, then erase evidence by deleting
a storage object and destroying a secret version.

The challenge asks you to identify what the attacker left behind (the backdoor),
how they got there (privilege escalation chain), and what they destroyed during
cleanup.

**GCP Project**: `helical-cursor-494913-k9`
**Attack IP**: `33.252.46.44`
**Normal admin IP**: `120.196.206.75`

---

## Artifacts Structure

```
artifacts/
  admin_activity_logs.csv          # IAM and admin API calls (~2507 rows)
  storage_data_access_logs.csv     # GCS read/write/delete events (~2503 rows)
  iam_exports.json                 # IAM state AFTER the attack (shows surviving backdoor)
  artifact_registry_inventory.json # Container registry state
  website_snapshot/                # Website snapshot (same as EXPOSEDSUPPLY)
```

---

## Step 1 - Understand the IAM Landscape (iam_exports.json)

Read `iam_exports.json` first. This is the IAM state captured AFTER the attack.
It tells you what the attacker left behind.

**Service Account bindings:**

```
supply-pipeline-sa:
  buildops-ci-runner → roles/iam.serviceAccountTokenCreator
  (buildops-ci-runner can impersonate supply-pipeline-sa)

elections-ghost-sa:
  user:gilded@d9.kor → roles/iam.serviceAccountTokenCreator   ← BACKDOOR (survives)
  (the attacker's external account can impersonate elections-ghost-sa)

elections-deployer:
  supply-pipeline-sa → roles/iam.serviceAccountTokenCreator
  (supply-pipeline-sa can impersonate elections-deployer)
```

**Project-level bindings:**
```
supply-pipeline-sa → roles/resourcemanager.projectIamAdmin   ← KEY PRIVILEGE
buildops-ci-runner → roles/iam.securityReviewer
buildops-ci-runner → roles/storage.objectAdmin
elections-deployer → roles/storage.admin
```

**The full privilege escalation chain the attacker used:**
```
buildops-ci-runner (leaked key from supply-bundle.zip)
  ↓  GenerateAccessToken (TokenCreator binding on supply-pipeline-sa)
supply-pipeline-sa
  ↓  holds roles/resourcemanager.projectIamAdmin at project level
     → can call SetIamPolicy on any resource in the project
  ↓  GenerateAccessToken (TokenCreator binding on elections-deployer)
elections-deployer
  ↓  used to make IAM changes (to avoid using supply-pipeline-sa directly)
     SetIamPolicy: grant self roles/iam.securityAdmin  → can now modify SA IAM policies
     SetIAMPolicy: plant gilded@d9.kor on elections-ghost-sa
     SetIamPolicy: remove securityAdmin from self       → cleanup
```

This is a "shadow admin" pattern: the attacker uses an intermediary SA
(`elections-deployer`) to make the changes, rather than acting directly as
`supply-pipeline-sa`, to reduce the traceability back to the initial compromise.

---

## Step 2 - Identify the Surviving Backdoor

**Method**: Read `iam_exports.json`. Look for bindings that reference external
accounts (not `serviceAccount:` prefixed, but `user:` prefixed) or unknown
external domains.

From `iam_exports.json`:
```json
"elections-ghost-sa@helical-cursor-494913-k9.iam.gserviceaccount.com": {
  "bindings": [
    {
      "members": ["user:gilded@d9.kor"],
      "role": "roles/iam.serviceAccountTokenCreator"
    }
  ]
}
```

This binding is the backdoor. `gilded@d9.kor` is an external account with no
connection to the legitimate organisation (`nightfall.net`). With `TokenCreator`
on `elections-ghost-sa`, the attacker can generate access tokens for that SA
at any time in the future, giving them persistent access to the project.

`elections-ghost-sa` itself has `roles/storage.admin` (via project level through
`elections-deployer`) - wait, actually check the chain again. The key point is
the backdoor identity is `gilded@d9.kor` impersonating `elections-ghost-sa`.
The attacker chose a "ghost" SA (one that may not be actively monitored) to
hide the backdoor.

**Answer**: 
- Backdoor principal: `user:gilded@d9.kor`
- Backdoor target SA: `elections-ghost-sa@helical-cursor-494913-k9.iam.gserviceaccount.com`
- IAM role: `roles/iam.serviceAccountTokenCreator`

---

## Step 3 - Find the Backdoor Timestamp

**Method**: Search `admin_activity_logs.csv` for `SetIAMPolicy` on `elections-ghost-sa`.

```python
import csv
with open('admin_activity_logs.csv') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        method = row.get('protoPayload.methodName','')
        resource = row.get('protoPayload.resourceName','')
        if 'SetIAMPolicy' in method and 'elections-ghost-sa' in resource:
            print(f"Row {i}: {row['timestamp']} | {method} | {row['protoPayload.authenticationInfo.principalEmail']}")
            print(f"  bindings: {row['protoPayload.request.policy.bindings']}")
```

From `admin_activity_logs.csv` (Row 1785):
```
timestamp:  2026-05-03T13:44:54.575385359Z
method:     google.iam.admin.v1.SetIAMPolicy
principal:  elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com
ip:         33.252.46.44
resource:   projects/helical-cursor-494913-k9/serviceAccounts/elections-ghost-sa@...
bindings:   [{"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:gilded@d9.kor"]}]
```

**Answer**: `2026-05-03T13:44:54Z`

---

## Step 4 - Identify the Attacker IP

**Method**: Look at the IP on the backdoor-planting event and all other attack events.
All attacker activity (from the automated SA chain) originates from one IP.

From Row 1785 and all other attack events:
```
ip: 33.252.46.44
```

This IP appears in thousands of rows from `2026-05-01` onwards as `buildops-ci-runner`
makes repeated API calls. This is the attacker's automation host that had the leaked
`buildops-ci-runner` SA key.

**Answer**: `33.252.46.44`

---

## Step 5 - Find the Privilege Escalation Role

**Method**: Look for `SetIamPolicy` events where `elections-deployer` grants itself
an elevated role. This will show how the attacker temporarily gained the power to
modify SA IAM policies.

From `admin_activity_logs.csv` (Row 1679):
```
timestamp:  2026-05-03T13:36:16.917899485Z
method:     SetIamPolicy
principal:  elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com
ip:         33.252.46.44
resource:   projects/helical-cursor-494913-k9
bindings:   [{"role": "roles/iam.securityAdmin", 
              "members": ["serviceAccount:elections-deployer@..."]}]
```

`elections-deployer` granted itself `roles/iam.securityAdmin` at the project level.
This role includes `iam.serviceAccounts.setIamPolicy`, which allows setting IAM
policies on individual service accounts - which is what it then used to plant
`gilded@d9.kor` on `elections-ghost-sa`.

But this was only possible because `supply-pipeline-sa` (which `buildops-ci-runner`
impersonated via TokenCreator) holds `roles/resourcemanager.projectIamAdmin`, giving
it the ability to call `SetIamPolicy` on the project. That is the root privilege.

**Answer**: `roles/resourcemanager.projectIamAdmin` (held by `supply-pipeline-sa`)

This is the role that made the entire chain possible. Without `projectIamAdmin` on
`supply-pipeline-sa`, `elections-deployer` could not have granted itself `securityAdmin`.

---

## Step 6 - Find the Cleanup: securityAdmin Removal

**Method**: Search for the `SetIamPolicy` event that removed `securityAdmin` from
`elections-deployer`. The attacker granted it temporarily and removed it immediately
after planting the backdoor, to reduce forensic evidence.

From `admin_activity_logs.csv` (Row 1788):
```
timestamp:  2026-05-03T13:45:13.736542231Z
method:     SetIamPolicy
principal:  elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com
ip:         33.252.46.44
resource:   projects/helical-cursor-494913-k9
bindings:   [] (empty - role removed)
```

The `securityAdmin` role was removed from `elections-deployer` just 19 seconds after
the backdoor was planted. This is a classic "just-in-time privilege" pattern to avoid
leaving elevated permissions in place.

**Answer**: `2026-05-03T13:45:13Z`

---

## Step 7 - Find the Deleted Storage Object

**Method**: Search `storage_data_access_logs.csv` for `storage.objects.delete` events.

```python
import csv
with open('storage_data_access_logs.csv') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        if 'delete' in row.get('protoPayload.methodName','').lower():
            print(f"Row {i}: {row['timestamp']}")
            print(f"  {row['protoPayload.methodName']} by {row['protoPayload.authenticationInfo.principalEmail']}")
            print(f"  resource: {row['protoPayload.resourceName']}")
```

From `storage_data_access_logs.csv` (Row 1763):
```
timestamp:  2026-05-03T13:45:19.119349958Z
method:     storage.objects.delete
principal:  elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com
ip:         33.252.46.44
resource:   projects/_/buckets/mec-elections-logistics-pub/objects/config/app.config.json
```

`app.config.json` was deleted 6 seconds after the `securityAdmin` was removed and
6 seconds before the secret was destroyed. It was likely a configuration file that
contained credentials or internal infrastructure details that the attacker wanted
to erase.

**Answer**: `gs://mec-elections-logistics-pub/config/app.config.json`

---

## Step 8 - Find the Destroyed Secret

**Method**: Search `admin_activity_logs.csv` for `DestroySecretVersion` events.

From `admin_activity_logs.csv` (Row 1790):
```
timestamp:  2026-05-03T13:45:25.581213991Z
method:     google.cloud.secretmanager.v1.SecretManagerService.DestroySecretVersion
principal:  elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com
ip:         33.252.46.44
resource:   projects/helical-cursor-494913-k9/secrets/election-db-credentials/versions/3
```

The attacker destroyed version 3 of the `election-db-credentials` secret. Earlier
in the logs, `buildops-ci-runner` had accessed versions 1, 2, and 3 of this secret
(e.g., Row 1457 accessed version 3, Row 1456 accessed version 2). After reading the
credentials, the attacker destroyed the latest version to impede incident response.

Note: `DestroySecretVersion` is irreversible. Unlike `DisableSecretVersion` (which
can be re-enabled), destroying a version permanently removes the secret material.

**Answer**: 
- Secret name: `election-db-credentials`
- Full resource path: `projects/helical-cursor-494913-k9/secrets/election-db-credentials/versions/3`

---

## Step 9 - Full Attack Timeline

```
2026-05-01T07:05Z
  buildops-ci-runner (33.252.46.44) - GetServiceAccount on elections-ghost-sa
  [Initial recon: attacker maps all service accounts in the project]

2026-05-01T08:06Z
  buildops-ci-runner (33.252.46.44) - GenerateIdToken for supply-pipeline-sa (ID: 114834742891578631905)
  [Attacker confirms the TokenCreator chain works: can impersonate supply-pipeline-sa]

2026-05-01T09:14Z
  buildops-ci-runner (33.252.46.44) - AccessSecretVersion election-db-credentials/versions/2
  [Attacker reads the database credentials]

2026-05-01T11:38Z
  buildops-ci-runner (33.252.46.44) - GetServiceAccount on elections-deployer
  [Attacker identifies elections-deployer as a useful intermediary SA]

2026-05-03T13:00Z - 13:35Z
  buildops-ci-runner (33.252.46.44) - repeated AccessSecretVersion, GenerateAccessToken, ListDockerImages
  [Attacker methodically enumerates all resources: secrets, containers, SAs]

2026-05-03T13:36:05Z
  buildops-ci-runner (33.252.46.44) - GenerateAccessToken for elections-deployer (ID: 107823456019264038175)
  [Attacker impersonates elections-deployer via the SA chain]

2026-05-03T13:36:12Z
  supply-pipeline-sa (33.252.46.44) - GenerateAccessToken for elections-deployer (ID: 111156569751647653741)
  [supply-pipeline-sa also generates a token for elections-deployer - confirms projectIamAdmin in use]

2026-05-03T13:36:16Z  ← PRIVILEGE ESCALATION
  elections-deployer (33.252.46.44) - SetIamPolicy on project
  → grants self: roles/iam.securityAdmin
  [Now has permission to modify SA-level IAM policies]

2026-05-03T13:44:54Z  ← BACKDOOR PLANTED
  elections-deployer (33.252.46.44) - SetIAMPolicy on elections-ghost-sa
  → adds: user:gilded@d9.kor with roles/iam.serviceAccountTokenCreator

2026-05-03T13:45:13Z  ← CLEANUP: IAM
  elections-deployer (33.252.46.44) - SetIamPolicy on project
  → removes: roles/iam.securityAdmin from elections-deployer

2026-05-03T13:45:19Z  ← CLEANUP: STORAGE
  elections-deployer (33.252.46.44) - storage.objects.delete
  → deletes: gs://mec-elections-logistics-pub/config/app.config.json

2026-05-03T13:45:25Z  ← CLEANUP: SECRETS
  elections-deployer (33.252.46.44) - DestroySecretVersion
  → destroys: election-db-credentials/versions/3
```

**Total time from securityAdmin grant to cleanup completion: ~69 seconds**
(13:36:16 → 13:45:25). This is highly automated - no human can move this fast.

---

## Flags / Answers Summary

| # | Question | Answer |
|---|----------|--------|
| 1 | Surviving backdoor binding (principal + role + target) | `user:gilded@d9.kor` → `roles/iam.serviceAccountTokenCreator` on `elections-ghost-sa` |
| 2 | SA the backdoor is on | `elections-ghost-sa@helical-cursor-494913-k9.iam.gserviceaccount.com` |
| 3 | IAM role in surviving binding | `roles/iam.serviceAccountTokenCreator` |
| 4 | Timestamp backdoor was written | `2026-05-03T13:44:54Z` |
| 5 | Attacker IP | `33.252.46.44` |
| 6 | Project-level role enabling privesc | `roles/resourcemanager.projectIamAdmin` |
| 7 | Timestamp securityAdmin was removed | `2026-05-03T13:45:13Z` |
| 8 | Storage object deleted | `gs://mec-elections-logistics-pub/config/app.config.json` |
| 9 | Secret name | `election-db-credentials` |
| 10 | Full secret version resource path | `projects/helical-cursor-494913-k9/secrets/election-db-credentials/versions/3` |

---

## Key Investigation Techniques

1. **Read iam_exports.json first**: It shows the IAM state AFTER the attack. Any
   `user:` member (not `serviceAccount:`) with `TokenCreator` on an SA is a red flag,
   especially if the domain doesn't match the organisation.

2. **Pivot from IAM snapshot to log evidence**: Once you spot the suspicious binding
   in `iam_exports.json`, grep `admin_activity_logs.csv` for `SetIAMPolicy` on that
   SA to find the exact timestamp and actor.

3. **Detect temporary privilege escalation**: Look for a `SetIamPolicy` event granting
   a role, followed closely (within minutes) by another `SetIamPolicy` removing that
   same role. This "grant → use → revoke" pattern is a strong attacker indicator.
   The total window here was 8m57s (13:36:16 → 13:45:13).

4. **Look for DestroySecretVersion vs AccessSecretVersion**: If an SA reads a secret
   AND later destroys the same secret version, the attacker was trying to cover their
   tracks. Note `Disable` is reversible but `Destroy` is permanent.

5. **Follow the SA impersonation chain**: In GCP logs, `GenerateAccessToken` calls
   reveal who is impersonating whom. The numeric resource IDs in these calls map to
   SA unique IDs - cross-reference with the SA emails in `iam_exports.json`.

6. **elections-ghost-sa was chosen intentionally**: The name "ghost" suggests this
   SA was dormant (not actively used by any workload), making it an ideal backdoor
   target. Dormant SAs are rarely monitored. Always review SA-level IAM bindings on
   SAs that aren't referenced in any running workloads.

7. **CSV analysis pattern for large log files**: These CSVs are ~2MB each (2500 rows),
   too large to `cat`. Use Python `csv.DictReader` and filter by field values:
   ```python
   import csv
   with open('admin_activity_logs.csv') as f:
       for row in csv.DictReader(f):
           if 'SetIAMPolicy' in row['protoPayload.methodName']:
               print(row['timestamp'], row['protoPayload.authenticationInfo.principalEmail'])
   ```
