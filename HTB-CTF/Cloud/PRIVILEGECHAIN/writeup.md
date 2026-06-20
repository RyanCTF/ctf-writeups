PRIVILEGECHAIN - HTB Cloud Challenge Notes
===========================================

## Overview

This challenge combines everything from EXPOSEDSUPPLY and GHOSTACCESS into a single
end-to-end investigation: the full kill chain from leaked SA key → credential exploitation
→ IAM privilege escalation via a token impersonation chain → malicious container image
pushed to Artifact Registry. There are 15 flags covering each step.

**GCP Project**: `helical-cursor-494913-k9`
**Attack IP**: `33.252.46.44`
**Admin IP**: `120.196.206.75`
**Upload IP** (key creation): `88.65.198.198`

---

## Artifacts Structure

```
artifacts/
  admin_activity_logs.csv          # IAM and admin API calls (~2507 rows)
  storage_data_access_logs.csv     # GCS read/write/delete events (~2503 rows)
  iam_exports.json                 # Current IAM state snapshot
  artifact_registry_inventory.json # Container registry state (10 entries)
  website_snapshot/
    assets/main.min.js             # Obfuscated JS with embedded SA email
    supply-bundle.zip              # Zip containing leaked SA JSON key
  docker/
    ballot_api.tar                 # Legitimate image
    ops_diagnostics_v0_9_7.tar    # MALICIOUS image (this is the one to analyze)
    results_ingestor.tar           # Legitimate image
```

---

## Flag 1 - Leaked Service Account `client_email`

**Question**: What `client_email` does the leaked service account key authenticate as?

**Method**: Extract `supply-bundle.zip` from `website_snapshot/` and read the JSON key file inside.

```python
import zipfile, json
zf = zipfile.ZipFile('website_snapshot/supply-bundle.zip')
key = json.loads(zf.read('pipeline-export/github-actions/buildops-ci-runner-svcacct.json'))
print(key['client_email'])
```

The zip contains:
- `pipeline-export/github-actions/buildops-ci-runner-svcacct.json` - the leaked SA key
- `vendor-export-manifest.json` - describes it as "Legacy CI runner service account key (rotation flagged overdue)"

Key fields from the SA JSON:
```json
{
  "type": "service_account",
  "project_id": "helical-cursor-494913-k9",
  "private_key_id": "a3f91c8e2d004b7f9012c0ffee4242ab0b1eca7d",
  "client_email": "buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com",
  "client_id": "114834742891578631905"
}
```

**Answer**: `buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com`

---

## Flag 2 - First Impersonation Hop Timestamp

**Question**: At what UTC timestamp did the first impersonation hop occur (buildops-ci-runner minting a token for supply-pipeline-sa)?

**Method**: Search `admin_activity_logs.csv` for `GenerateAccessToken` events where the
caller is `buildops-ci-runner` and the target (`resource.labels.email_id`) is `supply-pipeline-sa`.

**Key insight**: The `client_id` in the SA key JSON (`114834742891578631905`) is
buildops-ci-runner's OWN unique ID. Many earlier log entries show buildops-ci-runner
calling `GenerateAccessToken` for its own ID (self-token-refresh), which are NOT the
impersonation hop. The real hop to supply-pipeline-sa uses resource ID `107823456019264038175`.

```python
import csv
with open('admin_activity_logs.csv') as f:
    for i, row in enumerate(csv.DictReader(f)):
        method = row['protoPayload.methodName']
        caller = row['protoPayload.authenticationInfo.principalEmail'].strip("'")
        email_id = row.get('resource.labels.email_id','').strip("'")
        if method == 'GenerateAccessToken' and 'buildops-ci-runner' in caller and 'supply-pipeline' in email_id:
            print(f"Row {i}: {row['timestamp'].strip(chr(39))}")
            print(f"  scope={row['protoPayload.request.scope'].strip(chr(39))}")
```

From `admin_activity_logs.csv` (Row 1672):
```
timestamp:            2026-05-03T13:36:05.925331699Z
method:               GenerateAccessToken
caller:               buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com
resource (unique ID): projects/-/serviceAccounts/107823456019264038175
email_id:             supply-pipeline-sa@helical-cursor-494913-k9.iam.gserviceaccount.com
scope:                ["https://www.googleapis.com/auth/iam"]
```

**Answer**: `2026-05-03T13:36:05Z`

---

## Flag 3 - Second Impersonation Hop Timestamp

**Question**: At what UTC timestamp did the second impersonation hop occur (supply-pipeline-sa minting a token for elections-deployer)?

**Method**: Search for `GenerateAccessToken` events where caller is `supply-pipeline-sa`
and target is `elections-deployer`.

From `admin_activity_logs.csv` (Row 1676):
```
timestamp:            2026-05-03T13:36:12.606963361Z
method:               GenerateAccessToken
caller:               supply-pipeline-sa@helical-cursor-494913-k9.iam.gserviceaccount.com
resource (unique ID): projects/-/serviceAccounts/111156569751647653741
email_id:             elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com
scope:                ["https://www.googleapis.com/auth/cloud-platform"]
```

This call occurs 7 seconds after hop 1 (13:36:05 → 13:36:12). The SA impersonation
chain is executing in rapid sequence, confirming automated tooling.

**Answer**: `2026-05-03T13:36:12Z`

---

## Flag 4 - OAuth Scope in Second GenerateAccessToken Hop

**Question**: What OAuth scope did the attacker request in the second GenerateAccessToken hop?

**Method**: Read the `protoPayload.request.scope` field from Row 1676 (the second hop).

From Row 1676:
```
protoPayload.request.scope = ["https://www.googleapis.com/auth/cloud-platform"]
```

Note the contrast with hop 1 where scope was `https://www.googleapis.com/auth/iam`
(IAM-only operations) versus hop 2 which requested the full `cloud-platform` scope
(all GCP APIs), because `elections-deployer` is being used to push a container image
to Artifact Registry.

**Answer**: `https://www.googleapis.com/auth/cloud-platform`

---

## Flag 5 - Malicious Project IAM Binding

**Question**: What is the malicious project IAM binding in canonical `member:role` format?

**Method**: Search for `SetIamPolicy` events on the project (not on a specific SA) that
grant elevated roles. The attacker granted `elections-deployer` a temporary elevated
role at the project level to enable SA-level IAM modification.

From `admin_activity_logs.csv` (Row 1679):
```
timestamp:  2026-05-03T13:36:16.917899485Z
method:     SetIamPolicy
caller:     elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com
resource:   projects/helical-cursor-494913-k9
bindings:   [{"role": "roles/iam.securityAdmin", 
              "members": ["serviceAccount:elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com"]}]
```

This was only possible because `supply-pipeline-sa` holds `roles/resourcemanager.projectIamAdmin`
at the project level, and elections-deployer had been granted a token by supply-pipeline-sa
(hop 2). The securityAdmin role provides `iam.serviceAccounts.setIamPolicy`, needed to
plant the backdoor on `elections-ghost-sa`.

**Answer**: `serviceAccount:elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com:roles/iam.securityAdmin`

---

## Flag 6 - Privilege Escalation Timestamp

**Question**: At what UTC timestamp was privilege escalation achieved on the project?

**Method**: The privilege escalation event is the `SetIamPolicy` that granted the elevated
role. This is Row 1679, 4 seconds after the second impersonation hop (13:36:12 → 13:36:16).

**Answer**: `2026-05-03T13:36:16Z`

---

## Flag 7 - SA Key ID from CreateServiceAccountKey Response

**Question**: What is the key ID of the service account key created for `buildops-ci-runner`
and visible in the `CreateServiceAccountKey` response?

**Method**: Search for `CreateServiceAccountKey` events in `admin_activity_logs.csv`.
The response fields (prefixed `protoPayload.response.*`) contain the key metadata.

From `admin_activity_logs.csv` (Row 1111):
```
timestamp:                          2026-05-03T06:59:30.244955188Z
method:                             google.iam.admin.v1.CreateServiceAccountKey
caller:                             admin@nightfall.net
ip:                                 88.65.198.198
resource:                           projects/-/serviceAccounts/buildops-ci-runner@...
protoPayload.response.key_algorithm: KEY_ALG_RSA_2048
protoPayload.response.key_origin:   GOOGLE_PROVIDED
protoPayload.response.key_type:     USER_MANAGED
protoPayload.response.name:         projects/helical-cursor-494913-k9/serviceAccounts/
                                    buildops-ci-runner@.../keys/a3f91c8e2d004b7f9012c0ffee4242ab0b1eca7d
```

The key ID is the last path component of the `response.name` field. This is the same
value as `private_key_id` in the leaked SA JSON key - confirming that this is the key
that was leaked in `supply-bundle.zip`.

**Answer**: `a3f91c8e2d004b7f9012c0ffee4242ab0b1eca7d`

---

## Flag 8 - Artifact Registry Repository Name

**Question**: What is the name of the Artifact Registry repository where the malicious image was pushed?

**Method**: Read `artifact_registry_inventory.json`. All images in the registry share
the same repository path.

From `artifact_registry_inventory.json`:
```
package: "asia-southeast1-docker.pkg.dev/helical-cursor-494913-k9/elections-supply-registry/ops-diagnostics"
```

The full path format is: `{region}-docker.pkg.dev/{project}/{repository}/{image}`.

**Answer**: `elections-supply-registry`

---

## Flag 9 - Malicious Supply Image Name

**Question**: Which supply image name received a new push during the attack window?

**Method**: Compare `createTime` timestamps in `artifact_registry_inventory.json`.
The attack window is `2026-05-03T13:36-13:37Z`. All legitimate images were created
on `2026-05-02`. The images with `createTime` on `2026-05-03` are malicious.

From `artifact_registry_inventory.json`:
```json
{
  "createTime": "2026-05-03T13:36:56.142705Z",   ← attack window
  "package": "...elections-supply-registry/ops-diagnostics",
  "tags": [],
  "version": "sha256:8911413..."
},
{
  "createTime": "2026-05-03T13:37:01Z",            ← attack window
  "package": "...elections-supply-registry/ops-diagnostics",
  "tags": ["v0.9.7"],
  "version": "sha256:54a2f31d..."
}
```

Three images exist for `ops-diagnostics`: v0.9.5 (legitimate, 2026-05-02), plus two
new entries from 2026-05-03. No new entries for `ballot-api` or `results-ingestor`.

**Answer**: `ops-diagnostics`

---

## Flag 10 - Tag on Malicious Image

**Question**: What tag was applied to the malicious image push?

**Method**: From the `artifact_registry_inventory.json` entries from 2026-05-03,
find the entry with a non-empty `tags` array.

```json
{
  "createTime": "2026-05-03T13:37:01Z",
  "metadata": {"mediaType": "application/vnd.oci.image.index.v1+json"},
  "tags": ["v0.9.7"],
  "version": "sha256:54a2f31d..."
}
```

The previous legitimate version was `v0.9.5`. The attacker bumped to `v0.9.7`,
skipping `v0.9.6`, which may cause it to appear as a normal version bump to casual
observers.

**Answer**: `v0.9.7`

---

## Flag 11 - Index Manifest Creation Timestamp

**Question**: At what UTC timestamp was the malicious image index manifest created in Artifact Registry?

**Method**: The `createTime` of the index manifest entry (the one with `tags: ["v0.9.7"]`
and `mediaType: application/vnd.oci.image.index.v1+json`).

```json
{
  "createTime": "2026-05-03T13:37:01Z",
  "metadata": {
    "mediaType": "application/vnd.oci.image.index.v1+json"
  },
  "tags": ["v0.9.7"]
}
```

Note: there are TWO malicious ops-diagnostics entries on 2026-05-03 - one is the
OCI manifest (the actual image layers, created at 13:36:56) and one is the index
manifest (the multi-arch index, created at 13:37:01). The question asks for the
index manifest specifically.

**Answer**: `2026-05-03T13:37:01Z`

---

## Flag 12 - Full Index Digest of Malicious ops-diagnostics v0.9.7

**Question**: What is the full index digest (sha256) of the malicious `ops-diagnostics` `v0.9.7` manifest?

**Method**: From `artifact_registry_inventory.json`, find the entry with tag `v0.9.7`
and read its `version` field (which is the digest).

```json
{
  "tags": ["v0.9.7"],
  "version": "sha256:54a2f31d64746d77e0ff0e9587ffea4f91f48d496f5651717c74f9b867743eee"
}
```

**Answer**: `sha256:54a2f31d64746d77e0ff0e9587ffea4f91f48d496f5651717c74f9b867743eee`

---

## Flag 13 - imageSizeBytes of Malicious Layer Entry

**Question**: What is the `imageSizeBytes` value of the malicious layer entry pushed during the attack window?

**Method**: From `artifact_registry_inventory.json`, find the ops-diagnostics entry
from the attack window that has a numeric `imageSizeBytes` (NOT "None"). The index
manifest always has `imageSizeBytes: "None"` because it's just a pointer. The actual
image manifest has the size.

```json
{
  "createTime": "2026-05-03T13:36:56.142705Z",
  "metadata": {
    "buildTime": "2026-05-03T13:37:01.142705044Z",
    "imageSizeBytes": "89234512",
    "mediaType": "application/vnd.oci.image.manifest.v1+json"
  },
  "tags": [],
  "version": "sha256:8911413000606ef088b48c0bb0773653297afb37e30640e304f7df6b4da76f9a"
}
```

Compare with the legitimate ops-diagnostics `v0.9.5` manifest which has `imageSizeBytes: "1292"`.
The malicious image is 89MB (89,234,512 bytes) versus 1.3KB for the legitimate one -
a massive discrepancy that should have triggered alerts.

**Answer**: `89234512`

---

## Flag 14 - IOC Environment Variable Name

**Question**: What IOC environment variable name appears in the malicious image `config.Env` inside the Docker tar?

**Method**: Open `docker/ops_diagnostics_v0_9_7.tar`. Read `manifest.json` to find the
config blob path. Read the config blob JSON and inspect `config.Env`.

```python
import tarfile, json

with tarfile.open('docker/ops_diagnostics_v0_9_7.tar') as tf:
    manifest = json.loads(tf.extractfile('manifest.json').read())
    config_path = manifest[0]['Config']
    config = json.loads(tf.extractfile(config_path).read())
    for env in config['config']['Env']:
        print(env)
```

The config blob is at `blobs/sha256/5a98a928c65e91bad30b3da3e978a89f868bf8e720df9405ee85ab605ceec29e`.

Full `config.Env` list:
```
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=C.UTF-8
GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305
PYTHON_VERSION=3.12.13
PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684
DIAG_MODE=active
CALLBACK_HOST=185.220.101.47
CALLBACK_PATH=/diag/beacon
```

The first 5 env vars are standard Python base image vars (legitimate). The last 3 were
added by the attacker:
- `DIAG_MODE=active` - enables the beacon/callback behaviour
- `CALLBACK_HOST=185.220.101.47` - attacker-controlled C2 IP address
- `CALLBACK_PATH=/diag/beacon` - the callback URL path

The `CALLBACK_HOST` variable is the IOC - it contains an external IP address with no
connection to the legitimate organisation. The image history confirms these were added
on `2026-05-03T13:36:55Z` (attack window), layered on top of a legitimate Python base
image dating from `2026-04-15`.

**Answer**: `CALLBACK_HOST`

---

## Flag 15 - IOC Callback Variable Value

**Question**: What value does the IOC callback variable hold in the malicious image config?

**Method**: From the same image config (above), read the value of `CALLBACK_HOST`.

```
CALLBACK_HOST=185.220.101.47
```

`185.220.101.47` is a Tor exit node IP - a well-known anonymized C2 infrastructure
address. The container, when run, would beacon out to this address via the path
`/diag/beacon`, phone home credentials or telemetry, and await commands.

**Answer**: `185.220.101.47`

---

## Full Attack Timeline

```
2026-05-03T06:59:21Z
  admin@nightfall.net (88.65.198.198) - supply-bundle.zip uploaded to mec-elections-logistics-pub
  [Bucket made public, zip with leaked buildops-ci-runner key uploaded simultaneously]

2026-05-03T06:59:30Z
  admin@nightfall.net (88.65.198.198) - CreateServiceAccountKey for buildops-ci-runner
  [New key created, key ID: a3f91c8e2d004b7f9012c0ffee4242ab0b1eca7d - same as in leaked zip]

  [Hours pass - attacker uses leaked key to explore, access secrets, enumerate]

2026-05-03T13:36:05Z  ← HOP 1
  buildops-ci-runner (33.252.46.44) - GenerateAccessToken for supply-pipeline-sa
  scope=https://www.googleapis.com/auth/iam
  [IAM-scoped token for supply-pipeline-sa acquired, unique ID 107823456019264038175]

2026-05-03T13:36:12Z  ← HOP 2
  supply-pipeline-sa (33.252.46.44) - GenerateAccessToken for elections-deployer
  scope=https://www.googleapis.com/auth/cloud-platform
  [Full-scope token for elections-deployer acquired, unique ID 111156569751647653741]

2026-05-03T13:36:16Z  ← PRIVILEGE ESCALATION
  elections-deployer (33.252.46.44) - SetIamPolicy on project
  → grants self: roles/iam.securityAdmin
  [Supply-pipeline-sa's projectIamAdmin enabled this - full SA IAM control achieved]

2026-05-03T13:36:56Z
  elections-deployer (33.252.46.44) - Pushes malicious OCI manifest to Artifact Registry
  image: ops-diagnostics@sha256:8911413... (89234512 bytes)
  [Malicious image layer with CALLBACK_HOST=185.220.101.47 pushed]

2026-05-03T13:37:01Z
  elections-deployer (33.252.46.44) - Index manifest created
  tag: ops-diagnostics:v0.9.7
  digest: sha256:54a2f31d64746d77e0ff0e9587ffea4f91f48d496f5651717c74f9b867743eee

2026-05-03T13:44:54Z
  elections-deployer (33.252.46.44) - SetIAMPolicy on elections-ghost-sa
  → adds: user:gilded@d9.kor with roles/iam.serviceAccountTokenCreator
  [Persistent backdoor planted]

2026-05-03T13:45:13Z
  elections-deployer (33.252.46.44) - SetIamPolicy on project
  → removes: roles/iam.securityAdmin from self  [CLEANUP]

2026-05-03T13:45:19Z
  elections-deployer (33.252.46.44) - storage.objects.delete: config/app.config.json  [CLEANUP]

2026-05-03T13:45:25Z
  elections-deployer (33.252.46.44) - DestroySecretVersion: election-db-credentials/versions/3  [CLEANUP]
```

---

## Flags / Answers Summary

| # | Question | Answer |
|---|----------|--------|
| 1 | Leaked SA `client_email` | `buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com` |
| 2 | First hop timestamp (buildops-ci-runner → supply-pipeline-sa) | `2026-05-03T13:36:05Z` |
| 3 | Second hop timestamp (supply-pipeline-sa → elections-deployer) | `2026-05-03T13:36:12Z` |
| 4 | OAuth scope in second hop | `https://www.googleapis.com/auth/cloud-platform` |
| 5 | Malicious project IAM binding | `serviceAccount:elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com:roles/iam.securityAdmin` |
| 6 | Privilege escalation timestamp | `2026-05-03T13:36:16Z` |
| 7 | SA key ID from CreateServiceAccountKey response | `a3f91c8e2d004b7f9012c0ffee4242ab0b1eca7d` |
| 8 | Artifact Registry repository | `elections-supply-registry` |
| 9 | Malicious supply image name | `ops-diagnostics` |
| 10 | Tag on malicious image | `v0.9.7` |
| 11 | Index manifest creation timestamp | `2026-05-03T13:37:01Z` |
| 12 | Full index digest (sha256) | `sha256:54a2f31d64746d77e0ff0e9587ffea4f91f48d496f5651717c74f9b867743eee` |
| 13 | imageSizeBytes of malicious layer | `89234512` |
| 14 | IOC env var name | `CALLBACK_HOST` |
| 15 | IOC callback variable value | `185.220.101.47` |

---

## Key Investigation Techniques

### 1. Distinguish self-token-refresh from impersonation

In GCP logs, `GenerateAccessToken` entries where `resource.labels.email_id` matches
the caller's own SA email are self-token-refreshes (routine). The actual impersonation
hop shows a DIFFERENT email in `resource.labels.email_id`. Always check both
`protoPayload.authenticationInfo.principalEmail` (caller) and `resource.labels.email_id`
(target SA being impersonated).

### 2. Use `resource.labels.email_id` to resolve numeric SA IDs

Log entries for `GenerateAccessToken` show the target SA as a numeric unique ID in
`protoPayload.resourceName`. The human-readable email is in `resource.labels.email_id`
and `protoPayload.request.name`. Always read these fields, not just the resource path.

### 3. OAuth scope reveals intent

`https://www.googleapis.com/auth/iam` = IAM operations only (used for privilege escalation)
`https://www.googleapis.com/auth/cloud-platform` = all GCP APIs (used for Artifact Registry push)

The scope progression tells you what the attacker was doing with each hop.

### 4. Artifact Registry inventory: index manifest vs image manifest

Every OCI multi-arch image has TWO entries:
- **Image manifest** (`application/vnd.oci.image.manifest.v1+json`): has real `imageSizeBytes`
- **Index manifest** (`application/vnd.oci.image.index.v1+json`): has `imageSizeBytes: None`, carries the tag

Always compare both `createTime` and the `mediaType` to identify the right entry for each question.

### 5. Container forensics via tar + image config

Docker images saved as tars follow OCI layout:
```
manifest.json         → lists Config path and Layer paths
blobs/sha256/<hash>   → config JSON (contains Env, Labels, history)
blobs/sha256/<hash>   → layer tarballs
index.json            → OCI index
```

The `history` array in the config shows the exact `created_by` commands and timestamps
for every layer. Entries from 2026-05-03 vs 2026-04-15 immediately identify the injected
attacker layers versus the legitimate base image layers.

### 6. C2 IP indicators

`185.220.101.47` is a well-documented Tor exit node. Any container image with an
env var pointing to a Tor exit node is a strong supply chain compromise indicator.
Cross-reference unknown IPs against threat intel (AbuseIPDB, Shodan, Tor node lists).
