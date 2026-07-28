# Wrong Stamp - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Cloud - CloudTrail incident response / log forensics (LocalStack) |
| Tech stack | LocalStack (STS, CloudTrail, S3), custom Python briefing page |
| Scenario | An IAM user's access key is copied and reused by an attacker from a different source IP, who probes the environment and disables the audit trail before being fully cut off |
| Grading | This challenge has no `HTB{...}` flag - it is graded via 8 explicit investigation questions submitted through HTB's own portal |

---

## Overview - How The App Works

```
[You] --> :31691  StonepassBriefing (Python http.server) - lore page + /player-creds.json
       --> :30763  LocalStack - emulated AWS API (STS, CloudTrail, S3)
```

Same shape as the previous Cloud challenge in this event ("False Ferry"): a static briefing page
handing out starting IAM credentials, and a LocalStack instance emulating real AWS services behind
it. This challenge's fictional account belongs to `stonepass-investigator`, explicitly described on
the briefing page as read-only - there is no privilege-escalation chain here, the entire task is
reading and correctly ordering CloudTrail history.

The lore ("a seizure stamp... copies of that stamp... fresh tool marks... prove the stamp is fake")
maps directly onto the incident: a legitimate IAM user's access key (the "stamp") was copied and
used by an attacker from a different network location. The "fresh tool marks" are the forensic
tell - same credential, anomalous source IP - and "a quick way to reject future copies" is asking
for a detection rule based on that signal.

---

## Setup

```bash
curl -s http://154.57.164.73:31691/player-creds.json
```

```json
{
  "user": "stonepass-investigator",
  "access_key_id": "AKIAOZHRK7HL3XKHRFSO",
  "secret_access_key": "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",
  "region": "us-east-1"
}
```

```bash
export AWS_ACCESS_KEY_ID=AKIAOZHRK7HL3XKHRFSO
export AWS_SECRET_ACCESS_KEY=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
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://154.57.164.73:30763

aws sts get-caller-identity
```

Confirmed identity: `arn:aws:iam::491827305948:user/stonepass-investigator`.

`cloudtrail:DescribeTrails` is explicitly denied for this user - a deliberate nudge away from
inspecting trail *configuration* and toward reading trail *history* instead, which works directly:

```bash
aws cloudtrail lookup-events
```

This paginates (267 total events across the full history via repeated `--next-token`). Each event
is a `CloudTrailEvent` JSON blob with `eventTime`, `eventName`, `sourceIPAddress`, `userIdentity`
(`arn`/`userName`/`accessKeyId`), and, when denied, `errorCode`/`errorMessage`. Pulled everything,
parsed it, and sorted ascending by `eventTime` to build a clean timeline.

Against a flood of routine activity from the internal IP `10.30.41.118`, two other source IPs stand
out: `192.0.2.55` (6 events total, all clustered at the very end of the timeline) and `127.0.0.1`
(8 events, no `userName` - infrastructure noise, ignored). Both the internal session and the
`192.0.2.55` session authenticate as the exact same identity - `stonepass-warden`,
access key `AKIAQKSLTEGM7XSVP92F`. That is the "copied stamp": there is no separate attacker IAM
identity anywhere in this account, only one legitimate credential used from two different places.

---

## Q1 - Last CloudTrail action by the compromised user from the internal IP, immediately before the attacker session began

```
eventTime: 2026-07-28T20:46:22.202Z
eventName: ListAccessKeys
sourceIPAddress: 10.30.41.118
userIdentity.userName: stonepass-warden
```

The warden's own routine self-check of their access keys - in hindsight, arguably the exact moment
they last touched the credential that was about to be reused elsewhere.

**Answer: `iam:ListAccessKeys` at `2026-07-28T20:46:22.202Z` from `10.30.41.118`**

---

## Q2 - First CloudTrail action from the attacker IP

```
eventTime: 2026-07-28T20:46:43.238Z
eventName: GetTrailStatus
sourceIPAddress: 192.0.2.55
userIdentity.userName: stonepass-warden
```

21 seconds after the last internal-IP event, the same credential shows up from `192.0.2.55` and
immediately checks whether the audit trail is even running - reconnaissance before touching
anything else.

**Answer: `cloudtrail:GetTrailStatus` at `2026-07-28T20:46:43.238Z`**

---

## Q3 - API action the attacker attempted that was explicitly denied

```
eventTime: 2026-07-28T20:46:45.654Z
eventName: DeleteTrail
sourceIPAddress: 192.0.2.55
errorCode: AccessDeniedException
errorMessage: User is not authorized to perform: cloudtrail:DeleteTrail
```

The attacker's first instinct was to destroy the trail outright. Denied - the copied credential's
permissions don't stretch that far, forcing a fallback to a weaker disruption instead (see Q8).

**Answer: `cloudtrail:DeleteTrail`**

---

## Q4 - S3 bucket the attacker enumerated before stopping the trail

```
20:46:47.616Z  ListBucket        bucket: stonepass-audit-trail-logs
20:46:49.630Z  ListObjectsV2     bucket: stonepass-audit-trail-logs
20:46:51.449Z  GetObject         key: AWSLogs/us-east-1/CloudTrail/us-east-1/2026/06/24/audit.log.gz
               errorCode: NoSuchKey
```

Having failed to delete the trail, the attacker went looking for the delivered log files directly -
listed the bucket twice, then guessed at a log object path that doesn't exist.

**Answer: `stonepass-audit-trail-logs`**

---

## Q5 - Name of the CloudTrail trail that was stopped

From the `GetTrailStatus` call in Q2 and the final `StopLogging` call (Q8), both reference the same
trail ARN: `arn:aws:cloudtrail:us-east-1:491827305948:trail/stonepass-audit-trail`.

**Answer: `stonepass-audit-trail`**

---

## Q6 - IAM username whose credentials executed the trail disable

Every single event in the attacker's 6-event burst from `192.0.2.55` - including the final
`StopLogging` call - authenticates as `stonepass-warden`. There is no second identity in this
account; the attacker never created or assumed anything, they simply reused the warden's live
key.

**Answer: `stonepass-warden`**

---

## Q7 - IP address from which the trail was disabled

**Answer: `192.0.2.55`**

---

## Q8 - API action used to disable the audit trail

```
eventTime: 2026-07-28T20:46:53.076Z
eventName: StopLogging
sourceIPAddress: 192.0.2.55
userIdentity.userName: stonepass-warden
```

The last event in the attacker's burst, and the last CloudTrail event in the entire capture.
`DeleteTrail` (Q3) was tried first and denied; `StopLogging` doesn't require the same permission
and succeeded, silencing further audit capture without needing to remove the trail's configuration
at all.

**Answer: `cloudtrail:StopLogging` at `2026-07-28T20:46:53.076Z`**

---

## Incident Timeline Summary

```
20:46:22.202Z  [10.30.41.118]  stonepass-warden  iam:ListAccessKeys        <- last legit action
                                                                               (Q1)
--- credential reused elsewhere ---
20:46:43.238Z  [192.0.2.55]    stonepass-warden  cloudtrail:GetTrailStatus <- first attacker action
                                                                               (Q2)
20:46:45.654Z  [192.0.2.55]    stonepass-warden  cloudtrail:DeleteTrail    <- DENIED (Q3)
20:46:47.616Z  [192.0.2.55]    stonepass-warden  s3:ListBucket             <- stonepass-audit-trail-logs
20:46:49.630Z  [192.0.2.55]    stonepass-warden  s3:ListObjectsV2          <- same bucket (Q4)
20:46:51.449Z  [192.0.2.55]    stonepass-warden  s3:GetObject              <- NoSuchKey, guessed path
20:46:53.076Z  [192.0.2.55]    stonepass-warden  cloudtrail:StopLogging    <- trail silenced (Q5-Q8)
```

Six events, ten seconds, one already-issued credential - no exploitation of the LocalStack API
itself was needed, only patient log reconstruction.

---

## Detection Rule - "A Quick Way To Reject Future Copies"

The lore's final ask maps directly onto a real detection signal: the credential itself never
changes across the legitimate and attacker sessions, only the source IP does. A usable rule:

> Alert on any CloudTrail management-plane API call authenticated as `stonepass-warden` /
> `AKIAQKSLTEGM7XSVP92F` from any source IP other than the known-good `10.30.41.118` - with
> immediate/critical severity for `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, and
> `cloudtrail:GetTrailStatus` specifically, since those three calls are the actual attack surface
> against the audit trail itself.

---

## Key Takeaways

| Concept | Detail |
|---|---|
| A denied API call is not a denied credential | The attacker still authenticated successfully as a real, permitted user (`DeleteTrail` failed on authorization, not authentication) - don't conflate "one action was blocked" with "the attacker was stopped" |
| `StopLogging` vs `DeleteTrail` | Two different ways to blind an audit trail with very different permission requirements - a least-privilege policy that blocks the destructive one can still leave the quieter one open |
| Same identity, different location, is the whole signal | When an attacker reuses a stolen credential rather than creating a new one, source IP (and timing) is often the only distinguishing artifact available - build detections around that instead of assuming a new/unknown principal will always appear |
| `lookup-events` before hunting for raw logs | CloudTrail's own event history API can answer a full incident-reconstruction question without ever needing to locate or parse the underlying delivered S3 log files - check the simpler read path first |
| Denied API calls narrow the search space | `DescribeTrails` being denied for the investigator role was itself a hint - it ruled out inspecting trail configuration and pointed toward event history as the intended path |
