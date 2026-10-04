# Attachment GC is read-only

`POST /v1/attachment/gc` accepts `{chat_id, key}` (base64 CEK) and a user JWT.
For a valid, decryptable chat and successful controlplane read it returns HTTP 409:

```json
{"ok":false,"code":"ATTACHMENT_GC_DISABLED","disabled":true,"referenced":1,"indexed":4,"deleted":0,"remaining":3,"deferred":2,"retry_after":900}
```

- `referenced`: distinct attachment IDs carrying a server key in the chat snapshot.
- `indexed`: IDs returned by controlplane after its 15-minute age filter.
- `remaining`: returned IDs absent from the server-keyed `referenced` set above,
  excluding deferred rows.
- `deferred`: count of same-owner, same-chat v2 rows still inside the grace interval,
  whether referenced or not. Forwarded from controlplane #863.
- `retry_after`: conservative age-based diagnostic delay in **seconds**, 900 when
  deferred rows exist, otherwise 0. This is not permission to delete.
- `disabled`: always true. `ok` is false and `deleted` is zero even when no candidates
  are found. An older controlplane omits deferred metadata; that does not enable GC.

Authentication, malformed requests, missing chats, wrong keys, and upstream failures
retain their ordinary error responses. No bucket or index mutation is attempted.

## Webapp retry handling

Check `ATTACHMENT_GC_DISABLED`/`disabled` first: retain pending work but suspend
automatic retries until a safe protocol release. Do not loop on `remaining` or
schedule `retry_after` while disabled. Zero `remaining` is not completion when
young rows were omitted or GC is disabled. On a future enabled protocol, retain
pending work while `remaining > 0` or `deferred > 0`, honor the delay in seconds,
and fetch fresh snapshots on each retry. Retain pending work after transport errors.
These changes do not modify webapp.

## Why deletion is blocked

An age check cannot protect a re-registration between list and delete. A chat
revision fence under the registration/write lock would protect already-committed
changes, but not a later offline-client save that references a collected ID:
`Push` accepts those references without checking their lifetime. Upload retries
also reuse bucket keys. A durable queue alone would permit an expired deletion
claimant to wipe a reupload even after another claimant acknowledged cleanup.

Enabling deletion requires reference-aware chat commits and recovery behavior for
offline clients, plus generation-safe upload reservations and durable cleanup
jobs created atomically with index removal. Jobs must be retried until bucket
success and acknowledged with fenced tokens; acknowledgment alone does not fence
late bucket operations. Shared snapshots need an explicit retention policy too.

Those protocol and queue changes are **not implemented** here. Destructive GC is
disabled independently in both services, including during a mixed-version rollout.
Existing explicit deletion and background orphan/pending-write cleanup paths are
unchanged and are not certified by this fix.

The cross-service contract and prerequisites are documented in the controlplane
repository at `docs/attachment-gc.md` on `feat/attachment-index-gc` (#863).
