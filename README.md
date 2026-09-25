# secure-envelope-web

Envelope encryption review tool. It tracks how each sealed envelope is bound to
a data key wrapped by a **master key version**, and runs **versioned key
rotation** as reviewable, batchable tasks with failure reasons, retries and
manual confirmation.

## Model

- **Master key versions** (`mkv-*`): server-held AES-256 keys with a status
  (`active` / `disabled`) and the `seq` at which they were added. Key material
  never leaves the server.
- **Envelopes**: an envelope stores a payload ciphertext under a per-envelope
  data key (DEK). The DEK is itself AES-256-GCM wrapped by a master key version;
  each wrap is an explicit record
  (`current` / `candidate` / `superseded` / `abandoned`). The relationship
  envelope → data key wrap → master key version → rotation task is visible in
  the UI and in the API, while wrapped DEKs and ciphertexts are not.
- **Rotation tasks**: `from` version → `to` version. Envelopes whose current
  wrap uses `from` are enlisted as items with their own state:
  `pending → in_progress → succeeded`, with `failed` (retryable) and
  `needs_review` (manual confirm: retry or skip). The task status is derived
  from item states (`running` / `completed` / `completed_with_failures`), never
  from timestamps.
- **Transition log**: every state change is an event with a strictly increasing
  `seq`. Item rows show `updatedSeq`, so every status has a server-side source.

## Rotation protocol

Two phases per item, so a new wrap completes *before* the current reference is
replaced:

1. `process` (batched): unwrap the DEK with the `from` version, prepare a
   `candidate` wrap under the `to` version. The envelope's current reference is
   unchanged, and old-version reads keep working. A disabled/missing target
   (or an unwrap error) records `failed` with a reason and no candidate.
2. `commit`: replace the current reference with the candidate, but only if the
   wrap read in phase 1 is still current (compare-and-swap). The old wrap
   becomes `superseded`. A changed current reference becomes `needs_review`.

Retries re-wrap failed/in-progress items; stale candidates are marked
`abandoned`, so retries never produce competing current versions. Succeeded
and skipped items are untouched, making completed-task retries no-ops
(verified by unchanged `seq`). `POST /api/envelopes/:id/open` decrypts with the
current version, or with an explicit historical `keyVersion` against a
superseded wrap — decryption stays compatible after rotation (a disabled key
can still decrypt, only new wrapping is blocked).

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/keys` | add a master key version `{keyId}` |
| POST | `/api/keys/:keyId/status` | `active` / `disabled` (retry strategy) |
| POST | `/api/envelopes` | seal `{id, keyId, digest}` |
| POST | `/api/envelopes/:id/open` | decrypt; `{keyVersion?}` for historical reads |
| POST | `/api/rotations` | start `{from, to}` (enlists matching envelopes) |
| POST | `/api/rotations/:id/process` | wrap next batch `{batchSize}` |
| POST | `/api/rotations/:id/commit` | commit in-progress items (`{envelopeIds?}`) |
| POST | `/api/rotations/:id/retry` | retry failed / re-wrap in-progress |
| POST | `/api/rotations/:id/items/:envelopeId` | manual confirm `{action: "retry"|"skip"}` |
| GET | `/api/rotations/:id` | one task |
| GET | `/api/keyring` | browser-safe snapshot (`seq`, versions, wraps, items, events) |

Snapshots never include `material`, `wrappedDek` or `ciphertext`; the browser
sees only key-version references and statuses.

## Persistence

State is written atomically to `data/keyring.json`
(`KEYRING_DATA`, git-ignored because it contains server-side key material)
after every mutation and reloaded on boot, so reopening the review page or
restarting the server shows the same task results.

## Browser review

`public/app.js` keeps no local task list: it renders only server snapshots.
Each snapshot carries the server `seq`; stale/out-of-order responses with a
lower seq are discarded, switching rotation batches re-fetches, and a freshly
opened page renders nothing until the first snapshot arrives. Badges
distinguish pending, in progress, succeeded, failed, needs review (with
confirm/retry/skip) and skipped.

## Run

```bash
npm start   # http://localhost:4182
npm test    # node:test: ledger semantics, HTTP flow, frontend refresh
```

Failure-and-retry walkthrough: seal envelopes on the old version, start a
rotation, process/commit one batch, disable the target key version, process the
rest (items fail with reasons and stay reviewable), re-activate the target,
retry and commit, then open envelopes with both current and historical
versions.
