# Notes on the build

<!-- Ryan asked for a five-bullet note: what passed, what failed, what I'd
     improve next. Swap in your own numbers/phrasing before sending. -->

Hi Ryan - here's where `vouch` landed and how I'd take it further.

On scope: the implementation is bounded to the brief - schema with
canonical-JSON content addressing, immutable signed receipt, ledger, leases,
executor, harness, verifier, synthetic fixtures. Two things sit just outside
it and both buy reliability rather than surface area. `vouch scoreboard`
runs a bundled "cheating agent" (13 forgeries) straight through the verifier,
so every failure path is executable, not asserted once in a test.
`independent_reexecution` is opt-in and off by default - the verifier stays
a pure function unless you hand it a `reexecutor`. Neither adds a branch to
the happy path, and both are a clean removal if you'd rather the harness be
leaner.

- **What passed.** The core loop works the way I wanted: a worker claims a
  lease, runs a task, and emits an Ed25519-signed receipt that carries a
  *witness* - proof material the verifier can cheaply re-derive from the
  inputs alone. The verifier is a pure function (18 named checks, returns a
  report, never raises), so I can point it at a stored receipt later and get
  the same answer. All five failure modes I set out to cover are rejected by
  a specific named check, not a vague "invalid": duplicate completion, stale
  ownership (fencing-token epoch), bad signature / tampered body / fabricated
  witness, malformed bytes (parser fails to one typed error, no traceback),
  and a late receipt from a timed-out run. On top of that, `nth_prime` +
  `independent_reexecution` catch a wrong result the cheap witness check
  can't (any prime passes "is it prime"), and `tests/test_invariants.py`
  pins four named properties with Hypothesis. ~54 tests, ~94% coverage; the
  bundled adversary catches all 13 forgeries and documents 2 accepted
  limitations.

- **What's honestly still weak.** Re-execution is opt-in and only covers
  `deterministic` fixtures - `slow_task` / `flaky_task` are skipped, and if
  no reexecutor is supplied a plausible signed `output_digest` is taken on
  trust. It also only confirms the *result*, never that the agent's path to
  it was sound (`honest_but_unsound_process` stays an accepted case). The
  `runtime` block is self-asserted, so `forged_runtime_fingerprint` passes.
  Timestamps are self-reported; the deadline check only catches a receipt
  that *admits* being late.

- **A real bug I hit while building.** My first cut had the verifier take the
  ledger and run the replay / duplicate checks on every call. That meant
  re-verifying a receipt that was *already accepted* failed on `nonce_unseen`.
  I split it: those checks are submission-time only (inside the harness), and
  `vouch verify` now re-checks a stored receipt in isolation and separately
  reports whether the ledger has it and whether the chain is intact.

- **What I'd do next, in priority order.** (1) Re-execution for
  non-deterministic tasks - capture a seed / record the non-determinism so
  the check covers more than the deterministic fixtures. (2) A trusted
  timestamp source, or have the gatekeeper clock the run itself. (3) Move the
  ledger to SQLite with signed checkpoints so truncation is detectable, not
  just in-place edits. (4) Attestation - bind `worker_id` to a TPM/TEE quote
  so `runtime` isn't just self-asserted. (5) Quorum: N-of-M workers must
  agree before a task finalizes.

- **What I'm not claiming.** Single verifier, single ledger, no consensus, no
  sandbox, fixtures are trusted code. `vouch` verifies structure, identity,
  and recomputable postconditions - not an agent's reasoning, its side
  effects, or a compromised host. The full list is in the README under
  "What this harness does not verify," and every item there is staged as an
  accepted case in `vouch scoreboard` so the gaps are visible, not buried.
