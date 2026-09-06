# Notes on the build

<!-- Ryan asked for a five-bullet note: what passed, what failed, what I'd
     improve next. Swap in your own numbers/phrasing before sending. -->

Hi Ryan - here's where `vouch` landed and how I'd take it further.

- **What passed.** The core loop works the way I wanted: a worker claims a
  lease, runs a task, and emits an Ed25519-signed receipt that carries a
  *witness* - proof material the verifier can cheaply re-derive from the
  inputs alone. The verifier is a pure function (17 named checks, returns a
  report, never raises), so I can point it at a stored receipt later and get
  the same answer. All five failure modes I set out to cover are rejected by
  a specific named check, not a vague "invalid": duplicate completion, stale
  ownership (fencing-token epoch), bad signature / tampered body / fabricated
  witness, malformed bytes (parser fails to one typed error, no traceback),
  and a late receipt from a timed-out run. 35 tests, ~94% coverage, and the
  bundled adversary reports 12/12 forgeries caught.

- **What failed / where it's honestly weak.** The witness re-check is only as
  strong as the fixture's cheap postcondition. For a task where I can't
  re-derive the answer from the inputs, the verifier ends up trusting a
  self-computed `output_digest` - I staged that as `honest_but_unsound_process`
  and it passes, by design. Same story for the `runtime` block: it's
  self-asserted, so `forged_runtime_fingerprint` (a worker lying about its
  code version) also passes. Timestamps are self-reported; the deadline check
  only catches a receipt that *admits* being late.

- **A real bug I hit while building.** My first cut had the verifier take the
  ledger and run the replay / duplicate checks on every call. That meant
  re-verifying a receipt that was *already accepted* would fail on
  `nonce_unseen`. I split it: those checks are submission-time only
  (inside the harness), and `vouch verify` now re-checks a stored receipt in
  isolation and separately reports whether the ledger has it and whether the
  chain is intact.

- **What I'd do next, in priority order.** (1) Independent re-execution -
  have the verifier re-run the fixture in a clean process and compare digests
  instead of trusting the witness where the cheap check is weak; that closes
  the biggest gap above. (2) A trusted timestamp source (or have the
  gatekeeper clock the run itself). (3) Move the ledger to SQLite with signed
  checkpoints so truncation is detectable, not just in-place edits. (4) More
  Hypothesis coverage on the witness checks. (5) Quorum: N-of-M workers must
  agree before a task finalizes.

- **What I'm not claiming.** Single verifier, single ledger, no consensus, no
  sandbox, fixtures are trusted code. `vouch` verifies structure, identity,
  and recomputable postconditions - not an agent's reasoning, its side
  effects, or a compromised host. The full list is in the README under
  "What this harness does not verify," and every item there is staged as an
  accepted case in `vouch scoreboard` so the gaps are visible, not buried.
