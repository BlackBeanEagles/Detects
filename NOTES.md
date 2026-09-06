# Five-bullet note

> Draft, from the scaffold's behaviour. Rewrite in your own voice and add
> anything you changed or discovered while finishing it.

- **What passed.** Happy path produces an Ed25519-signed, proof-carrying
  receipt that chains into an append-only ledger and re-verifies standalone.
  All five required failure modes are rejected by a *named* check, with the
  reason surfaced in the `VerdictReport`: duplicate completion
  (`no_duplicate_completion`), stale ownership (`lease_epoch_current`),
  invalid evidence (`signature_valid` / `witness_recheck` / `fixture_known`),
  malformed evidence (`schema_parseable` and friends, no traceback leak),
  timeout + retry (executor + `within_deadline`). `vouch scoreboard`: 12/12
  forgeries rejected, 2/2 documented limitations still accepted. 24 tests
  green in ~3s.

- **What failed / where it is weak.** The witness re-check is only as strong
  as the fixture's cheap postcondition; for a task with no cheap check the
  verifier trusts a self-computed `output_digest` (staged as
  `honest_but_unsound_process`). Runtime identity is a local keypair, not
  attestation - `forged_runtime_fingerprint` passes. Timestamps are
  self-reported; the deadline check only catches a receipt that admits
  lateness. A timed-out worker thread is abandoned, not killed.

- **Design choices worth noting.** The verifier is a pure function with all
  context optional (absent context -> checks marked *skipped*, not failed),
  so the same code gates submission and re-audits a stored receipt.
  Determinism comes from canonical JSON + content addressing + an injectable
  clock. Fencing tokens (monotonic lease epochs) are what make stale
  ownership a one-line check.

- **What I'd improve next.** (1) Independent re-execution in the verifier for
  weak-witness tasks. (2) A trusted timestamp source. (3) SQLite ledger with
  signed checkpoints to detect truncation, not just in-place edits.
  (4) `hypothesis` fuzzing of the parser and witness checks. (5) Quorum:
  N-of-M workers must agree before finalize.

- **Scope / honesty.** Single verifier, single ledger, no consensus, no
  sandbox, trusted fixture code. `vouch` verifies structure, identity, and
  recomputable postconditions - not reasoning, side effects, or a
  compromised host. Full list in README "What this harness does not verify".
