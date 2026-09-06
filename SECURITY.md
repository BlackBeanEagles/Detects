# Security

## Scope

`vouch` is a verification *harness*, not a production trust anchor. It runs
entirely on **synthetic fixtures with locally generated keys**. It makes no
network calls and requires no credentials. Do not point it at real workloads
without first reading the limitations below.

## Threat model

The working adversary is executable: see [`src/vouch/adversary.py`](src/vouch/adversary.py)
and run `vouch scoreboard`. In summary:

- **Adversary can** submit arbitrary bytes to the verifier, and may replay,
  truncate, re-sign, back-date, pad, or substitute anything it sends. It may
  or may not hold a valid worker signing key.
- **Trusted:** the verifier's own code and process; the ledger write path
  (only the harness appends, only after an ACCEPT verdict); the reference
  clock passed to the verifier at submission time.

## What `vouch` does not defend against

Full detail in [README](README.md#what-this-harness-does-not-verify) and
[ARCHITECTURE](ARCHITECTURE.md#trust-boundary). Headlines:

1. Semantic correctness beyond a fixture's cheap, recomputable postcondition.
2. Forged `runtime` metadata - `worker_id` is a local keypair, not
   attestation.
3. Dishonest clocks - timestamps are self-reported; no timestamp authority.
4. Side effects a task performs outside its return value.
5. Byzantine / multi-node conditions - single verifier, single ledger.
6. Untrusted code execution - fixtures are trusted; there is no sandbox.

## Reporting

This is a technical-trial repository. Open an issue, or contact the author
directly.
