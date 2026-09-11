# Security

## Scope

`detects` is a verification *harness*, not a production trust anchor. It runs
entirely on **synthetic fixtures with locally generated keys**. It makes no
network calls and requires no credentials. Do not point it at real workloads
without first reading the limitations below.

## Threat model

The working adversary is executable: see [`src/detects/adversary.py`](src/detects/adversary.py)
and run `detects scoreboard`. In summary:

- **Adversary can** submit arbitrary bytes to the verifier, and may replay,
  truncate, re-sign, back-date, pad, or substitute anything it sends. It may
  or may not hold a valid worker signing key.
- **Trusted:** the verifier's own code and process; the ledger write path
  (only the harness appends, only after an ACCEPT verdict); the reference
  clock passed to the verifier at submission time.

## What `detects` does not defend against

Full detail in [README](README.md#what-this-harness-does-not-verify) and
[ARCHITECTURE](ARCHITECTURE.md#trust-boundary). Headlines:

1. An agent's reasoning. The result is checked - by the cheap witness, and
   (opt-in) by re-executing deterministic fixtures - but not the path to it,
   and a non-deterministic task with no reexecutor is trusted on its digest.
2. Forged `runtime` metadata - `worker_id` is a local keypair, not
   attestation.
3. Dishonest clocks - timestamps are self-reported; no timestamp authority.
4. Side effects a task performs outside its return value.
5. Byzantine / multi-node conditions - single verifier, single ledger.
6. Untrusted code execution - fixtures are trusted; there is no sandbox.

## Reporting

This is a technical-trial repository. Open an issue, or contact the author
directly.
