# vouch

[![CI](https://github.com/OWNER/vouch/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/vouch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2a6db2)](pyproject.toml)
[![Ruff](https://img.shields.io/badge/lint-ruff-000000)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A small, standalone **agent-execution verification harness**.

An "agent" (any autonomous worker) claims it completed a task. `vouch` turns
that claim into an **immutable, independently checkable evidence receipt**
that binds three identities together - *what was asked*, *which run produced
it*, and *what code/worker ran it* - and a **pure verifier** that can be
pointed at receipts it did not create.

Think of it as a courier's proof-of-delivery system: the driver files a
tamper-evident receipt (which package, which driver badge, which van, when,
a check anyone can repeat), and a clerk decides whether to believe it -
*is the signature real? did we already pay for this delivery? is this driver
still assigned the route?*

Everything here uses **synthetic fixtures and locally generated keys**. No
network, no live credentials.

---

## Quickstart

Requires Python 3.11+.

```bash
cd ryan
python -m venv .venv
# Windows:  .venv\Scripts\activate
# POSIX:    source .venv/bin/activate
pip install -e ".[dev]"      # or:  make install

pytest                        # 33 tests            (make test)
vouch scoreboard              # the bundled adversary
python examples/quickstart.py # narrated end-to-end run
```

### CLI

```bash
vouch keygen --out worker.key
vouch run --task sum_range --inputs '{"n": 100}'          # execute + sign + submit
vouch verify --receipt rcpt_XXXX.json --task sum_range --inputs '{"n": 100}' [--json]
vouch verify-chain --ledger ledger.jsonl
vouch ledger --ledger ledger.jsonl [--json]
vouch scoreboard
```

---

## What it does

| Piece | Module | Role |
|---|---|---|
| Task | `schema.TaskSpec` | Declarative unit of work. `task_id = sha256(canonical(spec))`. |
| Run | `schema.Run` | One attempt, by one worker, under one lease epoch, with a deadline. |
| Evidence receipt | `schema.Receipt` | Immutable, Ed25519-signed record binding task + run + source/runtime identity + outcome + a *witness*. |
| Ledger | `ledger.Ledger` | Append-only, hash-chained log of accepted receipts. |
| Lease manager | `lease.LeaseManager` | Time-limited task ownership with a monotonic fencing token (epoch). |
| Executor | `executor.execute` | Runs a fixture with a per-attempt timeout and bounded retries. |
| Harness | `harness.Harness` | `execute_and_sign` -> receipt; `submit` -> verify, then append iff ACCEPT. |
| **Verifier** | `verifier.verify_receipt` | **Pure function** `(receipt, *context) -> VerdictReport`. Never mutates, never raises. |
| Adversary | `adversary.py` | A bundled cheating agent: 12 forgeries + 2 documented limitations. |
| Scoreboard | `scoreboard.py` | Renders the adversary run as a pass/fail table. |

Full detail in **[ARCHITECTURE.md](ARCHITECTURE.md)** - receipt lifecycle
diagram, every field and what it binds, and the 17 verifier checks.

### The distinctive bit: proof-carrying receipts

A signature only proves *who* wrote a receipt, not that its claims are true.
So each fixture ships a **witness** and a **cheap re-check**:

| Fixture | Witness | Verifier re-checks (from inputs only) |
|---|---|---|
| `sum_range` | `claimed_output` | `== n(n+1)/2` |
| `sort_list` | `claimed_output` | same multiset as input **and** non-decreasing |
| `dedupe` | `claimed_output` | distinct set of input, first-seen order preserved |
| `sha_blob` | `claimed_output` | recompute `sha256(blob)` |

The verifier believes a `success` only if the witness survives its own
re-derivation - so a worker that signs a false result is still rejected
(`witness_recheck`). Where a cheap witness is not possible, the honest
answer is to say so rather than pretend (see *What it does not verify*).

---

## Failure model

**Faults assumed to happen.** Crashed workers; slow workers; a scheduler
that double-dispatches one task after a lease lapses; a network that
redelivers a receipt; a buggy worker that returns a wrong result; schema
drift between producer and verifier.

**Adversary capability assumed.** Can submit arbitrary bytes to the
verifier. May or may not possess a valid worker signing key. May replay,
truncate, re-sign, back-date, or pad anything it sends.

**Trusted.** The verifier's own code and the process that runs it; the
ledger's write path (only the harness appends, and only after ACCEPT); the
`now` handed to the verifier at submission time.

Concrete failure modes exercised by `tests/` (one file each):

| Failure mode | Staged as | Caught by |
|---|---|---|
| Duplicate completion | second valid `success` for a finalized `task_id` | `no_duplicate_completion` |
| Stale ownership | A's lease expires, B re-claims, A submits | `lease_epoch_current` |
| Invalid evidence | broken sig / tampered body / fabricated witness / unknown fixture | `signature_valid`, `witness_recheck`, `fixture_known` |
| Malformed evidence | truncated JSON / missing field / bad schema version / proof bomb | `schema_parseable`, `schema_version_supported`, `witness_size_bounded` |
| Timeout & retry | slow task past deadline; late receipt; flaky task; give-up | `within_deadline`; executor retry/backoff |

`vouch scoreboard` runs all 14 adversary cases and asserts each matches its
documented expectation. `tests/test_property.py` fuzzes the parser and the
witness checks with Hypothesis.

---

## What this harness does **not** verify

This is the honest part. `vouch` checks structure, identity, and
declared-and-recomputable postconditions. It does **not** establish:

1. **Semantic correctness beyond the witness.** If a task's real intent
   cannot be cheaply re-derived from its inputs, a signed `success` with a
   plausible `output_digest` passes. `vouch` verifies *results it can
   re-check*, not reasoning. (`adversary.honest_but_unsound_process`.)
2. **Genuine runtime identity.** `worker_id` is a locally generated Ed25519
   key, not hardware attestation or a CA-rooted identity. The `runtime`
   block (code version, platform) is self-asserted and **unchecked** - a
   worker can sign a lie about it. (`adversary.forged_runtime_fingerprint`.)
3. **Honest clocks.** `started_at` / `finished_at` are self-reported. The
   deadline check only catches a receipt that *admits* finishing late;
   there is no trusted timestamp authority. `not_from_the_future` is a
   coarse sanity bound against the verifier's own clock.
4. **Side effects.** `vouch` sees a returned value and a witness. A task
   that also wrote to a database or sent an email is outside its view.
5. **Byzantine / multi-node conditions.** Single verifier, single ledger,
   no quorum, no consensus. A compromised verifier host or ledger writer
   defeats it entirely.
6. **Untrusted code execution.** Fixtures are trusted Python. There is no
   sandbox; a timed-out worker thread is abandoned, not killed.

See also [SECURITY.md](SECURITY.md).

---

## Layout

```
src/vouch/
  canon.py       canonical JSON + sha256
  clock.py       injectable clocks
  identity.py    Ed25519 keys, sign/verify, runtime fingerprint
  schema.py      TaskSpec / Run / Receipt / VerdictReport / parse_receipt
  protocols.py   read-only views the verifier depends on
  fixtures.py    synthetic deterministic tasks + witness/recheck pairs
  lease.py       leases with fencing tokens
  ledger.py      append-only hash-chained log
  executor.py    timeout + bounded retry
  harness.py     claim -> execute -> sign -> verify -> append
  verifier.py    the pure verifier (17 named checks)
  adversary.py   bundled cheating agent
  scoreboard.py  adversary results table
  cli.py         keygen / run / verify / verify-chain / ledger / scoreboard
tests/           one file per failure mode + happy path + CLI + property-based
examples/        quickstart.py
```

## Quality gates

`make check` (and CI, on 3.11 / 3.12 / 3.13) runs:

- **ruff** - lint + format check (`ruff check`, `ruff format --check`)
- **mypy** - `strict = true` over `src/vouch`
- **pytest** - with `--cov`; coverage gate at 85% (currently ~92%)
- **`vouch scoreboard`** - the adversary must match its documentation

`pre-commit` config is included (`pre-commit install`).

## Extending it

Good next steps, roughly in order of value:

- **Independent re-execution.** Have the verifier re-run the fixture in a
  clean process and compare digests, instead of trusting the witness for
  tasks where a cheap check is weak. Closes limitation #1.
- **Trusted timestamps.** A signing timestamp authority, or have the
  gatekeeper clock the run itself. Closes limitation #3.
- **Attestation.** Bind `worker_id` to a TPM/TEE quote. Closes #2.
- **Durable ledger.** SQLite with WAL + periodic signed checkpoints;
  detect truncation, not just in-place tampering.
- **Quorum.** N-of-M independent workers must agree before finalize.

Changelog: [CHANGELOG.md](CHANGELOG.md).
