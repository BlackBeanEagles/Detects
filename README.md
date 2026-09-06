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

**Docs:** [DESIGN.md](DESIGN.md) is the reasoning (decisions, rejected
alternatives, trust boundary, non-goals); [ARCHITECTURE.md](ARCHITECTURE.md)
is the reference (lifecycle diagram, field tables, the 18 checks);
[NOTES.md](NOTES.md) is the five-bullet trial note.

---

## Quickstart

Requires Python 3.11+.

```bash
cd ryan
python -m venv .venv
# Windows:  .venv\Scripts\activate
# POSIX:    source .venv/bin/activate
pip install -e ".[dev]"      # or:  make install

pytest                        # ~49 tests           (make test)
vouch scoreboard              # the bundled adversary (13 caught, 2 accepted)
python examples/quickstart.py # narrated end-to-end run
```

### CLI

```bash
vouch keygen --out worker.key
vouch run --task sum_range --inputs '{"n": 100}'          # execute + sign + submit
vouch verify --receipt rcpt_XXXX.json --task nth_prime --inputs '{"n": 10}' [--reexecute] [--json]
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
| Adversary | `adversary.py` | A bundled cheating agent: 13 forgeries + 2 documented limitations. |
| Scoreboard | `scoreboard.py` | Renders the adversary run as a pass/fail table. |
| Re-execution | `reexec.py` | Opt-in: re-run a deterministic task and compare digests. |

Full detail in **[ARCHITECTURE.md](ARCHITECTURE.md)** - receipt lifecycle
diagram, every field and what it binds, and the 18 verifier checks.

### The distinctive bit: proof-carrying receipts + re-execution

A signature only proves *who* wrote a receipt, not that its claims are true.
So each fixture ships a **witness** and a **cheap re-check** from the inputs
alone:

| Fixture | Witness | Cheap re-check (`witness_recheck`) | Sufficient? |
|---|---|---|---|
| `sum_range` | `claimed_output` | `== n(n+1)/2` | yes |
| `sort_list` | `claimed_output` | same multiset as input **and** non-decreasing | yes |
| `dedupe` | `claimed_output` | distinct set of input, first-seen order preserved | yes |
| `sha_blob` | `claimed_output` | recompute `sha256(blob)` | yes |
| `nth_prime` | `claimed_output` | is prime | **no - any prime passes** |

The cheap check is *necessary* but not always *sufficient* - `nth_prime`
shows it: a worker can sign a wrong-but-prime answer and slip past. Passing
a **reexecutor** adds `independent_reexecution`, which re-runs the task
(in-process, or in a clean subprocess via `vouch verify --reexecute`) and
compares `output_digest`. That is the one input to `verify_receipt` that
lets it run code; without it the function stays pure. Non-deterministic
fixtures are skipped, and re-execution still cannot judge an agent's
*reasoning* - only its result (see *What it does not verify*).

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
| Wrong result the cheap check misses | a signed but wrong `nth_prime` (still prime) | `independent_reexecution` |

`vouch scoreboard` runs all 15 adversary cases (13 caught, 2 accepted
limitations) and asserts each matches its documented expectation.
`tests/test_property.py` fuzzes the parser and witness checks with
Hypothesis; `tests/test_invariants.py` backs four named invariants
(one terminal success per task; verdict stable over time; any unsigned
mutation ⇒ REJECT and never removes a failure; a re-signed lie stays caught).

---

## What this harness does **not** verify

This is the honest part. `vouch` checks structure, identity, and
declared-and-recomputable postconditions. It does **not** establish:

1. **An agent's reasoning.** `witness_recheck` and (opt-in)
   `independent_reexecution` verify the *result* - for deterministic tasks,
   exactly. Neither can tell you the agent reached it soundly rather than by
   luck or a wasteful path. (`adversary.honest_but_unsound_process`.) And
   for a non-deterministic task, or one with no reexecutor supplied, a
   plausible signed `output_digest` is taken on trust.
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
  fixtures.py    synthetic tasks + witness/recheck pairs (deterministic flag)
  lease.py       leases with fencing tokens
  ledger.py      append-only hash-chained log
  executor.py    timeout + bounded retry
  reexec.py      in-process / clean-subprocess re-execution
  harness.py     claim -> execute -> sign -> verify -> append
  verifier.py    the pure verifier (18 named checks)
  adversary.py   bundled cheating agent
  scoreboard.py  adversary results table
  cli.py         keygen / run / verify / verify-chain / ledger / scoreboard
tests/           failure modes + happy path + CLI + re-execution +
                 property-based + named invariants
examples/        quickstart.py
```

## Quality gates

`make check` (and CI, on 3.11 / 3.12 / 3.13) runs:

- **ruff** - lint + format check (`ruff check`, `ruff format --check`)
- **mypy** - `strict = true` over `src/vouch`
- **pytest** - ~49 tests with `--cov`; coverage gate at 85% (currently ~92%)
- **`vouch scoreboard`** - the adversary must match its documentation

`pre-commit` config is included (`pre-commit install`).

## Extending it

Good next steps, roughly in order of value:

- **Re-execution for non-deterministic tasks.** Record a seed / capture
  non-determinism so `independent_reexecution` can cover more than the
  `deterministic` fixtures it handles today.
- **Trusted timestamps.** A signing timestamp authority, or have the
  gatekeeper clock the run itself. Closes limitation #3.
- **Attestation.** Bind `worker_id` to a TPM/TEE quote. Closes #2.
- **Durable ledger.** SQLite with WAL + periodic signed checkpoints;
  detect truncation, not just in-place tampering.
- **Quorum.** N-of-M independent workers must agree before finalize.

Changelog: [CHANGELOG.md](CHANGELOG.md).
