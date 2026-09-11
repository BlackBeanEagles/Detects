# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `independent_reexecution` verifier check (#10 of 18) - opt-in via a
  `reexecutor`. `InProcessReexecutor` and `SubprocessReexecutor`
  (`python -m detects.reexec`, wired to `detects verify --reexecute` and
  `detects run --reexecute`). `verify_receipt` stays pure unless a reexecutor
  is passed.
- `nth_prime` fixture, whose cheap witness check ("is prime") is necessary
  but not sufficient - it exists to make re-execution earn its place.
- `Fixture.deterministic` flag; `slow_task` / `flaky_task` set it `False`
  and re-execution skips them.
- Adversary case `signed_wrong_prime` (a wrong-but-prime result the cheap
  check misses); 13 forgeries + 2 documented limitations.
- `tests/test_invariants.py` - four named invariants backed by Hypothesis
  (one terminal success per task; verdict stable over time; any unsigned
  mutation ⇒ REJECT and never removes a failure; a re-signed lie stays
  caught). `tests/test_reexecution.py`.
- `DESIGN.md` - the reasoning behind the design: decisions and rejected
  alternatives, the trust boundary as prose, and explicit non-goals.
- `tests/test_protocols.py` - `Ledger` / `LeaseManager` actually satisfy the
  `LedgerReadView` / `LeaseReadView` protocols the verifier is typed against.

### Changed

- `Run` is now constructed and used inside `Harness.execute_and_sign` - it
  had been declared to satisfy "deterministic task/run schema" but nothing
  built one. Now the run's identity fields are validated through it, not
  inlined as loose dict entries.
- The "canonical bytes minus `signature`" computation that `harness.py`,
  `verifier.py`, `adversary.py`, and six test files each re-implemented is
  now one function, `schema.signing_payload`.

### Fixed

- `Receipt.detail` - the executor already computed a human-readable reason
  for every outcome ("attempt 2 raised RuntimeError: ...", "exceeded
  deadline of 0.1s") and the harness silently discarded it. A `failure` or
  `timeout` receipt now carries that reason instead of an empty postcondition
  list.

### Removed

- `Receipt.unsigned()` / `Receipt.signing_payload()` - dead: nothing called
  them, since signing happens on a plain dict before it becomes a `Receipt`.
  Superseded by the module-level `signing_payload`.

## [0.1.0] - 2026-09-06

### Added

- Deterministic `TaskSpec` / `Run` / `Receipt` schema with canonical-JSON
  content addressing (`detects.canon`).
- Ed25519 source/runtime identity: keygen, sign, verify, runtime fingerprint
  (`detects.identity`).
- Proof-carrying fixtures: `sum_range`, `sort_list`, `dedupe`, `sha_blob`,
  plus `slow_task` / `flaky_task` for timeout and retry testing. Each ships a
  witness and a cheap independent re-check (`detects.fixtures`).
- Append-only, hash-chained ledger with tamper detection (`detects.ledger`).
- Time-limited leases with monotonic fencing tokens (`detects.lease`).
- Executor with per-attempt timeout and bounded exponential-backoff retry
  (`detects.executor`).
- `Harness`: claim -> execute -> sign -> verify -> append-iff-accepted
  (`detects.harness`).
- Pure `verify_receipt` with 17 named checks and optional context; returns a
  `VerdictReport`, never raises (`detects.verifier`).
- Bundled adversary: 12 forgeries + 2 documented limitations, with a
  scoreboard renderer (`detects.adversary`, `detects.scoreboard`).
- CLI: `keygen`, `run`, `verify` (`--json`), `verify-chain`, `ledger`,
  `scoreboard`, `--version` (`detects.cli`).
- Tests: one file per failure mode, happy path, CLI surface, and
  property-based fuzzing of the parser and witness checks.
- Tooling: ruff, mypy (strict), coverage gate, pre-commit, GitHub Actions
  matrix (3.11-3.13).

[Unreleased]: https://github.com/BlackBeanEagles/Detects/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/BlackBeanEagles/Detects/releases/tag/v0.1.0
