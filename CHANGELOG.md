# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-06

### Added

- Deterministic `TaskSpec` / `Run` / `Receipt` schema with canonical-JSON
  content addressing (`vouch.canon`).
- Ed25519 source/runtime identity: keygen, sign, verify, runtime fingerprint
  (`vouch.identity`).
- Proof-carrying fixtures: `sum_range`, `sort_list`, `dedupe`, `sha_blob`,
  plus `slow_task` / `flaky_task` for timeout and retry testing. Each ships a
  witness and a cheap independent re-check (`vouch.fixtures`).
- Append-only, hash-chained ledger with tamper detection (`vouch.ledger`).
- Time-limited leases with monotonic fencing tokens (`vouch.lease`).
- Executor with per-attempt timeout and bounded exponential-backoff retry
  (`vouch.executor`).
- `Harness`: claim -> execute -> sign -> verify -> append-iff-accepted
  (`vouch.harness`).
- Pure `verify_receipt` with 17 named checks and optional context; returns a
  `VerdictReport`, never raises (`vouch.verifier`).
- Bundled adversary: 12 forgeries + 2 documented limitations, with a
  scoreboard renderer (`vouch.adversary`, `vouch.scoreboard`).
- CLI: `keygen`, `run`, `verify` (`--json`), `verify-chain`, `ledger`,
  `scoreboard`, `--version` (`vouch.cli`).
- Tests: one file per failure mode, happy path, CLI surface, and
  property-based fuzzing of the parser and witness checks.
- Tooling: ruff, mypy (strict), coverage gate, pre-commit, GitHub Actions
  matrix (3.11-3.13).

[Unreleased]: https://example.invalid/vouch/compare/v0.1.0...HEAD
[0.1.0]: https://example.invalid/vouch/releases/tag/v0.1.0
