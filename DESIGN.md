# Design

This is the reasoning behind `vouch` - the problem, the shape I chose, the
decisions I made and the ones I rejected, and where the boundary sits.
[README.md](README.md) is the user-facing guide; [ARCHITECTURE.md](ARCHITECTURE.md)
is the reference (field tables, the check list, the lifecycle diagram). This
doc is the argument.

## The problem

An agent claims "I completed task X." In a real agent system that claim
drives money, state changes, and downstream work, and the agent that makes
it is also the thing that produced the output, the timing, and every piece
of metadata around it - and can sign all of it.

So the question I narrowed to is: **can a claim of completion be turned into
evidence a third party can check, without re-doing the work and without
trusting the worker?** And, just as much: be precise about what that
evidence does *not* establish.

The reason this is more than plumbing is that the worker is the adversary
(or is simply buggy). "Trust the exit code" or "trust a signed JSON blob"
don't reduce trust, they relocate it. The design work is in finding the
checks that hold *regardless of the worker's honesty*, and being honest
about the checks that don't.

## The model, in four sentences

Three content-addressed objects: a **task** (`task_id = sha256(canonical(spec))`),
a **run** (one attempt, one worker, one lease epoch, one deadline), and a
**receipt** (immutable, signed, binding all three identities plus the
outcome and a *witness*). A **ledger** is an append-only hash chain of
accepted receipts. A **verifier** is a pure function from a receipt - plus
whatever context you can supply - to a list of named pass/fail checks.
Nothing is believed because the worker said so; every field is recomputed,
cross-checked against trusted state, or explicitly marked as taken on trust.

## Principles that drove the rest

**Determinism is the substrate.** Every id and signature is computed over
canonical JSON - sorted keys, tight separators, no NaN. The same structure
produces the same bytes, the same hash, and the same signature on any
machine. Without that, "content-addressed" and "reproducible" are just
words.

**The verifier is a pure function.** Its context - ledger, leases, clock,
reexecutor - is injected and optional. Missing context marks a check
*skipped*, never *failed*. So one code path gates a live submission and
re-audits a receipt found on disk a month later, and each check can be
tested in isolation.

**Necessary versus sufficient is a real distinction.** The cheap witness
check proves a necessary property of the output from the inputs alone.
Sometimes that is the whole story (`sum_range`); sometimes it is not
(`nth_prime` - any prime passes "is it prime"). I made that gap concrete
with a fixture that has it, and closable with opt-in re-execution, rather
than pretending the cheap check is always enough.

**Limits are a feature, not an apology.** Every "vouch can't check this" is
staged as an accepted case in the adversary scoreboard, so the gaps are
executable and visible instead of buried in a caveats paragraph.

## Decisions, and what I rejected

### Ledger: a hash chain, not a Merkle tree

I chose a linear hash chain - each entry carries the previous entry's hash -
because the property I need is *tamper-evidence of an append-only log*, and a
chain delivers that in a dozen lines with an O(n) full verification. A
Merkle tree buys efficient inclusion and consistency proofs for third
parties who don't hold the whole log. That matters when the log is large and
you serve proofs to light clients. This log is single-node and small and
nobody requests proofs, so a tree would be complexity with no consumer. If
the ledger grew or became multi-reader I'd revisit - likely a Merkle
mountain range with periodic signed checkpoints.

### Integrity: Ed25519 signatures, not HMAC or a bare hash

A bare hash of the receipt proves nothing about origin - anyone can
recompute it. HMAC proves origin but needs a shared secret, which means the
verifier can also forge receipts; that is exactly the wrong trust model for
something whose job is to check the worker. Ed25519 keeps signing (the
worker's private key) and verification (its public key, carried in the
receipt) asymmetric, so the verifier can check a receipt it could never have
produced. The cost is that this "identity" is a locally generated keypair,
not attestation - I call that out plainly - but it is the right primitive,
and replacing the key's source with a TPM/TEE quote later touches nothing
else.

### Result-checking: cheap witness by default, re-execution opt-in

The default check re-derives a necessary property of the output from the
inputs (`witness_recheck`). It is cheap, side-effect-free, and it keeps
`verify_receipt` pure. Full re-execution is stronger - it catches wrong
results the cheap check cannot - but it runs the task's code, which is a
very different thing to hand a verifier: cost, non-determinism, side
effects. So re-execution is opt-in. You pass a `reexecutor`, and that is the
single argument that makes the function effectful. Deterministic fixtures
are re-run and digest-compared; non-deterministic ones are skipped, not
failed. I would rather ship a pure verifier that is honest about a gap than
one that quietly shells out on every call.

### Verifier shape: a pure function with injected read-views, not a stateful object

I considered a `Verifier` class holding references to the ledger and lease
manager. It reads well for the submission path and worse for everything
else - re-auditing an old receipt, verifying in another process, testing one
check alone. A function with optional keyword context, typed against small
read-only `Protocol`s (`LedgerReadView`, `LeaseReadView`), does all of those
and cannot accidentally mutate anything. The harness is the only writer to
the ledger, and only after an ACCEPT verdict.

### Ownership: fencing tokens, not heartbeats or lease timestamps

Stale ownership - a slow worker reporting after its lease lapsed and the
task was reassigned - is caught by a monotonic epoch. Every reassignment
bumps it; the receipt carries the epoch its run was claimed under; the
verifier rejects any epoch that is not current. Comparing lease timestamps
instead would fold in clock trust I am trying to avoid, and heartbeats add a
liveness protocol for no extra safety. A fencing token is one integer and
one comparison, and it is the standard answer to this exact problem.

### Timeout: a worker thread with `future.result(timeout)`, not signals or a subprocess

Each attempt runs in a thread and the executor waits with a timeout. It is
portable - no `SIGALRM`, works on Windows - and small. The honest cost: a
timed-out Python thread cannot be force-killed, so it is abandoned and
finishes in the background. A subprocess per attempt would be killable but
heavier, and it complicates moving fixtures and results around; for a
harness whose fixtures are trusted and short, the thread is the right trade.
Recorded timestamps still come from the injected clock, so only the timeout
race touches real time.

### Schema: pydantic and canonical JSON, with an explicit version field

JSON, because receipts should be readable in the ledger and diffable in
review. pydantic v2 with `extra="forbid"`, because an unknown field should
be a hard error, not silently dropped. `parse_receipt` is the single choke
point - every byte string, dict, or garbage blob goes through it and comes
out either a normalized dict or a typed `VouchParseError`, never a stray
traceback. `schema_version` is an explicit checked field with an allow-list,
so a producer on a newer format is rejected loudly rather than misread.
Protobuf or msgpack would be smaller and faster; I need neither, and
readability in the audit log is worth more here.

### Scope of "task": synthetic fixtures with a determinism flag

vouch verifies fixtures from a known registry, not arbitrary submitted code.
Verifying arbitrary code pulls in sandboxing, resource limits, and a real
threat model for the executor itself - a project of its own, and orthogonal
to "is this completion claim believable." The `deterministic` flag on a
fixture is the seam where that generality would enter; re-execution already
keys off it.

### One node, no consensus

No quorum, no Byzantine fault tolerance, one ledger, one verifier. BFT
answers "what if some of the verifiers lie," which is a real question for a
production system and a large one. Here the verifier and its ledger are
stated plainly as part of the trust base. N-of-M worker agreement is the
first place I would extend, and the receipt/witness shape already supports
collecting several and comparing them.

## Trust boundary

The adversary controls everything on the wire and everything the worker
produces: the receipt bytes, the `runtime` block, `started_at` /
`finished_at`, the witness contents, and possibly a valid signing key. It
can replay, truncate, re-sign, back-date, pad, or substitute.

Trusted: the verifier's own code and process; the ledger's write path
(harness only, post-ACCEPT); the `now` handed to the verifier at submission;
the fixture definitions.

Everything on the adversary's side is either re-derived (task id, witness,
output digest for deterministic tasks), cross-checked against trusted state
(nonce, lease epoch, previous-hash, prior completion), or explicitly taken
on trust and named as such (`runtime` contents, self-reported clocks, the
reasoning behind a correct result).

## Non-goals

- Verifying an agent's *reasoning* - only its result, and for a
  non-deterministic task only a signed digest of it.
- Real runtime attestation - `worker_id` is a local keypair.
- Trusted time - there is no timestamp authority.
- Observing side effects outside a task's return value.
- Byzantine or multi-node robustness.
- Sandboxed execution of untrusted code.
- Authorization, multi-tenancy, rate limiting, throughput - this is a
  harness, not a service.

## If I kept going

Independent re-execution for non-deterministic fixtures (capture a seed); a
trusted timestamp source; a durable ledger (SQLite plus signed checkpoints)
that detects truncation, not only in-place edits; attestation-backed
identity; and N-of-M quorum. Priority order and rationale are in
[NOTES.md](NOTES.md). The extension seams - the `deterministic` flag, the
read-view protocols, the opt-in reexecutor - are already in place.
