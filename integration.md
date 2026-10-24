# NovaMPC + Hyperledger Fabric: integration and thesis benchmark plan

This guide describes a research integration of the current NovaMPC v2 verifier with Hyperledger Fabric. It is a staged plan and coding brief, not a claim that the current custom MPC-in-the-head protocol is secure. The protocol analysis in `V2_PROTOCOL_NOTES.md` is still incomplete; Fabric integration does not repair that limitation.

## 1. What the integrated system should do

The client owns a private `u32` value and its membership path. It constructs either a membership proof or a combined range-and-membership proof locally. A Fabric chaincode invocation carries the **serialized proof** and public policy identifier. Every endorsing peer loads the policy from its ledger state and independently verifies the proof using the same versioned NovaMPC verifier. Only a successful verification writes an accepted transaction record.

The proof hides the value and membership path from the channel transaction payload, subject to the protocol's actual zero-knowledge properties being established. The proof, public statement, policy identifier, and application transaction metadata are visible to channel participants. A proof is not confidential data merely because it is a zero-knowledge proof.

```text
Client (Rust SDK / benchmark driver)
  ├─ constructs proof locally using NovaMPC v2
  ├─ submits {policy_id, proof_bytes, request_id} through Fabric Gateway
  ▼
Fabric Gateway peer -> endorsing peers execute the chaincode
                         ├─ read policy {root, count, depth, range, suite}
                         ├─ call deterministic NovaMPC v2 verifier
                         └─ write accepted record only on success
  ▼
Orderer orders endorsed transaction -> peers validate and commit -> client observes commit event
```

The orderer does not run the proof verifier. Endorsing peers do. For a two-organization endorsement policy, the chaincode and verifier run at least once on a peer from each required organization. Fabric Gateway coordinates endorsement; the client must wait for a commit event/status to distinguish proposal acceptance from a committed valid transaction. See the [Fabric transaction flow](https://hyperledger-fabric.readthedocs.io/en/latest/txflow.html) and [Gateway documentation](https://hyperledger-fabric.readthedocs.io/en/latest/gateway.html).

## 2. Important current-project facts and decision

The repository currently has a Rust library and a v2 API under `src/v2/`; it does not contain Fabric chaincode, a Fabric network, or a Fabric application client. The public v2 API has `V2Proof::to_bytes()`, `verify_statement()`, `verify_bytes_statement()`, and range, membership, and combined proof constructors. The raw `verify`/`verify_bytes` functions are crate-private. Verification must be called with the expected public statement **and** the expected 32-byte context hash; do not accept the statement or context embedded in a proof as the application's authority.

Current benchmark measurements in `V2_BENCHMARKS.md` are local CPU-only, not Fabric results. For a four-member combined proof, the measured serialized size is about 7.18 MiB at `M=96` and 16.40 MiB at `M=219`; local verification medians are about 169 ms and 391 ms. At 32 members those combined proofs reach about 11.48 MiB and 26.20 MiB. This size is material: large proofs can dominate endorsement, replication, block storage, and client/network time even when they fit the configured hard limit.

**Recommended thesis architecture:** keep the cryptographic prover and verifier in the existing Rust crate. Use a small Go Fabric chaincode to access ledger state and use a narrow, versioned C ABI to call a Rust verifier library compiled into the chaincode runtime image. Use Fabric's external chaincode service/custom builder path so the Go shim and Rust library are built and packaged reproducibly. This keeps the consensus-critical verification logic in one implementation rather than reimplementing cryptography in Go. Chaincode execution must be deterministic: no network calls to a verifier service, wall-clock checks, random choices, or local mutable files during transaction simulation. Fabric's documented chaincode languages are Go, Node.js, and Java, and its external-service documentation describes Go and Node shims; Rust is not a drop-in built-in chaincode language. See [supported chaincode development](https://hyperledger-fabric.readthedocs.io/en/latest/chaincode4ade.html), [external chaincode service](https://hyperledger-fabric.readthedocs.io/en/latest/cc_service.html), and [chaincode lifecycle](https://hyperledger-fabric.readthedocs.io/en/latest/chaincode_lifecycle.html).

The Go-to-Rust FFI/custom-builder bridge is technically feasible but adds deployment and ABI complexity. Prove it with a tiny C ABI smoke test before writing chaincode. An HTTP verifier service can be a useful *off-chain comparison benchmark*, but it must not be presented as Fabric-enforced proof verification: endorsing chaincode must not trust an external response that is outside Fabric's deterministic execution and endorsement result.

## 3. Security and correctness prerequisites

Complete these design checks before using Fabric results as evidence about the application:

1. **Treat v2 cryptography as experimental.** `V2_PROTOCOL_NOTES.md` records unresolved security questions. Never write that the proof system is secure because Fabric endorses it, because tests pass, or because the root is field-sized. Label the deployment and paper honestly as a prototype until the exact protocol has a complete proof and independent review.
2. **Verify against ledger-authoritative parameters.** Store the policy's canonical root, member count, depth, range bounds, suite/version, and policy state in the ledger. The chaincode builds the expected `StatementV2` and context hash from that record and calls `verify_statement` or `verify_bytes_statement`. Reject unknown versions, unsupported repetitions, malformed/noncanonical bytes, mismatched policy IDs, and statements that do not match the stored values.
3. **Bind proof to application context if replay matters.** Proof format v3 stores a 32-byte `context` hash bound into the transcript, and the public verifier requires the caller's expected context. Bind the request/policy identifier (or a nullifier input) into that context and persist the corresponding ledger check if one-time use is required. A `request_id` stored beside a proof is not replay protection by itself; the proof must be bound to the same authenticated context.
4. **Define authorization separately from proof validity.** Decide which MSP identities can register/update policies and which can submit proofs. The proof only establishes the relation encoded by the selected statement; it does not establish the sender's business authorization.
5. **Decide duplicate handling.** If an operation is consumable once, derive a ledger key from a context-bound nullifier and reject a previously used key. Do not derive it from the hidden value in plaintext. Without a context-bound nullifier design, demonstrate only reusable proof verification.
6. **Keep the chaincode deterministic and bounded.** Validate argument count, policy ID length, proof length, version, repetition count, and statement bounds before allocating or verifying. Do not use chaincode to call the prover or rebuild the public Merkle set on every transaction. Do not persist a full proof in world state unless the application needs it: the proof is already part of the submitted transaction history; store a digest and the minimal result record for state queries.
7. **Keep payload binary end to end.** `V2Proof::to_bytes()` is canonical binary. Avoid base64-in-JSON unless the SDK/interface forces it; base64 expands payload by about one third. Have the application pass raw bytes through a supported binary-safe encoding or a rigorously specified byte-string encoding, and measure the actual Fabric envelope, not only the proof vector length.

## 4. Integration stages and prompts for the coding agent

The agent should work one stage at a time. At session start, inspect `git status` and recent history, preserve `.freebuff/`, `.ua/`, `GUIDE.md`, `correct.md`, and any other uncommitted/user-owned files, and resume from the last verified `[FABRIC-STEP-XX]` commit. Do not reset, clean, or amend commits. For every completed stage, run the stated checks, review the diff for determinism/security/scope, and commit with a subject beginning with that stage ID. If a stage is blocked by an unresolved cryptographic question, stop and report it instead of inventing protocol behavior. Do not combine stages or add a general framework.

### FABRIC-STEP-00 — inspect environment and freeze integration design

**Prompt to agent:**

> Read `integration.md`, `V2_BENCHMARKS.md`, `V2_MIGRATION.md`, `V2_DESIGN.md`, and `V2_PROTOCOL_NOTES.md`. Inspect the existing v2 public APIs and repository state. Do not modify cryptographic protocol code or deploy anything. Record a short `FABRIC_DESIGN.md` with: exact Fabric version to use; actual server OS/CPU/RAM/disk; intended channel topology and endorsement policy; the Go-chaincode to Rust C ABI/custom-builder approach; exact process boundaries; policy state schema; proof input schema; access-control rules; proof-replay decision; configured block/gRPC limits; and how all endorsing peers will receive the exact same verifier binary. Cite official Fabric docs and identify anything that cannot yet be decided from repository/server facts. Explicitly label the one-server topology as a controlled research environment, not a decentralized or highly available deployment. Do not write chaincode yet.

**Acceptance:** no source code changed; the design states where proof verification runs, which ledger data is authoritative, how Rust is invoked deterministically, how proof version/context is bound, and what the experiment can and cannot claim. Commit as `[FABRIC-STEP-00] Record Fabric integration design`.

### FABRIC-STEP-01 — add a minimal Rust C ABI and Go FFI smoke test

**Prompt to agent:**

> Implement only the narrow ABI needed to verify a serialized v2 proof against an explicit expected statement and fixed `V2Params`. Do not expose arbitrary Rust object layouts. Define an ABI version, byte-pointer/length inputs, a stable status code, and a bounded error message/output buffer. Validate null pointers, lengths, enum/tag values, canonical statement encoding, and proof-size limits before parsing. Ensure no Rust panic/unwind crosses the C boundary (catch and translate panics); do not return secret witness data. Add a small Go executable/test that calls the built Rust library on one known-valid and one tampered proof and checks success/rejection. Use a custom reproducible build container/toolchain and pin dependency/build versions. Do not implement Fabric chaincode in this step.

**Acceptance:** Go and Rust compile together on the intended server architecture; known-valid proof succeeds, malformed/tampered proofs reject, invalid FFI arguments return errors without crashing, sanitizer or equivalent memory-safety checks are recorded where feasible, and the ABI docs specify ownership/lifetime. Confirm binary output and verifier result are deterministic for fixed inputs. Commit as `[FABRIC-STEP-01] Add bounded Rust verifier C ABI`.

### FABRIC-STEP-02 — implement minimum Go chaincode

**Prompt to agent:**

> Add a minimal Go chaincode that registers/updates a policy under an explicit MSP authorization rule and submits a proof. Policy state must contain a canonical policy ID, suite/proof version, root bytes, member count, depth, range bounds (when applicable), and enabled/revoked status. Parse only bounded inputs. Construct the expected statement from ledger state—not from untrusted proof fields—and call the Rust C ABI verifier. On success, write a compact result record containing policy ID, proof digest, request/context identifier if the proof format binds it, submitting MSP/client identity as appropriate, and accepted status. On failure, return an error and perform no write. Use stable serialization and deterministic keys; no clock, network, random, or environment-dependent business logic. Include explicit tests for authorized policy registration, unauthorized registration, valid proof, invalid proof, wrong policy/root/bounds/version, malformed/oversize input, duplicate request/nullifier behavior if supported, and no-write-on-failure. Do not add Fabric client code or tune limits yet.

**Acceptance:** chaincode simulation has the same result on repeated runs and on each peer; the verifier is called inside the endorsing chaincode process; all rejection cases are fail-closed; state updates are deterministic and bounded; chaincode unit tests pass. If application replay protection is required but proof context binding is absent, do not pretend `request_id` prevents replay—stop and report the prerequisite protocol change. Commit as `[FABRIC-STEP-02] Add deterministic proof-verification chaincode`.

### FABRIC-STEP-03 — package and deploy a controlled Fabric network on the server

**Prompt to agent:**

> Add reproducible deployment scripts/configuration for a pinned Fabric release and the chosen custom builder/external chaincode service. Start with two peer organizations, one peer per organization, one channel, one ordering service for functional testing, and a `2-of-2` endorsement policy so both organizations execute the proof check. Build/package the exact same chaincode and Rust verifier artifact for both peers; record package IDs and hashes. Use TLS and generated development certificates only for a local research network. Add commands to create/join the channel, package/install/approve/commit chaincode using the supported lifecycle, register one sample policy, submit one valid proof, query the resulting state, then submit invalid and malformed proofs and confirm no state update. Keep secrets and generated crypto material out of git. Do not describe the single-orderer network as production or HA. Include cleanup that removes only this deployment's named containers/volumes and requires an explicit target project name; never use broad host cleanup.

**Acceptance:** clean setup from documented prerequisites succeeds on the target server; two endorsing peers use byte-identical verifier/chaincode artifacts; valid transaction commits and both peers agree on state; invalid proofs are rejected; chaincode package and network configuration are reproducible. Capture Fabric peer/orderer/chaincode versions and config. Commit as `[FABRIC-STEP-03] Add reproducible Fabric research network`.

### FABRIC-STEP-04 — implement a Gateway client and correctness checks

**Prompt to agent:**

> Add a small client/CLI that loads a policy description and witness, builds the v2 proof using existing Rust APIs, serializes it with `V2Proof::to_bytes()`, and submits the raw bytes plus policy ID through Fabric Gateway. Report proof generation separately from submit/endorsement/commit. Wait for the commit event and report transaction validation status; do not label proposal endorsement as commit. Never print private witness or membership path. Add end-to-end cases for range-only, membership-only, and combined proof as appropriate; prove and verify policy statement equality; test tampered proof, wrong policy, disabled policy, unsupported version, and replay behavior. If request binding is not yet implemented, document replay as an open limitation and do not claim per-request uniqueness.

**Acceptance:** reproducible end-to-end results include proof bytes, proposal result, commit event/status, and resulting ledger key; invalid proof creates no accepted record; client logs do not disclose the witness. Commit as `[FABRIC-STEP-04] Add Fabric Gateway proof client`.

### FABRIC-STEP-05 — validate message sizes and establish a safe test envelope

**Prompt to agent:**

> Determine the actual configured channel `AbsoluteMaxBytes` and `PreferredMaxBytes`, peer/orderer gRPC send/receive limits, Gateway/client limits, chaincode argument limits, and any reverse-proxy limits from the running server config. Add a pre-submit client check against the conservative usable transaction budget including endorsements, proposal/transaction envelope overhead, and chosen encoding expansion. Do not silently increase production limits. Use raw binary arguments where possible. First test with the smallest v2 combined proof and then a matrix of proof sizes; confirm actual submitted envelope size, orderer acceptance, block creation, peer commit, and retrieval. Record the first failure threshold. Do not benchmark throughput until all rows have an explicit pass/fail size outcome.

**Acceptance:** a checked-in configuration report gives measured/actual limits and proof/envelope sizes; the client rejects too-large submissions before they waste peer/orderer work; successful transactions are committed and queryable. The test does not assume a universal Fabric default. The Fabric docs recommend keeping `AbsoluteMaxBytes` within about 49 MB because the default gRPC limit is 100 MB and communication can expand messages; validate the deployed configuration directly. See [channel configuration](https://hyperledger-fabric.readthedocs.io/en/latest/create_channel/create_channel_config.html) and [performance considerations](https://hyperledger-fabric.readthedocs.io/en/latest/performance.html). Commit as `[FABRIC-STEP-05] Bound and test Fabric proof payloads`.

### FABRIC-STEP-06 — benchmark design, instrumentation, and baseline

**Prompt to agent:**

> Add a benchmark driver and report template without changing the proof protocol or Fabric policy. For each case record: proof generation time on client; serialized proof bytes; standalone Rust verify time; chaincode/endorsement evaluation latency; Gateway submit-to-commit latency; committed transactions per second under stated concurrency; rejection latency; CPU, memory, disk/network utilization; block size and transaction count; valid/invalid counts; and transaction validation codes. Include warmup, fixed workload, repetitions, raw CSV/JSON, medians and p95/p99 where sample counts justify them, and confidence intervals or dispersion. Separate cryptographic work from Fabric ordering/commit time. Compare local Rust verification to Fabric chaincode execution on the same server. Pin proof statement, set size, membership index distribution, `M`, client concurrency, endorsement policy, block timeout/size, database type, and channel configuration. Include proof-only and transaction-level baselines; do not put proof generation inside chaincode. Do not claim a Fabric benchmark based only on Criterion or a single sequential transaction.

**Acceptance:** one dry-run produces complete machine-readable rows and a human-readable report; timestamps and phase definitions are unambiguous; instrumentation does not change verification outcomes. Commit as `[FABRIC-STEP-06] Add Fabric benchmark harness`.

### FABRIC-STEP-07 — run thesis benchmark matrix and document bottlenecks

**Prompt to agent:**

> Run the benchmark on the actual target server and preserve raw data. First test correctness and size for membership-only and combined proofs with 4, 8, 16, and 32 members at `M=96` and `M=219` (and any additional parameter only if the thesis explicitly labels it experimental). Then run concurrency/load tests only for payload sizes accepted by the actual configuration. Use at least a sequential latency run and a bounded concurrency sweep; report saturation, failures, timeouts, invalid proofs, and resource use. Include a local standalone baseline, single-peer evaluation if useful, and the two-organization endorsed transaction. Repeat runs after a clean restart and report run-to-run variation. Do not tune endorsement policy, repetition count, protocol, or block limits midway through the matrix; if a configuration changes, treat it as a new experiment. Do not hide rows that exceed message/block limits.

> In the report, explicitly compare measured v2 proof sizes with the current `V2_BENCHMARKS.md` local sizes and explain the difference between endorsement latency and commit latency. Note that increasing M from 96 to 219 changes the protocol parameter and is not a free optimization. Decide from measured results whether this design is feasible for the target workload. If proof payload size or verifier latency is unacceptable, present that evidence and recommend researching a different proof system/aggregation design; do not truncate proof bytes or loosen checks.

**Acceptance:** benchmark report states exact hardware, OS, Fabric release, topology, endorsement policy, channel and gRPC limits, chaincode artifact hash, compiler/build flags, proof suite/version, N/M, set sizes, sample count, workload rate/concurrency, and phase-specific results. Raw output is reproducible and checked in or linked as a separate artifact. Claims are limited to this setup. Commit as `[FABRIC-STEP-07] Report end-to-end Fabric benchmarks`.

### FABRIC-STEP-08 — final reproducibility and security review

**Prompt to agent:**

> Review the complete diff and deployment instructions as an independent reviewer. Trace policy registration through ledger read, expected-statement construction, Rust verification, successful write, endorsement, ordering, validation, and commit notification. Check FFI bounds/ownership/panics, deterministic execution, authorization, replay/context binding, version pinning, binary sizes, secrets handling, and exact error behavior. Confirm all endorsing organizations execute the same verifier and policy. Confirm invalid proofs cannot produce accepted state. Re-run setup and the documented correctness/benchmark smoke tests from a clean checkout without deleting user data. Do not improve performance by weakening proof checks or changing M. Write `FABRIC_SECURITY_AND_REPRODUCIBILITY.md` with issues and limitations. Explicitly state that this review is not a formal proof, protocol audit, or production certification.

**Acceptance:** setup and test commands work from clean state, security/data-flow review is documented, and all unresolved risks are prominently listed. Commit as `[FABRIC-STEP-08] Review Fabric integration and reproducibility`.

## 5. Fabric network and thesis experimental design

### Topology

For a controlled first experiment, use two organizations with one endorsing peer each, one channel, one ordering service, and a `2-of-2` chaincode endorsement policy. This makes each valid proposal run the verifier on both organizations' peers. A one-server setup is useful for repeatability, but all containers share CPU, memory, disk, and network; it is not evidence of geographical distribution, independent administration, fault tolerance, or production resilience. A single-node ordering service is for development/benchmarking, not a highly available production orderer. If resources permit, a separate experiment can use a multi-node Raft orderer and/or peers on separate hosts; report that as a distinct topology.

Record exact versions and configuration: peer/orderer/Gateway, Go and Rust toolchains, chaincode and verifier image digests, Docker/container settings, CPU quota/pinning, RAM limits, database type, TLS, channel policies, `BatchTimeout`, `MaxMessageCount`, `PreferredMaxBytes`, `AbsoluteMaxBytes`, and gRPC request/response limits. Fabric performance depends on the participating organizations' hardware, network, endorsement policy, block settings, and storage; see its [performance guidance](https://hyperledger-fabric.readthedocs.io/en/latest/performance.html).

### Operations and ledger data

- `RegisterPolicy(policyId, root, memberCount, depth, lo, hi, suiteVersion)` is an admin-only operation. Validate canonical root bytes, nonzero count, canonical depth, range order, supported version/suite, and immutable/update/revocation rules.
- `SubmitProof(policyId, proofBytes, context)` is available to the intended client identities. Chaincode reads the policy, validates bounds, verifies against the stored statement, and writes a compact acceptance record only after success.
- Keep only a proof digest and necessary business result in world state unless proof retrieval from state is an explicit requirement. The full invocation is recorded in the block history regardless, and block storage/replication cost still includes it.
- Use a context-bound nullifier plus ledger uniqueness check if the application needs a one-time action. Do not claim replay resistance from a fresh Fabric transaction ID alone.
- Query policy and accepted records through chaincode. For auditing full proof bytes, specify how clients retrieve invocation data from block history and account for its storage and access costs.

### Benchmark matrix and measurements

Separate these clocks; do not report them as one opaque “proof time”:

| Phase | What it measures |
|---|---|
| Prove | Client-side NovaMPC v2 witness sharing, commitments, and transcript construction |
| Serialize | `V2Proof::to_bytes()` output size and serialization time |
| Local verify | Direct Rust verifier CPU time without Fabric |
| Endorse | Proposal submission through Gateway until required peers return endorsements; includes chaincode proof verification per peer |
| Submit-to-commit | Gateway submission until a commit event reports validation status |
| Throughput | Completed valid committed transactions per second at a stated concurrency and duration |
| Reject path | Invalid proof response time and confirmation that no accepted state was written |

Minimum controlled matrix:

- predicates: membership-only and combined range+membership; range-only can be a smaller baseline;
- set sizes: 4, 8, 16, 32 members;
- repetitions: `M=96` and `M=219`, explicitly described as experimental parameter settings, not proven security levels;
- workload: sequential latency, then a stated concurrency sweep; identical input distribution and peer topology for comparisons;
- reporting: actual serialized proof bytes and actual Fabric transaction/envelope size, prove/verify/endorse/commit latency, throughput, p50/p95/p99 where statistically justified, resource use, invalid transaction codes, and failed/timeout rows;
- methodology: warm-up, fixed sample count/run duration, at least three independent runs where feasible, raw data, and exact machine/build/network configuration.

Do not put proof generation inside the chaincode benchmark: clients generate proofs before submitting proposals. The chaincode's job is to verify. Conversely, do not call local Rust verification time “Fabric verification latency”; the endorsing peer performs verification during proposal simulation.

### Payload-size decision

The project's own v2 report measures combined 4-member proofs at about 7.18 MiB (`M=96`) and 16.40 MiB (`M=219`), and combined 32-member proofs up to about 11.48 MiB and 26.20 MiB, respectively. The measured maximum, plus transaction/endorsement envelope overhead, must be compared with the **actual** channel and gRPC limits. Fabric documentation describes `AbsoluteMaxBytes` as the largest transaction/block message and recommends not exceeding roughly 49 MB because the default gRPC message limit is 100 MB with message expansion headroom; this is guidance, not a universal deployment limit. A large single proof can exceed `PreferredMaxBytes` and occupy a block by itself even if it is under `AbsoluteMaxBytes`. See [channel configuration](https://hyperledger-fabric.readthedocs.io/en/latest/create_channel/create_channel_config.html) and [Fabric performance considerations](https://hyperledger-fabric.readthedocs.io/en/latest/performance.html).

Do not base64-expand large proofs without measuring that overhead; do not simply raise all maximum message sizes to force a result through; do not lower M to meet a size target and then keep the old security wording. If the proof does not fit the target configuration or causes unacceptable latency/throughput, the honest result is that this proof construction is a poor fit for that Fabric workload and a different proof-system design may be needed.

## 6. What the thesis may conclude

After these stages, the thesis may report that a particular NovaMPC build was integrated into a particular Fabric topology and provide measurements for that setup. It may analyze whether proof size and verifier cost are practical under that topology. It must not infer that Fabric endorsement proves NovaMPC's cryptographic soundness, that a one-server network demonstrates decentralization, or that the protocol is secure because invalid test proofs were rejected. A complete protocol proof and independent cryptographic review remain separate work.

## Official Fabric references

- [Transaction flow](https://hyperledger-fabric.readthedocs.io/en/latest/txflow.html)
- [Fabric Gateway](https://hyperledger-fabric.readthedocs.io/en/latest/gateway.html)
- [Chaincode development](https://hyperledger-fabric.readthedocs.io/en/latest/chaincode4ade.html)
- [Chaincode as an external service](https://hyperledger-fabric.readthedocs.io/en/latest/cc_service.html)
- [Chaincode lifecycle](https://hyperledger-fabric.readthedocs.io/en/latest/chaincode_lifecycle.html)
- [Channel configuration and block size](https://hyperledger-fabric.readthedocs.io/en/latest/create_channel/create_channel_config.html)
- [Performance considerations](https://hyperledger-fabric.readthedocs.io/en/latest/performance.html)
