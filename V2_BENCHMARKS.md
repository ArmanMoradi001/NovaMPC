# NovaMPC v2 benchmark report (STEP-09)

Status: measurements for the implemented v2 proof path. This is an
implementation report, not a security proof or a deployment qualification.
**The MPC protocol remains unproven; STEP-10 has not been completed.** No
production, 128-bit, or post-quantum security claim is made.

## 1. Scope

Measured over the public v2 API:

- range-only and membership-only proofs are covered by
  `tests/v2_integration.rs`;
- membership-only and combined range+membership proof sizes and timings are
  reported below for 4, 8, 16, and 32 members;
- repetition counts `M=96` and `M=219`, with `N=3`;
- actual bytes from `V2Proof::to_bytes()`, not an estimate;
- circuit gate and multiplication-gate counts from the compiled canonical v2
  circuit.

The benchmark does not measure Fabric chaincode execution, transaction
envelopes, gossip, ordering, or network transfer. The numbers are local
CPU-only proof generation and verification.

## 2. Environment

| Item | Value |
|---|---|
| Date | 2026-10-21 |
| Host | Linux 7.0.0-38-generic, x86_64 |
| CPU | 13th Gen Intel Core i7-13620H, 10 physical / 16 logical CPUs, 24 MiB L3 |
| Memory / cache notes | CPU scaling was not pinned; the host was not isolated |
| Compiler | rustc 1.98.1 (48a229cea 2026-09-01), LLVM 22.1.8 |
| Build | `cargo bench` release profile: `opt-level=3`, `lto=true`, `codegen-units=1` |
| Harness | `benches/v2_bench.rs`; 3 timed iterations per row, medians reported |

Timings are machine- and load-dependent, especially on a laptop CPU without
CPU-frequency pinning. They are not a portable performance guarantee. The v1
reference was re-run on this same machine so the comparison is not only against
the older machine's recorded numbers.

## 3. Benchmark method

Run:

```text
cargo bench --bench v2_bench
```

Optional environment variables are documented in the harness:
`V2_BENCH_ITERS`, `V2_BENCH_SIZES`, `V2_BENCH_M`, and `V2_BENCH_MODE`.

For each row:

1. Build an ordered, duplicate-free v2 set from `100, 110, ...`.
2. Choose the middle member's authentication path.
3. Compile the canonical membership or combined circuit.
4. Prove, serialize with `V2Proof::to_bytes()`, and decode/verify the bytes.
5. Verify with `verify_statement` against the expected statement.
6. Report the median prove/verify wall time and the observed serialized-size
   range.

Proof size is not exactly constant across executions. When the hidden party is
party 2, party 2's residual input shares are not serialized; when party 2 is
opened, they are. The minimum/maximum columns capture that protocol-level size
variation. The observed maximum is the relevant measured value for a
transaction-size limit. A deliberately loose structural upper bound can be
obtained by adding one party-2 residual block for every repetition
(`witness_inputs * 32` bytes) to the observed maximum; even that bound is below
28.2 MB for the largest row.

The v1 reference row is `create_transaction_proof` with a 4-member v1 set,
range `[1, 1000]`, a context string, and `ProofParams::balanced()` (`M=96`).
It is the closest old transaction-style comparison, but its root is a 32-bit
MiMC value and it must not be treated as equivalent to v2.

## 4. Results: membership-only

Columns: `gates` = all v2 gates, `mul` = multiplication gates in one canonical
circuit. Timings are milliseconds; sizes are bytes unless labeled KiB/MiB.

| members | depth | M | gates | mul | prove ms | verify ms | bytes min | bytes max | max MiB |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 2 | 96 | 3603 | 1028 | 480.528 | 180.693 | 7,152,063 | 7,171,935 | 6.840 |
| 8 | 3 | 96 | 4429 | 1270 | 581.170 | 241.830 | 8,636,703 | 8,661,695 | 8.260 |
| 16 | 4 | 96 | 5255 | 1512 | 684.599 | 238.728 | 10,148,479 | 10,162,495 | 9.692 |
| 32 | 5 | 96 | 6081 | 1754 | 787.868 | 279.543 | 11,648,895 | 11,670,495 | 11.130 |
| 4 | 2 | 219 | 3603 | 1028 | 1,049.315 | 389.602 | 16,302,315 | 16,346,475 | 15.589 |
| 8 | 3 | 219 | 4429 | 1270 | 1,293.551 | 474.460 | 19,720,503 | 19,750,039 | 18.835 |
| 16 | 4 | 219 | 5255 | 1512 | 1,538.354 | 551.652 | 23,147,779 | 23,189,827 | 22.116 |
| 32 | 5 | 219 | 6081 | 1754 | 1,819.853 | 669.501 | 26,572,911 | 26,587,311 | 25.356 |

## 5. Results: combined range + membership

The combined circuit shares one private `x` wire and one bit decomposition
between the range and membership checks. Range is `[1, 1000]`.

| members | depth | M | gates | mul | prove ms | verify ms | bytes min | bytes max | max MiB |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 2 | 96 | 3708 | 1048 | 455.641 | 169.260 | 7,512,871 | 7,524,263 | 7.176 |
| 8 | 3 | 96 | 4534 | 1290 | 621.802 | 231.053 | 9,007,271 | 9,036,391 | 8.618 |
| 16 | 4 | 96 | 5360 | 1532 | 710.251 | 246.602 | 10,522,247 | 10,549,031 | 10.060 |
| 32 | 5 | 96 | 6186 | 1774 | 821.070 | 316.536 | 12,019,623 | 12,037,863 | 11.480 |
| 4 | 2 | 219 | 3708 | 1048 | 1,148.832 | 390.605 | 17,171,131 | 17,196,763 | 16.400 |
| 8 | 3 | 219 | 4534 | 1290 | 1,265.423 | 472.296 | 20,600,071 | 20,608,807 | 19.654 |
| 16 | 4 | 219 | 5360 | 1532 | 1,489.970 | 551.067 | 24,014,387 | 24,026,291 | 22.913 |
| 32 | 5 | 219 | 6186 | 1774 | 1,788.797 | 622.903 | 27,422,239 | 27,467,839 | 26.195 |

## 6. v1 baseline comparison

| proof | M | prove ms | verify ms | size |
|---|---:|---:|---:|---:|
| v1 4-member range+membership+context, this machine | 96 | 57.512 | 19.708 | 437,800–441,576 bytes (429.8 KiB mean) |
| v1 recorded baseline (previous machine) | 96 | ~59 | ~20 | ~429 KiB |
| v2 combined 4-member, this machine | 96 | 455.641 | 169.260 | 7,512,871–7,524,263 bytes (7.18 MiB max) |
| v2 combined 4-member, this machine | 219 | 1,148.832 | 390.605 | 17,171,131–17,196,763 bytes (16.40 MiB max) |

The v1 re-run is close to the recorded older-machine baseline, but this is
coincidental; hardware matters and the local v1 row should be used for a
same-machine comparison.

At `M=96`, the measured v2 combined 4-member proof is about **17x** the v1
size, **7.9x** the v1 prove time, and **8.6x** the v1 verify time. At `M=219`,
it is about **39x** the v1 size and about **20x** the v1 prove/verify time.
The v2 sizes are dominated by per-party field shares: 32-byte `Fr` elements and
three-party multiplication shares, not the set hash alone.

## 7. Fabric transaction-limit comparison

No Fabric channel configuration is present in this repository. Fabric channel
limits are deployment configuration, not universal defaults. The comparison
below therefore uses the commonly quoted sample values only as reference:

- **99 MB `AbsoluteMaxBytes` (sample reference):** every measured v2 proof,
  including the largest 4-member and 32-member cases at `M=219`, is below
  27.5 MiB. Even the loose structural upper bound described in section 3
  remains below 28.2 MB. On that reference limit, the proof itself fits.
- **512 KB `PreferredMaxBytes` (sample reference):** every measured v2 proof
  exceeds it. The smallest measured v2 proof (membership-only, 4 members,
  `M=96`) is about 6.84 MiB, over 13x the 512 KiB reference.

Do not treat those sample values as the configured limit. A deployment must
check its actual channel `AbsoluteMaxBytes`/`PreferredMaxBytes`, transaction
envelope overhead, and chaincode payload handling. If the configured absolute
limit is below the measured proof size, v2 as implemented does not fit that
configuration.

No protocol or hash optimization was applied in this step. The smallest
measured size lever is the repetition count (`M=96` versus `M=219`, about 56%
smaller), but that changes the security parameter and is not a free
optimization. Meeting a hard 512 KiB absolute limit would require a different
proof-system or aggregation design, not a hash-parameter tweak or silent
truncation. In particular, do not shorten BN254 `Fr` encodings by truncation or
weaken Poseidon2 framing to make the benchmark look better.

## 8. Limitations and next review

- The benchmark harness uses the fast timing path; it does not prove
  completeness, soundness, or zero knowledge.
- `M=96` and `M=219` are repetition-count presets only. They are not security
  qualifications for this protocol.
- The known hidden-party assertion/view and hidden-neighbor multiplication gaps
  remain. See `V2_PROTOCOL_NOTES.md`.
- STEP-10 is a separate proof/analysis project. Until it is completed and
  independently reviewed, the MPC protocol must be described as unproven.
- Migration from v1 is discussed in `V2_MIGRATION.md`.
