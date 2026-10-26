# V3 prototype benchmark record

Experimental V3 prototype measurements only. Not production performance
figures and not security guarantees. The P10 optimization did not change
proof size and makes no cryptographic security claim.

## Environment (fresh run)

- CPU: 13th Gen Intel Core i7-13620H, 10 cores / 16 threads.
- RAM: 14 GB total (about 9 GB in use during the run; background load unknown).
- OS: Linux 7.0.0-38-generic (Ubuntu), x86_64.
- Toolchain: rustc 1.98.1, cargo 1.98.1.
- Build profile: release with `opt-level = 3`, `lto = true`,
  `codegen-units = 1`; built via `cargo run --offline --release`.
- Worktree: `/home/neo/Projects/rust/NovaMPC` at P10 gate (`d0f3a8b`).

## Benchmark method

- Command: `cargo run --offline --release --example v3_bench_tmp`
- Harness: untracked `examples/v3_bench_tmp.rs` (present in the worktree,
  not committed). One process run performs 1 prove, 2 sequential
  verifications of the same proof, a proof-bytes length printout, and a
  codec round-trip assertion (`roundtrip ok`).
- Parameters: `V3Params::prototype_tau2()`, i.e. `N=8192, l=30, s=120,
  eta=6, rho=1, tau=2` (2 proof repetitions).
- Statement shape: 32-member combined range-and-membership statement;
  members `100 + 10*i`, range `[1, 1000]`, value `150`, membership leaf
  index 5, context `[7u8; 32]`, RNG `ChaCha20Rng::seed_from_u64(0x7331_5033)`.
- Runs measured: baseline 1 run (as recorded in `V3_PROGRESS.md` P10);
  optimized 3 runs total (2 recorded at the P10 gate, 1 fresh run below).
  Timings are single-shot wall-clock (`Instant`), not statistics.

## Results

| | prove (ms) | proof (bytes) | verify #0 (ms) | verify #1 (ms) | round-trip |
|---|---|---|---|---|---|
| Baseline (recorded) | 420193.7 | 215034 | 216844.8 | 202727.5 | ok |
| Optimized, run 1 (recorded) | 5514.9 | 215034 | 305.7 | 299.8 | ok |
| Optimized, run 2 (recorded) | 5763.8 | 215034 | 300.3 | 300.3 | ok |
| Optimized, run 3 (fresh, 2026-10-26) | 5686.5 | 215034 | 304.7 | 311.8 | ok |

Verification is ~700x faster at the identical 215,034-byte proof size;
proving is ~74x faster in the same harness. The fresh run reproduces the
reported optimized numbers within normal run-to-run variance.

## Limitations

- Baseline numbers are taken from the `V3_PROGRESS.md` P10 record; no
  machine log of the baseline run exists in the repo, so same-host /
  same-build-settings parity for the baseline cannot be independently
  verified from logs in this run. (The committed `benchmark_results.txt`
  is an older unrelated artifact from a different machine path and was
  not used here.)
- The harness is untracked and uncommitted, so future reproductions
  depend on a file that is not version-controlled. Recommend preserving
  a small reproducible benchmark harness in the repo if these numbers
  need to be re-checked later.
- Single-shot timings on a shared machine; no warm-up isolation, no
  variance analysis.
- Full test suite status at the P10 gate: 304 library tests plus all
  integration suites pass (2 pre-existing expensive V2 tests ignored).
