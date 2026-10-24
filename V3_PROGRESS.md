# V3 progress log

Experimental TCitH-MT/ΠLigero prototype. No security claim. V2 unchanged.

## P1.1 — suite identifiers, parameters, validation (`a94afb6`)

- Completed: `src/v3/{mod,suite,params}.rs` wired via `src/lib.rs`; structural
  validation (ranges, `ℓ < N`, `d_β + 2 ≤ N`); three experimental presets
  (published-reference-τ1, prototype-τ2, fast-insecure-test); derived degrees
  `d_β = s+ℓ−1`, `d_α = 2(s+ℓ−1)` tested against Phase 0 values.
- Validation: `cargo test --lib v3::` — 4 passed.
## P1.2 — packed witness-matrix layout (`cf14f7d`)

- Completed: `src/v3/matrix.rs` (`MatrixDims`, `pack_witness`, `unpack_matrix`);
  dims verified against Phase 0 model (`n=46` at `s=120`, `n=41` at `s=133`
  for `3·1774+95`); zero-padding and shape-rejection tests.
- Validation: `cargo test --lib v3::` — 7 passed.
- Next step: P1.3 packed Shamir sharing (`sharing.rs`).
## P1.3 — packed Shamir sharing (`bc6848a`)

- Completed: `src/v3/sharing.rs` — fixed points (`ω_k=k`, `e_i=s+i`),
  `P = I_v + F·R` sharing, Lagrange `reconstruct` (needs `s+ℓ` shares),
  coefficient interpolation + `degree_within_bound`; tamper/input tests.
- Validation: `cargo test --lib v3::` — 11 passed.
- Next step: P1.4 Merkle commitment/opening support (`commit.rs`).
## P1.4 — Merkle commitment/opening (`8fb1082`)

- Completed: `src/v3/commit.rs` — domain-separated BLAKE3 leaf/internal
  commits (canonical `Fr` encoding reused from v2), root/path/verify with
  odd-layer duplication; tamper and input tests.
- Validation: `cargo test --lib v3::` — 15 passed.
- Next step: P1.5 degree-enforcing round (`decs.rs`).
## P1.5 — degree-enforcing round (`pending hash`)

- Completed: `src/v3/decs.rs` — `Γ`-combination (zero-padded), exact
  `poly_degree`/`meets_degree`, response evaluation, `verify_responses`
  (consistency + interpolated degree); honest/high-degree/tamper tests.
- Validation: `cargo test --lib v3::` — 19 passed.
- Next step: Phase 2 constraint representation (`constraints.rs`); open item:
  exact PACS/`m₂` count for the combined circuit.
