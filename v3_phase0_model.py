#!/usr/bin/env python3
"""Reproducible Phase-0 proof-size / soundness model for NovaMPC V3.

Implements the published FR25b (TCitH, eprint 2023/1573, latest revision)
TCitH-MT size formula (Eq. 16) and Theorem 2 soundness terms for the
TCitH-PI_Ligero LPPC instantiation (degree d=2). No parameters are approved;
outputs are planning estimates only.

Reference calibration: SmallWood Table 2 row reproduced from FR25b:
  |C|=4096, |x|=100, 256-bit field, N=8192, l=27, s=133, eta=5, rho=1, tau=1
  -> published 130.0 KB; this model computes ~130.8 KiB (0.6% delta).
"""
import math
from math import ceil

# BN254 scalar field (Balanced; log2|F| ~= 253.6, generic collision ceiling ~2^127)
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
LOGF = math.log2(P)
LAM = 128  # hash digest width parameter: digests are 2*LAM bits


def log2_binom(n, k):
    if k < 0 or k > n:
        return float("-inf")
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


def model(N, ell, s, eta, rho=1, tau=1, C=1774, x=95, d=2):
    """Return (size_KiB, n_packs, n_hints, log2_thr1, log2_decs, log2_fp, log2_thr_tau)."""
    d_alpha = d * (s + ell - 1)      # max broadcast-sharing degree (LPPC, d=2)
    d_beta = s + ell - 1             # max hint degree (default choice)
    # Keep the a, b, and c vectors column-aligned for the parallel relation.
    # Each has ceil(C/s) packs; private inputs occupy ceil(x/s) extra packs.
    n = 3 * ceil(C / s) + ceil(x / s)
    n_hints = (ceil(((d - 1) * (s + ell - 1)) / (d_beta - ell + 1))
               + ceil((2 * s - 1) / (d_beta - ell + 1)))
    bits = (6 * LAM + tau * (
        (d_beta + 1) * eta * LOGF                 # DECS responses
        + ell * (n + n_hints * rho) * LOGF        # opened shares
        + ((d - 1) * (s + ell - 1) + (2 * s - 2)) * rho * LOGF  # broadcast shares
        + 2 * LAM * ell * math.log2(N)))          # Merkle auth paths (l leaves x logN x 2LAM)
    log_thr = log2_binom(d_alpha, ell) - log2_binom(N, ell)   # per-rep threshold term
    log_decs = log2_binom(N, d_beta + 2) - eta * LOGF         # DECS term
    log_fp = -rho * LOGF                                       # MPC false positive 1/|F|^rho
    return bits / 8 / 1024, n, n_hints, log_thr, log_decs, log_fp, log_thr * tau


if __name__ == "__main__":
    print("== calibration: published 130.0 KB row (C=4096,x=100) ==")
    kb, n, nh, lt, ld, lf, lrt = model(8192, 27, 133, 5, 1, 1, C=4096, x=100)
    print(f"size={kb:.2f} KiB n={n} nhints={nh} thr={lt:.1f} decs={ld:.1f} fp={lf:.0f}")

    print("== NovaMPC 32-member combined (C=1774,x=95), BN254 Fr ==")
    for (N, ell, s, eta, rho, tau, label) in [
        (8192, 27, 133, 5, 1, 1, "published-params tau=1 (no FS margin)"),
        (8192, 30, 120, 6, 1, 2, "RECOMMENDED prototype point tau=2"),
        (4096, 32, 80, 6, 1, 2, "smaller-N tau=2 alt"),
        (16384, 30, 120, 6, 1, 2, "larger-N tau=2 alt"),
    ]:
        kb, n, nh, lt, ld, lf, lrt = model(N, ell, s, eta, rho, tau)
        print(f"[{label}] N={N} l={ell} s={s} eta={eta} rho={rho} tau={tau} "
              f"-> {kb:.1f} KiB (n={n},nh={nh}) thr_tau={lrt:.1f} decs={ld:.1f} "
              f"margin_vs_1MB={1000/kb:.1f}x")
