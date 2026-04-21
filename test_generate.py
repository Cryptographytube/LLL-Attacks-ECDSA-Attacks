import os
import random
import argparse
import sys
import hashlib
import json

# Constants for secp256k1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def modinv(a, m=N):
    return pow(a, -1, m)

def pt_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2:
        if y1 != y2: return None
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3

def pt_mul(k, PT=(Gx, Gy)):
    R = None
    while k:
        if k & 1: R = pt_add(R, PT)
        PT = pt_add(PT, PT)
        k >>= 1
    return R

def privkey_to_addrs(k):
    pt = pt_mul(k)
    x, y = pt
    def _addr(pub):
        h = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        pay = b'\x00' + h
        chk = hashlib.sha256(hashlib.sha256(pay).digest()).digest()[:4]
        raw = pay + chk
        alp = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        nv = int.from_bytes(raw, 'big'); res = b''
        while nv: nv, r = divmod(nv, 58); res = bytes([alp[r]]) + res
        return (alp[:1] * (len(raw) - len(raw.lstrip(b'\x00'))) + res).decode()
    return (_addr(bytes([0x02 + (y & 1)]) + x.to_bytes(32, 'big')),
            _addr(b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--b", type=int, default=8, help="Bias bits")
    parser.add_argument("--sigs", type=int, default=60, help="Number of signatures")
    args = parser.parse_args()

    # 1. Private Key & Address
    d = random.SystemRandom().randint(1, N - 1)
    addr_c, addr_u = privkey_to_addrs(d)
    pubkey_hex = f"{pt_mul(d)[0]:x}"
    
    # 2. Bias params
    B = 1 << args.b
    k_lsb = random.SystemRandom().getrandbits(args.b)
    
    print("=" * 64)
    print("  ECDSA Bias Test Generator")
    print("=" * 64)
    print(f"[*] Address  : {addr_c}")
    print(f"[*] PrivKey  : {hex(d)}")
    print(f"[*] Bias     : {args.b} bits")
    
    # 3. Path setup
    root_dir = os.getcwd()
    address_dir = os.path.join(root_dir, "results", addr_c)
    group_dir = os.path.join(address_dir, f"pubkey_{pubkey_hex[:12]}")
    
    # Debug: Print full path
    print(f"[*] Target folder: {group_dir}")
    
    try:
        os.makedirs(group_dir, exist_ok=True)
        print(f"[+] Folder created/exists ✓")
    except Exception as e:
        print(f"[!] Error creating folder: {e}")
        sys.exit(1)
    
    vuln_path   = os.path.join(group_dir, "vulnerable_data.txt")
    params_path = os.path.join(group_dir, "forensic_params.json")
    legacy_path = os.path.join(root_dir, f"{addr_c}.txt")

    # 4. Generate signatures
    rsz_data = []
    for i in range(args.sigs):
        k = k_lsb + B * random.randint(0, 500)
        z = random.SystemRandom().randint(1, N - 1)
        R = pt_mul(k)
        r = R[0] % N
        s = (z + r * d) * modinv(k) % N
        rsz_data.append((f"sim_tx_{i}", hex(r), hex(s), hex(z)))
    
    # 5. File writing with verification
    try:
        with open(vuln_path, "w") as f:
            for txid, r, s, z in rsz_data:
                f.write(f"{txid},{r},{s},{z}\n")
        if os.path.exists(vuln_path):
            print(f"[+] vulnerable_data.txt SAVED (size: {os.path.getsize(vuln_path)} bytes) ✓")
        
        with open(params_path, "w") as f:
            json.dump({"b_list": [args.b], "k_lsb": k_lsb, "d_partial": 0}, f)
        if os.path.exists(params_path):
            print(f"[+] forensic_params.json SAVED ✓")
            
        with open(legacy_path, "w") as f:
            f.write(f"# Address: {addr_c}\n")
            for _, r, s, z in rsz_data:
                f.write(f"{r},{s},{z}\n")
        if os.path.exists(legacy_path):
            print(f"[+] {addr_c}.txt SAVED ✓")
            
    except Exception as e:
        print(f"[!] Error writing files: {e}")
        sys.exit(1)

    print(f"\n[>] RUN ATTACK: python3 run_attack.py {addr_c}")

if __name__ == "__main__":
    main()
