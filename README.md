# LLL-Attacks-ECDSA-Attacks
LLL-based ECDSA lattice attack toolkit for recovering private keys from weak or biased nonces. Includes CVP solving and real-world signature analysis

```bash
python3 test_generate.py --b 8 --sigs 60
```


# EXP
```bash
python3 test_generate.py
================================================================
  ECDSA Bias Test Generator
================================================================
[*] Address  : 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
[*] PrivKey  : 0x89ca32e6c0686533c8463151a4b36a7ad93fa712d572ab19770d28b3834827e7
[*] Bias     : 8 bits
[*] Target folder: /mnt/c/mnmo/scrio/results/1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5/pubkey_37f48173eb9d
[+] Folder created/exists ✓
[+] vulnerable_data.txt SAVED (size: 12647 bytes) ✓
[+] forensic_params.json SAVED ✓
[+] 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5.txt SAVED ✓

[>] RUN ATTACK: python3 run_attack.py 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
```


# ATTACK
```bash
python3 run_attack.py 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
```


# EXP
```bash
python3 run_attack.py 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
================================================================
  run_attack.py — Elite HNP Lattice Attack
================================================================
[*] Address  : 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
[*] Mode     : LLL | limit=50
[*] Sigs     : 60 total
[*] b values : [8]
[*] k_lsb   : 0xf9
[*] d_partial: 0 (soft hint only)

────────────────────────────────────────────────────────────────
[>] b=8  B=256  k_lsb=0xf9
    Stage1=SmallNonce | Stage2=SageLLL | Stage3=fpylll
    [filter] R=0.041 (clustering metric)
    [chi-circ] R=0.041  mu_angle=182.0/256
    [chi-circ] kept 42/60 (R=0.041, top 70% by circular distance)
  [n=2 attempt 1/10] sigs=2      [direct-solve] 1 candidate(s)
  [+] 1 candidate(s) — verifying ...

  Key      : 0x89ca32e6c0686533c8463151a4b36a7ad93fa712d572ab19770d28b3834827e7
  LSB OK   : 100% of sigs
  Compress : 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
  Uncompress: 15CB4e7hw8CrQJAYw8qnUQXNfeA9dL97dR
  Match    : ★ YES ★

★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
  PRIVATE KEY FOUND!
  Privkey : 0x89ca32e6c0686533c8463151a4b36a7ad93fa712d572ab19770d28b3834827e7
  b depth : 8  LSB match: 100%
★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
  Saved: results/1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5/pubkey_37f48173eb9d/found.txt

════════════════════════════════════════════════════════════════
  SUCCESS — 0x89ca32e6c0686533c8463151a4b36a7ad93fa712d572ab19770d28b3834827e7
════════════════════════════════════════════════════════════════
```
# ATTACK 2

```bash
python3 lll.py 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5.txt
```

# EXP
```bash

  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗  ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗██╗   ██╗████████╗██╗   ██╗██████╗ ███████╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║╚██╗ ██╔╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██║  ███╗██████╔╝███████║██████╔╝███████║ ╚████╔╝    ██║   ██║   ██║██████╔╝█████╗
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║  ╚██╔╝     ██║   ██║   ██║██╔══██╗██╔══╝
 ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║   ██║      ██║   ╚██████╔╝██████╔╝███████╗
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝      ╚═╝    ╚═════╝ ╚═════╝ ╚══════╝
                                          LLL-Attack CRYPTOGRAPHYTUBE  |  HNP/CVP  |  Biased-Nonce LSB Leakage

  Author : sisujhon

  [?] ecdsa_forensic.py has created a .txt file named after the address.
      Example: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.txt


  [+] Address  : 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
  [+] RSZ rows : 60

[LLL] ══ Starting LLL-Attack-v6 for 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5 ══
[LLL] Signatures supplied : 60
[LLL] Running NO-MISS Biased-Nonce LLL/BKZ multi-attack engine ...
[LLL] Launching 31 parallel workers across priority dimensions...

[LLL] ★ KEY FOUND via parallel worker! ★
[LLL] Total unique candidates: 8 — verifying ...
[LLL] no-match  C=18vCs8ssQujzgtNtUrJv94YWu9cjqLDhMX  U=1Mv3UW931MwrmC9ybNZ7tamDAzYvytATFg  key=0x84948745997b10551e8962b5472e3eb1075a289e018f2543f06e68e330cc843d
[LLL] no-match  C=1FnLqCzLXGXH2YDpm7ojf5mLwwbKXwcMAK  U=1N8YTNJU4x6BhWX8ScoKsQMtHNnAQciufe  key=0x9c488f46667f8fd5dfb345f8ddae6493710646b00efb0ffda38e51747da2634c
[LLL] no-match  C=1BSFnx9UmoEx2ZrCvGVJgxyjMMga3gKFNX  U=13ipB6GcGCN1iqZ6ABPHnFhyKb3zbNbZMR  key=0x837ab0afc21d5a6c6d1afcf1f3f31698ac0a315e6682fdc78f7cbee1ca17c7d7
[LLL] no-match  C=14e7isC89qLwNgPCNyyonaV2WbB4CMxeeE  U=1P8gpdw8xy5SYJRvZt5FGkBf2VB7UpzChi  key=0xf3c0709ac03eba928dd4afee7f64b3f2e61cbc9f5409258b1cd456037b17dc27

[LLL] ★★★ PRIVATE KEY FOUND ★★★
[LLL]   Compressed   : 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5 ← MATCH
[LLL]   Uncompressed : 15CB4e7hw8CrQJAYw8qnUQXNfeA9dL97dR
[LLL]   Private key  : 0x89ca32e6c0686533c8463151a4b36a7ad93fa712d572ab19770d28b3834827e7
[LLL]   Saved to     : ./1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5/found.txt
[LLL]   mathfound.txt: ./1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5/mathfound.txt
[LLL] no-match  C=1KrSyLYnxZapNJ1fUu8qVipYwMdMoncqzA  U=19PtdczwVVSU1LKZ6g7UqWW72N2gjabboR  key=0xa750a60b8f01774ae01a99b1ecf8f7d5368bc4901c2d5ed4eaa6150faff725ef
[LLL] no-match  C=1DCGEswET3HGda8nVRu41ZNQf596jt8qV4  U=1HxEogG6V59g614bgF2BNLVVcdMBqnmZ34  key=0x8acf294556147fb3f0f057ad28ed55c9bfec410d3b3183beebc7328fa9eb4f67
[LLL] no-match  C=19MHYwRCKVX8KgJGX8cMhUCFH3u7XFDSiH  U=1DCiUzYBzRaF7DK1CaBu6y6YVFDAjeZiGd  key=0x4897707e9f171aa2f957ba32874bafca8195742b0e9d8d05df3d158114f523f3
[LLL] ══ Done ══


  ★★★ FOUND: 1 key(s) — saved to found.txt ★★★
```

