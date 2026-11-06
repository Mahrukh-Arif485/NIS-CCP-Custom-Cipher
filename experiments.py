"""experiments.py -- reproduces every number in the report."""
import random, time, json
from custom_cipher import CustomCipher, ShiftCipher, clean
from attacks import (shift_frequency_attack, vigenere_frequency_attack,
                     known_plaintext_attack, index_of_coincidence, chi_squared)
from custom_cipher import c2n

SENT = """Computer networks allow many devices to exchange data across local and global links.
Security protects the confidentiality integrity and availability of information in transit and at rest.
A cipher transforms readable plaintext into unreadable ciphertext using a secret key known only to the communicating parties.
Classical ciphers such as shift affine and vigenere were used for centuries before modern cryptography appeared.
Frequency analysis exploits the fact that some letters of the english language appear far more often than others.
The hill cipher mixes neighbouring letters together using matrix multiplication modulo twenty six.
An attacker who knows some plaintext and the matching ciphertext may be able to recover the secret key directly.
Good engineers assume that the enemy knows the system and that only the key remains secret.
Routers firewalls and intrusion detection systems work together to defend an organisation against hostile traffic.
Strong passwords long keys and regular updates make brute force searching of the key space impractical for most attackers.
Public key exchange protocols allow two strangers to agree on a shared secret over an insecure channel.
Students in the network and information security course implement ciphers and then try to break them to understand their weaknesses."""
SENTS = [clean(s) for s in SENT.split("\n")]

def corpus(n, rng):
    out = ""
    while len(out) < n:
        out += rng.choice(SENTS)
    return out[:n]

rng = random.Random(486)
KEY = dict(a=7, b=11, hill_key="DDCF", vig_key="NETWORKSEC")
cipher = CustomCipher(**KEY)
res = {}

# ---- 0. correctness over many lengths
ok = True
for n in [1, 2, 3, 10, 11, 100, 999, 5000]:
    pt = corpus(n, rng)
    d = cipher.decrypt(cipher.encrypt(pt), strip_padding=(n % 2 == 1))
    ok &= (d == pt)
res["roundtrip_all_ok"] = ok

# ---- 1. frequency analysis: Shift vs custom
rows = []
for n in [50, 100, 200, 500, 1000, 5000]:
    sh_ok = cu_fraction = cu_full = 0; T = 200
    vig_period_ok = 0; ic_cu = ic_sh = 0
    for _ in range(T):
        pt = corpus(n, rng); k = rng.randrange(26)
        sc = ShiftCipher(k); ct_s = sc.encrypt(pt)
        kk, rec = shift_frequency_attack(ct_s)
        sh_ok += (rec == pt)
        ct_c = cipher.encrypt(pt)
        per, key, rec2 = vigenere_frequency_attack(ct_c)
        m = min(len(rec2), len(pt))
        frac = sum(rec2[i] == pt[i] for i in range(m)) / m
        cu_fraction += frac; cu_full += (rec2[:m] == pt[:m])
        vig_period_ok += (per % 10 == 0)
        ic_cu += index_of_coincidence([c2n(x) for x in ct_c]); ic_sh += index_of_coincidence([c2n(x) for x in ct_s])
    rows.append(dict(length=n, shift_success=sh_ok / T, custom_full_success=cu_full / T,
                     custom_letters_correct=round(cu_fraction / T, 4),
                     period_found_multiple_of_10=vig_period_ok / T,
                     IC_shift=round(ic_sh / T, 4), IC_custom=round(ic_cu / T, 4)))
res["frequency"] = rows

# ---- 2. KPA success rate vs known-plaintext length (random keys each trial)
def rand_cipher():
    while True:
        try:
            hk = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(4))
            a = rng.choice([1,3,5,7,9,11,15,17,19,21,23,25])
            vk = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(10))
            return CustomCipher(a, rng.randrange(26), hk, vk)
        except ValueError:
            continue

rows = []
T = 500
for kl in [10, 14, 18, 20, 22, 26, 30, 40, 60, 100]:
    succ = 0
    for _ in range(T):
        c = rand_cipher()
        pt = corpus(1000, rng); ct = c.encrypt(pt)
        rk, ops = known_plaintext_attack(pt[:kl], ct, 10)
        succ += (rk is not None and rk.decrypt(ct) == pt)
    rows.append(dict(known_chars=kl, success_rate=succ / T))
res["kpa_success"] = rows

# ---- 3. KPA effort vs ciphertext length (30 known chars)
rows = []
for n in [1000, 10000, 100000, 1000000]:
    pt = corpus(n, rng); ct = cipher.encrypt(pt)
    t0 = time.perf_counter(); rk, ops = known_plaintext_attack(pt[:40], ct, 10); t1 = time.perf_counter()
    dec = rk.decrypt(ct); t2 = time.perf_counter()
    rows.append(dict(ct_length=n, key_recovery_ms=round((t1 - t0) * 1000, 3), ops_key_recovery=ops,
                     full_decrypt_ms=round((t2 - t1) * 1000, 2), correct=(dec == pt)))
res["kpa_effort"] = rows

# ---- 4. enc/dec timing, custom vs shift
def best(f, r=5):
    ts = []
    for _ in range(r):
        t = time.perf_counter(); f(); ts.append(time.perf_counter() - t)
    return min(ts) * 1000
rows = []
sh = ShiftCipher(3)
for n in [1000, 10000, 100000, 1000000]:
    pt = corpus(n, rng); ct = cipher.encrypt(pt); cs = sh.encrypt(pt)
    rows.append(dict(length=n,
        custom_enc_ms=round(best(lambda: cipher.encrypt(pt)), 2), custom_dec_ms=round(best(lambda: cipher.decrypt(ct)), 2),
        shift_enc_ms=round(best(lambda: sh.encrypt(pt)), 2), shift_dec_ms=round(best(lambda: sh.decrypt(cs)), 2)))
res["timing"] = rows

# ---- 5. brute-force key space
from math import gcd
inv = 0
for a in range(26):
    for b in range(26):
        for c in range(26):
            for d in range(26):
                if gcd((a*d-b*c) % 26, 26) == 1: inv += 1
res["hill_invertible_matrices"] = inv
res["affine_keys"] = 12 * 26
res["vig_keys"] = 26 ** 10
res["naive_keyspace"] = inv * 312 * 26 ** 10
res["effective_keyspace"] = inv * 26 ** 10
json.dump(res, open("results.json", "w"), indent=1)
print(json.dumps(res, indent=1))
