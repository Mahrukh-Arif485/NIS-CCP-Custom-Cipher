"""
attacks.py -- attacks on the custom cipher.
 1. Frequency analysis (chi-squared / index of coincidence)  -> breaks Shift, fails on custom cipher
 2. Known-plaintext attack (algebraic, linear-algebra mod 26) -> fully breaks the custom cipher
"""
from math import gcd
from custom_cipher import clean, c2n, n2c, modinv, M

ENG = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
       0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
       2.758, 0.978, 2.360, 0.150, 1.974, 0.074]          # % frequencies


def letter_counts(nums):
    cnt = [0] * M
    for x in nums:
        cnt[x] += 1
    return cnt


def chi_squared(nums):
    n = len(nums)
    if n == 0:
        return 0.0
    cnt = letter_counts(nums)
    return sum((cnt[i] - n * ENG[i] / 100) ** 2 / (n * ENG[i] / 100) for i in range(M))


def index_of_coincidence(nums):
    n = len(nums)
    if n < 2:
        return 0.0
    cnt = letter_counts(nums)
    return sum(c * (c - 1) for c in cnt) / (n * (n - 1))


# ---------------------------------------------------------------- frequency
def shift_frequency_attack(ct: str):
    c = [c2n(x) for x in clean(ct)]
    best = min(range(M), key=lambda k: chi_squared([(x - k) % M for x in c]))
    return best, "".join(n2c(x - best) for x in c)


def vigenere_frequency_attack(ct: str, max_period: int = 20):
    """Classic IC period-finding + per-column chi-squared shift recovery."""
    c = [c2n(x) for x in clean(ct)]
    def avg_ic(p):
        return sum(index_of_coincidence(c[i::p]) for i in range(p)) / p
    scores = {p: avg_ic(p) for p in range(1, max_period + 1)}
    period = max(scores, key=lambda p: scores[p] - 0.0005 * p)   # slight bias to short periods
    key = []
    for i in range(period):
        col = c[i::period]
        key.append(min(range(M), key=lambda k: chi_squared([(x - k) % M for x in col])))
    pt = "".join(n2c(c[i] - key[i % period]) for i in range(len(c)))
    return period, key, pt


# ---------------------------------------------------------------- KPA
def _lcm(a, b): return a * b // gcd(a, b)


def _inv2(m):
    det = (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % M
    if gcd(det, M) != 1:
        return None
    d = modinv(det)
    return [[(d * m[1][1]) % M, (-d * m[0][1]) % M],
            [(-d * m[1][0]) % M, (d * m[0][0]) % M]]


def _mul(A, B):
    return [[(A[i][0] * B[0][j] + A[i][1] * B[1][j]) % M for j in range(2)] for i in range(2)]


class RecoveredKey:
    """Equivalent key: C_block = A * P_block + K[phase]  (mod 26)."""
    def __init__(self, A, K, period):
        self.A, self.K, self.P = A, K, period
        self.A_inv = _inv2(A)

    def decrypt(self, ct: str) -> str:
        c = [c2n(x) for x in clean(ct)]
        out = []
        for i in range(0, len(c) - 1, 2):
            ph = i % self.P
            if ph not in self.K:
                out += ["?", "?"]
                continue
            y0 = (c[i] - self.K[ph][0]) % M
            y1 = (c[i + 1] - self.K[ph][1]) % M
            out.append(n2c(self.A_inv[0][0] * y0 + self.A_inv[0][1] * y1))
            out.append(n2c(self.A_inv[1][0] * y0 + self.A_inv[1][1] * y1))
        return "".join(out)


def known_plaintext_attack(known_pt: str, ct: str, key_len: int = 10, max_pairs: int = 200):
    """
    Attacker knows the first len(known_pt) plaintext letters (position 0) and the
    ciphertext, plus the algorithm (Kerckhoffs) and the key length.
    Whole cipher collapses to  C_blk = A*P_blk + K_phase,  phase = pos mod lcm(2,L).
    Two blocks in the same phase give  dC = A dP ; two independent (dP) -> A.
    Returns (RecoveredKey, ops) or (None, ops) if the data is insufficient.
    """
    p = [c2n(x) for x in clean(known_pt)]
    c = [c2n(x) for x in clean(ct)]
    m = min(len(p), len(c)) // 2 * 2
    P = _lcm(2, key_len)
    ops = 0
    groups = {}
    for j in range(0, m, 2):
        groups.setdefault(j % P, []).append(j)
    diffs = []                                   # (dP, dC) pairs
    for ph, idxs in groups.items():
        b = idxs[0]
        for j in idxs[1:]:
            diffs.append(((p[j] - p[b]) % M, (p[j + 1] - p[b + 1]) % M,
                          (c[j] - c[b]) % M, (c[j + 1] - c[b + 1]) % M))
            ops += 4
    diffs = diffs[:max_pairs]
    A = None
    for i in range(len(diffs)):
        for j in range(i + 1, len(diffs)):
            ops += 1
            Dp = [[diffs[i][0], diffs[j][0]], [diffs[i][1], diffs[j][1]]]
            inv = _inv2(Dp)
            if inv is None:
                continue
            Dc = [[diffs[i][2], diffs[j][2]], [diffs[i][3], diffs[j][3]]]
            A = _mul(Dc, inv)
            ops += 16
            break
        if A is not None:
            break
    if A is None or _inv2(A) is None:
        return None, ops
    K = {}
    for ph, idxs in groups.items():
        b = idxs[0]
        K[ph] = ((c[b] - A[0][0] * p[b] - A[0][1] * p[b + 1]) % M,
                 (c[b + 1] - A[1][0] * p[b] - A[1][1] * p[b + 1]) % M)
        ops += 8
    return RecoveredKey(A, K, P), ops


if __name__ == "__main__":
    from custom_cipher import CustomCipher
    cph = CustomCipher(7, 11, "DDCF", "NETWORKSEC")
    pt = clean("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDKEEPSRUNNINGACROSSTHEFIELD")
    ct = cph.encrypt(pt)
    rk, ops = known_plaintext_attack(pt[:30], ct)
    print("recovered:", rk.decrypt(ct) == pt, "ops:", ops)
