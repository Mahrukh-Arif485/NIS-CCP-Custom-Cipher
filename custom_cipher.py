"""
custom_cipher.py  --  NIS (CT-486) Complex Computing Problem
Three-stage classical cipher:  Affine  ->  Hill (2x2)  ->  Vigenere (key >= 10)
plus a Shift cipher baseline for the efficiency comparison.
"""
from math import gcd

M = 26


def clean(text: str) -> str:
    """Keep only letters, upper-case (alphabet A-Z)."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def c2n(ch): return ord(ch) - 65
def n2c(n):  return chr(n % M + 65)


def modinv(a: int, m: int = M) -> int:
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"{a} has no inverse modulo {m}")


class CustomCipher:
    """
    Key = (a, b)           affine key            c = a*p + b         (stage 1)
          hill_key (4 ch)  2x2 matrix [[k0,k1],[k2,k3]]              (stage 2)
          vig_key (>=10)   Vigenere keyword                          (stage 3)
    """

    def __init__(self, a: int, b: int, hill_key: str, vig_key: str):
        if gcd(a, M) != 1:
            raise ValueError("Affine 'a' must be coprime with 26")
        hill_key, vig_key = clean(hill_key), clean(vig_key)
        if len(hill_key) != 4:
            raise ValueError("Hill key must be exactly 4 letters (2x2 matrix)")
        if len(vig_key) < 10:
            raise ValueError("Vigenere key must be at least 10 letters")
        k = [c2n(c) for c in hill_key]
        det = (k[0] * k[3] - k[1] * k[2]) % M
        if gcd(det, M) != 1:
            raise ValueError("Hill matrix is not invertible mod 26")
        dinv = modinv(det)
        self.a, self.b = a % M, b % M
        self.a_inv = modinv(a)
        self.H = [[k[0], k[1]], [k[2], k[3]]]
        self.H_inv = [[(dinv * k[3]) % M, (-dinv * k[1]) % M],
                      [(-dinv * k[2]) % M, (dinv * k[0]) % M]]
        self.vk = [c2n(c) for c in vig_key]
        self.L = len(self.vk)

    # ---------------- encryption ----------------
    def encrypt(self, plaintext: str) -> str:
        p = [c2n(c) for c in clean(plaintext)]
        if len(p) % 2:                       # Hill needs even length -> pad 'X'
            p.append(c2n("X"))
        # Stage 1: affine
        e = [(self.a * x + self.b) % M for x in p]
        # Stage 2: Hill on digraphs
        H = self.H
        h = []
        for i in range(0, len(e), 2):
            x0, x1 = e[i], e[i + 1]
            h.append((H[0][0] * x0 + H[0][1] * x1) % M)
            h.append((H[1][0] * x0 + H[1][1] * x1) % M)
        # Stage 3: Vigenere
        vk, L = self.vk, self.L
        return "".join(n2c(h[i] + vk[i % L]) for i in range(len(h)))

    # ---------------- decryption ----------------
    def decrypt(self, ciphertext: str, strip_padding: bool = False) -> str:
        c = [c2n(ch) for ch in clean(ciphertext)]
        vk, L = self.vk, self.L
        h = [(c[i] - vk[i % L]) % M for i in range(len(c))]       # undo Vigenere
        Hi = self.H_inv
        e = []
        for i in range(0, len(h) - 1, 2):                         # undo Hill
            e.append((Hi[0][0] * h[i] + Hi[0][1] * h[i + 1]) % M)
            e.append((Hi[1][0] * h[i] + Hi[1][1] * h[i + 1]) % M)
        p = [(self.a_inv * (x - self.b)) % M for x in e]          # undo affine
        text = "".join(n2c(x) for x in p)
        if strip_padding and text.endswith("X"):
            text = text[:-1]
        return text


class ShiftCipher:
    """Single-stage baseline."""
    def __init__(self, key: int):
        self.k = key % M

    def encrypt(self, pt: str) -> str:
        return "".join(n2c(c2n(c) + self.k) for c in clean(pt))

    def decrypt(self, ct: str) -> str:
        return "".join(n2c(c2n(c) - self.k) for c in clean(ct))


if __name__ == "__main__":
    cipher = CustomCipher(a=7, b=11, hill_key="DDCF", vig_key="NETWORKSEC")
    msg = "Network and Information Security is fun!"
    ct = cipher.encrypt(msg)
    print("Plaintext :", clean(msg))
    print("Ciphertext:", ct)
    print("Decrypted :", cipher.decrypt(ct))
