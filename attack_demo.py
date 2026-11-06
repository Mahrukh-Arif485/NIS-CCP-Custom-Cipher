import sys
from custom_cipher import CustomCipher, clean, c2n, M
from attacks import _inv2, _mul, RecoveredKey

cipher = CustomCipher(a=7, b=11, hill_key="DDCF", vig_key="NETWORKSEC")

text = clean(input("Enter plaintext: "))
ct = cipher.encrypt(text)
print("\nPlaintext  :", text)
print("Ciphertext :", ct, "   <- the attacker only sees this")

k = int(input("How many starting letters of the plaintext does the attacker know? "))
known = text[:k]
print("Known plaintext:", known)

p = [c2n(x) for x in known]
c = [c2n(x) for x in ct]
m = len(p) // 2 * 2
P = 10  # lcm(2, key length 10)

print("\nSTEP 1: Split the known text into 2-letter blocks")
groups = {}
for j in range(0, m, 2):
    groups.setdefault(j % P, []).append(j)
    print(f"  block {j//2}: plain={known[j:j+2]}  cipher={ct[j:j+2]}  phase={j % P}")

print("\nSTEP 2: Take differences of blocks in the same phase (the Vigenere part cancels out)")
diffs = []
for ph, idxs in groups.items():
    b = idxs[0]
    for j in idxs[1:]:
        d = ((p[j]-p[b]) % M, (p[j+1]-p[b+1]) % M,
             (c[j]-c[b]) % M, (c[j+1]-c[b+1]) % M)
        diffs.append(d)
        print(f"  phase {ph}: block {j//2} - block {b//2}:  dP=({d[0]},{d[1]})  dC=({d[2]},{d[3]})")

if len(diffs) < 2:
    print("\nATTACK FAILED: not enough differences. The attacker needs more known letters (at least about 20).")
    sys.exit()

print("\nSTEP 3: Recover the matrix A from two differences  (A = dC * dP^-1)")
A = None
for i in range(len(diffs)):
    for j in range(i + 1, len(diffs)):
        Dp = [[diffs[i][0], diffs[j][0]], [diffs[i][1], diffs[j][1]]]
        inv = _inv2(Dp)
        if inv is None:
            continue
        Dc = [[diffs[i][2], diffs[j][2]], [diffs[i][3], diffs[j][3]]]
        A = _mul(Dc, inv)
        print("  dP matrix =", Dp)
        print("  dC matrix =", Dc)
        break
    if A is not None:
        break
if A is None or _inv2(A) is None:
    print("\nATTACK FAILED: could not recover A. Give the attacker more known letters.")
    sys.exit()
print("  Recovered A =", A, "  (real value: 7 x [[3,3],[2,5]] = [[21,21],[14,9]])")

print("\nSTEP 4: Recover the Vigenere value K for each phase  (K = C - A*P)")
K = {}
for ph, idxs in groups.items():
    b = idxs[0]
    K[ph] = ((c[b] - A[0][0]*p[b] - A[0][1]*p[b+1]) % M,
             (c[b+1] - A[1][0]*p[b] - A[1][1]*p[b+1]) % M)
    print(f"  phase {ph}: K = {K[ph]}")

print("\nSTEP 5: Decrypt the whole ciphertext with the recovered key")
rec = RecoveredKey(A, K, P).decrypt(ct)
print("  Recovered :", rec)
print("  Original  :", text)
print("\nATTACK SUCCESSFUL! The full message was recovered without the secret key."
      if rec[:len(text)] == text else "\nATTACK FAILED: the result does not match.")