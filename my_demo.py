from custom_cipher import CustomCipher, clean
from attacks import known_plaintext_attack

cipher = CustomCipher(a=7, b=11, hill_key="DDCF", vig_key="NETWORKSEC")

text = input("Enter your plaintext: ")
ct = cipher.encrypt(text)
print("Cleaned plaintext:", clean(text))
print("Ciphertext       :", ct)
print("Decrypted        :", cipher.decrypt(ct))

# Optional: break it with a known-plaintext attack
known = int(input("How many starting letters does the attacker know? (try 30): "))
rk, ops = known_plaintext_attack(clean(text)[:known], ct)
if rk is None:
    print("Attack failed: not enough known letters (or text too short).")
else:
    print("Attack recovered:", rk.decrypt(ct))