# NIS (CT-486) CCP – Custom 3-Stage Classical Cipher (Affine -> Hill 2x2 -> Vigenere)

Files
- `custom_cipher.py` – cipher (encrypt/decrypt) + Shift baseline
- `attacks.py`       – frequency analysis and known-plaintext attack
- `experiments.py`   – reproduces all tables in the report (writes `results.json`)

Run (Python 3.8+, no external packages):
    python3 custom_cipher.py     # demo
    python3 attacks.py           # attack smoke test
    python3 experiments.py       # full experiments (~1 min)

Example key: a=7, b=11, Hill key "DDCF" ([[3,3],[2,5]]), Vigenere key "NETWORKSEC".
Group members: <names / roll numbers>
