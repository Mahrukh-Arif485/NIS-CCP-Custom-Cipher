# NIS (CT-486) CCP – Custom 3-Stage Classical Cipher (Affine -> Hill 2x2 -> Vigenere)

Complex Computing Problem, Network and Information Security (CT-486).

## Group Members
- Mahrukh Arif (CR-23302)
- Mayra Ahmer (CR-23303)
- Fatima Asif (CR-23304)

## Files
- `custom_cipher.py` – cipher (encrypt/decrypt) + Shift baseline
- `attacks.py` – frequency analysis and known-plaintext attack
- `experiments.py` – reproduces all tables in the report (writes `results.json`)
- `my_demo.py` – encrypt, decrypt and attack your own plaintext
- `attack_demo.py` – step-by-step known-plaintext attack demonstration
- `results.json` – results of the experiments

## How to Run
Requires Python 3.8+ and no external packages.

```
python custom_cipher.py    # demo: encrypt and decrypt
python attacks.py          # attack smoke test
python experiments.py      # full experiments (~1 min)
python my_demo.py          # enter your own plaintext
python attack_demo.py      # step-by-step attack demo
```

Use `python3` instead of `python` on Mac/Linux.

## Example Key
- Affine: a = 7, b = 11
- Hill key: "DDCF" = [[3,3],[2,5]]
- Vigenere key: "NETWORKSEC" (10 letters)

## Demo Example
- Plaintext: `NETWORKSECURITYPROTECTSOURDATA`
- Known letters for the attack: 20 (the attack succeeds with 20 or more, and fails with 10)
