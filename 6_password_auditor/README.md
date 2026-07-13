# 🔐 Password Strength Auditor & Hash Analyzer

Audits passwords for strength, detects weak patterns, analyzes hash algorithms, estimates crack times, and generates secure alternatives.

## What it does
- **Strength scoring** (0–100) with A–F grade
- **Entropy calculation** in bits (Shannon entropy formula)
- **Crack time estimation** at 1B guesses/sec (GPU hashcat speed)
- **Pattern detection** — sequences, repeated chars, l33t speak, years
- **Common password check** — against top-50 known-bad list (extend with rockyou.txt)
- **Hash identification** — MD5, SHA-1, SHA-256, SHA-512 with security rating
- **Secure password generator** using `secrets` module (cryptographically safe)
- **Passphrase generator** — EFF-style memorable passphrases

## Skills demonstrated
`Cryptography` · `Security policy` · `Risk scoring` · `Secure coding (secrets module)`

## Setup
```bash
python password_auditor.py
```

## Extending with rockyou.txt
```python
with open("rockyou.txt", errors="ignore") as f:
    COMMON_PASSWORDS = set(line.strip() for line in f)
```
