# 🔐 Project 7 — Caesar Cipher CLI Tool

A command-line tool to **encrypt**, **decrypt**, and **crack** Caesar cipher messages — including brute-force and frequency analysis.

## What is a Caesar Cipher?

Each letter is shifted a fixed number of positions down the alphabet. With shift 3: `A → D`, `Hello → Khoor`. Named after Julius Caesar, who used it with shift 3 for military communications. Trivially broken today — which makes it a perfect learning tool.

## Features

- Encrypt any text with a custom shift (1–25)
- Decrypt with a known shift
- Brute-force all 25 possible shifts
- Frequency analysis to auto-guess the shift
- Preserves punctuation, numbers, and spaces
- No external dependencies — pure Python stdlib

## Usage

```bash
# Encrypt
python caesar_cipher.py encrypt "Hello World" -s 13

# Decrypt
python caesar_cipher.py decrypt "Uryyb Jbeyq" -s 13

# Brute-force all 25 shifts
python caesar_cipher.py crack "Uryyb Jbeyq"

# Auto-detect shift via frequency analysis
python caesar_cipher.py crack "Khoor Zruog" --auto
```

## Skills Demonstrated

- Substitution cipher logic
- Brute-force attack fundamentals
- English letter frequency analysis (`E` is most common ~12.7%)
- Python `argparse` for CLI tools

## Legal Notice

For educational purposes only. Do not use Caesar cipher for any real security application.
