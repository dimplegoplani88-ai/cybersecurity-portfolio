# Caesar Cipher CLI Tool

A command-line tool to **encrypt**, **decrypt**, and **crack** Caesar cipher messages — including brute-force and frequency analysis.

## What is a Caesar Cipher?

The Caesar cipher is one of the oldest known encryption techniques. Each letter in the plaintext is shifted a fixed number of positions down the alphabet. For example, with shift 3:

```
A → D
B → E
Hello → Khoor
```

Named after Julius Caesar, who reportedly used it with a shift of 3 to protect military communications. It's trivially broken today — which is exactly why it's a great learning tool.

## Features

- Encrypt any text with a custom shift (1–25)
- Decrypt with known shift
- Brute-force all 25 possible shifts
- Frequency analysis to auto-guess the shift (works well on longer texts)
- Preserves punctuation, numbers, and spaces
- No external dependencies — pure Python stdlib

## Requirements

- Python 3.6+

## Usage

### Encrypt

```bash
python caesar_cipher.py encrypt "Hello World" -s 13
```

Output:
```
[+] Plaintext:  Hello World
[+] Shift:      13
[+] Ciphertext: Uryyb Jbeyq
```

### Decrypt

```bash
python caesar_cipher.py decrypt "Uryyb Jbeyq" -s 13
```

### Brute-Force (all 25 shifts)

```bash
python caesar_cipher.py crack "Uryyb Jbeyq"
```

### Auto-detect shift via Frequency Analysis

```bash
python caesar_cipher.py crack "Khoor Zruog" --auto
```

> Frequency analysis works best on longer texts. Short phrases may produce incorrect guesses.

## What You'll Learn

- How substitution ciphers work
- Why Caesar cipher is insecure (key space = 25)
- Brute-force attack fundamentals
- English letter frequency analysis (`E` is most common at ~12.7%)
- Python `argparse` for CLI tools

## Why Caesar Cipher is Broken

Only 25 possible keys exist. Any attacker can try all of them in milliseconds. It also preserves letter frequency — cryptanalysts can match frequency patterns against known English distributions to crack it without trying every key.

## Disclaimer

For educational purposes only. Do not use Caesar cipher for any real security application.
