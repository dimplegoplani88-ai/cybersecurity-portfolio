#!/usr/bin/env python3
"""
Caesar Cipher CLI Tool
Encrypt, decrypt, and brute-force crack Caesar cipher messages.
"""

import argparse
import string
import sys


def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt text using Caesar cipher with given shift."""
    result = []
    for char in text:
        if char in string.ascii_uppercase:
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        elif char in string.ascii_lowercase:
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt text by reversing the shift."""
    return caesar_encrypt(text, -shift)


def brute_force(text: str) -> None:
    """Try all 25 possible shifts and display results."""
    print(f"\n[*] Brute-forcing all 25 shifts for: '{text}'\n")
    print(f"{'Shift':<8} {'Result'}")
    print("-" * 60)
    for shift in range(1, 26):
        decrypted = caesar_decrypt(text, shift)
        print(f"  {shift:<6} {decrypted}")


def frequency_analysis(text: str) -> int:
    """
    Guess the shift using English letter frequency analysis.
    Most common English letter is 'E'. We find the most common
    letter in ciphertext and assume it maps to 'E'.
    """
    letters_only = [c.upper() for c in text if c.isalpha()]
    if not letters_only:
        return 0

    freq = {}
    for char in letters_only:
        freq[char] = freq.get(char, 0) + 1

    most_common = max(freq, key=freq.get)
    guessed_shift = (ord(most_common) - ord('E')) % 26
    return guessed_shift


def main():
    parser = argparse.ArgumentParser(
        description="Caesar Cipher — encrypt, decrypt, or crack messages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Encrypt:        python caesar_cipher.py encrypt "Hello World" -s 13
  Decrypt:        python caesar_cipher.py decrypt "Uryyb Jbeyq" -s 13
  Brute-force:    python caesar_cipher.py crack "Uryyb Jbeyq"
  Auto-detect:    python caesar_cipher.py crack "Uryyb Jbeyq" --auto
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt subcommand
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a message")
    enc_parser.add_argument("text", help="Text to encrypt")
    enc_parser.add_argument("-s", "--shift", type=int, required=True,
                            help="Shift value (1-25)")

    # Decrypt subcommand
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a message")
    dec_parser.add_argument("text", help="Text to decrypt")
    dec_parser.add_argument("-s", "--shift", type=int, required=True,
                            help="Shift value used during encryption")

    # Crack subcommand
    crack_parser = subparsers.add_parser("crack", help="Brute-force or auto-detect shift")
    crack_parser.add_argument("text", help="Ciphertext to crack")
    crack_parser.add_argument("--auto", action="store_true",
                              help="Use frequency analysis to guess the shift")

    args = parser.parse_args()

    if args.command == "encrypt":
        if not 1 <= args.shift <= 25:
            print("[!] Shift must be between 1 and 25.")
            sys.exit(1)
        result = caesar_encrypt(args.text, args.shift)
        print(f"\n[+] Plaintext:  {args.text}")
        print(f"[+] Shift:      {args.shift}")
        print(f"[+] Ciphertext: {result}\n")

    elif args.command == "decrypt":
        if not 1 <= args.shift <= 25:
            print("[!] Shift must be between 1 and 25.")
            sys.exit(1)
        result = caesar_decrypt(args.text, args.shift)
        print(f"\n[+] Ciphertext: {args.text}")
        print(f"[+] Shift:      {args.shift}")
        print(f"[+] Plaintext:  {result}\n")

    elif args.command == "crack":
        if args.auto:
            shift = frequency_analysis(args.text)
            result = caesar_decrypt(args.text, shift)
            print(f"\n[*] Frequency analysis guess:")
            print(f"    Guessed shift: {shift}")
            print(f"    Decrypted:     {result}\n")
        else:
            brute_force(args.text)


if __name__ == "__main__":
    main()
