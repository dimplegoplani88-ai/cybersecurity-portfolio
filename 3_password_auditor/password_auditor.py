"""
Project 3: Password Strength Auditor & Hash Analyzer
Author: Dimple Goplani
Description: Audits passwords for strength, checks against common wordlists,
             analyzes hashes, simulates cracking time, and produces a report.
Skills demonstrated: Cryptography, security policy enforcement, risk scoring
"""

import hashlib
import re
import math
import json
import string
import secrets
from datetime import datetime


# ─────────────────────────────────────────────
# COMMON PASSWORDS (top 50 — extend with rockyou.txt in prod)
# ─────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password123", "admin", "welcome", "login", "hello",
    "master123", "pass", "test", "guest", "root", "toor", "changeme",
    "secret", "pass1234", "p@ssword", "pa$$word", "password!", "P@ssw0rd"
}

# ─────────────────────────────────────────────
# 1. PASSWORD STRENGTH CHECKER
# ─────────────────────────────────────────────

def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy (bits).
    Higher = harder to guess/crack.
    Formula: entropy = length * log2(charset_size)
    """
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32

    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


def estimate_crack_time(entropy: float) -> str:
    """
    Estimate offline cracking time at 1 billion guesses/sec
    (modern GPU hashcat speed for MD5).
    """
    guesses_per_second = 1_000_000_000   # 1B/s (conservative GPU)
    total_combinations = 2 ** entropy
    seconds = total_combinations / (2 * guesses_per_second)   # avg = half search space

    if seconds < 1:         return "Instantly"
    if seconds < 60:        return f"{seconds:.0f} seconds"
    if seconds < 3600:      return f"{seconds/60:.0f} minutes"
    if seconds < 86400:     return f"{seconds/3600:.1f} hours"
    if seconds < 2592000:   return f"{seconds/86400:.0f} days"
    if seconds < 31536000:  return f"{seconds/2592000:.0f} months"
    years = seconds / 31536000
    if years < 1000:        return f"{years:.0f} years"
    if years < 1_000_000:   return f"{years/1000:.0f} thousand years"
    return "Practically uncrackable"


def check_patterns(password: str) -> list:
    """Detect weak patterns in a password."""
    issues = []

    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g., 'aaa')")
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|asd|zxc)', password.lower()):
        issues.append("Contains sequential characters (e.g., '123', 'abc')")
    if re.search(r'(19|20)\d{2}', password):
        issues.append("Contains a year — common substitution")
    if re.search(r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b', password.lower()):
        issues.append("Contains a month name")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("MATCHES COMMON PASSWORD LIST — immediately guessable")

    # l33t speak (weak substitutions)
    normalized = password.lower()
    normalized = normalized.replace("@", "a").replace("3", "e").replace("0", "o") \
                           .replace("1", "i").replace("$", "s").replace("!", "i")
    if normalized in COMMON_PASSWORDS:
        issues.append("l33t-speak substitution of a common password — easily cracked")

    return issues


def audit_password(password: str) -> dict:
    """Full password audit. Returns structured result."""
    result = {
        "password_masked": password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "**",
        "length": len(password),
        "entropy_bits": 0.0,
        "crack_time": "",
        "score": 0,        # 0–100
        "grade": "",       # A–F
        "issues": [],
        "checks": {}
    }

    # Character set checks
    checks = {
        "has_lowercase":  bool(re.search(r'[a-z]', password)),
        "has_uppercase":  bool(re.search(r'[A-Z]', password)),
        "has_digit":      bool(re.search(r'\d', password)),
        "has_special":    bool(re.search(r'[^a-zA-Z0-9]', password)),
        "length_ok":      len(password) >= 12,
        "length_strong":  len(password) >= 16,
        "not_common":     password.lower() not in COMMON_PASSWORDS,
    }
    result["checks"] = checks

    # Score
    score = 0
    if checks["has_lowercase"]:  score += 10
    if checks["has_uppercase"]:  score += 15
    if checks["has_digit"]:      score += 15
    if checks["has_special"]:    score += 20
    if checks["length_ok"]:      score += 20
    if checks["length_strong"]:  score += 10
    if checks["not_common"]:     score += 10

    entropy = calculate_entropy(password)
    result["entropy_bits"] = round(entropy, 2)
    result["crack_time"]   = estimate_crack_time(entropy)

    # Deduct for weak patterns
    issues = check_patterns(password)
    result["issues"] = issues
    score = max(0, score - len(issues) * 15)

    result["score"] = min(100, score)

    # Grade
    if score >= 85:   result["grade"] = "A"
    elif score >= 70: result["grade"] = "B"
    elif score >= 55: result["grade"] = "C"
    elif score >= 40: result["grade"] = "D"
    else:             result["grade"] = "F"

    return result


# ─────────────────────────────────────────────
# 2. HASH ANALYZER
# ─────────────────────────────────────────────

HASH_SIGNATURES = {
    32:  "MD5",
    40:  "SHA-1",
    56:  "SHA-224",
    64:  "SHA-256",
    96:  "SHA-384",
    128: "SHA-512",
}

HASH_SECURITY = {
    "MD5":     ("BROKEN",   "Collision attacks known. Never use for passwords."),
    "SHA-1":   ("BROKEN",   "Collision attacks demonstrated. Deprecated by NIST."),
    "SHA-224": ("WEAK",     "Truncated SHA-256. Not recommended for new systems."),
    "SHA-256": ("MODERATE", "Secure hash but fast — use bcrypt/Argon2 for passwords."),
    "SHA-384": ("GOOD",     "Secure, but use bcrypt/Argon2 for password storage."),
    "SHA-512": ("GOOD",     "Secure, but use bcrypt/Argon2 for password storage."),
}

def identify_hash(hash_string: str) -> dict:
    """Identify hash type and security rating from hex string length."""
    h = hash_string.strip().lower()
    if not re.match(r'^[0-9a-f]+$', h):
        return {"error": "Not a valid hex hash"}

    algo = HASH_SIGNATURES.get(len(h), "Unknown")
    status, advice = HASH_SECURITY.get(algo, ("UNKNOWN", "Cannot determine security."))

    return {
        "hash":      hash_string[:16] + "...",
        "length":    len(h),
        "algorithm": algo,
        "status":    status,
        "advice":    advice
    }


def hash_password(password: str) -> dict:
    """Generate multiple hashes of a password for comparison."""
    return {
        "MD5":    hashlib.md5(password.encode()).hexdigest(),
        "SHA1":   hashlib.sha1(password.encode()).hexdigest(),
        "SHA256": hashlib.sha256(password.encode()).hexdigest(),
        "SHA512": hashlib.sha512(password.encode()).hexdigest(),
    }


# ─────────────────────────────────────────────
# 3. SECURE PASSWORD GENERATOR
# ─────────────────────────────────────────────

def generate_strong_password(length: int = 20, exclude_ambiguous: bool = True) -> str:
    """
    Generate a cryptographically secure password.
    Uses secrets module (not random!) for security.
    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if exclude_ambiguous:
        # Remove visually ambiguous chars: 0,O,l,1,I
        for c in "0Ol1I":
            chars = chars.replace(c, "")

    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        # Ensure all character types present
        if (re.search(r'[a-z]', pwd) and re.search(r'[A-Z]', pwd) and
                re.search(r'\d', pwd) and re.search(r'[^a-zA-Z0-9]', pwd)):
            return pwd


def generate_passphrase(num_words: int = 4) -> str:
    """Generate a memorable passphrase (EFF-style wordlist subset)."""
    word_pool = [
        "correct", "horse", "battery", "staple", "purple", "monkey",
        "dragon", "secret", "laptop", "coffee", "turtle", "wizard",
        "rocket", "forest", "silver", "golden", "bridge", "castle",
        "jungle", "marble", "mirror", "pillow", "rocket", "stream"
    ]
    words = [secrets.choice(word_pool) for _ in range(num_words)]
    separator = secrets.choice(["-", "_", ".", "!"])
    return separator.join(words) + str(secrets.randbelow(999))


# ─────────────────────────────────────────────
# 4. BULK AUDIT & REPORT
# ─────────────────────────────────────────────

def bulk_audit(passwords: list) -> list:
    return [audit_password(p) for p in passwords]


def print_audit_report(results: list):
    print("\n" + "="*70)
    print("  PASSWORD AUDIT REPORT")
    print("="*70)
    print(f"  {'Password':<20} {'Grade':^5} {'Score':^6} {'Entropy':^8} {'Crack Time':<25} Issues")
    print("-"*70)
    for r in results:
        issues = len(r["issues"])
        print(f"  {r['password_masked']:<20} {r['grade']:^5} {r['score']:^6} "
              f"{r['entropy_bits']:^8.1f} {r['crack_time']:<25} {issues} issue(s)")
        for issue in r["issues"]:
            print(f"    ⚠  {issue}")
    print("="*70)


# ─────────────────────────────────────────────
# 5. MAIN
# ─────────────────────────────────────────────

TEST_PASSWORDS = [
    "password",
    "P@ssw0rd",
    "Tr0ub4dor&3",
    "correct-horse-battery-staple",
    "abc123",
    "X$9mK#2pL@7qR!5n",
    "Summer2024!",
    "qwerty",
]

def main():
    print("="*60)
    print("  PASSWORD AUDITOR v1.0 — Dimple Goplani")
    print("="*60)

    # 1. Bulk audit
    print("\n[*] Auditing test passwords...")
    results = bulk_audit(TEST_PASSWORDS)
    print_audit_report(results)

    # 2. Hash analysis
    print("\n[*] Hash identification demo:")
    sample_hashes = [
        hashlib.md5(b"password").hexdigest(),
        hashlib.sha256(b"password").hexdigest(),
    ]
    for h in sample_hashes:
        info = identify_hash(h)
        print(f"    {info['hash']} → {info['algorithm']} [{info['status']}] — {info['advice']}")

    # 3. Generate strong alternatives
    print("\n[*] Suggested strong passwords:")
    for _ in range(3):
        pwd = generate_strong_password(20)
        r   = audit_password(pwd)
        print(f"    {pwd}  (Grade: {r['grade']}, Entropy: {r['entropy_bits']:.0f} bits, Crack: {r['crack_time']})")

    print("\n[*] Suggested passphrases:")
    for _ in range(3):
        pp = generate_passphrase()
        r  = audit_password(pp)
        print(f"    {pp}  (Grade: {r['grade']}, Crack: {r['crack_time']})")

    # 4. Save JSON report
    report = {
        "generated": datetime.now().isoformat(),
        "audits": results
    }
    with open("password_audit.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n[*] Full report saved: password_audit.json")
    print("[✓] Done.\n")


if __name__ == "__main__":
    main()
