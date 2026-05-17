#!/usr/bin/env python3
"""
hash_id.py  —  figure out what algorithm made your hash
               written by hand, nothing fancy
"""

import sys
import re

# ──────────────────────────────────────────────
#  every format we know about
#  (prefix, name, confidence, note)
# ──────────────────────────────────────────────
PREFIX_RULES = [
    ("$argon2id$",   "Argon2id",          "high",   "modern default, use this for new projects"),
    ("$argon2i$",    "Argon2i",           "high",   "argon2 memory-hard, side-channel resistant"),
    ("$argon2d$",    "Argon2d",           "high",   "argon2 variant, not for passwords"),
    ("$2b$",         "bcrypt",            "high",   "current bcrypt prefix, blowfish-based"),
    ("$2a$",         "bcrypt (legacy)",   "high",   "older bcrypt — still valid, just older"),
    ("$2y$",         "bcrypt (PHP)",      "high",   "PHP bcrypt, functionally same as $2b$"),
    ("$6$",          "SHA-512-crypt",     "high",   "Linux /etc/shadow default"),
    ("$5$",          "SHA-256-crypt",     "high",   "Linux shadow, less common than $6$"),
    ("$1$",          "MD5-crypt",         "high",   "old Linux shadow, avoid"),
    ("$apr1$",       "Apache MD5-crypt",  "high",   "htpasswd -m output"),
    ("$P$",          "phpass",            "high",   "WordPress / older PHP apps"),
    ("$H$",          "phpass (alt)",      "high",   "same algo as $P$, different prefix"),
    ("pbkdf2_sha256$","PBKDF2-SHA256",    "high",   "Django default password hasher"),
    ("pbkdf2_sha512$","PBKDF2-SHA512",    "high",   "Django PBKDF2 SHA-512 variant"),
    ("pbkdf2_sha1$",  "PBKDF2-SHA1",      "high",   "Django legacy, still valid"),
    ("{SSHA}",       "Salted SHA-1",      "high",   "LDAP standard, base64 encoded"),
    ("{SHA}",        "SHA-1 (LDAP)",      "high",   "unsalted LDAP SHA-1"),
    ("{MD5}",        "MD5 (LDAP)",        "high",   "unsalted LDAP MD5"),
    ("sha1$",        "Django SHA-1",      "high",   "old Django, pre-1.4"),
    ("md5$",         "Django MD5",        "high",   "very old Django, deprecated"),
    ("scrypt$",      "scrypt",            "high",   "memory-hard KDF"),
]

# ──────────────────────────────────────────────
#  pure hex hashes — identified by length alone
# ──────────────────────────────────────────────
HEX_LENGTH_RULES = {
    32:  [("MD5",         "high",   "32 hex — classic MD5"),
          ("NTLM",        "medium", "32 hex — also possible, used in Windows auth"),
          ("MD4",         "low",    "32 hex — rare, but same length")],
    40:  [("SHA-1",       "high",   "40 hex — SHA-1"),
          ("RIPEMD-160",  "low",    "40 hex — same length, much rarer")],
    56:  [("SHA-224",     "high",   "56 hex — SHA-224")],
    64:  [("SHA-256",     "high",   "64 hex — SHA-256"),
          ("BLAKE2s",     "low",    "64 hex — same length, less common")],
    96:  [("SHA-384",     "high",   "96 hex — SHA-384")],
    128: [("SHA-512",     "high",   "128 hex — SHA-512"),
          ("SHA3-512",    "medium", "128 hex — SHA3 is same length"),
          ("BLAKE2b",     "low",    "128 hex — same length, less common")],
    86:  [("BLAKE2b-344", "low",    "86 hex — unusual length")],
}

CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
CONFIDENCE_COLOR = {"high": "\033[92m", "medium": "\033[93m", "low": "\033[91m"}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[96m"
WHITE = "\033[97m"


def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def looks_like_jwt(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 3 and s.startswith("eyJ")


def looks_like_base64(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", s)) and len(s) % 4 == 0


def looks_like_mysql5(s: str) -> bool:
    return bool(re.fullmatch(r"\*[0-9A-F]{40}", s))


def looks_like_des_crypt(s: str) -> bool:
    # traditional DES crypt: 13 chars, alphanumeric + ./
    return bool(re.fullmatch(r"[a-zA-Z0-9./]{13}", s))


def identify(hash_str: str) -> list[dict]:
    """
    returns a list of candidates, each a dict:
      { name, confidence, reason }
    sorted high → low confidence
    """
    s = hash_str.strip()
    results = []

    # ── special non-hash formats ───────────────
    if looks_like_jwt(s):
        return [{"name": "JWT (not a hash)", "confidence": "high",
                 "reason": "three base64 sections separated by dots — this is a token, not a hash"}]

    if looks_like_mysql5(s):
        return [{"name": "MySQL5 / MySQL4.1+", "confidence": "high",
                 "reason": "* followed by 40 uppercase hex chars — MySQL password hash"}]

    # ── prefix matching ────────────────────────
    for prefix, name, conf, reason in PREFIX_RULES:
        if s.startswith(prefix):
            results.append({"name": name, "confidence": conf, "reason": reason})

    if results:
        return results

    # ── hex length matching ────────────────────
    if is_hex(s):
        candidates = HEX_LENGTH_RULES.get(len(s))
        if candidates:
            for name, conf, reason in candidates:
                results.append({"name": name, "confidence": conf, "reason": reason})
            return results
        else:
            return [{"name": "Unknown hex", "confidence": "low",
                     "reason": f"{len(s)} hex chars — no rule matches this length"}]

    # ── traditional DES crypt ──────────────────
    if looks_like_des_crypt(s):
        return [{"name": "DES-crypt (traditional)", "confidence": "medium",
                 "reason": "13-char [a-zA-Z0-9./] — classic Unix crypt(3)"}]

    # ── base64 blob ────────────────────────────
    if looks_like_base64(s):
        return [{"name": "Base64-encoded blob", "confidence": "low",
                 "reason": "valid base64 — could be a hash, could be anything; decode and re-identify"}]

    return [{"name": "Unrecognized", "confidence": "low",
             "reason": "doesn't match any known pattern — double-check your input"}]


# ──────────────────────────────────────────────
#  output
# ──────────────────────────────────────────────

def banner():
    print(f"""
{CYAN}{BOLD}  hash_id.py{RESET}
{DIM}  tells you what made your hash{RESET}
""")


def print_results(hash_str: str, candidates: list[dict]):
    print(f"  {DIM}input :{RESET}  {hash_str[:80]}{'...' if len(hash_str) > 80 else ''}\n")

    for i, c in enumerate(candidates):
        col   = CONFIDENCE_COLOR[c["confidence"]]
        badge = f"{col}[{c['confidence']}]{RESET}"
        mark  = f"{BOLD}{WHITE}→{RESET}" if i == 0 else " "
        print(f"  {mark} {badge}  {BOLD}{c['name']}{RESET}")
        print(f"       {DIM}{c['reason']}{RESET}\n")


def usage():
    print(f"""
  {BOLD}usage:{RESET}
    python hash_id.py <hash>
    python hash_id.py --file hashes.txt

  {BOLD}examples:{RESET}
    python hash_id.py 5f4dcc3b5aa765d61d8327deb882cf99
    python hash_id.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK'
    python hash_id.py --file hashes.txt
""")


def main():
    banner()

    if len(sys.argv) < 2:
        usage()
        sys.exit(0)

    # ── file mode ─────────────────────────────
    if sys.argv[1] == "--file":
        if len(sys.argv) < 3:
            print("  error: --file needs a filename\n")
            sys.exit(1)
        try:
            lines = open(sys.argv[2]).read().splitlines()
        except FileNotFoundError:
            print(f"  error: file not found — {sys.argv[2]}\n")
            sys.exit(1)

        hashes = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        print(f"  {DIM}scanning {len(hashes)} hashes from {sys.argv[2]}{RESET}\n")
        print("  " + "─" * 60)
        for h in hashes:
            candidates = identify(h)
            print_results(h, candidates)
            print("  " + "─" * 60)
        sys.exit(0)

    # ── single hash mode ───────────────────────
    hash_str   = sys.argv[1]
    candidates = identify(hash_str)
    print_results(hash_str, candidates)

    # exit 0 if we got a confident hit, 1 if not
    sys.exit(0 if candidates[0]["confidence"] != "low" else 1)


if __name__ == "__main__":
    main()
