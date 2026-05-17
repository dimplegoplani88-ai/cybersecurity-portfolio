# hash_id.py

paste a hash, get told what it is. that's it.

identifies ~35 formats — bcrypt, argon2, SHA family, MD5, NTLM, phpass, Django, LDAP, MySQL, JWTs, and more.

no dependencies. one file. works on any system with Python 3.8+.

---

## usage

```bash
# single hash
python hash_id.py 5f4dcc3b5aa765d61d8327deb882cf99

# hashes starting with $ need single quotes (so your shell doesn't mangle them)
python hash_id.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK'

# scan a file full of hashes (one per line, # for comments)
python hash_id.py --file hashes.txt
```

---

## what it detects

**by prefix** — these are unambiguous, confidence is always `high`

| prefix | algorithm |
|--------|-----------|
| `$argon2id$` | Argon2id |
| `$2b$` / `$2a$` / `$2y$` | bcrypt |
| `$6$` | SHA-512-crypt (Linux shadow) |
| `$5$` | SHA-256-crypt |
| `$1$` | MD5-crypt (old Linux) |
| `$apr1$` | Apache MD5-crypt |
| `$P$` / `$H$` | phpass (WordPress) |
| `pbkdf2_sha256$` | Django PBKDF2 |
| `{SSHA}` | Salted SHA-1 (LDAP) |
| `*` + 40 hex | MySQL5 |
| `eyJ...` | JWT (not a hash — flagged) |

**by length** — hex-only hashes, ranked by likelihood

| length | most likely |
|--------|-------------|
| 32 | MD5 |
| 40 | SHA-1 |
| 64 | SHA-256 |
| 96 | SHA-384 |
| 128 | SHA-512 |

---

## output

```
  hash_id.py
  tells you what made your hash

  input :  5f4dcc3b5aa765d61d8327deb882cf99

  → [high]    MD5
              32 hex — classic MD5

    [medium]  NTLM
              32 hex — also possible, used in Windows auth

    [low]     MD4
              32 hex — rare, but same length
```

top result is your most likely answer. lower ones exist because some hash lengths are shared between algorithms — context matters.

---

## running tests

```bash
python -m pytest test_hash_id.py -v
```

17 tests. runs in under a second.

---

## how it works

three-step decision:

1. **prefix check** — if the string starts with a known prefix (`$2b$`, `$argon2id$`, etc.) the algorithm is identified immediately, no ambiguity
2. **hex length check** — if it's a pure hex string, length narrows it down to a ranked candidate list
3. **shape check** — catches edge cases: JWT structure, MySQL `*` prefix, traditional DES crypt (13-char), base64 blobs

the core `identify()` function is pure — no I/O, no side effects, easy to import and use in your own scripts.

---

## license

MIT
