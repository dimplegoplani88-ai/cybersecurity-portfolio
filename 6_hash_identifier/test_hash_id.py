"""
basic tests — run with:  python -m pytest test_hash_id.py -v
"""

import pytest
from hash_id import identify


def top(h):
    return identify(h)[0]["name"]

def conf(h):
    return identify(h)[0]["confidence"]


# ── prefix-based ──────────────────────────────
def test_bcrypt_2b():      assert top("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK") == "bcrypt"
def test_bcrypt_2a():      assert "bcrypt" in top("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
def test_argon2id():       assert top("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub") == "Argon2id"
def test_sha512crypt():    assert top("$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/En5Ng7/YWON50") == "SHA-512-crypt"
def test_apache_md5():     assert top("$apr1$JlOdSlVe$ipa1mTAv3LFRBHHzqaIaH/") == "Apache MD5-crypt"
def test_phpass():         assert top("$P$BsomehashedpasswordHere") == "phpass"
def test_django_pbkdf2():  assert top("pbkdf2_sha256$260000$abc$xyz") == "PBKDF2-SHA256"
def test_ldap_ssha():      assert top("{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=") == "Salted SHA-1"

# ── hex length-based ──────────────────────────
def test_md5():    assert top("5f4dcc3b5aa765d61d8327deb882cf99") == "MD5"
def test_sha1():   assert top("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "SHA-1"
def test_sha256(): assert top("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "SHA-256"
def test_sha512(): assert "SHA-512" in top("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")

# ── special formats ───────────────────────────
def test_mysql5():  assert "MySQL" in top("*A4B6157319038724E3560894F7F932C8886EBFCF")
def test_jwt():     assert "JWT" in top("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")

# ── confidence ────────────────────────────────
def test_bcrypt_is_high():  assert conf("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK") == "high"
def test_md5_is_high():     assert conf("5f4dcc3b5aa765d61d8327deb882cf99") == "high"

# ── unknown ───────────────────────────────────
def test_unknown(): assert identify("notahash!!!")[0]["confidence"] == "low"
