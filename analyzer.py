"""
analyzer.py - core logic of the Password Strength Analyzer.

Covers:
  * length + complexity checks
  * uniqueness checks (common-password list, leetspeak, sequences, repeats)
  * entropy calculation
  * strong password suggestions (uses `secrets`, which is cryptographically secure)
  * salted PBKDF2 hashing (the "basic cryptography" part)
"""
import hashlib
import hmac
import math
import os
import re
import secrets
import string
from pathlib import Path

# ----------------------------------------------------------------------------
# Common password list
# ----------------------------------------------------------------------------
COMMON_FILE = Path(__file__).with_name("common_passwords.txt")


def load_common_passwords(path=COMMON_FILE):
    """Load common passwords into a set. You can replace the file with rockyou.txt."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = load_common_passwords()

LEET_MAP = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "l", "3": "e",
                          "$": "s", "5": "s", "7": "t", "!": "i"})

KEYBOARD_RUNS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
                 "abcdefghijklmnopqrstuvwxyz"]

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

WORDS = ["river", "tiger", "cloud", "maple", "rocket", "silver", "garden", "planet",
         "orange", "thunder", "pencil", "castle", "forest", "island", "bridge",
         "falcon", "lotus", "monsoon", "temple", "coconut", "jasmine", "harbor",
         "meadow", "lantern", "compass", "ember", "violet", "canyon", "breeze",
         "anchor", "saffron", "pepper", "marble", "velvet", "comet", "aurora"]


# ----------------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------------
def check_complexity(pw):
    """Return a dict of rule -> True/False."""
    return {
        "At least 8 characters": len(pw) >= 8,
        "At least 12 characters (recommended)": len(pw) >= 12,
        "Has lowercase letter": bool(re.search(r"[a-z]", pw)),
        "Has uppercase letter": bool(re.search(r"[A-Z]", pw)),
        "Has digit": bool(re.search(r"\d", pw)),
        "Has symbol": bool(re.search(r"[^A-Za-z0-9]", pw)),
    }


def is_common(pw):
    """True if the password (or its leetspeak-decoded form) is in the common list."""
    low = pw.lower()
    decoded = low.translate(LEET_MAP)
    # also try with trailing digits/symbols stripped, e.g. "password2024!"
    stripped = re.sub(r"[\d\W_]+$", "", decoded)
    return any(c in COMMON_PASSWORDS for c in (low, decoded, stripped) if c)


def has_sequence(pw, n=4):
    """Detect runs like 1234, abcd, qwer (forward or backward)."""
    low = pw.lower()
    for run in KEYBOARD_RUNS:
        for i in range(len(run) - n + 1):
            chunk = run[i:i + n]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def has_repeats(pw, n=3):
    """Detect the same character repeated n or more times, e.g. aaa, 1111."""
    return bool(re.search(r"(.)\1{%d,}" % (n - 1), pw))


# ----------------------------------------------------------------------------
# Entropy
# ----------------------------------------------------------------------------
def pool_size(pw):
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        pool += 32
    return pool


def entropy_bits(pw):
    """Entropy = length x log2(size of the character pool)."""
    pool = pool_size(pw)
    return len(pw) * math.log2(pool) if pool else 0.0


# ----------------------------------------------------------------------------
# Main analysis
# ----------------------------------------------------------------------------
def analyze(pw):
    """Analyze a password and return a result dictionary."""
    if not pw:
        return {"score": 0, "rating": "Empty", "entropy": 0.0, "checks": check_complexity(""),
                "issues": ["Enter a password to analyze."], "common": False}

    checks = check_complexity(pw)
    raw_entropy = entropy_bits(pw)
    penalty = 0
    issues = []

    common = is_common(pw)
    if common:
        issues.append("Matches a commonly used password (or a simple variation of one).")
    if has_sequence(pw):
        penalty += 15
        issues.append("Contains a sequence like 1234, abcd or qwer.")
    if has_repeats(pw):
        penalty += 10
        issues.append("Contains repeated characters like aaa or 111.")
    if len(pw) < 8:
        issues.append("Too short. Use at least 12 characters.")
    for rule in ("Has lowercase letter", "Has uppercase letter", "Has digit", "Has symbol"):
        if not checks[rule]:
            issues.append("Missing: " + rule.replace("Has ", "") + ".")

    effective = max(0.0, raw_entropy - penalty)

    if common:
        rating = "Very Weak"
        effective = min(effective, 20)
    elif effective < 40:
        rating = "Weak"
    elif effective < 60:
        rating = "Medium"
    elif effective < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    score = int(min(100, effective / 80 * 100))
    return {"score": score, "rating": rating, "entropy": round(raw_entropy, 1),
            "effective_entropy": round(effective, 1), "checks": checks,
            "issues": issues, "common": common}


# ----------------------------------------------------------------------------
# Suggestions
# ----------------------------------------------------------------------------
def random_password(length=16):
    """Fully random password, guaranteed to contain all four character types."""
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)
                and re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw)):
            return pw


def passphrase(words=4):
    """Easy to remember, hard to guess: random words + number + symbol."""
    chosen = [secrets.choice(WORDS).capitalize() for _ in range(words)]
    return "-".join(chosen) + str(secrets.randbelow(90) + 10) + secrets.choice("!@#$%&*")


def strengthen(pw):
    """Turn the user's own password into a stronger one (keeps it recognisable)."""
    subs = {"a": "@", "s": "$", "o": "0", "e": "3", "i": "!", "l": "1"}
    out = []
    for ch in pw:
        if ch.lower() in subs and secrets.randbelow(2):
            out.append(subs[ch.lower()])
        elif ch.isalpha() and secrets.randbelow(3) == 0:
            out.append(ch.upper() if ch.islower() else ch.lower())
        else:
            out.append(ch)
    improved = "".join(out)
    tail = string.digits + SYMBOLS
    while len(improved) < 14 or not (re.search(r"\d", improved) and re.search(r"[^A-Za-z0-9]", improved)):
        improved += secrets.choice(tail)
    if not re.search(r"[A-Z]", improved):
        improved = improved[0].upper() + improved[1:]
    if not re.search(r"[a-z]", improved):
        improved += secrets.choice(string.ascii_lowercase)
    return improved


def suggest(pw="", count=3):
    """Return a list of stronger password alternatives."""
    options = []
    if pw:
        options.append(("Stronger version of yours", strengthen(pw)))
    options.append(("Random password", random_password(16)))
    options.append(("Memorable passphrase", passphrase()))
    options.append(("Long random password", random_password(20)))
    return options[:max(count, 1)]


# ----------------------------------------------------------------------------
# Cryptography: salted hashing
# ----------------------------------------------------------------------------
ITERATIONS = 200_000


def hash_password(pw, salt=None):
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(pw, salt_hex, hash_hex):
    """Re-hash with the stored salt and compare in constant time."""
    _, new_hash = hash_password(pw, bytes.fromhex(salt_hex))
    return hmac.compare_digest(new_hash, hash_hex)
