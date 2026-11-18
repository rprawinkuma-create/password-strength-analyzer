# Password Strength Analyzer

A Python tool that evaluates password strength, suggests stronger alternatives and
prevents reuse of old passwords using salted hashes.

## Features
- Length and complexity checks (lowercase, uppercase, digits, symbols)
- Uniqueness checks: common-password list, leetspeak (`P@ssw0rd`), sequences (`1234`, `qwer`), repeats (`aaa`)
- Entropy calculation: `length x log2(character pool size)`
- Strength rating: Very Weak / Weak / Medium / Strong / Very Strong
- Stronger password suggestions (random, passphrase, improved version of your own) using `secrets`
- Cryptography: PBKDF2-HMAC-SHA256 with a random 16-byte salt, 200,000 iterations
- SQLite database that rejects previously used passwords (only hashes stored)
- Two interfaces: Tkinter GUI and command line

## Requirements
Python 3.8+. No extra packages (Tkinter comes with Python on Windows/macOS;
on Linux: `sudo apt install python3-tk`).

## How to run
```
python gui.py     # graphical version
python cli.py     # command-line version
python test_analyzer.py   # run tests
```

## Files
| File | Purpose |
|------|---------|
| analyzer.py | checks, entropy, suggestions, hashing |
| database.py | SQLite reuse prevention |
| gui.py | Tkinter interface |
| cli.py | Command-line interface |
| common_passwords.txt | common passwords list (replace with rockyou.txt for a bigger one) |
| test_analyzer.py | quick tests |

## How the cryptography works
1. A random **salt** is generated for every password.
2. The password + salt go through **PBKDF2-HMAC-SHA256** 200,000 times (slow on purpose to make brute-force attacks expensive).
3. Only the salt and hash are stored. To check reuse, the new password is hashed with each stored salt and compared in constant time.
