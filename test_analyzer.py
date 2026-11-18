"""Run:  python test_analyzer.py"""
import os
import tempfile

import analyzer
import database

assert analyzer.analyze("password")["rating"] == "Very Weak"
assert analyzer.analyze("P@ssw0rd")["rating"] == "Very Weak"      # leetspeak caught
assert analyzer.analyze("abcd1234")["rating"] in ("Very Weak", "Weak")
assert analyzer.analyze("Tr!ger-Lotus-92xQ#")["rating"] in ("Strong", "Very Strong")

for _, s in analyzer.suggest("hello"):
    assert analyzer.analyze(s)["rating"] in ("Strong", "Very Strong"), s

salt, h = analyzer.hash_password("MySecret#1")
assert analyzer.verify_password("MySecret#1", salt, h)
assert not analyzer.verify_password("wrong", salt, h)

path = os.path.join(tempfile.mkdtemp(), "t.db")
conn = database.connect(path)
database.save_password(conn, "prawin", "OldPass#2026xYz")
assert database.is_reused(conn, "prawin", "OldPass#2026xYz")
assert not database.is_reused(conn, "prawin", "BrandNew#2026xYz")
print("All tests passed.")
