"""
database.py - SQLite storage that prevents reuse of old passwords.
Only salted hashes are stored, never the real passwords.
"""
import sqlite3
from pathlib import Path

from analyzer import hash_password, verify_password

DB_PATH = Path(__file__).with_name("passwords.db")


def connect(path=DB_PATH):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS password_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        hash TEXT NOT NULL,
                        created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    return conn


def is_reused(conn, username, pw):
    """True if this password matches any previous password of the user."""
    rows = conn.execute("SELECT salt, hash FROM password_history WHERE username = ?",
                        (username,)).fetchall()
    return any(verify_password(pw, salt, h) for salt, h in rows)


def save_password(conn, username, pw):
    salt, h = hash_password(pw)
    conn.execute("INSERT INTO password_history (username, salt, hash) VALUES (?, ?, ?)",
                 (username, salt, h))
    conn.commit()


def history(conn, username=None):
    if username:
        return conn.execute("SELECT username, salt, hash, created FROM password_history "
                            "WHERE username = ? ORDER BY id", (username,)).fetchall()
    return conn.execute("SELECT username, salt, hash, created FROM password_history "
                        "ORDER BY id").fetchall()
