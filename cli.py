"""cli.py - command-line version. Run:  python cli.py"""
import analyzer
import database


def show_result(r):
    print(f"\n  Rating  : {r['rating']}  (score {r['score']}/100)")
    print(f"  Entropy : {r['entropy']} bits")
    print("  Checks  :")
    for rule, ok in r["checks"].items():
        print(f"    [{'x' if ok else ' '}] {rule}")
    if r["issues"]:
        print("  Issues  :")
        for i in r["issues"]:
            print("    -", i)


def main():
    conn = database.connect()
    while True:
        print("\n=== Password Strength Analyzer ===")
        print("1. Analyze a password")
        print("2. Generate strong passwords")
        print("3. Set password for a user (with reuse check)")
        print("4. View stored hashes (proof: no plain text)")
        print("0. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            pw = input("Enter password: ")
            r = analyzer.analyze(pw)
            show_result(r)
            if r["rating"] in ("Very Weak", "Weak", "Medium"):
                print("\n  Suggestions:")
                for label, s in analyzer.suggest(pw):
                    print(f"    {label}: {s}")
        elif choice == "2":
            for label, s in analyzer.suggest("", 3):
                print(f"  {label}: {s}")
        elif choice == "3":
            user = input("Username: ").strip()
            pw = input("New password: ")
            r = analyzer.analyze(pw)
            show_result(r)
            if r["rating"] in ("Very Weak", "Weak"):
                print("\n  Rejected: password is too weak.")
            elif database.is_reused(conn, user, pw):
                print("\n  Rejected: you already used this password before.")
            else:
                database.save_password(conn, user, pw)
                print("\n  Password saved (as a salted hash).")
        elif choice == "4":
            for u, salt, h, created in database.history(conn):
                print(f"  {u} | salt={salt[:12]}... | hash={h[:20]}... | {created}")
        elif choice == "0":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
