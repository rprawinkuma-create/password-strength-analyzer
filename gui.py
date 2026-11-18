"""gui.py - Tkinter GUI version. Run:  python gui.py"""
import tkinter as tk
from tkinter import messagebox, ttk

import analyzer
import database

COLORS = {"Empty": "#cccccc", "Very Weak": "#d32f2f", "Weak": "#f57c00",
          "Medium": "#fbc02d", "Strong": "#7cb342", "Very Strong": "#2e7d32"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Analyzer")
        self.geometry("560x720")
        self.resizable(False, False)
        self.conn = database.connect()
        self.show = tk.BooleanVar(value=False)
        self.build()

    def build(self):
        pad = {"padx": 16, "pady": 6}
        ttk.Label(self, text="Password Strength Analyzer",
                  font=("Segoe UI", 16, "bold")).pack(pady=(14, 4))

        ttk.Label(self, text="Enter password:").pack(anchor="w", **pad)
        self.entry = ttk.Entry(self, show="*", font=("Consolas", 13))
        self.entry.pack(fill="x", padx=16)
        self.entry.bind("<KeyRelease>", lambda e: self.update_view())
        ttk.Checkbutton(self, text="Show password", variable=self.show,
                        command=lambda: self.entry.config(show="" if self.show.get() else "*")
                        ).pack(anchor="w", padx=16, pady=2)

        self.canvas = tk.Canvas(self, height=22, bg="#eeeeee", highlightthickness=0)
        self.canvas.pack(fill="x", padx=16, pady=(8, 2))
        self.bar = self.canvas.create_rectangle(0, 0, 0, 22, fill="#cccccc", width=0)
        self.rating_lbl = ttk.Label(self, text="Rating: -", font=("Segoe UI", 11, "bold"))
        self.rating_lbl.pack(anchor="w", padx=16)
        self.entropy_lbl = ttk.Label(self, text="Entropy: 0 bits")
        self.entropy_lbl.pack(anchor="w", padx=16)

        ttk.Label(self, text="Checklist:", font=("Segoe UI", 10, "bold")).pack(anchor="w", **pad)
        self.check_lbls = {}
        for rule in analyzer.check_complexity(""):
            lbl = ttk.Label(self, text="o  " + rule)
            lbl.pack(anchor="w", padx=28)
            self.check_lbls[rule] = lbl

        ttk.Label(self, text="Issues:", font=("Segoe UI", 10, "bold")).pack(anchor="w", **pad)
        self.issues = tk.Text(self, height=4, wrap="word", state="disabled", bg="#fafafa")
        self.issues.pack(fill="x", padx=16)

        ttk.Label(self, text="Suggestions (double-click to use):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", **pad)
        self.sug = tk.Listbox(self, height=4, font=("Consolas", 11))
        self.sug.pack(fill="x", padx=16)
        self.sug.bind("<Double-Button-1>", self.use_suggestion)
        ttk.Button(self, text="Suggest stronger passwords",
                   command=self.make_suggestions).pack(pady=6)

        ttk.Separator(self).pack(fill="x", padx=16, pady=6)
        row = ttk.Frame(self)
        row.pack(fill="x", padx=16)
        ttk.Label(row, text="Username:").pack(side="left")
        self.user = ttk.Entry(row, width=18)
        self.user.pack(side="left", padx=8)
        ttk.Button(row, text="Save password (reuse check)",
                   command=self.save).pack(side="left")
        ttk.Button(self, text="View stored hashes",
                   command=self.view_hashes).pack(pady=8)

        self.update_view()

    def update_view(self):
        pw = self.entry.get()
        r = analyzer.analyze(pw)
        color = COLORS.get(r["rating"], "#cccccc")
        self.canvas.update_idletasks()
        width = self.canvas.winfo_width() * r["score"] / 100
        self.canvas.coords(self.bar, 0, 0, width, 22)
        self.canvas.itemconfig(self.bar, fill=color)
        self.rating_lbl.config(text=f"Rating: {r['rating']}  (score {r['score']}/100)")
        self.entropy_lbl.config(text=f"Entropy: {r['entropy']} bits")
        for rule, ok in r["checks"].items():
            self.check_lbls[rule].config(text=("[x]  " if ok else "[ ]  ") + rule,
                                         foreground="#2e7d32" if ok else "#c62828")
        self.issues.config(state="normal")
        self.issues.delete("1.0", "end")
        self.issues.insert("end", "\n".join("- " + i for i in r["issues"]) or "No issues found.")
        self.issues.config(state="disabled")

    def make_suggestions(self):
        self.sug.delete(0, "end")
        for _, s in analyzer.suggest(self.entry.get(), 4):
            self.sug.insert("end", s)

    def use_suggestion(self, _event):
        sel = self.sug.curselection()
        if sel:
            self.entry.delete(0, "end")
            self.entry.insert(0, self.sug.get(sel[0]))
            self.update_view()

    def save(self):
        user, pw = self.user.get().strip(), self.entry.get()
        if not user or not pw:
            messagebox.showwarning("Missing", "Enter a username and a password.")
            return
        r = analyzer.analyze(pw)
        if r["rating"] in ("Very Weak", "Weak"):
            messagebox.showerror("Rejected", "Password is too weak to save.")
        elif database.is_reused(self.conn, user, pw):
            messagebox.showerror("Rejected", "You already used this password before.")
        else:
            database.save_password(self.conn, user, pw)
            messagebox.showinfo("Saved", "Password saved as a salted hash.")

    def view_hashes(self):
        rows = database.history(self.conn)
        text = "\n".join(f"{u} | salt={s[:10]}... | hash={h[:16]}..." for u, s, h, _ in rows)
        messagebox.showinfo("Stored hashes", text or "Nothing stored yet.")


if __name__ == "__main__":
    App().mainloop()
