"""Simple desktop window for truetype: drop or choose files, see a clear verdict."""
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog

from .scanner import analyze, collect, verdict

try:  # optional: real drag-and-drop (pip install tkinterdnd2)
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAVE_DND = True
except Exception:
    HAVE_DND = False

COLORS = {"CLEAN": "#1e8e3e", "SUSPICIOUS": "#e37400", "DANGEROUS": "#d93025", "IDLE": "#5f6368"}
LABEL = {"CLEAN": "OK", "SUSPICIOUS": "WARNING", "DANGEROUS": "DANGER"}


class App:
    def __init__(self, root, initial_paths=()):
        self.root = root
        self.q = queue.Queue()
        self.results = []
        root.title("TrueType - what is this file really?")
        root.geometry("720x620")
        root.minsize(560, 480)

        self.banner = tk.Label(root, text="Drop a file to check it", font=("Segoe UI", 18, "bold"),
                               bg=COLORS["IDLE"], fg="white", pady=18)
        self.banner.pack(fill="x")

        hint = ("Drag files or folders here" if HAVE_DND else "Click here to choose files") + \
               "\n(or use the buttons below)"
        self.drop = tk.Label(root, text=hint, font=("Segoe UI", 12), fg="#3c4043", bg="#f1f3f4",
                             relief="groove", bd=2, pady=26, cursor="hand2")
        self.drop.pack(fill="x", padx=14, pady=(12, 6))
        self.drop.bind("<Button-1>", lambda e: self.choose_files())
        if HAVE_DND:
            self.drop.drop_target_register(DND_FILES)
            self.drop.dnd_bind("<<Drop>>", self.on_drop)

        bar = tk.Frame(root)
        bar.pack(fill="x", padx=14)
        tk.Button(bar, text="Choose files...", command=self.choose_files, padx=10).pack(side="left")
        tk.Button(bar, text="Scan a folder...", command=self.choose_folder, padx=10).pack(side="left", padx=6)
        tk.Button(bar, text="Clear", command=self.clear, padx=10).pack(side="right")

        frame = tk.Frame(root)
        frame.pack(fill="both", expand=True, padx=14, pady=10)
        self.text = tk.Text(frame, wrap="word", font=("Consolas", 10), state="disabled", relief="flat",
                            bg="#ffffff", padx=8, pady=6)
        sb = tk.Scrollbar(frame, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        for name, col in COLORS.items():
            self.text.tag_configure(name, foreground=col, font=("Consolas", 10, "bold"))
        self.text.tag_configure("dim", foreground="#5f6368")

        self.poll()
        if initial_paths:
            self.scan(initial_paths)

    # ---- input
    def on_drop(self, event):
        self.scan(self.root.tk.splitlist(event.data))

    def choose_files(self):
        paths = filedialog.askopenfilenames(title="Choose files to check")
        if paths:
            self.scan(paths)

    def choose_folder(self):
        folder = filedialog.askdirectory(title="Choose a folder to scan")
        if folder:
            self.scan([folder])

    def clear(self):
        self.results = []
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self.set_banner("Drop a file to check it", "IDLE")

    # ---- scanning (background thread keeps the window responsive)
    def scan(self, paths):
        self.set_banner("Scanning...", "IDLE")
        threading.Thread(target=self._worker, args=(list(paths),), daemon=True).start()

    def _worker(self, paths):
        for p in collect(paths, recursive=True):
            res = analyze(p)
            res["verdict"] = verdict(res["findings"])
            self.q.put(("result", res))
        self.q.put(("done", None))

    def poll(self):
        try:
            while True:
                kind, res = self.q.get_nowait()
                if kind == "result":
                    self.results.append(res)
                    self.show(res)
                else:
                    self.summarize()
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    # ---- output
    def show(self, res):
        v = res["verdict"]
        t = self.text
        t.configure(state="normal")
        t.insert("end", f"[{LABEL[v]}] ", v)
        t.insert("end", os.path.basename(res["path"]) + "\n")
        t.insert("end", f"    real type: {res['detected']}\n", "dim")
        for sev, msg in res["findings"]:
            t.insert("end", f"    {'!!' if sev == 'danger' else ' !'} {msg}\n",
                     "DANGEROUS" if sev == "danger" else "SUSPICIOUS")
        t.insert("end", "\n")
        t.see("end")
        t.configure(state="disabled")

    def summarize(self):
        n = len(self.results)
        bad = sum(r["verdict"] == "DANGEROUS" for r in self.results)
        warn = sum(r["verdict"] == "SUSPICIOUS" for r in self.results)
        if n == 0:
            self.set_banner("No files found", "IDLE")
        elif bad:
            self.set_banner(f"DANGER: {bad} dangerous file(s) - do NOT open", "DANGEROUS")
        elif warn:
            self.set_banner(f"Warning: {warn} suspicious file(s)", "SUSPICIOUS")
        else:
            self.set_banner(f"All clear ({n} file{'s' if n != 1 else ''} checked)", "CLEAN")

    def set_banner(self, text, level):
        self.banner.configure(text=text, bg=COLORS[level])


def main(argv=None):
    paths = sys.argv[1:] if argv is None else argv
    root = TkinterDnD.Tk() if HAVE_DND else tk.Tk()
    App(root, paths)
    root.mainloop()


if __name__ == "__main__":
    main()
