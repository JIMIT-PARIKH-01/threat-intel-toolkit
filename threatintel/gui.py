"""
Tkinter GUI for the Threat Intel Toolkit (standard library only).
Tabs: Phishing (offline) · VirusTotal (needs API key).
"""

from __future__ import annotations

import os
import queue
import threading

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

try:
    from threatintel import phishing, vt_check
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from threatintel import phishing, vt_check


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Threat Intel Toolkit")
        self.geometry("820x600")
        self.minsize(680, 480)
        self.ui_queue: "queue.Queue" = queue.Queue()
        self.after(60, self._drain)
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        nb.add(PhishTab(nb, self), text="  Phishing  ")
        nb.add(VTTab(nb, self), text="  VirusTotal  ")
        self.status = ttk.Label(self, relief="sunken", anchor="w", text="Ready")
        self.status.pack(fill="x", side="bottom")

    def set_status(self, m): self.status.configure(text=m)

    def _drain(self):
        try:
            while True:
                cb = self.ui_queue.get_nowait()
                try:
                    cb()
                except Exception:  # noqa: BLE001
                    self.set_status("A UI update failed.")
        except queue.Empty:
            pass
        self.after(60, self._drain)


class _Base(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1); self.rowconfigure(3, weight=1)

    def _out(self):
        box = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                        state="disabled")
        box.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
        return box

    def _show(self, text):
        self.out.configure(state="normal"); self.out.delete("1.0", "end")
        self.out.insert("1.0", text); self.out.configure(state="disabled")


class PhishTab(_Base):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="URL to score (offline)").grid(row=0, column=0, sticky="w")
        self.url = tk.StringVar()
        ttk.Entry(self, textvariable=self.url).grid(row=1, column=0, columnspan=2, sticky="ew")
        ttk.Button(self, text="Analyze", command=self.run).grid(row=1, column=2, padx=6)
        self.out = self._out()

    def run(self):
        u = self.url.get().strip()
        if not u:
            messagebox.showinfo("No URL", "Enter a URL."); return
        self._show(phishing.analyze(u).as_text())


class VTTab(_Base):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Hash / URL / IP / domain").grid(row=0, column=0, sticky="w")
        self.ind = tk.StringVar()
        ttk.Entry(self, textvariable=self.ind).grid(row=1, column=0, sticky="ew")
        self.key = tk.StringVar(value=os.environ.get("VT_API_KEY", ""))
        ttk.Label(self, text="API key").grid(row=0, column=1, sticky="w", padx=6)
        ttk.Entry(self, textvariable=self.key, show="•", width=20).grid(row=1, column=1, padx=6)
        self.btn = ttk.Button(self, text="Look up", command=self.run); self.btn.grid(row=1, column=2)
        self.out = self._out()

    def run(self):
        ind = self.ind.get().strip()
        if not ind:
            messagebox.showinfo("No indicator", "Enter a hash/URL/IP/domain."); return
        key = self.key.get().strip() or None
        self.btn.configure(state="disabled"); self.app.set_status("Querying VirusTotal…")

        def worker():
            try:
                res = vt_check.check(ind, key=key).as_text()
            except Exception as exc:  # noqa: BLE001
                res = f"Error: {exc}"

            def finish():
                self._show(res); self.btn.configure(state="normal")
                self.app.set_status("Done.")
            self.app.ui_queue.put(finish)

        threading.Thread(target=worker, daemon=True).start()


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
