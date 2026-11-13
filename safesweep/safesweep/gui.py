"""Desktop window (Tkinter - ships with Python on Windows/macOS/Linux)."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading

from .config import Settings
from .junk import find_junk
from .models import Finding
from .review import ReviewFolder
from .scanner import clamav_available, scan


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _open_folder(path: str) -> None:
    if sys.platform.startswith("win"):
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def run() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("Tkinter is not available. Use the command line instead: safesweep --help")
        return 1

    settings = Settings.load()
    review = ReviewFolder(settings)
    events: queue.Queue = queue.Queue()

    root = tk.Tk()
    root.title("SafeSweep")
    root.geometry("980x620")
    root.minsize(720, 460)
    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("Treeview", rowheight=24)
    style.configure("Accent.TButton", font=("TkDefaultFont", 10, "bold"))

    status = tk.StringVar(value="Ready.")
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))
    ttk.Label(root, textvariable=status, anchor="w").pack(fill="x", padx=10, pady=6)

    # ---------- shared "results" tab builder ----------
    def results_tab(title: str, worker, default_paths_attr: str, intro: str):
        frame = ttk.Frame(nb, padding=8)
        nb.add(frame, text=title)
        ttk.Label(frame, text=intro, wraplength=900, foreground="#555").pack(anchor="w", pady=(0, 6))

        top = ttk.Frame(frame)
        top.pack(fill="x")
        paths_var = tk.StringVar(value="; ".join(getattr(settings, default_paths_attr)))
        ttk.Label(top, text="Folders:").pack(side="left")
        ttk.Entry(top, textvariable=paths_var).pack(side="left", fill="x", expand=True, padx=4)

        def add_folder():
            d = filedialog.askdirectory()
            if d:
                cur = [p for p in paths_var.get().split(";") if p.strip()]
                paths_var.set("; ".join([*map(str.strip, cur), d]))

        ttk.Button(top, text="Add…", command=add_folder).pack(side="left")
        start_btn = ttk.Button(top, text="Start", style="Accent.TButton")
        start_btn.pack(side="left", padx=(6, 0))

        cols = ("severity", "size", "reason", "path")
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        for c, w in zip(cols, (70, 80, 330, 460)):
            tree.heading(c, text=c.capitalize())
            tree.column(c, width=w, anchor="w", stretch=c in ("reason", "path"))
        tree.tag_configure("high", foreground="#b00020")
        tree.tag_configure("medium", foreground="#b36b00")
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        side = ttk.Frame(frame, padding=(8, 6))
        side.pack(side="right", fill="y")
        sb.pack(side="right", fill="y", pady=6)
        tree.pack(side="left", fill="both", expand=True, pady=6)
        found: dict[str, Finding] = {}
        cancel = threading.Event()

        def move_selected(all_items=False):
            ids = tree.get_children() if all_items else tree.selection()
            if not ids:
                messagebox.showinfo("SafeSweep", "Select one or more items first.")
                return
            moved, errors = 0, []
            for iid in ids:
                try:
                    review.move_in(found[iid])
                    tree.delete(iid)
                    moved += 1
                except OSError as e:
                    errors.append(f"{found[iid].path}: {e}")
            refresh_review()
            status.set(f"Moved {moved} item(s) to the Review folder. Nothing has been deleted.")
            if errors:
                messagebox.showwarning("Some items could not be moved", "\n".join(errors[:15]))

        def show_in_folder():
            sel = tree.selection()
            if sel:
                _open_folder(os.path.dirname(found[sel[0]].path))

        ttk.Button(side, text="Move selected\nto Review", command=move_selected).pack(fill="x", pady=2)
        ttk.Button(side, text="Move ALL\nto Review", command=lambda: move_selected(True)).pack(fill="x", pady=2)
        ttk.Button(side, text="Open location", command=show_in_folder).pack(fill="x", pady=(12, 2))
        ttk.Button(side, text="Stop", command=cancel.set).pack(fill="x", pady=2)

        def start():
            paths = [p.strip() for p in paths_var.get().split(";") if p.strip()]
            setattr(settings, default_paths_attr, paths)
            settings.save()
            tree.delete(*tree.get_children())
            found.clear()
            cancel.clear()
            start_btn.state(["disabled"])

            def job():
                try:
                    res = worker(settings, paths, lambda p: events.put(("status", f"Checking {p}")), cancel.is_set)
                    events.put(("done", (tree, found, res, start_btn, title)))
                except Exception as e:  # surface any failure in the UI
                    events.put(("error", (start_btn, str(e))))

            threading.Thread(target=job, daemon=True).start()

        start_btn.configure(command=start)

    results_tab("🛡 Virus Scan", scan, "scan_paths",
                "Scans for known malware (signature list"
                + (" + ClamAV" if clamav_available() else "; install ClamAV for full coverage")
                + "), disguised programs, fake extensions and dangerous scripts. "
                "Flagged items are moved to the Review folder and made non-executable.")
    results_tab("🧹 Cleanup", find_junk, "junk_paths",
                "Finds temporary files, old caches and logs, duplicates, empty files, old installers and "
                "downloads you haven't opened in a long time. Nothing is deleted - selected items go to "
                "the Review folder first.")

    # ---------- Review tab ----------
    rframe = ttk.Frame(nb, padding=8)
    nb.add(rframe, text="📂 Review Folder")
    ttk.Label(rframe, text="Items waiting for your decision. Restore puts a file back where it was; "
              "Delete removes it permanently.", foreground="#555").pack(anchor="w", pady=(0, 6))
    rcols = ("type", "size", "age", "reason", "original")
    rtree = ttk.Treeview(rframe, columns=rcols, show="headings", selectmode="extended")
    for c, w in zip(rcols, (60, 80, 60, 300, 440)):
        rtree.heading(c, text=c.capitalize())
        rtree.column(c, width=w, anchor="w", stretch=c in ("reason", "original"))
    rtree.tag_configure("threat", foreground="#b00020")
    rside = ttk.Frame(rframe, padding=(8, 0))
    rside.pack(side="right", fill="y")
    rtree.pack(side="left", fill="both", expand=True)
    total_var = tk.StringVar()

    def refresh_review():
        rtree.delete(*rtree.get_children())
        items = review.items()
        for it in items:
            rtree.insert("", "end", iid=it.id, tags=(it.category,),
                         values=(it.category, _human(it.size), f"{it.age_days:.0f}d", it.reason, it.original_path))
        total_var.set(f"{len(items)} item(s)\n{_human(sum(i.size for i in items))}")

    def do_restore():
        for iid in rtree.selection():
            item = next(i for i in review.items() if i.id == iid)
            if item.category == "threat" and not messagebox.askyesno(
                    "Restore a flagged threat?", f"{item.original_path}\n\n{item.reason}\n\nRestore anyway?"):
                continue
            review.restore(iid)
        refresh_review()
        status.set("Restored selected items.")

    def do_delete(all_items=False):
        ids = rtree.get_children() if all_items else rtree.selection()
        if not ids:
            return
        if not messagebox.askyesno("Delete permanently?", f"Permanently delete {len(ids)} item(s)? This cannot be undone."):
            return
        freed = sum(review.delete(i) for i in ids)
        refresh_review()
        status.set(f"Deleted {len(ids)} item(s), freed {_human(freed)}.")

    def purge_expired():
        days = settings.review_retention_days
        if messagebox.askyesno("Delete old items?", f"Permanently delete items that have been in review for {days}+ days?"):
            n, freed = review.purge(days)
            refresh_review()
            status.set(f"Deleted {n} expired item(s), freed {_human(freed)}.")

    ttk.Label(rside, textvariable=total_var, justify="center").pack(pady=(0, 8))
    ttk.Button(rside, text="Restore", command=do_restore).pack(fill="x", pady=2)
    ttk.Button(rside, text="Delete selected", command=do_delete).pack(fill="x", pady=2)
    ttk.Button(rside, text="Delete ALL", command=lambda: do_delete(True)).pack(fill="x", pady=2)
    ttk.Button(rside, text=f"Delete items\nolder than {settings.review_retention_days}d", command=purge_expired).pack(fill="x", pady=2)
    ttk.Button(rside, text="Open folder", command=lambda: _open_folder(str(review.files))).pack(fill="x", pady=(12, 2))
    ttk.Button(rside, text="Refresh", command=refresh_review).pack(fill="x", pady=2)
    refresh_review()

    # ---------- event pump ----------
    def pump():
        try:
            while True:
                kind, payload = events.get_nowait()
                if kind == "status":
                    status.set(payload[-140:])
                elif kind == "done":
                    tree, found, res, btn, title = payload
                    for i, f in enumerate(res):
                        iid = str(i)
                        found[iid] = f
                        tree.insert("", "end", iid=iid, tags=(f.severity,),
                                    values=(f.severity, _human(f.size), f.reason, f.path))
                    btn.state(["!disabled"])
                    total = _human(sum(f.size for f in res))
                    status.set(f"{title.split(' ', 1)[-1]} finished: {len(res)} item(s), {total}.")
                elif kind == "error":
                    btn, msg = payload
                    btn.state(["!disabled"])
                    status.set(f"Error: {msg}")
        except queue.Empty:
            pass
        root.after(100, pump)

    pump()
    root.mainloop()
    return 0
