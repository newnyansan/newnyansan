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
from .review import ReviewError, ReviewFolder
from .scanner import clamav_available, scan


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _reports_dir():
    from .config import app_home
    d = app_home() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _open_folder(path: str) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except OSError:
        pass


def run() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk
    except ImportError:
        print("Tkinter is not available. Use the command line instead: safesweep --help\n"
              "(Linux: sudo apt install python3-tk)")
        return 1

    settings = Settings.load()
    try:
        review = ReviewFolder(settings)
    except ReviewError as e:
        print(f"Could not open the Review folder: {e}")
        return 1
    events: queue.Queue = queue.Queue()
    busy = {"n": 0}

    if sys.platform.startswith("win"):
        try:  # crisp text on high-DPI screens + own taskbar icon
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SafeSweep.App")
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    root.title("SafeSweep")
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (getattr(sys, "_MEIPASS", None), os.path.join(here, ".."), here):
        icon_path = os.path.join(base, "assets", "icon.png") if base else ""
        if icon_path and os.path.exists(icon_path):
            try:
                root.iconphoto(True, tk.PhotoImage(file=icon_path))
            except tk.TclError:
                pass
            break
    root.geometry("1040x640")
    root.minsize(760, 480)
    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("Treeview", rowheight=24)
    style.configure("Accent.TButton", font=("TkDefaultFont", 10, "bold"))

    status = tk.StringVar(value="Ready. Nothing is ever deleted without your confirmation.")
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))
    ttk.Label(root, textvariable=status, anchor="w").pack(fill="x", padx=10, pady=6)

    def in_background(fn, done):
        busy["n"] += 1

        def job():
            try:
                res = fn()
                events.put(("call", lambda: done(res, None)))
            except Exception as e:  # surface every failure in the window
                events.put(("call", lambda e=e: done(None, e)))
            finally:
                events.put(("call", lambda: busy.__setitem__("n", busy["n"] - 1)))

        threading.Thread(target=job, daemon=True).start()

    # ---------- results tab (shared by Virus Scan and Cleanup) ----------
    feed_status = tk.StringVar(value="")

    def refresh_feed_status():
        from .feeds import status_text
        feed_status.set(status_text(settings))

    def results_tab(title: str, worker, paths_attr: str, intro: str, before=None, extra=None):
        frame = ttk.Frame(nb, padding=8)
        nb.add(frame, text=title)
        ttk.Label(frame, text=intro, wraplength=980, foreground="#555").pack(anchor="w", pady=(0, 6))
        if extra:
            extra(frame)

        top = ttk.Frame(frame)
        top.pack(fill="x")
        paths_var = tk.StringVar(value="; ".join(getattr(settings, paths_attr)))
        ttk.Label(top, text="Folders:").pack(side="left")
        ttk.Entry(top, textvariable=paths_var).pack(side="left", fill="x", expand=True, padx=4)

        def add_folder():
            d = filedialog.askdirectory()
            if d:
                cur = [p.strip() for p in paths_var.get().split(";") if p.strip()]
                if d not in cur:
                    paths_var.set("; ".join([*cur, d]))

        ttk.Button(top, text="Add…", command=add_folder).pack(side="left")
        start_btn = ttk.Button(top, text="Start", style="Accent.TButton")
        start_btn.pack(side="left", padx=(6, 0))

        side = ttk.Frame(frame, padding=(8, 6))
        side.pack(side="right", fill="y")
        cols = ("rec", "severity", "size", "reason", "path")
        heads = ("✓", "Severity", "Size", "Reason", "Path")
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        for c, h, w in zip(cols, heads, (30, 70, 80, 330, 440)):
            tree.heading(c, text=h)
            tree.column(c, width=w, minwidth=30, anchor="w", stretch=c in ("reason", "path"))
        tree.tag_configure("high", foreground="#b00020")
        tree.tag_configure("medium", foreground="#b36b00")
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", pady=6)
        tree.pack(side="left", fill="both", expand=True, pady=6)

        found: dict[str, Finding] = {}
        cancel = threading.Event()
        summary = tk.StringVar(value="")

        def select_recommended():
            tree.selection_set([i for i in tree.get_children() if found[i].recommended])

        def move_selected():
            ids = list(tree.selection())
            if not ids:
                messagebox.showinfo("SafeSweep", "Select one or more items first.")
                return
            picked = [(i, found[i]) for i in ids]
            not_rec = sum(1 for _, f in picked if not f.recommended)
            if not_rec and not messagebox.askyesno(
                    "Check these first?",
                    f"{not_rec} of the selected items are not marked ✓ (they may still be wanted).\n\n"
                    "They will only be moved to the Review folder, not deleted. Continue?"):
                return
            move_btn.state(["disabled"])
            status.set(f"Moving {len(picked)} item(s) to the Review folder…")

            def work():
                ok, errors = [], []
                for iid, f in picked:
                    try:
                        review.move_in(f)
                        ok.append(iid)
                    except (ReviewError, OSError) as e:
                        errors.append(f"{f.path}: {e}")
                return ok, errors

            def done(res, exc):
                move_btn.state(["!disabled"])
                if exc:
                    messagebox.showerror("SafeSweep", str(exc))
                    return
                ok, errors = res
                for iid in ok:
                    if tree.exists(iid):
                        tree.delete(iid)
                    found.pop(iid, None)
                refresh_review()
                status.set(f"Moved {len(ok)} item(s) to the Review folder. Nothing has been deleted.")
                if errors:
                    messagebox.showwarning(f"{len(errors)} item(s) were left in place",
                                           "\n".join(errors[:15]) + ("\n…" if len(errors) > 15 else ""))

            in_background(work, done)

        def show_in_folder(_e=None):
            sel = tree.selection() or tree.focus()
            iid = sel[0] if isinstance(sel, tuple) and sel else sel
            if iid and iid in found:
                _open_folder(os.path.dirname(found[iid].path))

        tree.bind("<Double-1>", show_in_folder)
        ttk.Label(side, textvariable=summary, justify="left", wraplength=150).pack(fill="x", pady=(0, 8))
        ttk.Button(side, text="Select ✓ items", command=select_recommended).pack(fill="x", pady=2)
        ttk.Button(side, text="Select all", command=lambda: tree.selection_set(tree.get_children())).pack(fill="x", pady=2)
        move_btn = ttk.Button(side, text="Move selected\nto Review", command=move_selected, style="Accent.TButton")
        move_btn.pack(fill="x", pady=(10, 2))
        ttk.Button(side, text="Open location", command=show_in_folder).pack(fill="x", pady=(12, 2))
        ttk.Button(side, text="Stop", command=cancel.set).pack(fill="x", pady=2)

        def start():
            paths = [p.strip() for p in paths_var.get().split(";") if p.strip()]
            missing = [p for p in paths if not os.path.exists(os.path.expanduser(p))]
            if not paths or missing:
                messagebox.showwarning("SafeSweep", "Folder not found:\n" + "\n".join(missing) if missing
                                       else "Add at least one folder.")
                return
            settings.set_value(paths_attr, paths)
            settings.save()
            tree.delete(*tree.get_children())
            found.clear()
            cancel.clear()
            summary.set("")
            start_btn.state(["disabled"])
            stats: dict = {}

            def done(res, exc):
                start_btn.state(["!disabled"])
                if exc:
                    status.set(f"Error: {exc}")
                    return
                for i, f in enumerate(res):
                    iid = str(i)
                    found[iid] = f
                    tree.insert("", "end", iid=iid, tags=(f.severity,),
                                values=("✓" if f.recommended else "", f.severity, _human(f.size), f.reason, f.path))
                select_recommended()
                rec = [f for f in res if f.recommended]
                lines = [f"{stats.get('files', 0)} files checked", f"{len(res)} found ({_human(sum(f.size for f in res))})",
                         f"{len(rec)} ✓ recommended ({_human(sum(f.size for f in rec))})"]
                if "clamav" in stats:
                    lines.append(f"ClamAV: {stats['clamav']}")
                if stats.get("threat_lists"):
                    lines.append(f"{stats['threat_lists']:,} online threat-list fingerprints")
                refresh_feed_status()
                if stats.get("cancelled"):
                    lines.append("STOPPED - incomplete")
                summary.set("\n".join(lines))
                name = title.split(" ", 1)[-1]
                status.set(f"{name} finished." + (" Nothing found." if not res else
                           " ✓ items are pre-selected; others need a closer look."))

            def job():
                if before:
                    before(lambda m: events.put(("status", m)), cancel.is_set)
                return worker(settings, paths, lambda p: events.put(("status", f"Checking {p}")),
                              cancel.is_set, stats=stats)

            in_background(job, done)

        start_btn.configure(command=start)

    def update_lists_before_scan(progress, cancelled):
        from .feeds import maybe_update
        maybe_update(settings, progress, cancelled=cancelled)

    def feed_bar(frame):
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, textvariable=feed_status, foreground="#0b6e63").pack(side="left")
        btn = ttk.Button(bar, text="Update threat lists now")
        btn.pack(side="right")

        def update_now():
            btn.state(["disabled"])
            status.set("Downloading threat lists from verified sources (abuse.ch)…")

            def work():
                from .feeds import update_all
                return update_all(settings, lambda m: events.put(("status", m)))

            def done(lines, exc):
                btn.state(["!disabled"])
                refresh_feed_status()
                if exc:
                    messagebox.showerror("Threat lists", str(exc))
                    return
                status.set(feed_status.get())
                messagebox.showinfo("Threat lists", "\n".join(lines) or "Nothing to update.")

            in_background(work, done)

        btn.configure(command=update_now)
        ttk.Button(bar, text="abuse.ch key…", command=key_dialog).pack(side="right", padx=(0, 6))
        refresh_feed_status()

    def key_dialog():
        from . import feeds
        win = tk.Toplevel(root)
        win.title("abuse.ch Auth-Key")
        win.transient(root)
        win.resizable(False, False)
        body = ttk.Frame(win, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(body, wraplength=460, justify="left", text=(
            "With a free abuse.ch Auth-Key, SafeSweep also downloads the malware lists that "
            "abuse.ch updates every day (MalwareBazaar and ThreatFox), so it recognises "
            "threats discovered in the last few days.\n\n"
            "1. Click 'Get a free key' and sign in.\n2. Copy the Auth-Key from your profile page.\n"
            "3. Paste it below (Ctrl+V) and click 'Save and test'.")).pack(anchor="w")
        current = tk.StringVar()

        def show_current():
            k = settings.abusech_auth_key
            current.set(f"Saved key: {feeds.masked_key(k)}" if k else "No key saved yet.")

        show_current()
        ttk.Label(body, textvariable=current, foreground="#0b6e63").pack(anchor="w", pady=(10, 4))
        row = ttk.Frame(body)
        row.pack(fill="x")
        key_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=key_var, show="•", width=54)
        entry.pack(side="left", fill="x", expand=True)
        shown = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Show", variable=shown,
                        command=lambda: entry.configure(show="" if shown.get() else "•")).pack(side="left", padx=6)
        result = tk.StringVar()
        ttk.Label(body, textvariable=result, wraplength=460, justify="left").pack(anchor="w", pady=(8, 0))
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(12, 0))

        def open_signup():
            import webbrowser
            webbrowser.open(feeds.KEY_SIGNUP_URL)

        def save_and_test():
            try:
                feeds.save_auth_key(settings, key_var.get())
            except ValueError as e:
                result.set(str(e))
                return
            key_var.set("")
            show_current()
            save_btn.state(["disabled"])
            result.set("Saved. Checking the key with abuse.ch…")

            def done(res, exc):
                if not win.winfo_exists():
                    return
                save_btn.state(["!disabled"])
                refresh_feed_status()
                result.set(f"Error: {exc}" if exc else res[1])

            in_background(lambda: feeds.test_auth_key(settings, progress=lambda m: events.put(("status", m))), done)

        def remove():
            if settings.abusech_auth_key and messagebox.askyesno(
                    "Remove key?", "Remove the saved abuse.ch key? The daily-updated lists will stop updating.",
                    parent=win):
                feeds.remove_auth_key(settings)
                show_current()
                refresh_feed_status()
                result.set("Key removed.")

        ttk.Button(buttons, text="Get a free key", command=open_signup).pack(side="left")
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")
        ttk.Button(buttons, text="Remove key", command=remove).pack(side="right", padx=6)
        save_btn = ttk.Button(buttons, text="Save and test", style="Accent.TButton", command=save_and_test)
        save_btn.pack(side="right")
        entry.focus_set()
        win.bind("<Return>", lambda e: save_and_test())

    clam = clamav_available()
    results_tab("🛡 Virus Scan", scan, "scan_paths",
                "Checks for known malware (" + ("ClamAV + " if clam else "") + "daily-updated threat lists from abuse.ch), programs "
                "disguised as documents, fake/hidden extensions and dangerous scripts. Flagged items are moved to "
                "the Review folder and made non-executable." + ("" if clam else
                "  Tip: install the free ClamAV for full virus definitions."),
                before=lambda p, c: settings.threat_feeds_enabled and update_lists_before_scan(p, c),
                extra=feed_bar)
    results_tab("🧹 Cleanup", find_junk, "junk_paths",
                "Finds temporary files, old caches and logs, exact duplicates, empty files, old installers and "
                "downloads you haven't opened in a long time. Programs, projects and app data are never touched. "
                "✓ = safe to remove; the rest are suggestions. Nothing is deleted - items go to the Review folder.")

    # ---------- Review tab ----------
    rframe = ttk.Frame(nb, padding=8)
    nb.add(rframe, text="📂 Review Folder")
    ttk.Label(rframe, text="Items waiting for your decision. Restore puts a file back exactly where it was; "
              "Delete removes it permanently.", foreground="#555").pack(anchor="w", pady=(0, 6))
    rside = ttk.Frame(rframe, padding=(8, 0))
    rside.pack(side="right", fill="y")
    rcols = ("type", "size", "age", "reason", "original")
    rtree = ttk.Treeview(rframe, columns=rcols, show="headings", selectmode="extended")
    for c, w in zip(rcols, (60, 80, 60, 300, 440)):
        rtree.heading(c, text=c.capitalize())
        rtree.column(c, width=w, minwidth=30, anchor="w", stretch=c in ("reason", "original"))
    rtree.tag_configure("threat", foreground="#b00020")
    rsb = ttk.Scrollbar(rframe, orient="vertical", command=rtree.yview)
    rtree.configure(yscrollcommand=rsb.set)
    rsb.pack(side="right", fill="y")
    rtree.pack(side="left", fill="both", expand=True)
    total_var = tk.StringVar()
    by_id: dict = {}

    def refresh_review():
        rtree.delete(*rtree.get_children())
        by_id.clear()
        items = review.items()
        for it in items:
            by_id[it.id] = it
            rtree.insert("", "end", iid=it.id, tags=(it.category,),
                         values=(it.category, _human(it.size), f"{it.age_days:.0f}d", it.reason, it.original_path))
        total_var.set(f"{len(items)} item(s)\n{_human(sum(i.size for i in items))}")

    def do_restore():
        errors, restored = [], 0
        for iid in rtree.selection():
            item = by_id.get(iid)
            if not item:
                continue
            if item.category == "threat" and not messagebox.askyesno(
                    "Restore a flagged threat?", f"{item.original_path}\n\n{item.reason}\n\nRestore it anyway?"):
                continue
            try:
                review.restore(iid)
                restored += 1
            except (ReviewError, OSError) as e:
                errors.append(f"{item.original_path}: {e}")
        refresh_review()
        status.set(f"Restored {restored} item(s).")
        if errors:
            messagebox.showwarning("Some items could not be restored", "\n".join(errors[:15]))

    def do_delete(all_items=False):
        ids = rtree.get_children() if all_items else rtree.selection()
        if not ids:
            return
        size = sum(by_id[i].size for i in ids if i in by_id)
        if not messagebox.askyesno("Delete permanently?",
                                   f"Permanently delete {len(ids)} item(s) ({_human(size)})?\nThis cannot be undone."):
            return
        status.set(f"Deleting {len(ids)} item(s)…")

        def done(res, exc):
            refresh_review()
            if exc:
                messagebox.showerror("Nothing was deleted", str(exc))
                status.set("Nothing was deleted.")
                return
            deleted, freed, errors = res
            status.set(f"Deleted {deleted} item(s), freed {_human(freed)}.")
            if errors:
                messagebox.showwarning(f"{len(errors)} item(s) could not be deleted", "\n".join(errors[:15]))

        in_background(lambda: review.delete_many(list(ids)), done)

    def purge_expired():
        days = settings.review_retention_days
        if messagebox.askyesno("Delete old items?", f"Permanently delete items that have been in review for {days}+ days?"):
            def done(res, exc):
                refresh_review()
                if exc:
                    messagebox.showerror("Could not delete old items", str(exc))
                    return
                status.set(f"Deleted {res[0]} expired item(s), freed {_human(res[1])}.")

            in_background(lambda: review.purge(days), done)

    folder_var = tk.StringVar(value=f"Folder: {review.files.parent}")
    floc = ttk.Frame(rframe)
    floc.pack(side="top", fill="x", pady=(0, 6), before=rside)
    ttk.Label(floc, textvariable=folder_var, foreground="#555").pack(side="left")

    def change_folder():
        d = filedialog.askdirectory(title="Where should the Review folder be?")
        if not d:
            return
        try:
            target = settings.check_review_location(d)
        except ValueError as e:
            messagebox.showwarning("SafeSweep", str(e))
            return
        n = len(review.items())
        if not messagebox.askyesno("Move the Review folder?",
                                   f"The Review folder will be:\n{target}\n\n{n} item(s) waiting there will be copied, "
                                   "checked, and only then removed from the old place. Continue?"):
            return
        status.set("Moving the Review folder…")

        def done(res, exc):
            if exc:
                messagebox.showerror("Could not move the Review folder", f"{exc}\n\nNothing was changed.")
                status.set("Review folder unchanged.")
                return
            folder_var.set(f"Folder: {res[1]}")
            refresh_review()
            status.set(f"Review folder moved to {res[1]} ({res[0]} item(s), all verified).")

        in_background(lambda: review.relocate(d), done)

    ttk.Button(floc, text="Change folder…", command=change_folder).pack(side="right", before=floc.winfo_children()[0])
    ttk.Label(rside, textvariable=total_var, justify="center").pack(pady=(0, 8))
    ttk.Button(rside, text="Restore", command=do_restore).pack(fill="x", pady=2)
    ttk.Button(rside, text="Delete selected", command=do_delete).pack(fill="x", pady=2)
    ttk.Button(rside, text="Delete ALL", command=lambda: do_delete(True)).pack(fill="x", pady=2)
    ttk.Button(rside, text=f"Delete items\nolder than {settings.review_retention_days}d",
               command=purge_expired).pack(fill="x", pady=2)
    ttk.Button(rside, text="Open folder", command=lambda: _open_folder(str(review.files))).pack(fill="x", pady=(12, 2))
    ttk.Button(rside, text="Refresh", command=refresh_review).pack(fill="x", pady=2)
    refresh_review()

    # ---------- menu: self-test ----------
    def selftest():
        win = tk.Toplevel(root)
        win.title("SafeSweep self-test")
        win.geometry("760x520")
        txt = scrolledtext.ScrolledText(win, font=("TkFixedFont", 9))
        txt.pack(fill="both", expand=True)

        def out(line):
            events.put(("call", lambda: (txt.insert("end", line + "\n"), txt.see("end"))))

        def work():
            from .selftest import run_selftest
            return run_selftest(out)

        def done(res, exc):
            if exc:
                out(f"Self-test crashed: {exc}")
            else:
                status.set("Self-test passed - everything works on this device." if res[0]
                           else f"Self-test: {len(res[1])} check(s) FAILED - see the report.")

        in_background(work, done)

    menubar = tk.Menu(root)
    automenu = tk.Menu(menubar, tearoff=0)
    auto_on = tk.BooleanVar(value=False)

    def load_auto_state():
        from . import schedule
        try:
            auto_on.set(schedule.status().startswith("on"))
        except Exception:
            auto_on.set(False)

    def toggle_auto():
        from . import schedule
        want = auto_on.get()
        try:
            msg = schedule.enable(settings.auto_check_time) if want else "turned off (" + schedule.disable() + ")"
            status.set(f"Daily automatic check: {msg}")
            if want:
                messagebox.showinfo("Daily automatic check",
                                    f"SafeSweep will check for threats every day at {settings.auto_check_time} "
                                    "(or as soon as the PC is on, if it was off), without asking.\n\n"
                                    "Confirmed threats are moved to the Review folder - nothing is deleted. "
                                    "You get a notification only when something is found.")
        except Exception as e:
            auto_on.set(not want)
            messagebox.showerror("Daily automatic check", str(e))

    def run_auto_now():
        status.set("Running the automatic check…")

        def work():
            from .auto import run_auto
            return run_auto(settings, lambda m: events.put(("status", m)))

        def done(res, exc):
            refresh_review()
            if exc:
                messagebox.showerror("Automatic check", str(exc))
                return
            status.set(res.headline())
            messagebox.showinfo("Automatic check", res.headline() + "\n\n" + res.details())

        in_background(work, done)

    automenu.add_checkbutton(label="Check for threats automatically every day", variable=auto_on,
                             command=toggle_auto)
    automenu.add_command(label="Run the automatic check now", command=run_auto_now)
    automenu.add_command(label="Open reports", command=lambda: _open_folder(str(_reports_dir())))
    menubar.add_cascade(label="Automatic", menu=automenu)
    load_auto_state()
    helpmenu = tk.Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Run self-test (checks SafeSweep works correctly here)", command=selftest)
    helpmenu.add_command(label="Open activity log", command=lambda: _open_folder(str(_reports_dir().parent)))
    menubar.add_cascade(label="Help", menu=helpmenu)
    root.config(menu=menubar)

    def on_close():
        if busy["n"] and not messagebox.askyesno("SafeSweep is busy",
                                                 "A task is still running. Quit anyway? (Files being moved are "
                                                 "repaired automatically next time.)"):
            return
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    # ---------- event pump ----------
    def pump():
        try:
            for _ in range(500):
                kind, payload = events.get_nowait()
                if kind == "status":
                    status.set(payload[-150:])
                elif kind == "call":
                    payload()
        except queue.Empty:
            pass
        root.after(80, pump)

    pump()
    root.mainloop()
    return 0
