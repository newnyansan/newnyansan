"""Command-line interface (works on PC and on Android via Termux)."""

from __future__ import annotations

import argparse
import sys
from dataclasses import asdict

from . import __version__
from .config import Settings
from .junk import find_junk
from .models import Finding
from .review import ReviewError, ReviewFolder
from .scanner import scan


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""


def _print_findings(findings: list[Finding], stats: dict) -> None:
    for i, f in enumerate(findings, 1):
        star = "*" if f.recommended else " "
        print(f"[{i:>3}]{star} {f.severity.upper():6} {human(f.size):>9}  {f.path}\n         -> {f.reason}")
    rec = [f for f in findings if f.recommended]
    print(f"\nChecked {stats.get('files', 0)} file(s)"
          + (f", skipped {stats['skipped']} unreadable/protected item(s)" if stats.get("skipped") else "")
          + (f", ClamAV: {stats['clamav']}" if "clamav" in stats else "") + ".")
    if stats.get("cancelled"):
        print("Scan was stopped early - results are incomplete.")
    if not findings:
        print("Nothing found.")
        return
    print(f"{len(findings)} item(s), {human(sum(f.size for f in findings))} total. "
          f"{len(rec)} marked * are recommended ({human(sum(f.size for f in rec))}).")


def _parse_selection(ans: str, n: int) -> list[int] | None:
    chosen: set[int] = set()
    for part in ans.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if not (a.isdigit() and b.isdigit()):
                return None
            chosen.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            chosen.add(int(part))
        else:
            return None
    if any(not 1 <= i <= n for i in chosen):
        return None
    return sorted(chosen)


def _choose(findings: list[Finding], auto_yes: bool, move_all: bool) -> list[Finding]:
    if auto_yes:
        return findings if move_all else [f for f in findings if f.recommended]
    while True:
        ans = _ask("\nMove to the Review folder? [r]ecommended (*) / [a]ll / numbers e.g. 1,3-5 / [n]one: ")
        ans = ans.strip().lower()
        if ans in ("", "n", "none", "q"):
            return []
        if ans in ("r", "rec", "recommended"):
            return [f for f in findings if f.recommended]
        if ans in ("a", "all"):
            return findings
        sel = _parse_selection(ans, len(findings))
        if sel is not None:
            return [findings[i - 1] for i in sel]
        print(f"Please type r, a, n, or numbers between 1 and {len(findings)}.")


def _move(findings: list[Finding], settings: Settings) -> int:
    if not findings:
        print("Nothing moved.")
        return 0
    rf = ReviewFolder(settings)
    moved = 0
    for f in findings:
        try:
            rf.move_in(f)
            moved += 1
        except (ReviewError, OSError) as e:
            print(f"  skipped {f.path}: {e}")
    print(f"Moved {moved} item(s) to the Review folder: {rf.root}")
    print("Nothing has been deleted. Check them with `safesweep review list`, then `restore` or `delete`.")
    return moved


def _progress(verbose: bool):
    return (lambda p: print(f"  {p}", file=sys.stderr)) if verbose else None


def cmd_scan(args, settings: Settings) -> int:
    stats: dict = {}
    findings = scan(settings, args.paths or None, _progress(args.verbose), stats=stats)
    _print_findings(findings, stats)
    if findings and not args.report_only:
        _move(_choose(findings, args.yes, args.all), settings)
    return 1 if any(f.severity in ("high", "medium") for f in findings) else 0


def cmd_clean(args, settings: Settings) -> int:
    stats: dict = {}
    findings = find_junk(settings, args.paths or None, _progress(args.verbose), stats=stats)
    _print_findings(findings, stats)
    if findings and not args.report_only:
        _move(_choose(findings, args.yes, args.all), settings)
    return 0


def cmd_review(args, settings: Settings) -> int:
    rf = ReviewFolder(settings)
    try:
        if args.action == "list":
            items = rf.items()
            if not items:
                print("Review folder is empty.")
            for it in items:
                print(f"{it.id}  {it.category:6} {human(it.size):>9}  {it.age_days:5.1f}d  {it.original_path}\n"
                      f"              -> {it.reason}")
            print(f"\n{len(items)} item(s), {human(sum(i.size for i in items))}. Folder: {rf.files}")
        elif args.action in ("restore", "delete"):
            if not args.ids:
                print("Give one or more ids (see `safesweep review list`).")
                return 2
            if args.action == "delete" and not args.yes and \
                    _ask(f"Permanently delete {len(args.ids)} item(s)? This cannot be undone. [y/N] ").lower() != "y":
                return 0
            for i in args.ids:
                if args.action == "restore":
                    print(f"Restored to {rf.restore(i)}")
                else:
                    print(f"Deleted {i} ({human(rf.delete(i))} freed)")
        elif args.action == "purge":
            days = settings.review_retention_days if args.expired else None
            what = f"items older than {days} days" if days else "ALL items"
            if not args.yes and _ask(f"Permanently delete {what} in the Review folder? [y/N] ").lower() != "y":
                return 0
            n, freed = rf.purge(days)
            print(f"Permanently deleted {n} item(s), {human(freed)} freed.")
    except (ReviewError, OSError, KeyError) as e:
        print(f"Error: {e}")
        return 2
    return 0


def cmd_settings(args, settings: Settings) -> int:
    if args.set:
        for kv in args.set:
            key, sep, val = kv.partition("=")
            if not sep:
                print(f"Use KEY=VALUE, got {kv!r}")
                return 2
            try:
                settings.set_value(key.strip(), val)
            except (KeyError, ValueError) as e:
                print(f"Error: {e}")
                return 2
        settings.save()
    for k, v in asdict(settings).items():
        print(f"{k} = {v}")
    print(f"\nsettings file: {Settings.path()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="safesweep",
                                description="Virus scanner + junk cleaner. Everything goes to a Review folder first.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")

    for name, helptext in (("scan", "scan for viruses / suspicious files"),
                           ("clean", "find files that are no longer needed")):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("paths", nargs="*", help="folders or files to check (default: from settings)")
        sp.add_argument("-y", "--yes", action="store_true", help="move the recommended (*) items without asking")
        sp.add_argument("--all", action="store_true", help="with --yes: move every item found, not just recommended")
        sp.add_argument("--report-only", action="store_true", help="only list, don't move anything")
        sp.add_argument("-v", "--verbose", action="store_true")

    rv = sub.add_parser("review", help="manage the Review folder")
    rv.add_argument("action", choices=["list", "restore", "delete", "purge"])
    rv.add_argument("ids", nargs="*")
    rv.add_argument("--expired", action="store_true", help="purge only items past review_retention_days")
    rv.add_argument("-y", "--yes", action="store_true")

    st = sub.add_parser("settings", help="show or change settings")
    st.add_argument("--set", nargs="+", metavar="KEY=VALUE", help="lists use ';' as separator")

    sg = sub.add_parser("signatures", help="add SHA-256 malware hashes from a file")
    sg.add_argument("action", choices=["add"])
    sg.add_argument("file")

    sub.add_parser("selftest", help="check that detection and the Review folder work correctly on this device")
    sub.add_parser("gui", help="open the desktop window")

    for stream in (sys.stdout, sys.stderr):  # odd filenames must never crash printing
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = p.parse_args(argv)
    if args.command is None or args.command == "gui":
        from .gui import run
        return run()
    if args.command == "selftest":
        from .selftest import run_selftest
        ok, _ = run_selftest(print)
        return 0 if ok else 1
    settings = Settings.load()
    if args.command == "signatures":
        from .scanner import add_signatures
        try:
            print(f"Added {add_signatures(args.file)} signature(s).")
        except OSError as e:
            print(f"Error: {e}")
            return 2
        return 0
    return {"scan": cmd_scan, "clean": cmd_clean, "review": cmd_review,
            "settings": cmd_settings}[args.command](args, settings)


if __name__ == "__main__":
    sys.exit(main())
