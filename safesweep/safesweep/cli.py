"""Command-line interface (works on PC and on Android via Termux)."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import Settings
from .junk import find_junk
from .models import Finding
from .review import ReviewFolder
from .scanner import add_signatures, clamav_available, scan


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("Nothing found.")
        return
    for i, f in enumerate(findings, 1):
        print(f"[{i:>3}] {f.severity.upper():6} {human(f.size):>9}  {f.path}\n        -> {f.reason}")
    print(f"\n{len(findings)} item(s), {human(sum(f.size for f in findings))} total.")


def _choose(findings: list[Finding], auto_yes: bool) -> list[Finding]:
    if auto_yes:
        return findings
    ans = input("\nMove which items to the Review folder? [a]ll / numbers e.g. 1,3-5 / [n]one: ").strip().lower()
    if ans in ("a", "all"):
        return findings
    if ans in ("", "n", "none"):
        return []
    chosen: set[int] = set()
    for part in ans.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            chosen.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            chosen.add(int(part))
    return [findings[i - 1] for i in sorted(chosen) if 1 <= i <= len(findings)]


def _move(findings: list[Finding], settings: Settings) -> None:
    rf = ReviewFolder(settings)
    moved = 0
    for f in findings:
        try:
            rf.move_in(f)
            moved += 1
        except OSError as e:
            print(f"  ! could not move {f.path}: {e}")
    print(f"Moved {moved} item(s) to the Review folder: {rf.root}")
    print("Check them with `safesweep review list`, then `restore` or `delete`.")


def cmd_scan(args, settings: Settings) -> int:
    if settings.use_clamav and not clamav_available():
        print("Note: ClamAV not found - using built-in signatures + heuristics only.")
    progress = (lambda p: print(f"  scanning {p}", file=sys.stderr)) if args.verbose else None
    findings = scan(settings, args.paths or None, progress)
    _print_findings(findings)
    if findings and not args.report_only:
        _move(_choose(findings, args.yes), settings)
    return 1 if findings else 0


def cmd_clean(args, settings: Settings) -> int:
    progress = (lambda p: print(f"  checking {p}", file=sys.stderr)) if args.verbose else None
    findings = find_junk(settings, args.paths or None, progress)
    _print_findings(findings)
    if findings and not args.report_only:
        _move(_choose(findings, args.yes), settings)
    return 0


def cmd_review(args, settings: Settings) -> int:
    rf = ReviewFolder(settings)
    if args.action == "list":
        items = rf.items()
        if not items:
            print("Review folder is empty.")
        for it in items:
            print(f"{it.id}  {it.category:6} {human(it.size):>9}  {it.age_days:5.1f}d  {it.original_path}\n"
                  f"              -> {it.reason}")
        print(f"\nFolder: {rf.root}")
    elif args.action == "restore":
        for i in args.ids:
            print(f"Restored to {rf.restore(i)}")
    elif args.action == "delete":
        for i in args.ids:
            print(f"Deleted {i} ({human(rf.delete(i))} freed)")
    elif args.action == "purge":
        if not args.yes and input("Permanently delete items from the Review folder? [y/N] ").lower() != "y":
            return 0
        n, freed = rf.purge(settings.review_retention_days if args.expired else None)
        print(f"Permanently deleted {n} item(s), {human(freed)} freed.")
    return 0


def cmd_settings(args, settings: Settings) -> int:
    if args.set:
        for kv in args.set:
            key, _, val = kv.partition("=")
            cur = getattr(settings, key)
            if isinstance(cur, bool):
                setattr(settings, key, val.lower() in ("1", "true", "yes", "on"))
            elif isinstance(cur, int):
                setattr(settings, key, int(val))
            elif isinstance(cur, list):
                setattr(settings, key, [v for v in val.split(";") if v])
            else:
                setattr(settings, key, val)
        settings.save()
    from dataclasses import asdict
    for k, v in asdict(settings).items():
        print(f"{k} = {v}")
    print(f"\nsettings file: {Settings.path()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="safesweep", description="Virus scanner + junk cleaner with a Review folder.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")

    for name, helptext in (("scan", "scan for viruses / suspicious files"),
                           ("clean", "find files that are no longer needed")):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("paths", nargs="*", help="folders to check (default: from settings)")
        sp.add_argument("-y", "--yes", action="store_true", help="move everything found without asking")
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

    sub.add_parser("gui", help="open the desktop window")

    args = p.parse_args(argv)
    settings = Settings.load()
    if args.command is None or args.command == "gui":
        from .gui import run
        return run()
    if args.command == "signatures":
        print(f"Added {add_signatures(args.file)} signature(s).")
        return 0
    return {"scan": cmd_scan, "clean": cmd_clean, "review": cmd_review,
            "settings": cmd_settings}[args.command](args, settings)


if __name__ == "__main__":
    sys.exit(main())
