"""The automatic daily check - runs on a schedule without asking anything.

Each run:
  1. refreshes the online threat lists (verified sources only),
  2. scans your scan folders - quickly, re-reading only new/changed files;
     once a week everything is re-read ("deep" check),
  3. moves *confirmed, high-confidence* threats into the Review folder
     (reversible - nothing is ever deleted automatically; junk is never touched),
  4. writes a report and notifies you only when something needs your attention.

Daily, because abuse.ch's "recent" lists only cover the last 48 hours.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .config import Settings, app_home

DAY = 86400.0
DEEP_EVERY_DAYS = 7
KEEP_REPORTS = 60


@dataclass
class AutoResult:
    started: float
    finished: float = 0.0
    deep: bool = False
    files: int = 0
    changed: int = 0
    found: list = field(default_factory=list)       # findings left for you to look at
    moved: list = field(default_factory=list)       # threats moved to Review automatically
    move_errors: list = field(default_factory=list)
    feed_lines: list = field(default_factory=list)
    feed_status: str = ""
    skipped: str = ""                               # reason the run didn't happen
    report_path: str = ""

    @property
    def needs_attention(self) -> bool:
        return bool(self.moved or self.found or self.move_errors)

    def headline(self) -> str:
        if self.skipped:
            return f"Automatic check skipped: {self.skipped}"
        if self.moved:
            n = len(self.moved)
            return f"SafeSweep moved {n} threat{'s' if n > 1 else ''} to the Review folder"
        if self.found:
            return f"SafeSweep found {len(self.found)} item(s) worth a look"
        return "SafeSweep: no threats found"

    def details(self) -> str:
        parts = []
        for f in self.moved[:3]:
            parts.append(f"{os.path.basename(f.path)} - {f.reason}")
        for f in self.found[:3 - min(3, len(self.moved))]:
            parts.append(f"{os.path.basename(f.path)} - {f.reason}")
        more = len(self.moved) + len(self.found) - len(parts)
        if more > 0:
            parts.append(f"and {more} more")
        if not parts:
            parts.append(f"{self.files:,} files checked" + (" (weekly deep check)" if self.deep else ""))
        return "\n".join(parts)


def _state_path() -> Path:
    return app_home() / "auto-state.json"


def read_state() -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(state: dict) -> None:
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
    os.replace(tmp, p)


@contextlib.contextmanager
def _run_lock(max_age: float = 6 * 3600):
    lock = app_home() / "auto.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            if time.time() - lock.stat().st_mtime < max_age:
                yield False
                return
            lock.unlink()
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except OSError:
            yield False
            return
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        yield True
    finally:
        with contextlib.suppress(OSError):
            lock.unlink()


def status_text(now: Optional[float] = None) -> str:
    st = read_state()
    if not st.get("last_run"):
        return "Automatic check: hasn't run yet"
    now = time.time() if now is None else now
    age = now - st["last_run"]
    when = "less than an hour ago" if age < 3600 else f"{age / 3600:.0f} h ago" if age < 2 * DAY \
        else f"{age / DAY:.0f} days ago"
    return f"Automatic check: last run {when} - {st.get('summary', '')}"


def run_auto(settings: Optional[Settings] = None, progress: Optional[Callable[[str], None]] = None,
             now: Optional[float] = None, deep: Optional[bool] = None,
             update_lists: bool = True) -> AutoResult:
    from .feeds import maybe_update, status_text as feed_status
    from .review import ReviewError, ReviewFolder
    from .scanner import load_hash_cache, save_hash_cache, scan

    settings = settings or Settings.load()
    now = time.time() if now is None else now
    res = AutoResult(started=now)
    with _run_lock() as got:
        if not got:
            res.skipped = "another check is already running"
            return res
        state = read_state()
        if deep is None:
            deep = now - state.get("last_deep", 0) >= DEEP_EVERY_DAYS * DAY
        res.deep = deep

        if update_lists and settings.threat_feeds_enabled:
            try:
                res.feed_lines = maybe_update(settings, progress)
            except Exception as e:  # never let the internet stop the scan
                res.feed_lines = [f"threat list update failed: {e}"]
        res.feed_status = feed_status(settings)

        paths = [p for p in settings.scan_paths if os.path.exists(os.path.expanduser(p))]
        if not paths:
            res.skipped = "none of the scan folders exist"
        else:
            cache = {} if deep else load_hash_cache()
            stats: dict = {}
            findings = scan(settings, paths, progress, stats=stats, cache=cache, clamav_changed_only=not deep)
            save_hash_cache(cache)
            res.files, res.changed = stats.get("files", 0), stats.get("changed", 0)
            auto_move = [f for f in findings if f.category == "threat" and f.severity == "high" and f.recommended]
            res.found = [f for f in findings if f not in auto_move and f.severity in ("high", "medium")]
            if settings.auto_quarantine and auto_move:
                rf = ReviewFolder(settings)
                for f in auto_move:
                    try:
                        rf.move_in(f)
                        res.moved.append(f)
                    except (ReviewError, OSError) as e:
                        res.move_errors.append(f"{f.path}: {e}")
                        res.found.append(f)
            else:
                res.found = auto_move + res.found

        res.finished = time.time()
        summary = ("skipped - " + res.skipped) if res.skipped else (
            f"{len(res.moved)} moved to Review, {len(res.found)} to look at" if res.needs_attention
            else "no threats found")
        state.update({"last_run": now, "summary": summary, "last_files": res.files})
        if deep and not res.skipped:
            state["last_deep"] = now
        _write_state(state)
        res.report_path = _write_report(res)
    return res


def _write_report(res: AutoResult) -> str:
    d = app_home() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d_%H%M%S", time.localtime(res.started))
    p = d / f"auto-check_{stamp}.txt"
    lines = [f"SafeSweep automatic check - {time.strftime('%Y-%m-%d %H:%M', time.localtime(res.started))}",
             res.headline(), ""]
    if not res.skipped:
        lines.append(f"{'Deep (weekly) check' if res.deep else 'Quick daily check'}: {res.files:,} files, "
                     f"{res.changed:,} new or changed, {res.finished - res.started:.0f} s")
    lines += [res.feed_status, *[f"  {l}" for l in res.feed_lines], ""]
    if res.moved:
        lines.append("Moved to the Review folder (restore them from there if they are yours):")
        lines += [f"  {f.path}\n      {f.reason}" for f in res.moved]
    if res.found:
        lines.append("Worth a look (not moved):")
        lines += [f"  [{f.severity}] {f.path}\n      {f.reason}" for f in res.found]
    if res.move_errors:
        lines.append("Could not move:")
        lines += [f"  {e}" for e in res.move_errors]
    try:
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        for old in sorted(d.glob("auto-check_*.txt"))[:-KEEP_REPORTS]:
            old.unlink()
    except OSError:
        return ""
    return str(p)
