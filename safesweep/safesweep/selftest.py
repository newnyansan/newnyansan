"""Built-in self-test: proves detection and the Review folder work on *this* device.

It builds a throw-away sandbox with
  * real threat patterns that MUST be caught,
  * harmless look-alikes that must NOT be flagged (false-positive traps),
  * junk that must be found, and important files that must be left alone,
then checks every verdict and exercises the Review folder, including crash recovery.
Nothing outside the sandbox is touched.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Callable

DAY = 86400.0


def _pe_bytes() -> bytes:
    """A minimal byte layout of a Windows .exe header (not a working program)."""
    head = bytearray(b"MZ" + b"\0" * 0x3A + (0x40).to_bytes(4, "little"))
    head += b"PE\0\0" + b"\0" * 200
    return bytes(head)


class _Checker:
    def __init__(self, out: Callable[[str], None]):
        self.out = out
        self.failures: list[str] = []
        self.count = 0

    def check(self, name: str, cond: bool, detail: str = "") -> None:
        self.count += 1
        if cond:
            self.out(f"  PASS  {name}")
        else:
            self.failures.append(name)
            self.out(f"  FAIL  {name}" + (f"  ({detail})" if detail else ""))


def run_selftest(out: Callable[[str], None] = print, keep: bool = False) -> tuple[bool, list[str]]:
    from .config import Settings
    user_settings = Settings.load()  # only used for the ClamAV options
    from .config import is_protected
    base = None if not is_protected(tempfile.gettempdir()) else str(Path.home())
    sandbox = Path(tempfile.mkdtemp(prefix="safesweep-selftest-", dir=base))
    old_home = os.environ.get("SAFESWEEP_HOME")
    os.environ["SAFESWEEP_HOME"] = str(sandbox / "app")
    c = _Checker(out)
    try:
        settings = Settings(scan_paths=[], junk_paths=[], use_clamav=False, large_file_mb=1)
        _threat_tests(c, sandbox / "scan", settings)
        _junk_tests(c, sandbox / "junk", settings)
        _feed_tests(c, sandbox / "feeds", settings)
        _review_tests(c, sandbox / "review", settings)
        _clamav_info(c, sandbox / "clam", out, user_settings)
    except Exception as e:  # a crash is a failure, not a traceback for the user
        import traceback
        c.check(f"self-test ran without crashing: {e!r}", False, traceback.format_exc(limit=3))
    finally:
        from .feeds import ThreatLists
        ThreatLists.reset()  # release list files so the sandbox can be removed (Windows)
        if old_home is None:
            os.environ.pop("SAFESWEEP_HOME", None)
        else:
            os.environ["SAFESWEEP_HOME"] = old_home
        if not keep:
            shutil.rmtree(sandbox, ignore_errors=True)
    ok = not c.failures
    out(f"\n{c.count - len(c.failures)}/{c.count} checks passed." + ("" if ok else f"  FAILED: {len(c.failures)}"))
    return ok, c.failures


# --------------------------------------------------------------------------- threats
def _threat_tests(c: _Checker, root: Path, settings) -> None:
    from .scanner import EICAR, add_signatures, scan
    c.out("Virus scanner - must detect:")
    root.mkdir(parents=True)
    w = lambda rel, data: (root / rel).parent.mkdir(parents=True, exist_ok=True) or (root / rel).write_bytes(data)

    ps = b"power" + b"shell"
    bad = {
        "eicar.com": EICAR,
        "eicar-with-newline.txt": EICAR + b"\r\n",
        "Invoice_2024.pdf.exe": _pe_bytes(),
        "photo.JPG.scr": b"anything",
        "contract.docx          .exe": b"x",
        "song‮gpj.exe": b"x",
        "holiday.jpg": _pe_bytes(),                         # program disguised as a photo
        "track.mp3": b"\x7fELF\x02\x01\x01" + b"\0" * 40,   # Linux program disguised as music
        "update.ps1": ps + b" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "fix.bat": b"@echo off\r\nvssadmin delete shadows /all /quiet\r\n",
        "known-bad.bin": b"pretend this is a known malware sample 42",
    }
    for rel, data in bad.items():
        w(rel, data)
    import hashlib
    sigfile = root.parent / "sigs.txt"
    sigfile.write_text(hashlib.sha256(bad["known-bad.bin"]).hexdigest() + "  Test.KnownBad\n")
    add_signatures(str(sigfile))

    good = {
        "readme.txt": b"MZ is the postal code prefix for... not a program. " * 4,
        "report.final.pdf": b"%PDF-1.4 normal document",
        "jquery.min.js": b"/*! jQuery */ (function(){})();",
        "install.sh": b"#!/bin/sh\ncurl -fsSL https://example.org/install.sh | sh\n",
        "Recent/budget.xlsx.lnk": b"L\0\0\0 shortcut",
        "notes.py": b"print('powershell is a shell')\n",
        "big.txt": b"hello " + EICAR + b" this is a document that merely quotes the test string",
        "family.jpg": b"\xff\xd8\xff\xe0 real jpeg data",
        "archive.tar.gz": b"\x1f\x8b normal",
    }
    for rel, data in good.items():
        w(rel, data)
    w("budget.xlsm", b"PK macro workbook")

    stats: dict = {}
    res = {Path(f.path).name: f for f in scan(settings, [str(root)], stats=stats)}
    for name in bad:
        f = res.get(Path(name).name)
        c.check(f"detects {name!r}", bool(f and f.severity == "high" and f.recommended),
                f"got {f.severity + ': ' + f.reason if f else 'nothing'}")
    c.out("Virus scanner - must NOT flag harmless look-alikes:")
    for name in good:
        f = res.get(Path(name).name)
        if name == "install.sh":
            c.check("install script with 'curl | sh' is only a low, unselected hint",
                    bool(f and f.severity == "low" and not f.recommended), f.reason if f else "")
        else:
            c.check(f"ignores {name!r}", f is None, f.reason if f else "")
    f = res.get("budget.xlsm")
    c.check("macro workbook is informational only (not pre-selected)", bool(f and not f.recommended))
    c.check("scanner counted all files", stats.get("files", 0) == len(bad) + len(good) + 1, str(stats))


# --------------------------------------------------------------------------- junk
def _junk_tests(c: _Checker, root: Path, settings) -> None:
    from .junk import find_junk
    c.out("Cleaner - finds junk:")
    future = time.time() + 400 * DAY  # simulate 400 days passing instead of faking file dates

    def w(rel, data=b"x", fresh=False):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if fresh:  # changed "1 hour ago" in the simulated future
            os.utime(p, (future - 3600, future - 3600))
        return p

    photo = os.urandom(150 * 1024)
    user = "home"
    w(f"{user}/Downloads/old.tmp")
    w(f"{user}/Downloads/Thumbs.db")
    w(f"{user}/Documents/~$report.docx", b"owner file")
    w(f"{user}/Downloads/broken.jpg", b"")
    keeper = w(f"{user}/Pictures/beach.jpg", photo)
    w(f"{user}/Downloads/beach (1).jpg", photo)
    w(f"{user}/Downloads/manual.pdf", b"old download")
    w(f"{user}/Downloads/requirements.txt", b"stray file must not hide Downloads")
    w(f"{user}/Downloads/setup.exe", b"installer")
    w(f"{user}/Documents/thesis.docx.bak", b"backup")
    w(f"{user}/Videos/movie.mkv", os.urandom(1024 * 1024 + 1000))
    w(f"{user}/DCIM/.thumbnails/123.jpg", b"thumb")
    must = {
        "old.tmp": True, "Thumbs.db": True, "~$report.docx": True, "broken.jpg": True,
        "beach (1).jpg": True, "manual.pdf": False, "setup.exe": False, "thesis.docx.bak": False,
        "movie.mkv": False, "123.jpg": True, "requirements.txt": False,
    }
    # --- false-positive traps (must NOT be flagged)
    w(f"{user}/Downloads/new.part", b"downloading right now", fresh=True)
    w(f"{user}/Downloads/fresh.tmp", b"in use", fresh=True)
    w(f"{user}/Downloads/new-photo.jpg", b"just downloaded", fresh=True)
    w(f"{user}/Code/app/.git/HEAD", b"ref")
    w(f"{user}/Code/app/build.tmp", b"x")
    w(f"{user}/Code/app/__init__.py", b"")
    w(f"{user}/Code/app/a.png", photo)
    w(f"{user}/Code/app/b.png", photo)
    w(f"{user}/Downloads/tool/requirements.txt", b"flask")
    w(f"{user}/Downloads/tool/app.py", b"import flask")
    w(f"{user}/Downloads/portable-app/manifest.json", b"{}")
    w(f"{user}/Downloads/portable-app/app.exe", b"MZ")
    w(f"{user}/Downloads/portable-app/lib.dll", b"MZ")
    w(f"{user}/Downloads/game/Game.sln", b"solution")
    w(f"{user}/Downloads/game/old.tmp", b"x")
    w(f"{user}/Downloads/firefox/freebl3.chk", b"crypto checksum")
    w(f"{user}/Downloads/firefox/freebl3.dll", b"MZ")
    w(f"{user}/Downloads/firefox/update.tmp", b"x")
    w(f"{user}/Documents/scripts/__pycache__/tool.cpython-312.pyc", b"x")
    w(f"{user}/Documents/scripts/tool.py", b"print(1)")
    w(f"{user}/Downloads/tool/data.zip", b"project data")
    w(f"{user}/Downloads/node_modules/x/logo.png", photo)
    w(f"{user}/Pictures/Photos Library.photoslibrary/originals/beach.jpg", photo)
    w(f"{user}/.config/app/settings.ini", b"")
    w(f"{user}/AppData/Local/App/cache.png", photo)
    w(f"{user}/Documents/__init__.py", b"")
    w(f"{user}/Documents/.nomedia", b"")
    w(f"{user}/Documents/LOCK", b"")
    w(f"{user}/Documents/a.txt", b"same small text")
    w(f"{user}/Documents/b.txt", b"same small text")
    w(f"{user}/Documents/x.py", photo)
    w(f"{user}/Documents/y.py", photo)
    w(f"{user}/Documents/Thumbnails/my-design.png", b"my own work")
    w(f"{user}/Documents/downloader/notes.pdf", b"not in a Downloads folder")
    w(f"{user}/Documents/desktop.ini", b"[.ShellClassInfo]")
    linked = w(f"{user}/Music/song.mp3", os.urandom(150 * 1024))
    with contextlib.suppress(OSError):
        os.link(linked, root / user / "Music" / "song-hardlink.mp3")
    with contextlib.suppress(OSError, NotImplementedError):
        os.symlink(keeper, root / user / "Documents" / "beach-link.jpg")
    with contextlib.suppress(OSError, NotImplementedError):
        os.symlink(root / user, root / user / "Documents" / "loop")  # must not loop forever

    res = {Path(f.path).name: f for f in find_junk(settings, [str(root / user)], now=future, kind="user")}
    for name, rec in must.items():
        f = res.get(name)
        label = "flags" + (" + recommends" if rec else " (not pre-selected)")
        c.check(f"{label} {name!r}", bool(f and f.recommended == rec),
                f"got {(f.reason + (' [recommended]' if f.recommended else '')) if f else 'nothing'}")
    dup = res.get("beach (1).jpg")
    c.check("duplicate keeps the copy outside Downloads", bool(dup and dup.extra.get("duplicate_of") == str(keeper)),
            dup.extra.get("duplicate_of", "") if dup else "")
    c.out("Cleaner - must NOT flag important files:")
    allowed = set(must)
    unexpected = sorted(set(res) - allowed)
    c.check("nothing else flagged (fresh files, projects, app data, bundles, hard links, symlinks, code, markers)",
            not unexpected, ", ".join(unexpected))

    cache = root / "cache"
    (cache / "app").mkdir(parents=True)
    (cache / "app" / "blob.bin").write_bytes(b"cached")
    (cache / "app" / "debug.log").write_bytes(b"old log")
    res = find_junk(settings, [str(cache)], now=future, kind="cache")
    c.check("cache folder: old cache + logs recommended",
            len(res) == 2 and all(f.recommended for f in res), [f.reason for f in res].__repr__())
    temp = root / "temp"
    temp.mkdir()
    (temp / "leftover.dat").write_bytes(b"x")
    (temp / ".X0-lock").write_bytes(b"x")
    (temp / "now.dat").write_bytes(b"x")
    os.utime(temp / "now.dat", (future - 60, future - 60))
    res = {Path(f.path).name for f in find_junk(settings, [str(temp)], now=future, kind="temp")}
    c.check("temp folder: only old, non-hidden files", res == {"leftover.dat"}, str(res))
    real_now = {Path(f.path).name for f in find_junk(settings, [str(root / user)], kind="user")}
    c.check("brand-new files are never flagged (24h safety window)", not real_now, str(real_now))


# --------------------------------------------------------------------------- online threat lists
def _feed_tests(c: _Checker, root: Path, settings) -> None:
    import hashlib
    from . import feeds
    from .scanner import scan
    c.out("Online threat lists (offline simulation of the real abuse.ch formats):")
    root.mkdir(parents=True)
    dropper = b"pretend malware sample from MalwareBazaar 7"
    stealer = b"pretend malware sample from ThreatFox 3"
    unsure = b"low-confidence ThreatFox entry 1"
    (root / "dropper.exe").write_bytes(dropper)
    (root / "stealer.bin").write_bytes(stealer)
    (root / "unsure.bin").write_bytes(unsure)
    (root / "empty.txt").write_bytes(b"")
    (root / "normal.pdf").write_bytes(b"%PDF normal")
    h = lambda b: hashlib.sha256(b).hexdigest()
    empty = h(b"")
    bazaar = (
        '################################################################\n'
        '# MalwareBazaar recent malware samples (last 48 hours)         #\n'
        '################################################################\n'
        '# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess",'
        '"mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"\n'
        f'"2026-11-13 08:00:01", "{h(dropper)}", "x", "y", "abuse_ch", "inv.exe", "exe", "application/x-dosexec", '
        '"AgentTesla", "n/a", "n/a", "x", "x", "x"\n'
        f'"2026-11-13 08:00:02", "{empty}", "x", "y", "abuse_ch", "e", "unknown", "x", "n/a", "n/a", "n/a", "", "", ""\n'
        '"garbage line without a hash"\n'
        '# Number of entries: 3\n')
    threatfox = (
        '# ThreatFox IOCs: CSV export\n'
        '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias",'
        '"malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"\n'
        f'"2026-11-13 07:00:00","1","{h(stealer)}","sha256_hash","payload","win.lumma","","Lumma Stealer","","100","","","0","x"\n'
        f'"2026-11-13 07:00:00","2","{h(unsure)}","sha256_hash","payload","win.x","","Maybe","","25","","","0","x"\n'
        '"2026-11-13 07:00:00","3","http://bad.example/x","url","payload_delivery","win.x","","X","","100","","","0","x"\n')
    served = {}

    def fake_fetch(url, dest, max_bytes, headers):
        data = served.get(url, b"")
        Path(dest).write_bytes(data)
        return len(data)

    by_id = {s.id: s for s in feeds.SOURCES}
    served[by_id["malwarebazaar"].url] = bazaar.encode()
    served[by_id["threatfox"].url] = threatfox.encode()
    lines = feeds.update_all(settings, fetch=fake_fetch)
    c.check("both lists download and parse", all("failed" not in l for l in lines), "; ".join(lines))
    res = {Path(f.path).name: f for f in scan(settings, [str(root)])}
    f = res.get("dropper.exe")
    c.check("detects a file listed by MalwareBazaar, with its malware name",
            bool(f and "AgentTesla" in f.reason and f.recommended), f.reason if f else "nothing")
    f = res.get("stealer.bin")
    c.check("detects a file listed by ThreatFox, with its malware name",
            bool(f and "Lumma Stealer" in f.reason), f.reason if f else "nothing")
    c.check("ignores low-confidence ThreatFox entries", "unsure.bin" not in res)
    c.check("harmless fingerprints in a list (empty file) never cause alarms", "empty.txt" not in res)
    c.check("normal files untouched", "normal.pdf" not in res)
    c.check("no update needed right after updating", not feeds.needs_update(settings))
    c.check("update is due after 24 hours", feeds.needs_update(settings, now=time.time() + 25 * 3600))

    before = feeds.read_meta(by_id["malwarebazaar"])["count"]
    served[by_id["malwarebazaar"].url] = b"<!DOCTYPE html><html>Service unavailable</html>"
    served[by_id["threatfox"].url] = b"# empty export\n"
    lines = feeds.update_all(settings, fetch=fake_fetch)
    meta = feeds.read_meta(by_id["malwarebazaar"])
    c.check("a broken download (web page) is rejected", not meta["ok"] and "web page" in meta["error"])
    c.check("an empty list is rejected", "no valid entries" in feeds.read_meta(by_id["threatfox"])["error"])
    still = {Path(f.path).name for f in scan(settings, [str(root)])}
    c.check("previous lists are kept after a failed update",
            meta["count"] == before and {"dropper.exe", "stealer.bin"} <= still)

    for url, why in (("http://bazaar.abuse.ch/export/csv/recent/", "plain http"),
                     ("https://evil.example.com/list.csv", "unknown host")):
        try:
            feeds.download(url, str(root / "x"), 1000)
            ok = False
        except feeds.FeedError:
            ok = True
        c.check(f"refuses unverified source ({why})", ok)

    served[by_id["malwarebazaar"].url] = bazaar.replace(h(dropper), "a" * 64).encode()
    feeds.update_source(by_id["malwarebazaar"], settings, fake_fetch, now=time.time() + 400 * DAY)
    feeds.ThreatLists.reset()
    after = {Path(f.path).name for f in scan(settings, [str(root)])}
    c.check("entries older than a year expire", "dropper.exe" not in after and "stealer.bin" in after)


# --------------------------------------------------------------------------- review folder
def _review_tests(c: _Checker, root: Path, settings) -> None:
    from . import review as rv
    from .config import app_home
    from .models import Finding
    c.out("Review folder - safe moving, restoring and deleting:")
    root.mkdir(parents=True)

    def mk(name, data=b"data", mode=0o644):
        p = root / name
        p.write_bytes(data)
        os.chmod(p, mode)
        return p

    def finding(p, cat="junk", **kw):
        st = os.stat(p)
        return Finding(str(p), cat, "test", "low", st.st_size, True, st.st_mtime_ns, kw)

    rf = rv.ReviewFolder(settings)
    a = mk("keep.txt", b"keep me", 0o640)
    it = rf.move_in(finding(a))
    c.check("move: file leaves its folder and is in Review", not a.exists() and rf.stored_path(it).exists())
    c.check("move: recorded with original path", rf.items()[0].original_path == str(a))
    a.write_bytes(b"a NEW file now sits at the old path")
    dest = rf.restore(it.id)
    c.check("restore never overwrites an existing file",
            a.read_bytes().startswith(b"a NEW") and Path(dest).read_bytes() == b"keep me", dest)
    if os.name != "nt":
        c.check("restore brings back original permissions", stat.S_IMODE(os.stat(dest).st_mode) == 0o640)

    t = mk("evil.exe", b"MZ bad", 0o755)
    it = rf.move_in(finding(t, "threat"))
    sp = rf.stored_path(it)
    c.check("threat is renamed .quarantined", sp.name.endswith(".quarantined"))
    if os.name != "nt":
        c.check("threat can no longer be executed", not os.access(sp, os.X_OK))
    c.check("delete removes it for good", rf.delete(it.id) == 6 and not sp.exists() and not rf.items())

    ch = mk("changing.txt", b"v1")
    f = finding(ch)
    time.sleep(0.01)
    ch.write_bytes(b"v2 - edited after the scan")
    try:
        rf.move_in(f)
        moved = True
    except rv.ReviewError:
        moved = False
    c.check("refuses to move a file that changed after the scan", not moved and ch.exists())

    orig, copy = mk("orig.jpg", b"same"), mk("orig (1).jpg", b"same")
    f = finding(copy, duplicate_of=str(orig))
    orig.write_bytes(b"different now")
    try:
        rf.move_in(f)
        moved = True
    except rv.ReviewError:
        moved = False
    c.check("refuses to move a 'duplicate' whose original changed", not moved and copy.exists())
    orig.unlink()
    try:
        rf.move_in(f)
        moved = True
    except rv.ReviewError:
        moved = False
    c.check("refuses to move a 'duplicate' whose original is gone", not moved and copy.exists())

    inside = app_home() / "settings.json"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_text("{}")
    try:
        rf.move_in(finding(inside))
        moved = True
    except rv.ReviewError:
        moved = False
    c.check("refuses to move protected / own files", not moved and inside.exists())

    # cross-drive move: force the copy -> verify -> delete path
    x = mk("other-drive.bin", os.urandom(200_000))
    data = x.read_bytes()
    real_rename = os.rename
    calls = {"n": 0}

    def fake_rename(src, dst, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_rename(src, dst, *a, **k)

    rv.os.rename = fake_rename
    try:
        it = rf.move_in(finding(x))
    finally:
        rv.os.rename = real_rename
    c.check("cross-drive move: copied, verified, original removed",
            not x.exists() and rf.stored_path(it).read_bytes() == data and not list(rf.files.glob("*.copying")))
    rf.delete(it.id)

    # crash recovery
    y = mk("crash.txt", b"in flight")
    items = rf._load()
    stored = f"deadbeef0001__crash.txt"
    os.replace(y, rf.files / stored)
    items["deadbeef0001"] = rv.ReviewItem("deadbeef0001", str(y), stored, "junk", "t", "low", 9, time.time(),
                                          status="pending")
    rf._save(items)
    (rf.files / "stray.bin").write_bytes(b"orphan")
    (rf.files / "half.copying").write_bytes(b"partial")
    rf2 = rv.ReviewFolder(settings)
    names = {i.stored_name for i in rf2.items()}
    c.check("after a crash: interrupted move is completed", stored in names)
    c.check("after a crash: unknown files are recovered, partial copies removed",
            "stray.bin" in names and not (rf.files / "half.copying").exists())

    rf2._manifest.write_text("{ this is not json")
    rf3 = rv.ReviewFolder(settings)
    c.check("corrupted record file falls back to the backup", stored in {i.stored_name for i in rf3.items()})

    old = rf3.items()[0]
    items = rf3._load()
    items[old.id].moved_at -= 40 * DAY
    rf3._save(items)
    n, _ = rf3.purge(30)
    c.check("auto-delete only removes items past the retention period", n == 1 and len(rf3.items()) == 1)
    rf3.purge()
    c.check("empty Review folder after purge", not rf3.items() and not any(rf3.files.iterdir()))
    log = app_home() / "activity.log"
    c.check("every action is written to activity.log", log.exists() and "moved to review" in log.read_text())


def _clamav_info(c: _Checker, root: Path, out, settings) -> None:
    from .scanner import EICAR, clamav_available, clamav_scan
    exe = clamav_available()
    if not exe:
        out("ClamAV: not installed (optional - install it for full virus definitions).")
        return
    out("ClamAV integration:")
    root.mkdir(parents=True)
    p = root / "eicar.com"
    p.write_bytes(EICAR)
    stats: dict = {}
    res = clamav_scan([str(p)], settings, stats)
    if str(stats.get("clamav", "")).startswith("error"):
        out(f"  WARN  ClamAV is installed but not working: {stats['clamav']} (run `freshclam`)")
    else:
        c.check("ClamAV detects the EICAR test file", bool(res), str(stats))
