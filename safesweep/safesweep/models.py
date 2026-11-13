"""Shared data types, hashing and the safe file walker."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from .config import is_protected

ProgressFn = Callable[[str], None]
CancelFn = Callable[[], bool]
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    path: str
    category: str              # "threat" or "junk"
    reason: str                # human readable
    severity: str = "low"      # low / medium / high
    size: int = 0
    recommended: bool = False  # safe to move without a closer look
    mtime_ns: int = 0          # file state at scan time; a changed file is never moved
    extra: dict = field(default_factory=dict)


def sha256_of(path: str, chunk: int = 1 << 20, cancelled: Optional[CancelFn] = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
            if cancelled and cancelled():
                raise InterruptedError("cancelled")
    return h.hexdigest()


def hashes_of(path: str, chunk: int = 1 << 20, cancelled: Optional[CancelFn] = None) -> tuple[str, str]:
    """(sha256, md5) computed in one pass over the file."""
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            sha.update(block)
            md5.update(block)
            if cancelled and cancelled():
                raise InterruptedError("cancelled")
    return sha.hexdigest(), md5.hexdigest()


def files_identical(a: str, b: str, chunk: int = 1 << 20) -> bool:
    """Byte-by-byte comparison (no reliance on hashes)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(chunk), fb.read(chunk)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


# Windows file attributes
_ATTR_SYSTEM = 0x4
_ATTR_OFFLINE = 0x1000
_ATTR_RECALL_ON_OPEN = 0x40000
_ATTR_RECALL_ON_DATA_ACCESS = 0x400000
_SF_DATALESS = 0x40000000  # macOS: file content lives in iCloud only


def is_cloud_placeholder(st: os.stat_result, name: str) -> bool:
    """OneDrive / iCloud / Dropbox 'online-only' files. Reading them would download them."""
    attrs = getattr(st, "st_file_attributes", 0)
    if attrs & (_ATTR_OFFLINE | _ATTR_RECALL_ON_OPEN | _ATTR_RECALL_ON_DATA_ACCESS):
        return True
    if getattr(st, "st_flags", 0) & _SF_DATALESS:
        return True
    return name.startswith(".") and name.endswith(".icloud")


def is_system_file(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & _ATTR_SYSTEM)


def last_used(st: os.stat_result) -> float:
    """Most recent of modified / accessed / created / metadata-changed.

    Deliberately conservative: a file extracted from an old zip keeps its old
    modification date, but its creation/change time reveals it is new here.
    """
    times = [st.st_mtime, st.st_atime, getattr(st, "st_birthtime", 0) or 0]
    if os.name != "nt":
        times.append(st.st_ctime)  # inode change time on POSIX
    return max(times)


def last_changed(st: os.stat_result) -> float:
    """When the file's content/identity last changed on this device (creation counts)."""
    times = [st.st_mtime, getattr(st, "st_birthtime", 0) or 0]
    if os.name != "nt":
        times.append(st.st_ctime)
    return max(times)


def fingerprint(st: os.stat_result) -> int:
    return st.st_mtime_ns ^ (st.st_size << 1)


@dataclass
class FileInfo:
    path: str
    name: str
    st: os.stat_result
    root: str
    rel_dirs: tuple  # lower-cased folder names between the root and the file


def _matches(path: str, name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(name, p) for p in patterns)


def _is_link(entry: os.DirEntry) -> bool:
    try:
        if entry.is_symlink():
            return True
        is_junction = getattr(entry, "is_junction", None)  # Windows junctions (Python 3.12+)
        if is_junction and is_junction():
            return True
        if os.name == "nt":
            st = entry.stat(follow_symlinks=False)
            if getattr(st, "st_file_attributes", 0) & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
                return True
    except OSError:
        return True
    return False


PruneFn = Callable[[str, list, bool], bool]


def walk_files(roots: list[str], exclude: Optional[list[str]] = None,
               progress: Optional[ProgressFn] = None,
               cancelled: Optional[CancelFn] = None,
               prune: Optional[PruneFn] = None,
               stats: Optional[dict] = None) -> Iterator[FileInfo]:
    """Yield regular files under roots (a root may also be a single file).

    Never follows symlinks/junctions, never enters protected locations, never
    visits a folder twice, skips cloud online-only files. `prune(dirpath,
    entries, is_root)` may return True to skip a whole folder.
    """
    exclude = exclude or []
    stats = stats if stats is not None else {}
    stats.setdefault("files", 0)
    stats.setdefault("skipped", 0)
    visited: set = set()
    last_progress = 0.0

    for root in roots:
        root = os.path.abspath(os.path.expanduser(root))
        if is_protected(root):
            stats["skipped"] += 1
            continue
        if os.path.isfile(root) and not os.path.islink(root):
            try:
                st = os.stat(root, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and not is_cloud_placeholder(st, os.path.basename(root)):
                stats["files"] += 1
                yield FileInfo(root, os.path.basename(root), st, os.path.dirname(root), ())
            continue
        if not os.path.isdir(root):
            continue

        stack: list[tuple[str, tuple]] = [(root, ())]
        while stack:
            if cancelled and cancelled():
                return
            d, rel = stack.pop()
            try:
                dst = os.stat(d)
                key = (dst.st_dev, dst.st_ino) if dst.st_ino else os.path.normcase(os.path.realpath(d))
            except OSError:
                stats["skipped"] += 1
                continue
            if key in visited:
                continue
            visited.add(key)
            now = time.monotonic()
            if progress and now - last_progress > 0.05:
                last_progress = now
                progress(d)
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                stats["skipped"] += 1
                continue
            if prune and prune(d, entries, not rel and d == root):
                stats["skipped"] += 1
                continue
            for e in entries:
                if _matches(e.path, e.name, exclude) or _is_link(e):
                    continue
                try:
                    if e.is_dir(follow_symlinks=False):
                        if not is_protected(e.path):
                            stack.append((e.path, rel + (e.name.lower(),)))
                        continue
                    if not e.is_file(follow_symlinks=False):
                        continue  # sockets, pipes, devices
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    stats["skipped"] += 1
                    continue
                if not stat.S_ISREG(st.st_mode) or is_cloud_placeholder(st, e.name):
                    stats["skipped"] += 1
                    continue
                stats["files"] += 1
                yield FileInfo(e.path, e.name, st, root, rel)
