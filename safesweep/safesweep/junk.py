"""Find files that are probably no longer needed."""

from __future__ import annotations

import os
import time
from collections import defaultdict
from typing import Callable

from .config import Settings
from .models import Finding, ProgressFn, sha256_of, walk_files

TEMP_EXT = {".tmp", ".temp", ".bak", ".old", ".dmp", ".crdownload", ".part", ".partial",
            ".download", ".chk", ".~tmp"}
TEMP_NAMES = {"thumbs.db", ".ds_store", "desktop.ini.bak", "ehthumbs.db"}
LOG_EXT = {".log"}
INSTALLER_EXT = {".exe", ".msi", ".dmg", ".pkg", ".apk", ".deb", ".rpm", ".appimage", ".iso"}
CACHE_DIR_NAMES = {"cache", "caches", ".cache", "__pycache__", "tmp", "temp", "crashdumps", "logs"}

DAY = 86400


def _in_cache_dir(path: str, root: str) -> bool:
    """True if the file sits in a cache/temp folder at or below the scanned root."""
    rel = os.path.relpath(os.path.dirname(path), root)
    parts = [] if rel == "." else rel.lower().split(os.sep)
    parts.append(os.path.basename(os.path.normpath(root)).lower())
    return any(p in CACHE_DIR_NAMES for p in parts)


def find_junk(settings: Settings, paths: list[str] | None = None,
              progress: ProgressFn | None = None,
              cancelled: Callable[[], bool] | None = None) -> list[Finding]:
    roots = paths or settings.junk_paths
    now = time.time()
    old_cutoff = now - settings.old_download_days * DAY
    large = settings.large_file_mb * 1024 * 1024
    findings: dict[str, Finding] = {}
    by_size: dict[int, list[str]] = defaultdict(list)

    for root in roots:
        root = os.path.expanduser(root)
        for entry in walk_files([root], settings.exclude, progress, cancelled):
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            name = entry.name.lower()
            ext = os.path.splitext(name)[1]
            last_used = max(st.st_mtime, st.st_atime)
            in_downloads = f"{os.sep}download" in entry.path.lower()

            reason = None
            if name in TEMP_NAMES:
                reason = "System thumbnail/metadata cache (rebuilt automatically)"
            elif ext in TEMP_EXT or name.startswith("~$"):
                reason = "Temporary / leftover file"
            elif ext in LOG_EXT and st.st_mtime < now - 30 * DAY:
                reason = "Old log file (30+ days)"
            elif _in_cache_dir(entry.path, root) and st.st_mtime < now - 7 * DAY:
                reason = "Cache file not used in 7+ days"
            elif st.st_size == 0:
                reason = "Empty file"
            elif in_downloads and ext in INSTALLER_EXT and last_used < now - 30 * DAY:
                reason = "Old installer in Downloads (already installed or unused)"
            elif in_downloads and last_used < old_cutoff:
                reason = f"Not opened in {settings.old_download_days}+ days"
            elif st.st_size >= large and last_used < old_cutoff:
                reason = f"Large file ({st.st_size // (1024 * 1024)} MB) unused for {settings.old_download_days}+ days"

            if reason:
                findings[entry.path] = Finding(entry.path, "junk", reason, "low", st.st_size)
            elif settings.find_duplicates and st.st_size > 0:
                by_size[st.st_size].append(entry.path)

    if settings.find_duplicates and not (cancelled and cancelled()):
        for f in _duplicates(by_size, progress, cancelled):
            findings.setdefault(f.path, f)

    return sorted(findings.values(), key=lambda f: (-f.size, f.path))


def _duplicates(by_size: dict[int, list[str]], progress: ProgressFn | None,
                cancelled: Callable[[], bool] | None) -> list[Finding]:
    out: list[Finding] = []
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        if cancelled and cancelled():
            break
        by_hash: dict[str, list[str]] = defaultdict(list)
        for p in paths:
            try:
                by_hash[sha256_of(p)].append(p)
            except OSError:
                continue
        for digest, same in by_hash.items():
            if len(same) < 2:
                continue
            # keep the oldest copy (most likely the "original"), flag the rest
            same.sort(key=lambda p: (os.path.getmtime(p), len(p)))
            keep = same[0]
            if progress:
                progress(f"Duplicate group: {os.path.basename(keep)}")
            for dup in same[1:]:
                out.append(Finding(dup, "junk", f"Duplicate of {keep}", "low", size,
                                   {"duplicate_of": keep, "sha256": digest}))
    return out
