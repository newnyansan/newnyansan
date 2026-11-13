"""Find files that are probably no longer needed.

Safety rules (each one exists because of a real-world way cleaners break things):
  * Files changed in the last `min_age_hours` are never flagged (may be in use / downloading).
  * Software never gets touched: project folders (.git, package.json, ...), app bundles
    (.app, Photos Library, ...), virtualenvs/node_modules, hidden config folders and
    AppData/Library are skipped entirely in personal folders.
  * Empty files and duplicates are only considered for personal content types
    (photos, videos, music, documents, archives) - never code or app files.
  * Duplicates are verified byte-for-byte, hard links are not duplicates, and one
    copy is always kept.
  * Anything that might still be wanted (old downloads, big files, backups) is
    reported but NOT pre-selected.
"""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from typing import Optional

from .config import Settings, cache_roots, path_is_within, system_temp_dirs
from .models import (CancelFn, FileInfo, Finding, ProgressFn, files_identical, is_system_file,
                     last_changed, last_used, sha256_of, walk_files)

DAY = 86400.0

TEMP_NAMES = {"thumbs.db", ".ds_store", "ehthumbs.db", "ehthumbs_vista.db"}
TEMP_EXT = {".tmp", ".temp", ".crdownload", ".part", ".partial", ".dmp", ".~tmp", ".opdownload"}
BACKUP_EXT = {".bak", ".old", ".orig", ".backup"}
LOG_EXT = {".log"}
INSTALLER_EXT = {".exe", ".msi", ".dmg", ".pkg", ".apk", ".deb", ".rpm", ".appimage", ".iso", ".msix",
                 ".appx", ".xapk"}
CONTENT_EXT = {
    # photos / images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif", ".webp", ".raw", ".cr2",
    ".cr3", ".nef", ".arw", ".dng", ".orf", ".rw2", ".psd",
    # video / audio
    ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".wmv", ".webm", ".3gp", ".mpg", ".mpeg",
    ".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".opus", ".wma",
    # documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf",
    ".pages", ".numbers", ".key", ".epub", ".csv",
    # archives & disk images
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".iso", ".dmg", ".msi", ".pkg", ".apk", ".deb", ".rpm", ".appimage",
}
CACHE_DIR_NAMES = {"cache", "caches", ".cache", "__pycache__", "crashdumps", ".thumbnails", "thumbnails",
                   "gpucache", "code cache", "shadercache", "inetcache"}
VCS_MARKERS = {".git", ".hg", ".svn"}
# In personal folders only these unmistakable cache folders count (a folder you named
# "Thumbnails" or "cache" yourself is left alone).
USER_ZONE_CACHE_NAMES = {".thumbnails", ".cache"}
APP_DATA_NAMES = {"appdata", "library", "application support", "android", "obb"}
# A folder holding one of these is a software project / app: never touched.
PROJECT_MARKERS = {".git", ".hg", ".svn", "package.json", "pyproject.toml", "setup.py", "cargo.toml",
                   "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "cmakelists.txt", "gemfile",
                   "composer.json", ".project", "pubspec.yaml", "*.sln", "*.csproj", "*.xcodeproj"}
# Weak hints: only count when the folder also contains program/source files.
WEAK_MARKERS = {"makefile", "requirements.txt", "manifest.json", "readme.md", "license", "license.txt"}
CODE_EXT = {".py", ".js", ".ts", ".c", ".cpp", ".h", ".java", ".kt", ".go", ".rs", ".rb", ".php", ".cs",
            ".swift", ".dll", ".so", ".dylib", ".exe", ".jar", ".pyd", ".class", ".lua", ".sh"}
LIBRARY_RE = re.compile(r"\.(dll|dylib|pyd|so(\.\d+)*)$", re.I)
# Standard personal folders are never mistaken for projects (a stray file must not hide them).
PERSONAL_FOLDERS = {"downloads", "download", "desktop", "documents", "pictures", "photos", "videos",
                    "movies", "music", "dcim", "camera", "screenshots", "home", "onedrive", "dropbox"}
SKIP_DIR_NAMES = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "site-packages",
                  "dist-packages", ".tox", ".gradle", ".idea", ".vscode", "bower_components", ".npm",
                  "system volume information", "$recycle.bin", "lost+found", "windowsapps"}
PACKAGE_EXT = {".app", ".photoslibrary", ".musiclibrary", ".tvlibrary", ".imovielibrary", ".fcpbundle",
               ".framework", ".bundle", ".plugin", ".kext", ".lrdata", ".lrcat-data", ".aplibrary",
               ".photolibrary", ".band", ".logicx", ".xcodeproj", ".xcworkspace", ".sparsebundle",
               ".vmwarevm", ".pvm", ".utm", ".download", ".pkg", ".mpkg", ".rtfd", ".playground"}
COPY_MARKER = re.compile(r"(\(\d+\)|\bcopy\b|\bkopie\b|- copy|_copy|\bcopie\b)", re.I)


def _root_kind(root: str) -> str:
    if any(path_is_within(root, t) for t in system_temp_dirs()):
        return "temp"
    if any(path_is_within(root, c) for c in cache_roots()) or os.path.basename(root).lower() in CACHE_DIR_NAMES:
        return "cache"
    return "user"


def _make_prune(kind: str):
    def prune(path: str, entries: list, is_root: bool) -> bool:
        name = os.path.basename(path).lower()
        if not is_root:
            if name in SKIP_DIR_NAMES or os.path.splitext(name)[1] in PACKAGE_EXT:
                return True
            if kind == "user" and (name in APP_DATA_NAMES or (name.startswith(".") and name not in CACHE_DIR_NAMES)):
                return True
        # Software project / app data folder: leave it alone completely.
        names = {e.name.lower() for e in entries}
        if names & VCS_MARKERS:
            return True
        if is_root or name in PERSONAL_FOLDERS:
            return False
        return is_project(names)
    return prune


def is_project(names: set) -> bool:
    import fnmatch
    if any(fnmatch.fnmatch(n, pat) for n in names for pat in PROJECT_MARKERS):
        return True
    if any(LIBRARY_RE.search(n) for n in names):
        return True  # program libraries: an installed / portable app lives here
    return bool(names & WEAK_MARKERS) and any(os.path.splitext(n)[1] in CODE_EXT for n in names)


def _in_downloads(info: FileInfo) -> bool:
    parts = [p.lower() for p in os.path.normpath(info.path).split(os.sep)[:-1]]
    return "downloads" in parts or "download" in parts


def classify(info: FileInfo, kind: str, settings: Settings, now: float) -> Optional[Finding]:
    """Return a Finding for a junk file, or None. Duplicates are handled separately."""
    st = info.st
    name = info.name.lower()
    ext = os.path.splitext(name)[1]
    changed = last_changed(st)
    used = last_used(st)
    if now - changed < settings.min_age_hours * 3600 or is_system_file(st):
        return None
    hidden_path = name.startswith(".") or any(d.startswith(".") and d not in CACHE_DIR_NAMES for d in info.rel_dirs)
    cache_names = USER_ZONE_CACHE_NAMES if kind == "user" else CACHE_DIR_NAMES
    in_cache_dir = kind == "cache" or any(d in cache_names for d in info.rel_dirs)

    def f(reason, recommended):
        return Finding(info.path, "junk", reason, "low", st.st_size, recommended, st.st_mtime_ns)

    if name in TEMP_NAMES:
        return f("Thumbnail/folder-view cache (Windows/macOS rebuild it automatically)", True)
    if ext in TEMP_EXT or (name.startswith("~$") and st.st_size < 4096):
        return f("Leftover temporary file", True)
    if ext in LOG_EXT and now - changed >= 30 * DAY:
        return f("Old log file (30+ days)", kind != "user")
    if kind == "temp" and not hidden_path and now - changed >= 7 * DAY:
        return f("Old file in the system temp folder (7+ days)", True)
    if in_cache_dir and now - used >= 7 * DAY:
        return f("Cache file not used in 7+ days (apps recreate cache when needed)", True)
    if ext in BACKUP_EXT or name.endswith("~"):
        return f("Backup copy - check you don't still need it", False)

    if kind != "user" or hidden_path:
        return None
    in_dl = _in_downloads(info)
    if st.st_size == 0 and ext in CONTENT_EXT:
        return f(f"Empty {ext} file (0 bytes, contains nothing - e.g. a failed download)", True)
    if in_dl and ext in INSTALLER_EXT and now - used >= 30 * DAY:
        return f("Old installer in Downloads (30+ days) - can usually be re-downloaded", False)
    if in_dl and now - used >= settings.old_download_days * DAY:
        return f(f"Download not opened in {settings.old_download_days}+ days", False)
    if st.st_size >= settings.large_file_mb * 1024 * 1024 and now - used >= settings.old_download_days * DAY:
        return f(f"Large file ({st.st_size / 1048576:.0f} MB) not used in {settings.old_download_days}+ days", False)
    return None


def find_junk(settings: Settings, paths: Optional[list[str]] = None,
              progress: Optional[ProgressFn] = None,
              cancelled: Optional[CancelFn] = None,
              stats: Optional[dict] = None, now: Optional[float] = None,
              kind: Optional[str] = None) -> list[Finding]:
    """`now` and `kind` exist for testing (simulate the future / force a folder type)."""
    stats = stats if stats is not None else {}
    roots = [os.path.abspath(os.path.expanduser(r)) for r in (paths or settings.junk_paths)]
    now = time.time() if now is None else now
    findings: dict[str, Finding] = {}
    dup_candidates: dict[int, list[FileInfo]] = defaultdict(list)
    min_dup = max(1, settings.min_duplicate_kb * 1024)

    forced_kind = kind
    for root in roots:
        kind = forced_kind or _root_kind(root)
        for info in walk_files([root], settings.exclude, progress, cancelled, _make_prune(kind), stats):
            if info.path in findings:
                continue
            found = classify(info, kind, settings, now)
            if found:
                findings[info.path] = found
                if found.recommended:
                    continue  # otherwise it may still turn out to be an exact duplicate
            ext = os.path.splitext(info.name.lower())[1]
            if (settings.find_duplicates and kind == "user" and info.st.st_size >= min_dup
                    and not info.name.startswith(".")
                    and (ext in CONTENT_EXT or (ext == ".exe" and _in_downloads(info)))
                    and now - last_changed(info.st) >= settings.min_age_hours * 3600):
                dup_candidates[info.st.st_size].append(info)

    if settings.find_duplicates and not (cancelled and cancelled()):
        for d in find_duplicates(dup_candidates, progress, cancelled):
            prev = findings.get(d.path)
            if prev is None or not prev.recommended:
                findings[d.path] = d
    if cancelled and cancelled():
        stats["cancelled"] = True
    return sorted(findings.values(), key=lambda x: (not x.recommended, -x.size, x.path))


def _partial_hash(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(65536))
        size = os.fstat(f.fileno()).st_size
        if size > 131072:
            f.seek(-65536, os.SEEK_END)
            h.update(f.read(65536))
    return h.hexdigest()


def _keeper_key(info: FileInfo):
    return (bool(COPY_MARKER.search(os.path.splitext(info.name)[0])), _in_downloads(info),
            info.st.st_mtime, len(info.path), info.path)


def find_duplicates(by_size: dict[int, list[FileInfo]], progress: Optional[ProgressFn] = None,
                    cancelled: Optional[CancelFn] = None) -> list[Finding]:
    out: list[Finding] = []
    for size, infos in by_size.items():
        if cancelled and cancelled():
            break
        # Hard links / the same file reached twice are NOT duplicates.
        unique: dict = {}
        for i in infos:
            try:
                st = i.st if i.st.st_ino else os.stat(i.path)  # Windows folder listings report inode 0
            except OSError:
                continue
            key = (st.st_dev, st.st_ino) if st.st_ino else os.path.normcase(os.path.realpath(i.path))
            unique.setdefault(key, i)
        infos = list(unique.values())
        if len(infos) < 2:
            continue
        stage: dict[str, list[FileInfo]] = defaultdict(list)
        for i in infos:  # cheap first pass: start + end of the file
            try:
                stage[_partial_hash(i.path)].append(i)
            except OSError:
                continue
        for group in stage.values():
            if len(group) < 2:
                continue
            full: dict[str, list[FileInfo]] = defaultdict(list)
            for i in group:
                try:
                    full[sha256_of(i.path, cancelled=cancelled)].append(i)
                except (OSError, InterruptedError):
                    continue
            for digest, same in full.items():
                if len(same) < 2:
                    continue
                same.sort(key=_keeper_key)
                keep = same[0]
                if progress:
                    progress(f"Duplicate group: {keep.name}")
                for dup in same[1:]:
                    if not files_identical(keep.path, dup.path):  # final byte-by-byte proof
                        continue
                    out.append(Finding(dup.path, "junk", f"Exact duplicate of {keep.path}", "low", size, True,
                                       dup.st.st_mtime_ns, {"duplicate_of": keep.path, "sha256": digest}))
    return out
