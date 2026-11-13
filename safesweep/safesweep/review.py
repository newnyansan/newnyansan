"""The Review folder: flagged items wait here until you restore or delete them.

Reliability guarantees:
  * A file is never moved if it changed since the scan, and a duplicate is never
    moved unless the kept copy still exists and is still byte-identical.
  * Moves are crash-safe: the manifest records the move *before* it happens; moves
    across drives copy -> verify -> then remove the original. On start-up any
    half-finished operation is repaired and unknown files are recovered.
  * Restores never overwrite an existing file and restore the original permissions.
  * The manifest is written atomically, a backup copy is kept, and a lock file
    stops two SafeSweep windows from editing it at the same time.
  * Every action is written to activity.log.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import shutil
import stat
import time
import uuid
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Optional

from .config import Settings, app_home, is_protected, path_is_within
from .models import Finding, files_identical, sha256_of

MANIFEST = "manifest.json"
DEFANG_SUFFIX = ".quarantined"


class ReviewError(Exception):
    pass


@dataclass
class ReviewItem:
    id: str
    original_path: str
    stored_name: str
    category: str
    reason: str
    severity: str
    size: int
    moved_at: float
    mode: int = 0o644
    status: str = "ok"          # "pending" while a move is in progress
    sha256: str = ""

    @property
    def age_days(self) -> float:
        return max(0.0, (time.time() - self.moved_at) / 86400)


def _log(msg: str) -> None:
    try:
        p = app_home() / "activity.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}\n")
    except OSError:
        pass


def _retry(fn, attempts: int = 20):
    """Windows briefly locks a file another process is reading; retry instead of failing."""
    for i in range(attempts):
        try:
            return fn()
        except PermissionError:
            if os.name != "nt" or i == attempts - 1:
                raise
            time.sleep(0.05)


def _safe_name(name: str, limit: int = 120) -> str:
    """Keep stored names short enough for every filesystem (255-byte limit)."""
    if len(name.encode("utf-8")) <= limit:
        return name
    stem, ext = os.path.splitext(name)
    ext = ext[:20]
    while len((stem + ext).encode("utf-8")) > limit:
        stem = stem[:-1]
    return stem + ext


def _transfer(src: str, dest: str) -> str:
    """Move src to dest (dest must not exist). Returns the sha256 of the data."""
    if os.path.lexists(dest):
        raise ReviewError(f"Destination already exists: {dest}")
    digest = sha256_of(src)
    if os.stat(src).st_dev == os.stat(os.path.dirname(dest)).st_dev:
        try:
            os.rename(src, dest)  # same drive: atomic, nothing is copied
            return digest
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
    # Different drive: copy, verify, and only then remove the original.
    size = os.path.getsize(src)
    free = shutil.disk_usage(os.path.dirname(dest)).free
    if free < size + 50 * 1024 * 1024:
        raise ReviewError(f"Not enough free space to move {os.path.basename(src)} "
                          f"({size / 1048576:.0f} MB needed)")
    tmp = dest + ".copying"
    try:
        shutil.copy2(src, tmp)
        with contextlib.suppress(OSError), open(tmp, "r+b") as f:
            os.fsync(f.fileno())  # make sure the copy is really on disk
        if sha256_of(tmp) != digest:
            raise ReviewError("Copy verification failed - original left untouched")
        os.rename(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    try:
        os.unlink(src)
    except OSError:
        os.unlink(dest)  # could not remove original: undo so we don't end up with two copies
        raise
    return digest


class ReviewFolder:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root: Path = settings.review_dir
        self.files = self.root / "files"
        self.files.mkdir(parents=True, exist_ok=True)
        self._manifest = self.root / MANIFEST
        self._backup = self.root / (MANIFEST + ".bak")
        self._lockfile = self.root / "lock"
        self.repair()

    # -- locking ----------------------------------------------------------------
    def _lock_is_stale(self) -> bool:
        age = time.time() - self._lockfile.stat().st_mtime
        try:
            pid = int(self._lockfile.read_text().strip() or 0)
        except (OSError, ValueError):
            pid = 0
        if pid and os.name != "nt":
            try:
                os.kill(pid, 0)
                return age > 6 * 3600  # owner alive: only if absurdly old
            except ProcessLookupError:
                return True
            except PermissionError:
                pass
        return age > 600

    @contextlib.contextmanager
    def _locked(self, timeout: float = 15.0):
        deadline = time.time() + timeout
        while True:
            try:
                fd = os.open(self._lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                break
            except FileExistsError:
                try:  # stale lock from a crashed process
                    if self._lock_is_stale():
                        self._lockfile.unlink()
                        continue
                except OSError:
                    continue
                if time.time() > deadline:
                    raise ReviewError("The Review folder is busy (another SafeSweep window?). Try again.")
                time.sleep(0.05)
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                self._lockfile.unlink()

    # -- manifest ---------------------------------------------------------------
    def _read(self, path: Path) -> Optional[dict[str, ReviewItem]]:
        try:
            raw = json.loads(_retry(lambda: path.read_text(encoding="utf-8")))
            names = {f.name for f in fields(ReviewItem)}
            return {k: ReviewItem(**{kk: vv for kk, vv in v.items() if kk in names}) for k, v in raw.items()}
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def _load(self) -> dict[str, ReviewItem]:
        items = self._read(self._manifest)
        if items is None and self._manifest.exists():
            # Corrupted: keep the broken file for inspection, fall back to the backup.
            with contextlib.suppress(OSError):
                self._manifest.replace(self.root / f"manifest.corrupt-{int(time.time())}.json")
            _log("manifest was corrupted - restored from backup")
            items = self._read(self._backup)
        return items or {}

    def _save(self, items: dict[str, ReviewItem]) -> None:
        data = json.dumps({k: asdict(v) for k, v in items.items()}, indent=2)
        tmp = self._manifest.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if self._manifest.exists():
            with contextlib.suppress(OSError):
                shutil.copy2(self._manifest, self._backup)
        _retry(lambda: os.replace(tmp, self._manifest))

    def repair(self) -> list[str]:
        """Fix half-finished operations and recover files missing from the manifest."""
        notes: list[str] = []
        with self._locked():
            items = self._load()
            changed = False
            for leftover in self.files.glob("*.copying"):
                with contextlib.suppress(OSError):
                    leftover.unlink()
            for iid, it in list(items.items()):
                stored = self.files / it.stored_name
                if it.status == "pending":
                    if stored.exists() and not os.path.lexists(it.original_path):
                        it.status = "ok"
                        notes.append(f"completed interrupted move of {it.original_path}")
                    elif stored.exists() and os.path.lexists(it.original_path) and \
                            os.path.getsize(it.original_path) == stored.stat().st_size and \
                            files_identical(it.original_path, str(stored)):
                        stored.unlink()  # original is intact: undo the half move
                        del items[iid]
                        notes.append(f"rolled back interrupted move of {it.original_path}")
                    elif not stored.exists():
                        del items[iid]
                        notes.append(f"discarded unfinished move of {it.original_path}")
                    else:  # both exist and differ: the stored file is the one we moved
                        it.status = "ok"
                        notes.append(f"completed interrupted move of {it.original_path}")
                    changed = True
                elif not stored.exists():
                    del items[iid]
                    changed = True
                    notes.append(f"{it.original_path} was removed from the Review folder outside SafeSweep")
            known = {it.stored_name for it in items.values()}
            for f in self.files.iterdir():
                if f.is_file() and f.name not in known:
                    iid = uuid.uuid4().hex[:12]
                    items[iid] = ReviewItem(iid, str(self.files / f.name), f.name, "junk",
                                            "Recovered: file found in the Review folder without a record",
                                            "low", f.stat().st_size, f.stat().st_mtime)
                    changed = True
                    notes.append(f"recovered unknown file {f.name}")
            if changed:
                self._save(items)
        for n in notes:
            _log("repair: " + n)
        return notes

    def items(self) -> list[ReviewItem]:
        return sorted((i for i in self._load().values() if i.status == "ok"),
                      key=lambda i: i.moved_at, reverse=True)

    def get(self, item_id: str) -> ReviewItem:
        items = self._load()
        if item_id not in items:
            # allow unique prefixes, like git
            matches = [k for k in items if k.startswith(item_id)]
            if len(matches) != 1:
                raise ReviewError(f"No review item with id {item_id!r}")
            item_id = matches[0]
        return items[item_id]

    def stored_path(self, item: ReviewItem) -> Path:
        return self.files / item.stored_name

    # -- checks before moving -----------------------------------------------------
    def verify_still_valid(self, finding: Finding) -> None:
        """Raise ReviewError if the file must not be moved any more."""
        src = finding.path
        if not os.path.lexists(src):
            raise ReviewError("File no longer exists")
        if os.path.islink(src) or not os.path.isfile(src):
            raise ReviewError("Not a regular file")
        if is_protected(src) or path_is_within(src, str(self.root)):
            raise ReviewError("File is in a protected location")
        st = os.stat(src, follow_symlinks=False)
        if finding.mtime_ns and st.st_mtime_ns != finding.mtime_ns:
            raise ReviewError("File changed since the scan - scan again first")
        if finding.size and st.st_size != finding.size:
            raise ReviewError("File changed since the scan - scan again first")
        keep = finding.extra.get("duplicate_of")
        if keep:
            if not os.path.isfile(keep) or os.path.islink(keep):
                raise ReviewError(f"The copy that would be kept is gone: {keep}")
            if os.path.samefile(keep, src):
                raise ReviewError("Both 'copies' are the same file")
            if not files_identical(keep, src):
                raise ReviewError(f"No longer identical to {keep}")

    # -- operations ---------------------------------------------------------------
    def move_in(self, finding: Finding) -> ReviewItem:
        """Move a flagged file into the Review folder (nothing is deleted)."""
        self.verify_still_valid(finding)
        src = os.path.abspath(finding.path)
        st = os.stat(src)
        iid = uuid.uuid4().hex[:12]
        stored = f"{iid}__{_safe_name(os.path.basename(src))}"
        if finding.category == "threat":
            stored += DEFANG_SUFFIX  # can't be double-clicked / executed by accident
        item = ReviewItem(iid, src, stored, finding.category, finding.reason, finding.severity,
                          st.st_size, time.time(), stat.S_IMODE(st.st_mode), "pending")
        with self._locked():
            items = self._load()
            items[iid] = item
            self._save(items)  # write-ahead record
            dest = str(self.files / stored)
            try:
                item.sha256 = _transfer(src, dest)
            except BaseException:
                items.pop(iid, None)
                self._save(items)
                raise
            if finding.category == "threat":
                with contextlib.suppress(OSError):
                    os.chmod(dest, stat.S_IMODE(os.stat(dest).st_mode)
                             & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            item.status = "ok"
            self._save(items)
        _log(f"moved to review [{finding.category}] {src}  ({finding.reason})")
        return item

    def restore(self, item_id: str) -> str:
        """Put an item back. Never overwrites: picks 'name (restored).ext' if needed."""
        with self._locked():
            items = self._load()
            item = items[self.get(item_id).id]
            src = str(self.stored_path(item))
            if not os.path.exists(src):
                raise ReviewError("The stored file is missing")
            dest = Path(item.original_path)
            base, ext = os.path.splitext(dest.name)
            n = 1
            while os.path.lexists(dest):
                dest = dest.with_name(f"{base} (restored{'' if n == 1 else ' ' + str(n)}){ext}")
                n += 1
            dest.parent.mkdir(parents=True, exist_ok=True)
            _transfer(src, str(dest))
            with contextlib.suppress(OSError):
                os.chmod(dest, item.mode)
            del items[item.id]
            self._save(items)
        _log(f"restored {dest}")
        return str(dest)

    def delete(self, item_id: str) -> int:
        """Permanently delete one item. Returns bytes freed."""
        with self._locked():
            items = self._load()
            item = items.pop(self.get(item_id).id)
            p = self.stored_path(item)
            size = 0
            if p.exists():
                size = p.stat().st_size
                with contextlib.suppress(OSError):
                    os.chmod(p, stat.S_IWRITE | stat.S_IREAD)  # Windows read-only files
                p.unlink()
            self._save(items)
        _log(f"deleted permanently {item.original_path}")
        return size

    def purge(self, older_than_days: Optional[float] = None) -> tuple[int, int]:
        """Permanently delete everything (or only items older than N days)."""
        count = freed = 0
        for item in self.items():
            if older_than_days is None or item.age_days >= older_than_days:
                freed += self.delete(item.id)
                count += 1
        return count, freed
