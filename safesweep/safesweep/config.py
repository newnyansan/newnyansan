"""Platform-aware defaults and user settings."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path


def is_android() -> bool:
    return "ANDROID_ROOT" in os.environ or "com.termux" in os.environ.get("PREFIX", "")


def app_home() -> Path:
    """Where SafeSweep keeps its settings and the Review folder."""
    override = os.environ.get("SAFESWEEP_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "SafeSweep"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "SafeSweep"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "safesweep"


def default_scan_paths() -> list[str]:
    home = Path.home()
    if is_android():
        shared = home / "storage" / "shared"  # created by `termux-setup-storage`
        return [str(shared / "Download"), str(shared)] if shared.exists() else [str(home)]
    candidates = [home / "Downloads", home / "Desktop", home / "Documents"]
    found = [str(p) for p in candidates if p.exists()]
    return found or [str(home)]


def default_junk_paths() -> list[str]:
    home = Path.home()
    paths = [tempfile.gettempdir()]
    if sys.platform.startswith("win"):
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        paths += [str(local / "Temp"), str(local / "CrashDumps")]
    elif sys.platform == "darwin":
        paths += [str(home / "Library" / "Caches"), str(home / "Library" / "Logs")]
    elif is_android():
        shared = home / "storage" / "shared"
        paths += [str(shared / "Download")] if shared.exists() else []
    else:
        paths += [str(home / ".cache"), str(home / ".local" / "share" / "Trash")]
    paths += [str(home / "Downloads")]
    # de-duplicate, keep order, keep only existing
    seen, out = set(), []
    for p in paths:
        rp = os.path.realpath(p)
        if rp not in seen and os.path.isdir(rp):
            seen.add(rp)
            out.append(p)
    return out


# Never touch these, no matter what the user selects.
PROTECTED_PREFIXES_POSIX = ["/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/boot",
                            "/System", "/Library/Apple", "/proc", "/sys", "/dev",
                            "/system", "/vendor", "/apex"]
PROTECTED_PREFIXES_WIN = [r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)",
                          r"C:\ProgramData\Microsoft"]


@dataclass
class Settings:
    scan_paths: list[str] = field(default_factory=default_scan_paths)
    junk_paths: list[str] = field(default_factory=default_junk_paths)
    exclude: list[str] = field(default_factory=list)
    old_download_days: int = 180          # downloads untouched this long are "probably unneeded"
    large_file_mb: int = 500              # large + old files are flagged
    review_retention_days: int = 30       # `purge --expired` deletes review items older than this
    use_clamav: bool = True               # use clamscan if it is installed
    find_duplicates: bool = True
    max_hash_mb: int = 200                # don't hash files bigger than this when scanning for viruses

    @property
    def review_dir(self) -> Path:
        return app_home() / "Review"

    @classmethod
    def path(cls) -> Path:
        return app_home() / "settings.json"

    @classmethod
    def load(cls) -> "Settings":
        p = cls.path()
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
                return cls(**known)
            except (OSError, ValueError, TypeError):
                pass
        return cls()

    def save(self) -> None:
        p = self.path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


def is_protected(path: str | os.PathLike) -> bool:
    rp = os.path.realpath(path)
    # Never let SafeSweep scan/move its own data.
    if rp.startswith(os.path.realpath(app_home())):
        return True
    prefixes = PROTECTED_PREFIXES_WIN if sys.platform.startswith("win") else PROTECTED_PREFIXES_POSIX
    norm = os.path.normcase(rp)
    for pref in prefixes:
        pn = os.path.normcase(pref)
        if norm == pn or norm.startswith(pn + os.sep):
            return True
    return False
