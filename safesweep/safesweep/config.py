"""Platform-aware defaults, protected locations and user settings."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

WINDOWS = sys.platform.startswith("win")
MACOS = sys.platform == "darwin"


def is_android() -> bool:
    return "ANDROID_ROOT" in os.environ or "com.termux" in os.environ.get("PREFIX", "")


def app_home() -> Path:
    """Where SafeSweep keeps its settings, log and the Review folder."""
    override = os.environ.get("SAFESWEEP_HOME")
    if override:
        return Path(override).expanduser()
    if WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "SafeSweep"
    if MACOS:
        return Path.home() / "Library" / "Application Support" / "SafeSweep"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "safesweep"


def _existing(paths) -> list[str]:
    seen, out = set(), []
    for p in paths:
        p = str(p)
        rp = os.path.normcase(os.path.realpath(p))
        if rp not in seen and os.path.isdir(p):
            seen.add(rp)
            out.append(p)
    return out


def default_scan_paths() -> list[str]:
    home = Path.home()
    if is_android():
        shared = home / "storage" / "shared"  # created by `termux-setup-storage`
        return _existing([shared]) or [str(home)]
    return _existing([home / "Downloads", home / "Desktop", home / "Documents"]) or [str(home)]


def system_temp_dirs() -> list[str]:
    dirs = [tempfile.gettempdir()]
    if WINDOWS:
        dirs.append(os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"))
    return _existing(dirs)


def cache_roots() -> list[str]:
    """Folders whose whole content is disposable cache (rebuilt automatically)."""
    home = Path.home()
    if WINDOWS:
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return _existing([local / "CrashDumps"])
    if MACOS:
        return _existing([home / "Library" / "Caches", home / "Library" / "Logs"])
    return _existing([Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))])


def default_junk_paths() -> list[str]:
    home = Path.home()
    extra = []
    if is_android():
        extra.append(home / "storage" / "shared" / "Download")
    else:
        extra.append(home / "Downloads")
    return _existing([*system_temp_dirs(), *cache_roots(), *extra])


def protected_prefixes() -> list[str]:
    """Locations SafeSweep never scans into or moves files out of."""
    if WINDOWS:
        sysdrive = os.environ.get("SystemDrive", "C:")
        env = [os.environ.get(k) for k in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
                                            "ProgramW6432", "ProgramData")]
        fixed = [sysdrive + "\\Windows", sysdrive + "\\Program Files", sysdrive + "\\Program Files (x86)",
                 sysdrive + "\\ProgramData", sysdrive + "\\$Recycle.Bin", sysdrive + "\\System Volume Information",
                 sysdrive + "\\Recovery", sysdrive + "\\$WinREAgent"]
        return [p for p in env + fixed if p]
    prefixes = ["/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/boot", "/opt",
                "/proc", "/sys", "/dev", "/run", "/snap", "/var/lib", "/var/cache/apt",
                # macOS
                "/System", "/Library", "/Applications", "/private/var/db", "/private/etc", "/cores",
                # Android
                "/system", "/vendor", "/apex", "/product", "/odm", "/data/app", "/data/system"]
    prefix = os.environ.get("PREFIX")
    if prefix and "com.termux" in prefix:
        prefixes.append(prefix)  # Termux's own /usr - deleting it breaks Termux
    return prefixes


def _norm(p: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(p))))


def path_is_within(path: str, parent: str) -> bool:
    path, parent = _norm(path), _norm(parent)
    return path == parent or path.startswith(parent.rstrip(os.sep) + os.sep)


def is_protected(path: str | os.PathLike) -> bool:
    path = os.fspath(path)
    if path_is_within(path, str(app_home())):
        return True  # never scan/move SafeSweep's own data (incl. the Review folder)
    return any(path_is_within(path, pref) for pref in protected_prefixes())


@dataclass
class Settings:
    scan_paths: list[str] = field(default_factory=default_scan_paths)
    junk_paths: list[str] = field(default_factory=default_junk_paths)
    exclude: list[str] = field(default_factory=list)  # glob patterns, e.g. "*.iso" or "*/Photos/*"
    old_download_days: int = 180          # downloads untouched this long are "probably unneeded"
    large_file_mb: int = 500              # large + old files are reported
    min_age_hours: int = 24               # never flag junk changed more recently than this (may be in use)
    min_duplicate_kb: int = 100           # ignore tiny duplicates
    review_retention_days: int = 30       # "purge --expired" deletes review items older than this
    use_clamav: bool = True               # use ClamAV if installed
    clamav_extra_args: list[str] = field(default_factory=list)
    report_macros: bool = True            # list Office files with macros (informational)
    find_duplicates: bool = True
    max_hash_mb: int = 512                # don't hash files bigger than this when scanning for viruses

    @property
    def review_dir(self) -> Path:
        return app_home() / "Review"

    @classmethod
    def path(cls) -> Path:
        return app_home() / "settings.json"

    @classmethod
    def load(cls) -> "Settings":
        s = cls()
        p = cls.path()
        if not p.exists():
            return s
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return s
        if isinstance(data, dict):
            for f in fields(cls):
                if f.name in data:
                    try:
                        s.set_value(f.name, data[f.name])
                    except (TypeError, ValueError):
                        pass  # ignore a bad value, keep the default
        return s

    def set_value(self, key: str, value) -> None:
        """Set a setting with type checking and sane limits. Raises KeyError/ValueError."""
        if key not in {f.name for f in fields(self)}:
            raise KeyError(f"Unknown setting: {key}")
        cur = getattr(self, key)
        if isinstance(cur, bool):
            if isinstance(value, str):
                low = value.strip().lower()
                if low not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                    raise ValueError(f"{key} must be true or false")
                value = low in ("1", "true", "yes", "on")
            value = bool(value)
        elif isinstance(cur, int):
            value = int(value)
            if value < 0:
                raise ValueError(f"{key} cannot be negative")
            if key in ("old_download_days", "review_retention_days") and value < 1:
                raise ValueError(f"{key} must be at least 1")
        elif isinstance(cur, list):
            if isinstance(value, str):
                value = [v.strip() for v in value.split(";") if v.strip()]
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"{key} must be a list of text values")
        setattr(self, key, value)

    def save(self) -> None:
        p = self.path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        os.replace(tmp, p)
