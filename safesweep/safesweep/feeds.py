"""Threat lists downloaded from verified sources only.

Sources (hard-coded - no user-supplied URLs, so nothing unverified can be added):
  * abuse.ch MalwareBazaar - malware samples confirmed by security researchers
  * abuse.ch ThreatFox     - indicators of compromise (file hashes) from incident responders
  * ClamAV official definitions via `freshclam`, if ClamAV is installed

Safety rules:
  * HTTPS only, certificate verified, host must be on the allow-list (also after redirects)
  * size limits; HTML/error pages and lists with no valid entries are rejected
  * a failed or suspicious download never replaces the lists you already have
  * fingerprints of harmless content (e.g. an empty file) are ignored so they can't cause
    false alarms
  * new entries are merged into what you already have, so coverage grows over time;
    entries older than `keep_days` are dropped
"""

from __future__ import annotations

import csv
import io
import json
import mmap
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

from .config import Settings, app_home

ALLOWED_HOSTS = frozenset({"bazaar.abuse.ch", "threatfox.abuse.ch"})
USER_AGENT = "SafeSweep-threat-list-updater"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DAY = 86400

# Fingerprints that must never count as malware, whatever a list says.
NEVER_MALWARE = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file
}


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    url: str
    kind: str          # "bazaar_csv", "threatfox_csv", "sha256_zip"
    max_bytes: int
    optional: bool = False  # only with settings.threat_feed_full


SOURCES = [
    Source("malwarebazaar", "MalwareBazaar (abuse.ch)", "https://bazaar.abuse.ch/export/csv/recent/",
           "bazaar_csv", 64 * 1024 * 1024),
    Source("threatfox", "ThreatFox (abuse.ch)", "https://threatfox.abuse.ch/export/csv/recent/",
           "threatfox_csv", 64 * 1024 * 1024),
    Source("malwarebazaar_full", "MalwareBazaar full archive (abuse.ch)",
           "https://bazaar.abuse.ch/export/txt/sha256/full/", "sha256_zip", 600 * 1024 * 1024, optional=True),
]


class FeedError(Exception):
    pass


def feeds_dir() -> Path:
    return app_home() / "feeds"


# ----------------------------------------------------------------------------- download
def _ssl_context() -> ssl.SSLContext:
    """Verified TLS. Uses certifi's CA bundle when present (needed on Android)."""
    try:
        import certifi  # type: ignore
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class _NoForeignRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed: frozenset):
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urlparse(newurl)
        if u.scheme != "https" or u.hostname not in self.allowed:
            raise FeedError(f"refused redirect to unverified address {u.scheme}://{u.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, dest: str, max_bytes: int, allowed_hosts: frozenset = ALLOWED_HOSTS,
             context: Optional[ssl.SSLContext] = None, headers: Optional[dict] = None,
             timeout: float = 60, cancelled: Optional[Callable[[], bool]] = None) -> int:
    """Download url to dest with all safety checks. Returns bytes written."""
    u = urlparse(url)
    if u.scheme != "https":
        raise FeedError("only https:// sources are allowed")
    if u.hostname not in allowed_hosts:
        raise FeedError(f"{u.hostname} is not a verified source")
    ctx = context or _ssl_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                         _NoForeignRedirect(allowed_hosts))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with opener.open(req, timeout=timeout) as resp:
            final = urlparse(resp.geturl())
            if final.scheme != "https" or final.hostname not in allowed_hosts:
                raise FeedError("response came from an unverified address")
            length = resp.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > max_bytes:
                raise FeedError("download is larger than allowed")
            total = 0
            with open(dest, "wb") as out:
                while True:
                    if cancelled and cancelled():
                        raise FeedError("cancelled")
                    block = resp.read(1 << 16)
                    if not block:
                        break
                    total += len(block)
                    if total > max_bytes:
                        raise FeedError("download is larger than allowed")
                    out.write(block)
            return total
    except urllib.error.HTTPError as e:
        hint = " (abuse.ch may require a free Auth-Key: set abusech_auth_key)" if e.code in (401, 403) else ""
        raise FeedError(f"server answered {e.code} {e.reason}{hint}") from None
    except ssl.SSLError as e:
        raise FeedError(f"secure connection could not be verified: {e}") from None
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLError):
            raise FeedError(f"secure connection could not be verified: {reason}") from None
        raise FeedError(f"could not connect: {reason}") from None
    except (OSError, ValueError) as e:
        if isinstance(e, FeedError):
            raise
        raise FeedError(f"download failed: {e}") from None


# ----------------------------------------------------------------------------- parsing
def _looks_like_html(head: bytes) -> bool:
    h = head.lstrip()[:200].lower()
    return h.startswith(b"<") or b"<html" in h or b"<!doctype" in h


def _csv_rows(text: str) -> tuple[list[str], Iterable[list[str]]]:
    """abuse.ch CSV: '#' comment lines, the last of which holds the column names."""
    header: list[str] = []
    body = []
    for line in text.splitlines():
        if line.startswith("#"):
            cand = next(csv.reader([line.lstrip("# ")], skipinitialspace=True), [])
            if len(cand) > 3 and all(re.fullmatch(r"[a-z0-9_]+", c or "x") for c in cand):
                header = [c.strip() for c in cand]
        elif line.strip():
            body.append(line)
    return header, csv.reader(body, skipinitialspace=True)


def parse_bazaar_csv(text: str) -> dict[str, str]:
    header, rows = _csv_rows(text)
    i_hash = header.index("sha256_hash") if "sha256_hash" in header else None
    i_name = header.index("signature") if "signature" in header else None
    i_type = header.index("file_type_guess") if "file_type_guess" in header else None
    out = {}
    for row in rows:
        cells = [c.strip() for c in row]
        h = cells[i_hash].lower() if i_hash is not None and i_hash < len(cells) else \
            next((c.lower() for c in cells if SHA256_RE.match(c.lower())), "")
        if not SHA256_RE.match(h):
            continue
        name = cells[i_name] if i_name is not None and i_name < len(cells) else ""
        if not name or name.lower() in ("n/a", "null", "none"):
            ftype = cells[i_type] if i_type is not None and i_type < len(cells) else ""
            name = f"malware sample ({ftype})" if ftype and ftype.lower() != "unknown" else "malware sample"
        out[h] = name[:80]
    return out


def parse_threatfox_csv(text: str) -> dict[str, str]:
    header, rows = _csv_rows(text)
    idx = {n: i for i, n in enumerate(header)}
    out = {}
    for row in rows:
        cells = [c.strip() for c in row]
        get = lambda n: cells[idx[n]] if n in idx and idx[n] < len(cells) else ""
        if header:
            if get("ioc_type").lower() != "sha256_hash":
                continue
            h = get("ioc_value").lower()
            name = get("malware_printable") or get("fk_malware") or "malware"
            if get("confidence_level").isdigit() and int(get("confidence_level")) < 50:
                continue  # only well-confirmed indicators
        else:
            h = next((c.lower() for c in cells if SHA256_RE.match(c.lower())), "")
            name = "malware"
        if SHA256_RE.match(h):
            out[h] = name[:80]
    return out


def parse_sha256_lines(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        h = line.strip().split()[0].lower() if line.strip() and not line.startswith("#") else ""
        if SHA256_RE.match(h):
            out[h] = ""
    return out


# ----------------------------------------------------------------------------- storage
class HashIndex:
    """Sorted file of 32-byte digests; membership test by binary search (fast, low memory)."""

    def __init__(self, path: Path):
        self.path = path
        self._mm = None
        self.count = 0
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size >= 32 and size % 32 == 0:
            self._f = open(path, "rb")
            self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
            self.count = size // 32

    def __contains__(self, digest: bytes) -> bool:
        lo, hi = 0, self.count
        mm = self._mm
        while lo < hi:
            mid = (lo + hi) // 2
            cur = mm[mid * 32:(mid + 1) * 32]
            if cur < digest:
                lo = mid + 1
            elif cur > digest:
                hi = mid
            else:
                return True
        return False

    def close(self):
        if self._mm is not None:
            self._mm.close()
            self._f.close()
            self._mm = None

    @staticmethod
    def write(path: Path, hashes: Iterable[str]) -> int:
        digests = sorted({bytes.fromhex(h) for h in hashes if h not in NEVER_MALWARE})
        tmp = path.with_suffix(".bin.tmp")
        with open(tmp, "wb") as f:
            for d in digests:
                f.write(d)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return len(digests)


def _meta_path(src: Source) -> Path:
    return feeds_dir() / f"{src.id}.json"


def read_meta(src: Source) -> dict:
    try:
        return json.loads(_meta_path(src).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_meta(src: Source, meta: dict) -> None:
    p = _meta_path(src)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    os.replace(tmp, p)


def _merge_store(src: Source, fresh: dict[str, str], keep_days: int, now: float) -> int:
    """Merge new entries into <id>.tsv (hash, first seen, name), prune old, rebuild index."""
    d = feeds_dir()
    tsv = d / f"{src.id}.tsv"
    entries: dict[str, tuple[int, str]] = {}
    try:
        with open(tsv, encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 3 and SHA256_RE.match(parts[0]) and parts[1].isdigit():
                    entries[parts[0]] = (int(parts[1]), parts[2])
    except OSError:
        pass
    for h, name in fresh.items():
        if h in NEVER_MALWARE:
            continue
        old = entries.get(h)
        entries[h] = (old[0] if old else int(now), name or (old[1] if old else ""))
    cutoff = now - keep_days * DAY
    entries = {h: v for h, v in entries.items() if v[0] >= cutoff}
    tmp = tsv.with_suffix(".tsv.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for h in sorted(entries):
            ts, name = entries[h]
            f.write(f"{h}\t{ts}\t{name.replace(chr(9), ' ').replace(chr(10), ' ')}\n")
    os.replace(tmp, tsv)
    return HashIndex.write(d / f"{src.id}.bin", entries.keys())


Fetcher = Callable[[str, str, int, dict], int]


def _default_fetcher(settings: Settings, cancelled=None) -> Fetcher:
    def fetch(url, dest, max_bytes, headers):
        return download(url, dest, max_bytes, headers=headers, cancelled=cancelled)
    return fetch


def update_source(src: Source, settings: Settings, fetch: Fetcher, now: Optional[float] = None) -> dict:
    """Update one source. On any problem the previous data stays in place."""
    now = time.time() if now is None else now
    d = feeds_dir()
    d.mkdir(parents=True, exist_ok=True)
    meta = read_meta(src)
    meta.update({"label": src.label, "last_attempt": now})
    headers = {"Auth-Key": settings.abusech_auth_key} if settings.abusech_auth_key else {}
    fd, tmp = tempfile.mkstemp(prefix=f"{src.id}-", dir=str(d))
    os.close(fd)
    try:
        fetch(src.url, tmp, src.max_bytes, headers)
        with open(tmp, "rb") as f:
            head = f.read(4096)
        if src.kind == "sha256_zip":
            if not zipfile.is_zipfile(tmp):
                raise FeedError("expected a zip archive")
            with zipfile.ZipFile(tmp) as z:
                members = [m for m in z.infolist() if not m.is_dir()]
                if len(members) != 1 or members[0].file_size > 2 * src.max_bytes:
                    raise FeedError("unexpected archive contents")
                text = z.read(members[0]).decode("utf-8", "replace")
            fresh = parse_sha256_lines(text)
        else:
            if _looks_like_html(head):
                raise FeedError("got a web page instead of a threat list")
            with open(tmp, encoding="utf-8", errors="replace") as f:
                text = f.read()
            fresh = parse_bazaar_csv(text) if src.kind == "bazaar_csv" else parse_threatfox_csv(text)
        fresh = {h: n for h, n in fresh.items() if h not in NEVER_MALWARE}
        if not fresh:
            raise FeedError("the list contained no valid entries")
        if src.kind == "sha256_zip":
            count = HashIndex.write(d / f"{src.id}.bin", fresh.keys())
        else:
            count = _merge_store(src, fresh, settings.threat_feed_keep_days, now)
        meta.update({"ok": True, "last_success": now, "count": count, "new": len(fresh), "error": ""})
    except FeedError as e:
        meta.update({"ok": False, "error": str(e)})
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        meta.update({"ok": False, "error": f"{type(e).__name__}: {e}"})
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    _write_meta(src, meta)
    return meta


def run_freshclam(timeout: int = 900) -> str:
    exe = shutil.which("freshclam")
    if not exe:
        return "ClamAV not installed"
    try:
        p = subprocess.run([exe, "--quiet"], capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"ClamAV update failed: {e}"
    if p.returncode == 0:
        return "ClamAV definitions up to date"
    msg = [m.strip() for m in (p.stderr + "\n" + p.stdout).splitlines() if m.strip()]
    errs = [m for m in msg if re.search(r"error|can't|cannot|failed|denied", m, re.I)]
    best = (errs or msg or [f"error {p.returncode}"])[0]
    return f"ClamAV update failed: {best}"


def active_sources(settings: Settings) -> list[Source]:
    return [s for s in SOURCES if not s.optional or settings.threat_feed_full]


def update_all(settings: Settings, progress: Optional[Callable[[str], None]] = None,
               fetch: Optional[Fetcher] = None, cancelled=None) -> list[str]:
    """Update every source. Returns human-readable result lines."""
    fetch = fetch or _default_fetcher(settings, cancelled)
    ThreatLists.reset()  # release the files first (Windows can't replace files that are open)
    lines = []
    for src in active_sources(settings):
        if progress:
            progress(f"Updating threat list: {src.label} …")
        m = update_source(src, settings, fetch)
        if m.get("ok"):
            lines.append(f"{src.label}: {m['count']:,} known malware fingerprints ({m['new']:,} in latest list)")
        else:
            have = f"; keeping previous list ({m['count']:,})" if m.get("count") else ""
            lines.append(f"{src.label}: update failed - {m.get('error')}{have}")
    if settings.use_clamav and shutil.which("freshclam"):
        if progress:
            progress("Updating ClamAV definitions …")
        lines.append(run_freshclam())
    ThreatLists.reset()
    return lines


def needs_update(settings: Settings, now: Optional[float] = None) -> bool:
    if not settings.threat_feeds_enabled:
        return False
    now = time.time() if now is None else now
    for src in active_sources(settings):
        last = read_meta(src).get("last_attempt", 0)
        if now - last >= settings.threat_feed_update_hours * 3600:
            return True
    return False


def maybe_update(settings: Settings, progress=None, fetch=None, cancelled=None) -> list[str]:
    return update_all(settings, progress, fetch, cancelled) if needs_update(settings) else []


def status_text(settings: Settings, now: Optional[float] = None) -> str:
    if not settings.threat_feeds_enabled:
        return "Online threat lists: turned off"
    now = time.time() if now is None else now
    total, newest, errors = 0, 0.0, []
    for src in active_sources(settings):
        m = read_meta(src)
        total += m.get("count", 0)
        newest = max(newest, m.get("last_success", 0))
        if m.get("last_attempt") and not m.get("ok"):
            errors.append(src.label.split(" (")[0])
    if not newest:
        return "Online threat lists: not downloaded yet" + (f" (failed: {', '.join(errors)})" if errors else "")
    age = now - newest
    when = "just now" if age < 120 else f"{age / 3600:.0f} h ago" if age < 2 * DAY else f"{age / DAY:.0f} days ago"
    return f"Online threat lists: {total:,} known malware fingerprints, updated {when}" + \
        (f" (last update failed: {', '.join(errors)})" if errors else "")


class ThreatLists:
    """Lookup across all downloaded lists. Cached per process; reset after updates."""
    _cache: Optional["ThreatLists"] = None

    def __init__(self):
        self.indexes = []
        d = feeds_dir()
        for src in SOURCES:
            idx = HashIndex(d / f"{src.id}.bin")
            if idx.count:
                self.indexes.append((src, idx))

    @classmethod
    def get(cls) -> "ThreatLists":
        if cls._cache is None or cls._cache._home != str(app_home()):
            cls._cache = cls()
            cls._cache._home = str(app_home())
        return cls._cache

    @classmethod
    def reset(cls):
        if cls._cache:
            for _, idx in cls._cache.indexes:
                idx.close()
        cls._cache = None

    def __bool__(self):
        return bool(self.indexes)

    def lookup(self, sha256_hex: str) -> Optional[str]:
        if sha256_hex in NEVER_MALWARE:
            return None
        digest = bytes.fromhex(sha256_hex)
        for src, idx in self.indexes:
            if digest in idx:
                return f"{src.label.split(' (')[0]}: {self._name(src, sha256_hex) or 'confirmed malware sample'}"
        return None

    def _name(self, src: Source, h: str) -> str:
        try:
            with open(feeds_dir() / f"{src.id}.tsv", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(h):
                        return line.rstrip("\n").split("\t")[2]
        except (OSError, IndexError):
            pass
        return ""
