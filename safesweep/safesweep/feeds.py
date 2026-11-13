"""Threat lists downloaded from verified sources only.

Sources (hard-coded - no user-supplied URLs, so nothing unverified can be added):
  * abuse.ch MalwareBazaar - malware samples confirmed by security researchers (updated
    continuously; needs a free abuse.ch Auth-Key)
  * abuse.ch ThreatFox     - file indicators from incident responders (free Auth-Key)
  * VirusShare             - large archive of known malware (MD5 lists, no key needed)
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

ALLOWED_HOSTS = frozenset({"mb-api.abuse.ch", "threatfox-api.abuse.ch", "virusshare.com"})
USER_AGENT = "SafeSweep-threat-list-updater"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MD5_RE = re.compile(r"^[0-9a-f]{32}$")
DAY = 86400

# Fingerprints that must never count as malware, whatever a list says.
NEVER_MALWARE = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file (SHA-256)
    "d41d8cd98f00b204e9800998ecf8427e",                                  # empty file (MD5)
}


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    url: str           # may contain {key}
    kind: str          # "bazaar_csv", "threatfox_csv", "virusshare"
    max_bytes: int
    needs_key: bool = False
    refresh_days: float = 1.0
    algo: str = "sha256"


SOURCES = [
    Source("malwarebazaar", "MalwareBazaar (abuse.ch)",
           "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv",
           "bazaar_csv", 64 * 1024 * 1024, needs_key=True),
    Source("threatfox", "ThreatFox (abuse.ch)",
           "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip",
           "threatfox_csv", 256 * 1024 * 1024, needs_key=True, refresh_days=1.0),
    Source("virusshare", "VirusShare archive", "https://virusshare.com/hashes",
           "virusshare", 8 * 1024 * 1024, refresh_days=7.0, algo="md5"),
]
VIRUSSHARE_FILE = "https://virusshare.com/hashfiles/VirusShare_{n:05d}.md5"


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
        hint = " - check your abuse.ch Auth-Key" if e.code in (401, 403) else ""
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
    """Sorted file of fixed-size digests; membership test by binary search (fast, low memory)."""

    def __init__(self, path: Path, size: int = 32):
        self.path, self.size = path, size
        self._mm = None
        self.count = 0
        try:
            n = path.stat().st_size
        except OSError:
            return
        if n >= size and n % size == 0:
            self._f = open(path, "rb")
            self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
            self.count = n // size

    def __contains__(self, digest: bytes) -> bool:
        lo, hi, w, mm = 0, self.count, self.size, self._mm
        while lo < hi:
            mid = (lo + hi) // 2
            cur = mm[mid * w:(mid + 1) * w]
            if cur < digest:
                lo = mid + 1
            elif cur > digest:
                hi = mid
            else:
                return True
        return False

    def __iter__(self):
        if self._mm is not None:
            w = self.size
            for i in range(self.count):
                yield self._mm[i * w:(i + 1) * w]

    def close(self):
        if self._mm is not None:
            self._mm.close()
            self._f.close()
            self._mm = None

    @staticmethod
    def write(path: Path, hashes: Iterable[str]) -> int:
        digests = sorted({bytes.fromhex(h) for h in hashes if h not in NEVER_MALWARE})
        return HashIndex._write_sorted(path, digests)

    @staticmethod
    def _write_sorted(path: Path, digests: Iterable[bytes]) -> int:
        tmp = path.with_suffix(".bin.tmp")
        n = 0
        with open(tmp, "wb") as f:
            for d in digests:
                f.write(d)
                n += 1
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return n

    @staticmethod
    def merge(path: Path, new_hashes: Iterable[str], size: int) -> int:
        """Add hashes to a sorted index without loading the whole index into memory."""
        import heapq
        new = sorted({bytes.fromhex(h) for h in new_hashes if h not in NEVER_MALWARE})
        old = HashIndex(path, size)
        try:
            def unique(it):
                last = None
                for d in it:
                    if d != last:
                        yield d
                        last = d
            tmp_path = path.with_suffix(".merge")
            n = HashIndex._write_sorted(tmp_path, unique(heapq.merge(iter(old), new)))
        finally:
            old.close()
        os.replace(tmp_path, path)
        return n


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


def _read_text(path: str, max_unzipped: int) -> str:
    """Plain or single-file zip download -> text."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            if len(members) != 1 or members[0].file_size > max_unzipped:
                raise FeedError("unexpected archive contents")
            return z.read(members[0]).decode("utf-8", "replace")
    with open(path, "rb") as f:
        head = f.read(4096)
    if _looks_like_html(head):
        raise FeedError("got a web page instead of a threat list")
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _virusshare_update(src: Source, settings: Settings, fetch: Fetcher, tmp: str, meta: dict) -> tuple[int, int]:
    """VirusShare publishes numbered, never-changing MD5 lists. Keep the newest N of them."""
    want = max(0, int(settings.virusshare_lists))
    if want == 0:
        raise FeedError("turned off (virusshare_lists = 0)")
    fetch(src.url, tmp, src.max_bytes, {})
    with open(tmp, encoding="utf-8", errors="replace") as f:
        page = f.read()
    numbers = sorted({int(n) for n in re.findall(r"hashfiles/VirusShare_(\d{5})\.md5", page)})
    if not numbers:
        raise FeedError("could not read the VirusShare list index")
    newest = numbers[-want:]
    have = set(meta.get("files", []))
    d = feeds_dir()
    added = 0
    for n in reversed(newest):  # newest first
        if n in have:
            continue
        fetch(VIRUSSHARE_FILE.format(n=n), tmp, 16 * 1024 * 1024, {})
        with open(tmp, encoding="utf-8", errors="replace") as f:
            text = f.read()
        if _looks_like_html(text[:2000].encode()):
            raise FeedError(f"list {n} was a web page")
        hashes = [l.strip().lower() for l in text.splitlines() if MD5_RE.match(l.strip().lower())]
        if len(hashes) < 1000:
            raise FeedError(f"list {n} looks incomplete ({len(hashes)} entries)")
        meta["count"] = HashIndex.merge(d / f"{src.id}.bin", hashes, 16)
        have.add(n)
        meta["files"] = sorted(have)
        _write_meta(src, meta)  # progress is kept even if a later file fails
        added += len(hashes)
    return meta.get("count", 0), added


def update_source(src: Source, settings: Settings, fetch: Fetcher, now: Optional[float] = None) -> dict:
    """Update one source. On any problem the previous data stays in place."""
    now = time.time() if now is None else now
    ThreatLists.reset()  # Windows can't replace list files while they are open
    d = feeds_dir()
    d.mkdir(parents=True, exist_ok=True)
    meta = read_meta(src)
    meta.update({"label": src.label, "last_attempt": now})
    fd, tmp = tempfile.mkstemp(prefix=f"{src.id}-", dir=str(d))
    os.close(fd)
    try:
        if src.needs_key and not settings.abusech_auth_key.strip():
            raise FeedError("needs a free abuse.ch Auth-Key (get one at auth.abuse.ch)")
        if src.kind == "virusshare":
            count, new = _virusshare_update(src, settings, fetch, tmp, meta)
        else:
            key = re.sub(r"[^A-Za-z0-9_-]", "", settings.abusech_auth_key.strip())
            fetch(src.url.format(key=key), tmp, src.max_bytes, {})
            text = _read_text(tmp, 4 * src.max_bytes)
            fresh = parse_bazaar_csv(text) if src.kind == "bazaar_csv" else parse_threatfox_csv(text)
            fresh = {h: n for h, n in fresh.items() if h not in NEVER_MALWARE}
            if not fresh:
                raise FeedError("the list contained no valid entries")
            count, new = _merge_store(src, fresh, settings.threat_feed_keep_days, now), len(fresh)
        meta.update({"ok": True, "last_success": now, "count": count, "new": new, "error": ""})
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
    return [s for s in SOURCES if not (s.kind == "virusshare" and settings.virusshare_lists <= 0)]


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
            lines.append(f"{src.label}: {m['count']:,} known malware fingerprints ({m['new']:,} new)")
        elif "Auth-Key" in str(m.get("error")) and not settings.abusech_auth_key:
            lines.append(f"{src.label}: skipped - {m.get('error')}")
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
        if src.needs_key and not settings.abusech_auth_key:
            continue
        last = read_meta(src).get("last_attempt", 0)
        if now - last >= max(settings.threat_feed_update_hours * 3600, src.refresh_days * DAY * 0.95):
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
        if src.needs_key and not settings.abusech_auth_key:
            continue
        if m.get("last_attempt") and not m.get("ok"):
            errors.append(src.label.split(" (")[0])
    if not newest:
        return "Online threat lists: not downloaded yet" + (f" (failed: {', '.join(errors)})" if errors else "")
    age = now - newest
    when = "just now" if age < 120 else f"{age / 3600:.0f} h ago" if age < 2 * DAY else f"{age / DAY:.0f} days ago"
    tip = "" if settings.abusech_auth_key else " - add a free abuse.ch key for daily-updated lists"
    return f"Online threat lists: {total:,} known malware fingerprints, updated {when}" + \
        (f" (last update failed: {', '.join(errors)})" if errors else "") + tip


class ThreatLists:
    """Lookup across all downloaded lists. Cached per process; reset after updates."""
    _cache: Optional["ThreatLists"] = None

    def __init__(self):
        self.indexes = []
        d = feeds_dir()
        for src in SOURCES:
            idx = HashIndex(d / f"{src.id}.bin", 16 if src.algo == "md5" else 32)
            if idx.count:
                self.indexes.append((src, idx))
        self._home = str(app_home())

    @classmethod
    def get(cls) -> "ThreatLists":
        if cls._cache is None or cls._cache._home != str(app_home()):
            cls.reset()
            cls._cache = cls()
        return cls._cache

    @classmethod
    def reset(cls):
        if cls._cache:
            for _, idx in cls._cache.indexes:
                idx.close()
        cls._cache = None

    def __bool__(self):
        return bool(self.indexes)

    def lookup(self, sha256_hex: str, md5_hex: str = "") -> Optional[str]:
        for src, idx in self.indexes:
            h = md5_hex if src.algo == "md5" else sha256_hex
            if not h or h in NEVER_MALWARE:
                continue
            if bytes.fromhex(h) in idx:
                name = self._name(src, h) or "confirmed malware sample"
                return f"{src.label.split(' (')[0]}: {name}"
        return None

    def _name(self, src: Source, h: str) -> str:
        if src.algo != "sha256":
            return ""
        try:
            with open(feeds_dir() / f"{src.id}.tsv", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(h):
                        return line.rstrip("\n").split("\t")[2]
        except (OSError, IndexError):
            pass
        return ""
