"""Threat scanning: hash signatures, EICAR, heuristics and (optional) ClamAV.

Design rule: a "high" verdict needs strong evidence (known signature, a program
disguised as a document, a filename trick, or clearly malicious commands).
Weak hints are reported as "medium"/"low" and are never pre-selected.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .config import Settings, app_home, is_protected
from .models import (SEVERITY_ORDER, CancelFn, FileInfo, Finding, ProgressFn, sha256_of,
                     walk_files)

BUILTIN_SIGS = Path(__file__).with_name("data") / "signatures.txt"

EXECUTABLE_EXT = {".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                  ".wsf", ".wsh", ".ps1", ".hta", ".msi", ".jar", ".apk", ".lnk", ".dll", ".cpl",
                  ".msc", ".reg", ".iso", ".img", ".vhd", ".appref-ms", ".url", ".chm", ".application"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".rtf", ".txt",
           ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".heic", ".webp", ".mp3", ".wav", ".m4a",
           ".mp4", ".mov", ".avi", ".mkv", ".zip", ".rar", ".7z", ".html", ".htm", ".eml"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppsm", ".xlam", ".sldm"}
SCRIPT_EXT = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta", ".sh", ".wsf"}
# Windows' own "Recent items" folders legitimately contain names like "report.pdf.lnk"
RECENT_DIR_MARKERS = (os.sep + "recent" + os.sep,)

# (pattern, description, strong?) - built so that this source file itself doesn't match.
_P = re.compile
SCRIPT_PATTERNS = [
    (_P(rb"power" rb"shell(\.exe)?[^\n]{0,80}\s-(e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I),
     "Runs a hidden (encoded) PowerShell command", True),
    (_P(rb"I" rb"EX\s*\(?\s*\(?\s*New-Object\s+(System\.)?Net\.WebClient\)?\.Download", re.I),
     "Downloads and immediately runs code from the internet", True),
    (_P(rb"(Invoke-Expression|I" rb"EX)[\s\S]{0,200}FromBase64String", re.I),
     "Decodes and runs hidden code", True),
    (_P(rb"FromBase64String[\s\S]{0,200}(Invoke-Expression|\bI" rb"EX\b)", re.I),
     "Decodes and runs hidden code", True),
    (_P(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.I), "Deletes Windows backups (ransomware behaviour)", True),
    (_P(rb"wmic(\.exe)?\s+shadowcopy\s+delete", re.I), "Deletes Windows backups (ransomware behaviour)", True),
    (_P(rb"bcdedit[^\n]{0,60}recoveryenabled\s+no", re.I), "Disables Windows recovery (ransomware behaviour)", True),
    (_P(rb"Set-MpPreference[^\n]{0,80}-Disable(RealtimeMonitoring|IOAVProtection)\s+\$?true", re.I),
     "Turns off Windows Defender", True),
    (_P(rb"Add-MpPreference[^\n]{0,40}-ExclusionPath", re.I), "Hides files from Windows Defender", False),
    (_P(rb"(curl|wget)\s[^\n|;]{1,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I),
     "Downloads a script and runs it (common in installers, but risky)", False),
    (_P(rb"WScript\.Shell[\s\S]{0,300}\.Run\s*\(", re.I), "Script launches other programs", False),
    (_P(rb"-WindowStyle\s+Hidden", re.I), "Runs in a hidden window", False),
]

# The standard harmless antivirus test file (https://www.eicar.org).
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def load_signatures() -> dict[str, str]:
    sigs: dict[str, str] = {}
    for src in (BUILTIN_SIGS, app_home() / "signatures.txt"):
        try:
            text = src.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            parts = line.strip().split(None, 1)
            if parts and not parts[0].startswith("#") and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
                sigs[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else "Known malware"
    return sigs


def add_signatures(source: str) -> int:
    """Append valid SHA-256 lines from `source` to the user signature file."""
    dest = app_home() / "signatures.txt"
    dest.parent.mkdir(parents=True, exist_ok=True)
    existing = load_signatures()
    added = 0
    with open(source, encoding="utf-8", errors="ignore") as src, open(dest, "a", encoding="utf-8") as out:
        for line in src:
            parts = line.strip().split(None, 1)
            if parts and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]) and parts[0].lower() not in existing:
                name = parts[1].strip() if len(parts) > 1 else "Imported signature"
                out.write(f"{parts[0].lower()}  {name}\n")
                existing[parts[0].lower()] = name
                added += 1
    return added


# ---------------------------------------------------------------- file types
def is_windows_program(head: bytes) -> bool:
    """A real PE executable: 'MZ' header whose e_lfanew points at 'PE\\0\\0'."""
    if len(head) < 0x40 or head[:2] != b"MZ":
        return False
    off = int.from_bytes(head[0x3C:0x40], "little")
    return 0x40 <= off <= len(head) - 4 and head[off:off + 4] == b"PE\0\0"


def native_program_kind(head: bytes) -> Optional[str]:
    if is_windows_program(head):
        return "Windows program"
    if head[:4] == b"\x7fELF" and len(head) >= 20 and head[4] in (1, 2) and head[5] in (1, 2):
        return "Linux/Android program"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "Mac program"
    return None


def is_eicar(head: bytes, size: int) -> bool:
    # The spec allows the string to be followed by whitespace, total file <= 128 bytes.
    return size <= 128 and head.startswith(EICAR) and not head[len(EICAR):].strip(b" \t\r\n\x1a")


def heuristic_checks(info: FileInfo, head: bytes, report_macros: bool = True) -> list[tuple[str, str, bool]]:
    """Return (reason, severity, recommended) tuples for one file."""
    name = info.name
    lower = name.lower()
    stem, ext = os.path.splitext(lower)
    hits: list[tuple[str, str, bool]] = []

    if "‮" in name or "‭" in name:
        hits.append(("Filename hides its real extension with an invisible right-to-left character", "high", True))

    inner = os.path.splitext(stem)[1]
    padded = stem != stem.rstrip(" 　_") and len(stem) - len(stem.rstrip(" 　_")) >= 3
    if ext in EXECUTABLE_EXT and (inner.strip() in DOC_EXT or padded):
        in_recent = ext == ".lnk" and any(m in info.path.lower() for m in RECENT_DIR_MARKERS)
        if not in_recent:
            fake = inner.strip() or "a document"
            hits.append((f"Fake extension: looks like {fake} but is really {ext}", "high", True))

    kind = native_program_kind(head)
    if kind and ext in DOC_EXT:
        hits.append((f"{kind} disguised as a {ext} file", "high", True))

    if lower == "autorun.inf" and re.search(rb"^\s*(open|shellexecute|shell\\[^\n]*command)\s*=", head, re.I | re.M):
        hits.append(("autorun.inf that starts a program automatically from this drive", "medium", False))

    if report_macros and ext in MACRO_EXT:
        hits.append(("Office file with macros - only open it if you trust the sender", "low", False))

    if ext in SCRIPT_EXT:
        strong = [r for p, r, s in SCRIPT_PATTERNS if s and p.search(head)]
        weak = [r for p, r, s in SCRIPT_PATTERNS if not s and p.search(head)]
        if strong:
            hits.append(("; ".join(dict.fromkeys(strong + weak)), "high", True))
        elif len(weak) >= 2:
            hits.append(("Suspicious script: " + "; ".join(dict.fromkeys(weak)), "medium", False))
        elif weak:
            hits.append(("Script worth a look: " + weak[0], "low", False))
    return hits


# ---------------------------------------------------------------- ClamAV
def clamav_available() -> Optional[str]:
    return shutil.which("clamscan") or shutil.which("clamdscan")


def _run_clam(exe: str, list_file: str, extra: list[str]) -> tuple[int, str, str]:
    cmd = [exe, "--no-summary", "--infected", f"--file-list={list_file}", *extra]
    if os.path.basename(exe).lower().startswith("clamdscan"):
        cmd.insert(1, "--fdpass")
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=12 * 3600)
    return proc.returncode, proc.stdout, proc.stderr


def clamav_scan(files: list[str], settings: Settings, stats: dict,
                progress: Optional[ProgressFn] = None) -> list[Finding]:
    """Scan exactly the given files with ClamAV. Daemon first (fast), then clamscan."""
    candidates = [shutil.which("clamdscan"), shutil.which("clamscan")]
    candidates = [c for c in candidates if c]
    if not candidates:
        stats["clamav"] = "not installed"
        return []
    if not files:
        stats["clamav"] = "no files"
        return []
    fd, list_file = tempfile.mkstemp(prefix="safesweep-", suffix=".lst")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(files) + "\n")
        out = ""
        for exe in candidates:
            if progress:
                progress(f"ClamAV ({os.path.basename(exe)}) is checking {len(files)} files ...")
            try:
                rc, out, err = _run_clam(exe, list_file, settings.clamav_extra_args)
            except (OSError, subprocess.TimeoutExpired) as e:
                rc, out, err = 2, "", str(e)
            # 0 = clean, 1 = virus found, 2 = error (errors on single unreadable files are normal)
            if rc in (0, 1) or " FOUND" in out:
                stats["clamav"] = f"used {os.path.basename(exe)}"
                break
            msg = [m for m in (err + "\n" + out).splitlines() if m.strip()]
            best = [m for m in msg if "database" in m.lower() or "connect" in m.lower()] or msg[-1:]
            stats["clamav"] = (f"error from {os.path.basename(exe)}: "
                               f"{best[0].strip() if best else 'unknown error'}")
        else:
            return []
    finally:
        try:
            os.unlink(list_file)
        except OSError:
            pass

    wanted = set(files)
    findings = []
    for line in out.splitlines():
        line = line.rstrip()
        if not line.endswith(" FOUND") or ": " not in line:
            continue
        path, sig = line[: -len(" FOUND")].rsplit(": ", 1)
        if path not in wanted or is_protected(path):
            continue  # only ever report files we asked about
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            continue
        findings.append(Finding(path, "threat", f"ClamAV: {sig}", "high", st.st_size, True, st.st_mtime_ns))
    return findings


# ---------------------------------------------------------------- main entry
def scan(settings: Settings, paths: Optional[list[str]] = None,
         progress: Optional[ProgressFn] = None,
         cancelled: Optional[CancelFn] = None,
         stats: Optional[dict] = None) -> list[Finding]:
    stats = stats if stats is not None else {}
    roots = paths or settings.scan_paths
    sigs = load_signatures()
    from .feeds import ThreatLists
    lists = ThreatLists.get() if settings.threat_feeds_enabled else None
    max_hash = settings.max_hash_mb * 1024 * 1024
    findings: dict[str, Finding] = {}
    scanned: list[str] = []

    for info in walk_files(roots, settings.exclude, progress, cancelled, stats=stats):
        st = info.st
        try:
            with open(info.path, "rb") as f:
                head = f.read(64 * 1024)
        except OSError:
            stats["unreadable"] = stats.get("unreadable", 0) + 1
            continue
        scanned.append(info.path)

        if is_eicar(head, st.st_size):
            findings[info.path] = Finding(info.path, "threat", "EICAR antivirus test file (harmless, used to test scanners)",
                                          "high", st.st_size, True, st.st_mtime_ns)
            continue

        if (sigs or lists) and 0 < st.st_size <= max_hash:
            try:
                digest = sha256_of(info.path, cancelled=cancelled)
            except InterruptedError:
                break
            except OSError:
                digest = ""
            known = sigs.get(digest) if digest else None
            if digest and not known and lists:
                known = lists.lookup(digest)
            if known:
                findings[info.path] = Finding(info.path, "threat", f"Known malware - {known}", "high",
                                              st.st_size, True, st.st_mtime_ns, {"sha256": digest})
                continue

        hits = heuristic_checks(info, head, settings.report_macros)
        if hits:
            sev = min((s for _, s, _ in hits), key=SEVERITY_ORDER.__getitem__)
            findings[info.path] = Finding(info.path, "threat", "; ".join(r for r, _, _ in hits), sev,
                                          st.st_size, any(rec for _, _, rec in hits), st.st_mtime_ns)

    if cancelled and cancelled():
        stats["cancelled"] = True
    elif settings.use_clamav:
        for f in clamav_scan(scanned, settings, stats, progress):
            prev = findings.get(f.path)
            if prev and prev.reason != f.reason:
                f.reason = f"{f.reason}; {prev.reason}"
            findings[f.path] = f
    else:
        stats["clamav"] = "turned off"
    if lists is not None:
        stats["threat_lists"] = sum(idx.count for _, idx in lists.indexes)

    return sorted(findings.values(), key=lambda f: (SEVERITY_ORDER[f.severity], f.path))
