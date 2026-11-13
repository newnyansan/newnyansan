"""Threat scanning: hash signatures, heuristics and (optional) ClamAV."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

from .config import Settings, app_home
from .models import Finding, ProgressFn, sha256_of, walk_files

BUILTIN_SIGS = Path(__file__).with_name("data") / "signatures.txt"

EXECUTABLE_EXT = {".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                  ".wsf", ".wsh", ".ps1", ".hta", ".msi", ".jar", ".apk", ".lnk", ".dll", ".cpl"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png",
           ".gif", ".txt", ".mp3", ".mp4", ".zip", ".rar"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

# Patterns frequently found in malicious scripts. Each one alone is only "suspicious".
SCRIPT_PATTERNS = [
    (re.compile(rb"powershell(\.exe)?\s+[^\n]{0,80}-(enc|encodedcommand)\b", re.I), "Encoded PowerShell command"),
    (re.compile(rb"IEX\s*\(\s*New-Object\s+Net\.WebClient", re.I), "PowerShell download-and-execute"),
    (re.compile(rb"(curl|wget)\s+[^\n|]{1,200}\|\s*(ba)?sh\b", re.I), "Downloads and pipes into a shell"),
    (re.compile(rb"WScript\.Shell[\s\S]{0,300}\.Run", re.I), "VBScript launches programs"),
    (re.compile(rb"FromBase64String\([\s\S]{0,40}\)[\s\S]{0,200}(Invoke|IEX)", re.I), "Decodes and runs hidden code"),
    (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.I), "Deletes backups (ransomware behaviour)"),
    (re.compile(rb"bcdedit[^\n]{0,40}recoveryenabled\s+no", re.I), "Disables recovery (ransomware behaviour)"),
]
SCRIPT_EXT = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta", ".sh", ".wsf", ".py"}

RIGHT_TO_LEFT_OVERRIDE = "‮"


def load_signatures() -> dict[str, str]:
    sigs: dict[str, str] = {}
    for src in (BUILTIN_SIGS, app_home() / "signatures.txt"):
        if not src.exists():
            continue
        for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            h = parts[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", h):
                sigs[h] = parts[1].strip() if len(parts) > 1 else "Known malware"
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
                name = parts[1] if len(parts) > 1 else "Imported signature"
                out.write(f"{parts[0].lower()}  {name}\n")
                existing[parts[0].lower()] = name
                added += 1
    return added


def heuristic_checks(entry: os.DirEntry, head: bytes) -> list[tuple[str, str]]:
    """Return (reason, severity) pairs for one file."""
    name = entry.name
    lower = name.lower()
    stem, ext = os.path.splitext(lower)
    hits: list[tuple[str, str]] = []

    if RIGHT_TO_LEFT_OVERRIDE in name:
        hits.append(("Filename uses a hidden right-to-left character to fake its extension", "high"))

    inner_ext = os.path.splitext(stem)[1]
    if ext in EXECUTABLE_EXT and inner_ext in DOC_EXT:
        hits.append((f"Double extension: pretends to be {inner_ext} but is {ext}", "high"))

    # Windows executable header hidden behind a harmless extension
    if head.startswith(b"MZ") and ext in DOC_EXT:
        hits.append((f"Windows program disguised as {ext}", "high"))
    if head.startswith(b"\x7fELF") and ext in DOC_EXT:
        hits.append((f"Linux program disguised as {ext}", "high"))

    if lower == "autorun.inf":
        hits.append(("autorun.inf can auto-launch programs from removable drives", "medium"))

    if ext in MACRO_EXT:
        hits.append(("Office document with macros enabled", "low"))

    if ext in SCRIPT_EXT:
        for pattern, reason in SCRIPT_PATTERNS:
            if pattern.search(head):
                hits.append((reason, "high"))
    return hits


def clamav_available() -> str | None:
    return shutil.which("clamdscan") or shutil.which("clamscan")


def clamav_scan(paths: list[str], progress: ProgressFn | None = None) -> list[Finding]:
    exe = clamav_available()
    if not exe or not paths:
        return []
    if progress:
        progress(f"Running ClamAV ({os.path.basename(exe)}) ...")
    cmd = [exe, "--infected", "--no-summary"]
    if "clamscan" in os.path.basename(exe):
        cmd.append("--recursive")
    try:
        proc = subprocess.run(cmd + paths, capture_output=True, text=True, timeout=6 * 3600)
    except (OSError, subprocess.TimeoutExpired):
        return []
    findings = []
    for line in proc.stdout.splitlines():
        if line.endswith(" FOUND") and ": " in line:
            path, sig = line[:-6].rsplit(": ", 1)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            findings.append(Finding(path, "threat", f"ClamAV: {sig}", "high", size))
    return findings


def scan(settings: Settings, paths: list[str] | None = None,
         progress: ProgressFn | None = None,
         cancelled: Callable[[], bool] | None = None) -> list[Finding]:
    roots = paths or settings.scan_paths
    sigs = load_signatures()
    max_hash = settings.max_hash_mb * 1024 * 1024
    findings: dict[str, Finding] = {}

    for entry in walk_files(roots, settings.exclude, progress, cancelled):
        try:
            size = entry.stat(follow_symlinks=False).st_size
            with open(entry.path, "rb") as f:
                head = f.read(64 * 1024)
        except OSError:
            continue

        if size <= max_hash:
            try:
                digest = sha256_of(entry.path)
            except OSError:
                digest = ""
            if digest in sigs:
                findings[entry.path] = Finding(entry.path, "threat", f"Known malware: {sigs[digest]}",
                                               "high", size, {"sha256": digest})
                continue

        hits = heuristic_checks(entry, head)
        if hits:
            order = {"low": 0, "medium": 1, "high": 2}
            sev = max((s for _, s in hits), key=order.__getitem__)
            findings[entry.path] = Finding(entry.path, "threat", "; ".join(r for r, _ in hits), sev, size)

    if settings.use_clamav and not (cancelled and cancelled()):
        for f in clamav_scan([os.path.expanduser(p) for p in roots if os.path.isdir(os.path.expanduser(p))], progress):
            findings[f.path] = f  # ClamAV verdict wins

    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings.values(), key=lambda f: (order[f.severity], f.path))
