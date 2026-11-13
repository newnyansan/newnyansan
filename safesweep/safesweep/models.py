"""Shared data types and the safe file walker."""

from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .config import is_protected

ProgressFn = Callable[[str], None]


@dataclass
class Finding:
    path: str
    category: str        # "threat" or "junk"
    reason: str          # human readable
    severity: str = "low"  # low / medium / high
    size: int = 0
    extra: dict = field(default_factory=dict)


def sha256_of(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def walk_files(roots: list[str], exclude: list[str] | None = None,
               progress: ProgressFn | None = None,
               cancelled: Callable[[], bool] | None = None) -> Iterator[os.DirEntry]:
    """Yield regular files under roots. Never follows symlinks, skips protected paths."""
    exclude = exclude or []
    seen_roots: set[str] = set()
    for root in roots:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        real = os.path.realpath(root)
        if real in seen_roots or is_protected(real):
            continue
        seen_roots.add(real)
        stack = [root]
        while stack:
            if cancelled and cancelled():
                return
            d = stack.pop()
            if progress:
                progress(d)
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                continue
            for e in entries:
                if any(fnmatch.fnmatch(e.path, pat) or fnmatch.fnmatch(e.name, pat) for pat in exclude):
                    continue
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if not is_protected(e.path):
                            stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        yield e
                except OSError:
                    continue
