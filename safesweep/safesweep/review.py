"""The Review folder: flagged items wait here until you restore or delete them."""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import Settings
from .models import Finding

MANIFEST = "manifest.json"
DEFANG_SUFFIX = ".quarantined"


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

    @property
    def age_days(self) -> float:
        return (time.time() - self.moved_at) / 86400


class ReviewFolder:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root: Path = settings.review_dir
        self.files = self.root / "files"
        self.files.mkdir(parents=True, exist_ok=True)
        self._manifest = self.root / MANIFEST

    # -- manifest -----------------------------------------------------------
    def _load(self) -> dict[str, ReviewItem]:
        if not self._manifest.exists():
            return {}
        try:
            raw = json.loads(self._manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {k: ReviewItem(**v) for k, v in raw.items()}

    def _save(self, items: dict[str, ReviewItem]) -> None:
        tmp = self._manifest.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: asdict(v) for k, v in items.items()}, indent=2), encoding="utf-8")
        os.replace(tmp, self._manifest)

    def items(self) -> list[ReviewItem]:
        return sorted(self._load().values(), key=lambda i: i.moved_at, reverse=True)

    def stored_path(self, item: ReviewItem) -> Path:
        return self.files / item.stored_name

    # -- operations ---------------------------------------------------------
    def move_in(self, finding: Finding) -> ReviewItem:
        """Move a flagged file into the Review folder (nothing is deleted)."""
        src = Path(finding.path)
        if not src.is_file() or src.is_symlink():
            raise FileNotFoundError(f"Not a regular file: {src}")
        item_id = uuid.uuid4().hex[:12]
        stored = f"{item_id}__{src.name}"
        if finding.category == "threat":
            stored += DEFANG_SUFFIX  # can't be double-clicked / executed by accident
        dest = self.files / stored
        shutil.move(str(src), str(dest))
        if finding.category == "threat":
            try:  # strip execute permissions
                mode = dest.stat().st_mode
                dest.chmod(mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            except OSError:
                pass
        item = ReviewItem(item_id, str(src.resolve() if src.exists() else src.absolute()), stored,
                          finding.category, finding.reason, finding.severity, finding.size, time.time())
        items = self._load()
        items[item_id] = item
        self._save(items)
        return item

    def restore(self, item_id: str, overwrite: bool = False) -> str:
        items = self._load()
        item = items[item_id]
        dest = Path(item.original_path)
        if dest.exists() and not overwrite:
            base, ext = os.path.splitext(dest.name)
            dest = dest.with_name(f"{base} (restored){ext}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.stored_path(item)), str(dest))
        del items[item_id]
        self._save(items)
        return str(dest)

    def delete(self, item_id: str) -> int:
        """Permanently delete one item. Returns bytes freed."""
        items = self._load()
        item = items.pop(item_id)
        p = self.stored_path(item)
        size = p.stat().st_size if p.exists() else 0
        if p.exists():
            p.unlink()
        self._save(items)
        return size

    def purge(self, older_than_days: float | None = None) -> tuple[int, int]:
        """Permanently delete everything (or only items older than N days)."""
        count = freed = 0
        for item in self.items():
            if older_than_days is None or item.age_days >= older_than_days:
                freed += self.delete(item.id)
                count += 1
        return count, freed
