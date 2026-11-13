import os
import time
import unittest
import tempfile
from pathlib import Path

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class SafeSweepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        os.environ["SAFESWEEP_HOME"] = str(base / "home")
        self.data = base / "data"
        (self.data / "Downloads").mkdir(parents=True)
        from safesweep.config import Settings
        self.settings = Settings(scan_paths=[str(self.data)], junk_paths=[str(self.data)], use_clamav=False)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, content=b"x", age_days=0):
        p = self.data / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        if age_days:
            t = time.time() - age_days * 86400
            os.utime(p, (t, t))
        return p

    def test_scan_detects_threats(self):
        from safesweep.scanner import scan
        self.write("eicar.com", EICAR)
        self.write("invoice.pdf.exe", b"MZ....")
        self.write("photo.jpg", b"MZ\x90\x00 fake image")
        self.write("run.ps1", b"powershell -enc SQBFAFgA")
        self.write("notes.txt", b"hello world")
        reasons = {Path(f.path).name: f.reason for f in scan(self.settings)}
        self.assertIn("EICAR", reasons["eicar.com"])
        self.assertIn("Double extension", reasons["invoice.pdf.exe"])
        self.assertIn("disguised", reasons["photo.jpg"])
        self.assertIn("PowerShell", reasons["run.ps1"])
        self.assertNotIn("notes.txt", reasons)

    def test_junk_detection(self):
        from safesweep.junk import find_junk
        self.write("a.tmp")
        self.write("empty.txt", b"")
        self.write("Downloads/setup.exe", b"installer", age_days=60)
        self.write("Downloads/old.pdf", b"old doc", age_days=400)
        self.write("Downloads/new.pdf", b"fresh doc")
        orig = self.write("docs/report.docx", b"same bytes", age_days=10)
        self.write("docs/report (1).docx", b"same bytes")
        found = {Path(f.path).name: f.reason for f in find_junk(self.settings)}
        for name in ("a.tmp", "empty.txt", "setup.exe", "old.pdf", "report (1).docx"):
            self.assertIn(name, found)
        self.assertNotIn("new.pdf", found)
        self.assertNotIn("report.docx", found)  # original copy is kept
        self.assertIn(str(orig), found["report (1).docx"])

    def test_review_move_restore_delete(self):
        from safesweep.models import Finding
        from safesweep.review import ReviewFolder
        rf = ReviewFolder(self.settings)
        a = self.write("keep.txt", b"keep me")
        b = self.write("bad.exe", b"MZ bad")
        b.chmod(0o755)
        ia = rf.move_in(Finding(str(a), "junk", "test", size=7))
        ib = rf.move_in(Finding(str(b), "threat", "test", "high", 6))
        self.assertFalse(a.exists())
        self.assertTrue(rf.stored_path(ib).name.endswith(".quarantined"))
        if os.name != "nt":
            self.assertFalse(os.access(rf.stored_path(ib), os.X_OK))
        self.assertEqual(len(rf.items()), 2)

        self.assertEqual(rf.restore(ia.id), str(a.resolve()))
        self.assertEqual(a.read_bytes(), b"keep me")
        self.assertEqual(rf.delete(ib.id), 6)
        self.assertEqual(rf.items(), [])
        self.assertEqual(list(rf.files.iterdir()), [])

    def test_purge_expired_only(self):
        from safesweep.models import Finding
        from safesweep.review import ReviewFolder
        rf = ReviewFolder(self.settings)
        old = rf.move_in(Finding(str(self.write("old.tmp")), "junk", "t"))
        rf.move_in(Finding(str(self.write("new.tmp")), "junk", "t"))
        items = rf._load()
        items[old.id].moved_at -= 40 * 86400
        rf._save(items)
        self.assertEqual(rf.purge(30)[0], 1)
        self.assertEqual(len(rf.items()), 1)

    def test_protected_paths_skipped(self):
        from safesweep.config import is_protected
        self.assertTrue(is_protected(os.environ["SAFESWEEP_HOME"]))
        if os.name != "nt":
            self.assertTrue(is_protected("/usr/bin"))


if __name__ == "__main__":
    unittest.main()
