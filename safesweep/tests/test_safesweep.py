import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parents[1]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self._old_home = os.environ.get("SAFESWEEP_HOME")
        os.environ["SAFESWEEP_HOME"] = str(self.base / "app")
        from safesweep.config import Settings
        self.settings = Settings(scan_paths=[], junk_paths=[], use_clamav=False)
        self.data = self.base / "data"
        self.data.mkdir()

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop("SAFESWEEP_HOME", None)
        else:
            os.environ["SAFESWEEP_HOME"] = self._old_home
        self.tmp.cleanup()

    def write(self, rel, content=b"x"):
        p = self.data / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return p

    def finding(self, p, cat="junk", **extra):
        from safesweep.models import Finding
        st = os.stat(p)
        return Finding(str(p), cat, "test", "low", st.st_size, True, st.st_mtime_ns, extra)


class SelfTest(Base):
    def test_builtin_selftest_passes(self):
        from safesweep.selftest import run_selftest
        lines = []
        ok, failures = run_selftest(lines.append)
        self.assertTrue(ok, "\n".join(lines))
        self.assertEqual(failures, [])

    def test_own_source_code_scans_clean(self):
        """SafeSweep must not flag itself (its patterns/test strings are built to avoid that)."""
        from safesweep.scanner import scan
        res = scan(self.settings, [str(PKG_DIR)])
        self.assertEqual([(f.path, f.reason) for f in res], [])


class ScannerTests(Base):
    def test_single_file_root(self):
        from safesweep.scanner import EICAR, scan
        p = self.write("x.com", EICAR)
        self.assertEqual(len(scan(self.settings, [str(p)])), 1)

    def test_exclude_patterns(self):
        from safesweep.scanner import EICAR, scan
        self.write("skipme/x.com", EICAR)
        self.write("y.com", EICAR)
        self.settings.exclude = ["*skipme*"]
        res = scan(self.settings, [str(self.data)])
        self.assertEqual([Path(f.path).name for f in res], ["y.com"])

    def test_cancel_stops_quickly(self):
        from safesweep.scanner import scan
        for i in range(200):
            self.write(f"d{i % 20}/f{i}.txt", b"hello")
        stats = {}
        res = scan(self.settings, [str(self.data)], cancelled=lambda: True, stats=stats)
        self.assertEqual(res, [])
        self.assertTrue(stats.get("cancelled"))

    def test_unicode_and_long_names(self):
        from safesweep.scanner import scan
        self.write("ünïcødé 写真.jpg.exe", b"x")
        self.write(("a" * 150) + ".pdf.exe", b"x")
        self.assertEqual(len(scan(self.settings, [str(self.data)])), 2)

    @unittest.skipIf(os.name == "nt", "uses shell scripts")
    def test_clamav_fallback_and_output_filtering(self):
        from safesweep.config import Settings
        from safesweep.scanner import clamav_scan
        target = self.write("infected.bin", b"x")
        other = self.data / "not-requested.bin"
        bindir = self.base / "bin"
        bindir.mkdir()
        (bindir / "clamdscan").write_text("#!/bin/sh\necho 'ERROR: Could not connect to clamd' >&2\nexit 2\n")
        (bindir / "clamscan").write_text(
            "#!/bin/sh\n"
            f"echo '{target}: Win.Test.Fake FOUND'\n"
            f"echo '{other}: Should.Be.Ignored FOUND'\n"
            "exit 1\n")
        for f in bindir.iterdir():
            f.chmod(0o755)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{bindir}{os.pathsep}{old_path}"
        try:
            stats = {}
            res = clamav_scan([str(target)], Settings(use_clamav=True), stats)
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual([(f.path, f.reason) for f in res], [(str(target), "ClamAV: Win.Test.Fake")])
        self.assertEqual(stats["clamav"], "used clamscan")

    @unittest.skipIf(os.name == "nt", "uses shell scripts")
    def test_clamav_total_failure_is_reported(self):
        from safesweep.config import Settings
        from safesweep.scanner import clamav_scan
        t = self.write("a.bin")
        bindir = self.base / "bin"
        bindir.mkdir()
        for name in ("clamscan", "clamdscan"):
            (bindir / name).write_text("#!/bin/sh\necho 'LibClamAV Error: No supported database files found' >&2\nexit 2\n")
            (bindir / name).chmod(0o755)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = str(bindir)
        try:
            stats = {}
            self.assertEqual(clamav_scan([str(t)], Settings(), stats), [])
        finally:
            os.environ["PATH"] = old_path
        self.assertIn("database", stats["clamav"])


class WalkerTests(Base):
    def test_protected_and_own_data_skipped(self):
        from safesweep.config import app_home, is_protected
        self.assertTrue(is_protected(str(app_home())))
        self.assertTrue(is_protected(str(app_home() / "Review" / "x")))
        self.assertFalse(is_protected(str(app_home()) + "-other"))  # prefix trick
        if os.name != "nt":
            self.assertTrue(is_protected("/usr/bin"))
            self.assertTrue(is_protected("/etc/passwd"))

    @unittest.skipIf(os.name == "nt", "symlinks need admin on Windows")
    def test_symlink_loops_and_links_not_followed(self):
        from safesweep.models import walk_files
        self.write("a/real.txt")
        os.symlink(self.data, self.data / "a" / "loop")
        os.symlink(self.data / "a" / "real.txt", self.data / "link.txt")
        files = [i.name for i in walk_files([str(self.data)])]
        self.assertEqual(files, ["real.txt"])

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "permissions are not enforced for root")
    def test_unreadable_folder_does_not_crash(self):
        from safesweep.scanner import scan
        d = self.data / "locked"
        d.mkdir()
        (d / "x.exe").write_bytes(b"x")
        d.chmod(0)
        try:
            stats = {}
            scan(self.settings, [str(self.data)], stats=stats)
            self.assertGreaterEqual(stats["skipped"], 1)
        finally:
            d.chmod(0o755)


class JunkTests(Base):
    def test_root_kind_detection(self):
        from safesweep.junk import _root_kind
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(_root_kind(t), "temp")
        self.assertEqual(_root_kind(str(Path.home() / "Documents")), "user")
        self.assertEqual(_root_kind(str(Path.home() / "SomeApp" / "Caches")), "cache")

    def test_stress_many_files(self):
        from safesweep.junk import find_junk
        payload = os.urandom(120 * 1024)
        for i in range(3000):
            self.write(f"Pictures/{i % 30}/img{i}.jpg", payload if i < 4 else str(i).encode() * 10)
        t = time.time()
        res = find_junk(self.settings, [str(self.data)], now=time.time() + 400 * 86400, kind="user")
        self.assertLess(time.time() - t, 30)
        dups = [f for f in res if "duplicate" in f.reason.lower()]
        self.assertEqual(len(dups), 3)  # 4 identical photos -> 3 duplicates, 1 kept


class ReviewTests(Base):
    def test_concurrent_moves_from_two_windows(self):
        from safesweep.review import ReviewFolder
        files = [self.write(f"f{i}.tmp", str(i).encode()) for i in range(40)]
        a, b = ReviewFolder(self.settings), ReviewFolder(self.settings)
        errors = []

        def mover(rf, chunk):
            for p in chunk:
                try:
                    rf.move_in(self.finding(p))
                except Exception as e:
                    errors.append(e)

        t1 = threading.Thread(target=mover, args=(a, files[::2]))
        t2 = threading.Thread(target=mover, args=(b, files[1::2]))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(ReviewFolder(self.settings).items()), 40)

    def test_busy_lock_gives_clear_error(self):
        from safesweep.review import ReviewError, ReviewFolder
        rf = ReviewFolder(self.settings)
        with rf._locked():
            with self.assertRaises(ReviewError):
                with rf._locked(timeout=0.2):
                    pass

    def test_stale_lock_from_crashed_process_is_cleared(self):
        from safesweep.review import ReviewFolder
        rf = ReviewFolder(self.settings)
        rf._lockfile.write_text("999999999")  # a PID that doesn't exist
        old = time.time() - 4000
        os.utime(rf._lockfile, (old, old))
        rf.move_in(self.finding(self.write("a.tmp")))
        self.assertEqual(len(rf.items()), 1)

    def test_long_unicode_name_roundtrip(self):
        from safesweep.review import ReviewFolder
        rf = ReviewFolder(self.settings)
        p = self.write(("ü" * 110) + ".jpg", b"photo")
        it = rf.move_in(self.finding(p))
        self.assertLessEqual(len(it.stored_name.encode()), 255)
        self.assertEqual(rf.restore(it.id), str(p))
        self.assertEqual(p.read_bytes(), b"photo")

    def test_restore_twice_occupied_names(self):
        from safesweep.review import ReviewFolder
        rf = ReviewFolder(self.settings)
        paths = []
        for _ in range(3):
            p = self.write("doc.txt", b"v")
            it = rf.move_in(self.finding(p))
            paths.append(it.id)
        self.write("doc.txt", b"current")
        restored = sorted(Path(rf.restore(i)).name for i in paths)
        self.assertEqual(restored, ["doc (restored 2).txt", "doc (restored 3).txt", "doc (restored).txt"])
        self.assertEqual((self.data / "doc.txt").read_bytes(), b"current")

    def test_id_prefix_and_unknown_id(self):
        from safesweep.review import ReviewError, ReviewFolder
        rf = ReviewFolder(self.settings)
        it = rf.move_in(self.finding(self.write("a.tmp")))
        self.assertEqual(rf.get(it.id[:6]).id, it.id)
        with self.assertRaises(ReviewError):
            rf.get("nope")

    def test_symlink_never_moved(self):
        if os.name == "nt":
            self.skipTest("symlinks need admin on Windows")
        from safesweep.models import Finding
        from safesweep.review import ReviewError, ReviewFolder
        real = self.write("real.txt")
        link = self.data / "link.txt"
        os.symlink(real, link)
        with self.assertRaises(ReviewError):
            ReviewFolder(self.settings).move_in(Finding(str(link), "junk", "t"))
        self.assertTrue(real.exists() and link.is_symlink())


class SettingsTests(Base):
    def test_validation(self):
        s = self.settings
        with self.assertRaises(KeyError):
            s.set_value("nope", "1")
        for key, bad in (("old_download_days", "-5"), ("old_download_days", "0"), ("use_clamav", "maybe"),
                         ("large_file_mb", "lots")):
            with self.assertRaises(ValueError):
                s.set_value(key, bad)
        s.set_value("exclude", "*.iso; */Photos/* ;")
        self.assertEqual(s.exclude, ["*.iso", "*/Photos/*"])
        s.set_value("use_clamav", "off")
        self.assertFalse(s.use_clamav)

    def test_corrupt_or_bad_settings_file(self):
        from safesweep.config import Settings
        Settings.path().parent.mkdir(parents=True, exist_ok=True)
        Settings.path().write_text("{not json")
        self.assertEqual(Settings.load().old_download_days, 180)
        Settings.path().write_text(json.dumps({"old_download_days": "abc", "large_file_mb": 7, "x": 1}))
        s = Settings.load()
        self.assertEqual((s.old_download_days, s.large_file_mb), (180, 7))


class CliTests(Base):
    def run_cli(self, *args, stdin=""):
        env = dict(os.environ, PYTHONPATH=str(PKG_DIR))
        return subprocess.run([sys.executable, "-m", "safesweep", *args], input=stdin, capture_output=True,
                              text=True, env=env, cwd=str(PKG_DIR), timeout=120)

    def test_parse_selection(self):
        from safesweep.cli import _parse_selection
        self.assertEqual(_parse_selection("1,3-4", 5), [1, 3, 4])
        self.assertIsNone(_parse_selection("0", 5))
        self.assertIsNone(_parse_selection("9", 5))
        self.assertIsNone(_parse_selection("x", 5))

    def test_scan_report_only_and_exit_code(self):
        from safesweep.scanner import EICAR
        self.write("e.com", EICAR)
        r = self.run_cli("settings", "--set", "use_clamav=false")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self.run_cli("scan", str(self.data), "--report-only")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("EICAR", r.stdout)
        self.assertTrue((self.data / "e.com").exists())

    def test_interactive_move_then_restore(self):
        from safesweep.scanner import EICAR
        self.write("e.com", EICAR)
        self.run_cli("settings", "--set", "use_clamav=false")
        r = self.run_cli("scan", str(self.data), stdin="bogus\nr\n")
        self.assertIn("Please type", r.stdout)
        self.assertFalse((self.data / "e.com").exists())
        listing = self.run_cli("review", "list").stdout
        item_id = listing.split()[0]
        r = self.run_cli("review", "restore", item_id)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue((self.data / "e.com").exists())

    def test_delete_requires_confirmation(self):
        from safesweep.review import ReviewFolder
        it = ReviewFolder(self.settings).move_in(self.finding(self.write("a.tmp")))
        r = self.run_cli("review", "delete", it.id, stdin="n\n")
        self.assertEqual(len(ReviewFolder(self.settings).items()), 1, r.stdout)
        r = self.run_cli("review", "purge", stdin="\n")  # EOF / empty = no
        self.assertEqual(len(ReviewFolder(self.settings).items()), 1, r.stdout)

    def test_bad_settings_command(self):
        r = self.run_cli("settings", "--set", "nope=1")
        self.assertEqual(r.returncode, 2)
        self.assertIn("Unknown setting", r.stdout)

    def test_selftest_command(self):
        r = self.run_cli("selftest")
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
