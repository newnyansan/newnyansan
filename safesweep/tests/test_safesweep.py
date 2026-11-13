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


class AppTests(Base):
    def test_mobile_module_imports_without_kivy(self):
        import importlib
        m = importlib.import_module("safesweep.mobile")
        self.assertEqual(m.human(2048), "2.0 KB")
        self.assertTrue(m.has_storage_access())  # desktop: always true

    def test_installed_program_folder_is_protected(self):
        from safesweep import config
        os.environ["ANDROID_PRIVATE"] = str(self.data)
        try:
            self.assertTrue(config.is_protected(str(self.data / "app" / "main.pyc")))
        finally:
            del os.environ["ANDROID_PRIVATE"]
        self.assertFalse(config.is_protected(str(self.data / "x")))

    def test_packaging_files_are_consistent(self):
        spec = (PKG_DIR / "buildozer.spec").read_text()
        for needed in ("main.py", "safesweep/data/*.txt", "assets/icon.png", "MANAGE_EXTERNAL_STORAGE"):
            self.assertIn(needed, spec)
        for p in ("assets/icon.png", "assets/icon.ico", "assets/presplash.png", "main.py",
                  "packaging/windows/safesweep.spec", "packaging/windows/installer.iss",
                  "packaging/android/manifest_application_args.xml"):
            self.assertTrue((PKG_DIR / p).exists(), p)


class FeedSecurityTests(Base):
    """Real HTTPS against a local server: verification must not be bypassable."""

    def setUp(self):
        super().setUp()
        import shutil
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        self.cert, self.key = str(self.base / "cert.pem"), str(self.base / "key.pem")
        r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                            "-keyout", self.key, "-out", self.cert], capture_output=True)
        if r.returncode:
            self.skipTest("openssl could not create a test certificate")
        import http.server
        import ssl
        body = b'# "sha256_hash","signature"\n"' + b"b" * 64 + b'","Test"\n'

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://evil.example.com/x")
                    self.end_headers()
                    return
                if self.path == "/big":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"x" * 300_000)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        self._no_proxy = os.environ.get("NO_PROXY"), os.environ.get("no_proxy")
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

    def tearDown(self):
        if hasattr(self, "httpd"):
            self.httpd.shutdown()
            for k, v in zip(("NO_PROXY", "no_proxy"), self._no_proxy):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        super().tearDown()

    def test_untrusted_certificate_is_refused(self):
        from safesweep.feeds import FeedError, download
        with self.assertRaises(FeedError) as cm:
            download(self.url + "/list", str(self.base / "out"), 10_000, allowed_hosts=frozenset({"127.0.0.1"}))
        self.assertIn("verified", str(cm.exception))
        self.assertFalse((self.base / "out").exists() and (self.base / "out").stat().st_size)

    def test_trusted_certificate_works_and_limits_apply(self):
        import ssl
        from safesweep.feeds import FeedError, download
        ctx = ssl.create_default_context(cafile=self.cert)
        n = download(self.url + "/list", str(self.base / "out"), 10_000,
                     allowed_hosts=frozenset({"127.0.0.1"}), context=ctx)
        self.assertGreater(n, 60)
        with self.assertRaises(FeedError):  # redirect to a host that is not on the list
            download(self.url + "/redirect", str(self.base / "o2"), 10_000,
                     allowed_hosts=frozenset({"127.0.0.1"}), context=ctx)
        with self.assertRaises(FeedError):  # bigger than the size limit
            download(self.url + "/big", str(self.base / "o3"), 100_000,
                     allowed_hosts=frozenset({"127.0.0.1"}), context=ctx)

    def test_hash_index_lookup(self):
        import hashlib
        from safesweep.feeds import HashIndex
        hs = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(5000)]
        p = self.base / "x.bin"
        self.assertEqual(HashIndex.write(p, hs), 5000)
        idx = HashIndex(p)
        try:
            self.assertTrue(all(bytes.fromhex(h) in idx for h in hs[::97]))
            self.assertFalse(bytes.fromhex("0" * 64) in idx)
            self.assertFalse(bytes.fromhex("f" * 64) in idx)
        finally:
            idx.close()


class ScheduleTests(Base):
    def test_windows_task_definition(self):
        import xml.etree.ElementTree as ET
        from safesweep import schedule
        xml = schedule.windows_task_xml(12, 30, [r"C:\Users\Me\AppData\Local\Programs\SafeSweep\SafeSweep.exe",
                                                 "--auto"], "PC\\Me")
        root = ET.fromstring(xml.encode("utf-16"))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        get = lambda path: root.find(path, ns).text
        self.assertEqual(get("t:Settings/t:StartWhenAvailable"), "true")        # catches up missed runs
        self.assertEqual(get("t:Settings/t:DisallowStartIfOnBatteries"), "false")
        self.assertEqual(get("t:Principals/t:Principal/t:RunLevel"), "LeastPrivilege")  # no admin rights
        self.assertEqual(get("t:Triggers/t:CalendarTrigger/t:ScheduleByDay/t:DaysInterval"), "1")  # daily
        self.assertTrue(get("t:Triggers/t:CalendarTrigger/t:StartBoundary").endswith("T12:30:00"))
        self.assertEqual(get("t:Actions/t:Exec/t:Arguments"), "--auto")

    def test_linux_and_mac_definitions(self):
        import plistlib
        from safesweep import schedule
        service, timer = schedule.systemd_units(7, 5, ["/usr/bin/python3", "-m", "safesweep", "auto"])
        self.assertIn("OnCalendar=*-*-* 07:05:00", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("ExecStart=/usr/bin/python3 -m safesweep auto", service)
        plist = plistlib.loads(schedule.launchd_plist(7, 5, ["/usr/bin/python3", "-m", "safesweep", "auto"]).encode())
        self.assertEqual(plist["StartCalendarInterval"], {"Hour": 7, "Minute": 5})
        self.assertEqual(plist["ProgramArguments"][-1], "auto")

    def test_time_validation(self):
        from safesweep import schedule
        self.assertEqual(schedule._parse_time("09:05"), (9, 5))
        for bad in ("25:00", "9", "12:60", "noon"):
            with self.assertRaises(ValueError):
                schedule._parse_time(bad)


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
        r = self.run_cli("settings", "--set", "use_clamav=false", "threat_feeds_enabled=false")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self.run_cli("scan", str(self.data), "--report-only")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("EICAR", r.stdout)
        self.assertTrue((self.data / "e.com").exists())

    def test_interactive_move_then_restore(self):
        from safesweep.scanner import EICAR
        self.write("e.com", EICAR)
        self.run_cli("settings", "--set", "use_clamav=false")
        r = self.run_cli("scan", str(self.data), "--offline", stdin="bogus\nr\n")
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

    def test_auto_command_and_review_location(self):
        from safesweep.scanner import EICAR
        self.write("e.com", EICAR)
        self.write("fine.txt", b"ok")
        self.run_cli("settings", "--set", f"scan_paths={self.data}", "use_clamav=false", "threat_feeds_enabled=false")
        r = self.run_cli("auto", "--no-notify")
        self.assertEqual(r.returncode, 1, r.stdout)  # 1 = something needed attention
        self.assertIn("moved 1 threat", r.stdout)
        self.assertFalse((self.data / "e.com").exists())
        r = self.run_cli("auto", "--no-notify")
        self.assertEqual(r.returncode, 0, r.stdout)
        other = self.base / "elsewhere"
        other.mkdir()
        r = self.run_cli("review", "location", str(other))
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(any((other / "SafeSweep Review" / "files").iterdir()))
        r = self.run_cli("review", "location", str(self.base / "nope"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("not found", r.stdout)
        r = self.run_cli("settings", "--set", f"review_folder={other}")
        self.assertEqual(r.returncode, 2)

    def test_selftest_command(self):
        r = self.run_cli("selftest")
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
