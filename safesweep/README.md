# SafeSweep

A cautious **virus scanner + junk cleaner** for PC (Windows, macOS, Linux) and Android (via Termux).

**Nothing is ever deleted straight away.** Everything SafeSweep flags is first moved to a
**Review folder**, where you can look at it and then **Restore** it or **Delete** it permanently.

## What it does

| Feature | Details |
|---|---|
| 🛡 **Virus Scan** | Known-malware hashes, the EICAR test file, **ClamAV** if installed (used automatically, falls back from the ClamAV service to `clamscan`, and tells you if ClamAV isn't working instead of pretending it scanned), plus heuristics: fake double extensions (`invoice.pdf.exe`, `contract.docx      .exe`), hidden right-to-left filename tricks, real Windows/Linux/Mac programs disguised as photos/documents (checked by file structure, not just the first bytes), and clearly malicious scripts (encoded PowerShell, download-and-run, deleting backups, turning off Defender). |
| 🧹 **Cleanup** | Leftover temp files, stale caches, old logs, thumbnail caches, empty media/document files, **exact duplicates** (proved byte-for-byte; one copy always kept, preferring the one outside Downloads), old installers, downloads not opened in 180+ days, big unused files. |
| ✓ **Recommended vs. "take a look"** | Items that are clearly safe to remove are marked ✓ and pre-selected. Things you might still want (old downloads, backups, big files, macro documents, install scripts) are listed but **not** pre-selected. |
| 📂 **Review Folder** | Flagged files are moved here, not deleted. Threats get a `.quarantined` suffix and lose execute permission. Restore puts files back exactly where they were (never overwriting anything) with their original permissions. Optional auto-delete after 30 days. |
| 🧪 **Self-test** | `safesweep selftest` (or *Help → Run self-test*) builds a sandbox with 50+ tricky cases - real threat patterns, harmless look-alikes, junk vs. important files, crash scenarios - and proves everything behaves correctly **on your device**. |

## Safety rules (why it doesn't misfire)

- **Never deletes on its own.** Only you delete, from the Review folder, after a confirmation.
- **Never touches software:** folders with `.git`, `package.json`, `pyproject.toml`, `.sln`, program libraries (`.dll`/`.so`/`.dylib`), `node_modules`, virtual environments, Mac app bundles and libraries (`.app`, *Photos Library*), hidden config folders and `AppData`/`Library` are skipped.
- **System folders are off-limits** (`C:\Windows`, `Program Files`, `ProgramData`, `/usr`, `/etc`, `/System`, `/Library`, `/Applications`, Android `/system`, Termux's own files).
- **Anything changed in the last 24 hours is ignored** (it may be downloading or open).
- **Old-age checks look at modified, opened *and* created/added dates**, so files freshly extracted from an old zip aren't mistaken for old ones.
- **Duplicates:** only photos, videos, music, documents and archives of 100 KB+; hard links aren't duplicates; checked with a quick hash, a full SHA-256 *and* a byte-by-byte comparison.
- **Just before moving, everything is re-checked:** if the file changed since the scan, or a duplicate's kept copy changed or disappeared, the move is refused.
- **Never follows shortcuts/symlinks/junctions**, never loops, and never opens OneDrive/iCloud "online-only" files (which would download them).
- **Crash-safe Review folder:** a record is written before each move; moves between drives are copy → verify → delete; a lock stops two windows clashing; a backup of the record file is kept; leftovers are repaired automatically on the next start. Every action is written to `activity.log`.

Tested against ~6,600 real-world files (the Python standard library, system libraries, `/usr/share/doc`), including a simulated "3 years later" run: **zero false alarms**.

## Install & run

Requires Python 3.9+. No third-party packages.

```bash
cd safesweep
pip install .            # gives you the `safesweep` and `safesweep-gui` commands
safesweep                # opens the window
```

Or run without installing: `python -m safesweep` (window) / `python -m safesweep --help`.
Double-click launchers: **`SafeSweep.bat`** (Windows), **`SafeSweep.command`** (macOS/Linux).

### Command line

```bash
safesweep scan                      # scan Downloads/Desktop/Documents, then pick: r(ecommended) / a(ll) / 1,3-5 / n(one)
safesweep scan D:\ E:\USB --report-only
safesweep clean                     # find unneeded files
safesweep clean ~/Downloads -y      # move the recommended (✓) items to Review without asking
safesweep clean ~/Downloads -y --all  # ...or everything found
safesweep selftest                  # prove it works correctly on this device

safesweep review list               # see what's waiting
safesweep review restore <id>       # put it back
safesweep review delete <id>        # delete one permanently
safesweep review purge --expired    # delete items older than review_retention_days
safesweep review purge              # empty the Review folder

safesweep settings                  # show settings
safesweep settings --set old_download_days=90 "exclude=*.iso;*/Photos/*"
safesweep signatures add hashes.txt # import more SHA-256 malware hashes
```

`safesweep scan` exits with code 1 if a medium/high threat was found (handy for scheduled tasks).

### Get real-world malware coverage: install ClamAV (free)

SafeSweep's built-in list is deliberately tiny (it contains the harmless EICAR test file so you can
check it works). For actual virus definitions install ClamAV - SafeSweep detects and uses it automatically:

- Windows: <https://www.clamav.net/downloads> (then run `freshclam` once)
- macOS: `brew install clamav && freshclam`
- Linux: `sudo apt install clamav && sudo freshclam`
- Android/Termux: `pkg install clamav && freshclam`

## Mobile

- **Android**: install [Termux](https://f-droid.org/packages/com.termux/), then:
  ```bash
  pkg install python git
  termux-setup-storage            # allow access to your phone's shared storage
  git clone <this repo> && cd newnyansan/safesweep && pip install .
  safesweep scan && safesweep clean
  ```
  It scans your shared storage (Download, DCIM, WhatsApp media, etc.). Android doesn't let any app
  read other apps' private data, so installed-app scanning isn't possible without root.
- **iPhone/iPad**: iOS doesn't allow any app to scan or delete other apps' files, so a real virus
  scanner/cleaner can't exist there (that's also why App Store "antivirus" apps can't scan files).

## Where things are stored

| OS | Settings + Review folder |
|---|---|
| Windows | `%LOCALAPPDATA%\SafeSweep\` |
| macOS | `~/Library/Application Support/SafeSweep/` |
| Linux / Android | `~/.local/share/safesweep/` |

Override with the `SAFESWEEP_HOME` environment variable.

## Honest limitations

SafeSweep is a helpful second line of defence and a tidy-up tool. It is **not** a replacement for
real-time protection: keep Windows Defender / your OS protection on. It scans files on disk; it
doesn't inspect running processes or memory.

## Tests

```bash
python -m unittest discover -s tests -v   # 28 unit tests (includes the 56-check self-test)
python -m safesweep selftest
```

GitHub Actions runs everything on Windows, macOS and Linux with Python 3.9 and 3.13 on every push
(`.github/workflows/safesweep-tests.yml`).
