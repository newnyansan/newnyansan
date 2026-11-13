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

## Automatic daily check (no prompts)

SafeSweep checks for threats **every day on its own** - you don't need to open it or approve anything.

| | How it runs | Turn on/off |
|---|---|---|
| **Windows** | Task Scheduler, every day at 12:30 (or as soon as the PC is on if it was off); no window, no admin rights | Installer option (on by default), menu **Automatic**, or `safesweep schedule on/off` |
| **Android** | Exact daily alarm + a background job that survives restarts; catches up if the phone was off | Switch on the Scan screen (on by default) |
| **macOS / Linux** | launchd agent / systemd user timer | `safesweep schedule on/off` |

Each run: refreshes the threat lists → scans your scan folders (only new or changed files are read;
everything is re-read once a week) → **moves confirmed, high-confidence threats to the Review folder**
→ writes a report (`reports/` in SafeSweep's data folder) → **notifies you only if something was found**.
Nothing is ever deleted automatically and junk cleaning stays manual.

**Why daily, not weekly:** the abuse.ch "recent" lists only cover the last 48 hours, so a weekly check
would miss most new samples.

Change the time with `safesweep schedule on --time 08:15`; run a check right now with `safesweep auto`.

## Choosing where the Review folder is

By default it lives in SafeSweep's data folder. Pick another place - e.g. *Documents*, another drive,
or an SD card on Android - with **Change folder…** (Review tab), the location picker on the phone's
Review screen, or `safesweep review location <folder>` (`default` to go back).

- SafeSweep creates a dedicated `SafeSweep Review` folder inside the place you pick.
- Items already waiting are **copied and verified first**; only then are the old copies removed.
  If anything fails, nothing changes.
- The Review folder is never scanned, wherever you put it (no "finding" the quarantined threats again).
- System and program folders are refused.

## Online threat lists (verified sources only)

SafeSweep checks every scanned file's fingerprint against lists of **confirmed malware** - viruses,
trojans, ransomware, info-stealers, etc. Only these built-in sources are used, only over verified HTTPS:

| Source | What it is | Key needed? |
|---|---|---|
| [MalwareBazaar](https://bazaar.abuse.ch) by abuse.ch | Malware confirmed by security researchers, updated continuously, with family names (e.g. *AgentTesla*) | **Free Auth-Key** |
| [ThreatFox](https://threatfox.abuse.ch) by abuse.ch | File fingerprints from incident responders (confidence ≥ 50% only) | **Free Auth-Key** |
| [VirusShare](https://virusshare.com) | Large archive of known malware (MD5 lists; the newest 16 lists ≈ 1 million samples). No new lists since 2022, so it covers older malware | No |
| [ClamAV](https://www.clamav.net) official definitions | Updated daily with `freshclam` when ClamAV is installed | No |

**Get the daily-updated abuse.ch lists (recommended):** abuse.ch requires a free personal key for downloads.
Sign in at <https://auth.abuse.ch>, copy your Auth-Key, then run
`safesweep settings --set abusech_auth_key=YOUR_KEY` (the key is never printed or written into logs).

- Lists refresh automatically (daily; VirusShare weekly) and build up over time; abuse.ch entries expire after a year.
- Certificates are verified; redirects to other hosts, oversized downloads, web/error pages and empty
  lists are rejected. **A failed update never replaces the lists you already have.**
- Fingerprints of harmless content (e.g. an empty file) are ignored even if a list contains them.

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

## Install

### Windows (installer)

1. Download **`SafeSweep-Setup-<version>.exe`** (see *Getting the installers* below).
2. Double-click it. No administrator rights are needed - it installs just for you.
   Windows may show *"Windows protected your PC"* because the installer isn't code-signed:
   click **More info → Run anyway**.
3. Start **SafeSweep** from the Start menu (there is also a *SafeSweep self-test* shortcut).

Uninstall from *Settings → Apps*. Your Review folder (`%LOCALAPPDATA%\SafeSweep`) is kept, so
nothing waiting for review is lost.

### Android (APK)

1. Copy **`safesweep-<version>-*-debug.apk`** to your phone and tap it.
2. Allow *Install unknown apps* for your browser/file manager when asked.
3. Open SafeSweep and tap **Open settings → Allow access to manage all files** (needed to scan
   your storage; your files never leave the phone).
4. Scan / Clean / Review work like on the PC. The Review folder is `SafeSweep/Review` on your phone
   storage, so you can also look at it in any file manager (it's hidden from the gallery).

Works on Android 7+ (64-bit and 32-bit ARM phones, and x86_64 Chromebooks/emulators).
Android doesn't let any app look inside other apps' private data, so SafeSweep checks your shared
storage: Downloads, photos, WhatsApp/Telegram media, documents, etc.

### Getting the installers

Every push builds both automatically (GitHub → *Actions* → **SafeSweep apps** → latest run →
*Artifacts*): `SafeSweep-Windows-Installer` and `SafeSweep-Android-APK`.
Before they are published, each one is tested for real:

- **Windows:** the built program runs its self-test, then the installer is installed silently, the
  installed program runs its self-test, the window is opened, and it is uninstalled again.
- **Android:** the APK is installed on an Android 13 emulator with test files; the app runs its
  self-test, a virus scan, a cleanup and a move to Review, and every result is checked.

### Build them yourself

```bash
# Windows (on a Windows PC with Python 3.9+ and Inno Setup 6)
pip install pyinstaller
pyinstaller packaging/windows/safesweep.spec
iscc /DAppVersion=0.3.0 packaging/windows/installer.iss     # -> dist/SafeSweep-Setup-0.3.0.exe

# Android (on Linux/macOS/WSL)
pip install buildozer "cython<=3.0.12"
# python-for-android needs a one-line fix for multi-architecture builds (see the
# "Get python-for-android" step in .github/workflows/safesweep-apps.yml), or build one
# architecture at a time by setting android.archs = arm64-v8a
buildozer android debug                                     # -> bin/*.apk
```

### Run from source (any OS)

```bash
pip install .            # gives you the `safesweep` and `safesweep-gui` commands
safesweep                # opens the window
pip install kivy && python main.py   # the phone app, in a desktop window
```

### Command line

```bash
safesweep scan                      # scan Downloads/Desktop/Documents, then pick: r(ecommended) / a(ll) / 1,3-5 / n(one)
safesweep scan D:\ E:\USB --report-only
safesweep clean                     # find unneeded files
safesweep clean ~/Downloads -y      # move the recommended (✓) items to Review without asking
safesweep clean ~/Downloads -y --all  # ...or everything found
safesweep selftest                  # prove it works correctly on this device
safesweep update                    # download the latest threat lists now
safesweep auto                      # run the automatic check now (what the daily schedule runs)
safesweep schedule on|off|status    # the daily automatic check
safesweep review location D:\Quarantine   # move the Review folder (and its items) somewhere else

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

- **Android app**: see *Install → Android* above. Alternatively install [Termux](https://f-droid.org/packages/com.termux/), then:
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
python -m unittest discover -s tests -v   # 38 unit tests (includes the 90-check self-test)
python -m safesweep selftest
```

GitHub Actions runs everything on Windows, macOS and Linux with Python 3.9 and 3.13 on every push
(`.github/workflows/safesweep-tests.yml`).
