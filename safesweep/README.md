# SafeSweep

A cautious **virus scanner + junk cleaner** for PC (Windows, macOS, Linux) and Android (via Termux).

**Nothing is ever deleted straight away.** Everything SafeSweep flags is first moved to a
**Review folder**, where you can look at it and then **Restore** it or **Delete** it permanently.

## What it does

| Feature | Details |
|---|---|
| 🛡 **Virus Scan** | Known-malware hashes (SHA-256 list), **ClamAV** if installed (used automatically), and heuristics: fake double extensions (`invoice.pdf.exe`), programs disguised as images/docs, hidden right-to-left filename tricks, `autorun.inf`, macro documents, and dangerous script patterns (encoded PowerShell, download-and-run, ransomware commands like deleting shadow copies). |
| 🧹 **Cleanup** | Temp/leftover files (`.tmp`, `.part`, `.crdownload`, `~$` …), stale caches, old logs, empty files, `Thumbs.db`/`.DS_Store`, **duplicates** (byte-identical; the oldest copy is kept), old installers in Downloads, downloads not opened in 180+ days, large unused files. |
| 📂 **Review Folder** | Flagged files are moved here with a record of where they came from and why. Threats get a `.quarantined` suffix and their execute permission removed so they can't be run by accident. Restore puts files back exactly where they were. Auto-delete items older than N days (default 30) if you want. |
| 🔒 **Safety** | Never follows symlinks, never touches OS folders (`C:\Windows`, `Program Files`, `/usr`, `/System`, Android `/system` …), skips its own data, supports exclude patterns. |

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
safesweep scan                      # scan your Downloads/Desktop/Documents, then pick what to move
safesweep scan D:\ E:\USB --report-only
safesweep clean                     # find unneeded files
safesweep clean ~/Downloads -y      # move everything found to Review without asking

safesweep review list               # see what's waiting
safesweep review restore <id>       # put it back
safesweep review delete <id>        # delete one permanently
safesweep review purge --expired    # delete items older than review_retention_days
safesweep review purge              # empty the Review folder

safesweep settings                  # show settings
safesweep settings --set old_download_days=90 "exclude=*.iso;*/Photos/*"
safesweep signatures add hashes.txt # import more SHA-256 malware hashes
```

`safesweep scan` exits with code 1 if anything was found (handy for scheduled tasks).

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
python -m unittest discover -s tests -v
```
