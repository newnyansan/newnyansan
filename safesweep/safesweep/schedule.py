"""Turn the automatic daily check on/off with the operating system's own scheduler.

  * Windows: Task Scheduler (per user, no administrator rights; catches up if the PC was off)
  * macOS:   launchd agent (runs at the next wake if the Mac was asleep)
  * Linux:   systemd user timer (Persistent=true catches up missed runs)
  * Android: handled by the app itself (exact daily alarm + WorkManager, see mobile.py)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape

TASK_NAME = "SafeSweep Daily Threat Check"
UNIT = "safesweep-check"
LAUNCHD_LABEL = "org.safesweep.check"
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    if os.name == "nt":
        kw.setdefault("creationflags", NO_WINDOW)
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=60, **kw)


def _parse_time(hhmm: str) -> tuple[int, int]:
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", hhmm.strip())
    if not m:
        raise ValueError("time must look like 12:30 (24-hour clock)")
    return int(m.group(1)), int(m.group(2))


def auto_command() -> list[str]:
    """How to start a silent automatic check (no console window)."""
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        gui = os.path.join(exe_dir, "SafeSweep.exe" if os.name == "nt" else "SafeSweep")
        if os.path.exists(gui):
            return [gui, "--auto"]
        return [sys.executable, "auto"]
    py = sys.executable
    if os.name == "nt":
        pyw = os.path.join(os.path.dirname(py), "pythonw.exe")
        py = pyw if os.path.exists(pyw) else py
    return [py, "-m", "safesweep", "auto"]


def _pkg_parent() -> str:
    return str(Path(__file__).resolve().parent.parent)


# ----------------------------------------------------------------------------- Windows
def windows_task_xml(hour: int, minute: int, command: list[str], user: str = "") -> str:
    start = time.strftime("%Y-%m-%d") + f"T{hour:02d}:{minute:02d}:00"
    args = " ".join(f'"{a}"' if " " in a else a for a in command[1:])
    user_xml = f"<UserId>{escape(user)}</UserId>" if user else ""
    workdir = escape(os.path.dirname(command[0])) if not command[0].lower().endswith("python.exe") else escape(_pkg_parent())
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>SafeSweep checks your files for viruses and other threats once a day, using the latest verified threat lists. Confirmed threats are moved to the Review folder - nothing is deleted.</Description>
    <URI>\\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>PT15M</RandomDelay>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      {user_xml}
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(command[0])}</Command>
      <Arguments>{escape(args)}</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _windows_enable(hour: int, minute: int) -> str:
    user = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".strip("\\")
    xml = windows_task_xml(hour, minute, auto_command(), user)
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-16") as f:
            f.write(xml)
        r = _run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", path, "/F"])
    finally:
        os.unlink(path)
    if r.returncode:
        raise RuntimeError((r.stderr or r.stdout).strip() or "schtasks failed")
    return f"Windows Task Scheduler: '{TASK_NAME}' every day at {hour:02d}:{minute:02d}"


def _windows_disable() -> str:
    r = _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    return "removed" if r.returncode == 0 else "was not scheduled"


def _windows_status() -> str:
    r = _run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"])
    if r.returncode:
        return "off"
    info = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(":")
        info[k.strip()] = v.strip()
    nxt = info.get("Next Run Time", "?")
    return f"on (next run: {nxt})"


# ----------------------------------------------------------------------------- Linux
def _systemd_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd" / "user"


def systemd_units(hour: int, minute: int, command: list[str]) -> tuple[str, str]:
    exec_line = " ".join(f'"{c}"' if " " in c else c for c in command)
    service = f"""[Unit]
Description=SafeSweep daily threat check

[Service]
Type=oneshot
Nice=15
IOSchedulingClass=idle
Environment=PYTHONPATH={_pkg_parent()}
ExecStart={exec_line}
"""
    timer = f"""[Unit]
Description=Run the SafeSweep threat check every day

[Timer]
OnCalendar=*-*-* {hour:02d}:{minute:02d}:00
Persistent=true
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
"""
    return service, timer


def _linux_enable(hour: int, minute: int) -> str:
    d = _systemd_dir()
    d.mkdir(parents=True, exist_ok=True)
    service, timer = systemd_units(hour, minute, auto_command())
    (d / f"{UNIT}.service").write_text(service)
    (d / f"{UNIT}.timer").write_text(timer)
    if not shutil.which("systemctl"):
        raise RuntimeError(f"systemd not available; unit files written to {d}")
    _run(["systemctl", "--user", "daemon-reload"])
    r = _run(["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"])
    if r.returncode:
        raise RuntimeError((r.stderr or r.stdout).strip() or "systemctl failed")
    return f"systemd user timer '{UNIT}.timer' every day at {hour:02d}:{minute:02d}"


def _linux_disable() -> str:
    if shutil.which("systemctl"):
        _run(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"])
    for ext in ("timer", "service"):
        try:
            (_systemd_dir() / f"{UNIT}.{ext}").unlink()
        except OSError:
            pass
    return "removed"


def _linux_status() -> str:
    if not (_systemd_dir() / f"{UNIT}.timer").exists():
        return "off"
    if shutil.which("systemctl"):
        r = _run(["systemctl", "--user", "is-enabled", f"{UNIT}.timer"])
        return "on" if r.stdout.strip() == "enabled" else "installed but not enabled"
    return "installed (systemd not running)"


# ----------------------------------------------------------------------------- macOS
def _plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def launchd_plist(hour: int, minute: int, command: list[str]) -> str:
    args = "\n".join(f"    <string>{escape(c)}</string>" for c in command)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>PYTHONPATH</key><string>{escape(_pkg_parent())}</string></dict>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>{hour}</integer><key>Minute</key><integer>{minute}</integer></dict>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>15</integer>
</dict>
</plist>
"""


def _mac_enable(hour: int, minute: int) -> str:
    p = _plist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    _run(["launchctl", "unload", str(p)])
    p.write_text(launchd_plist(hour, minute, auto_command()))
    r = _run(["launchctl", "load", "-w", str(p)])
    if r.returncode:
        raise RuntimeError((r.stderr or r.stdout).strip() or "launchctl failed")
    return f"launchd agent '{LAUNCHD_LABEL}' every day at {hour:02d}:{minute:02d}"


def _mac_disable() -> str:
    p = _plist_path()
    if p.exists():
        _run(["launchctl", "unload", "-w", str(p)])
        p.unlink()
        return "removed"
    return "was not scheduled"


# ----------------------------------------------------------------------------- public
def enable(at: str = "12:30") -> str:
    hour, minute = _parse_time(at)
    if os.name == "nt":
        return _windows_enable(hour, minute)
    if sys.platform == "darwin":
        return _mac_enable(hour, minute)
    from .config import is_android
    if is_android():
        raise RuntimeError("On Android the SafeSweep app schedules the daily check itself.")
    return _linux_enable(hour, minute)


def disable() -> str:
    if os.name == "nt":
        return _windows_disable()
    if sys.platform == "darwin":
        return _mac_disable()
    return _linux_disable()


def status() -> str:
    if os.name == "nt":
        return _windows_status()
    if sys.platform == "darwin":
        return "on" if _plist_path().exists() else "off"
    return _linux_status()


# ----------------------------------------------------------------------------- notifications
def notify(title: str, text: str) -> bool:
    """Best-effort desktop notification. Never raises."""
    try:
        if os.name == "nt":
            ps = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$n = $t.GetElementsByTagName('text')
$n.Item(0).AppendChild($t.CreateTextNode($env:SS_TITLE)) > $null
$n.Item(1).AppendChild($t.CreateTextNode($env:SS_TEXT)) > $null
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('SafeSweep.App').Show([Windows.UI.Notifications.ToastNotification]::new($t))
"""
            env = dict(os.environ, SS_TITLE=title, SS_TEXT=text[:250])
            r = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                      "-Command", ps], env=env)
            return r.returncode == 0
        if sys.platform == "darwin":
            def q(s):
                return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
            r = _run(["osascript", "-e", f"display notification {q(text[:250])} with title {q(title)}"])
            return r.returncode == 0
        if shutil.which("notify-send"):
            return _run(["notify-send", "-a", "SafeSweep", title, text[:250]]).returncode == 0
    except (OSError, subprocess.SubprocessError):
        pass
    return False
