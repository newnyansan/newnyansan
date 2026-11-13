# PyInstaller spec: one folder containing SafeSweep.exe (window) and safesweep-cli.exe.
# Build from the project folder:  pyinstaller packaging/windows/safesweep.spec
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
ICON = os.path.join(ROOT, "assets", "icon.ico")
datas = [(os.path.join(ROOT, "safesweep", "data"), os.path.join("safesweep", "data")),
         (os.path.join(ROOT, "assets", "icon.png"), "assets")]
common = dict(pathex=[ROOT], datas=datas, excludes=["kivy", "PIL", "numpy"])

gui = Analysis([os.path.join(SPECPATH, "gui_main.py")], **common)
cli = Analysis([os.path.join(SPECPATH, "cli_main.py")], **common)

gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="SafeSweep",
              console=False, icon=ICON, upx=False)
cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="safesweep-cli",
              console=True, icon=ICON, upx=False)

COLLECT(gui_exe, gui.binaries, gui.datas, cli_exe, cli.binaries, cli.datas,
        name="SafeSweep", upx=False)
