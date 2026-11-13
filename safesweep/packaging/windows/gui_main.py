"""Entry point for the windowed SafeSweep.exe.

`SafeSweep.exe --auto` runs the scheduled daily check silently (no window, no console).
"""
import sys

if "--auto" in sys.argv[1:]:
    from safesweep.cli import main
    sys.exit(main(["auto"]))

from safesweep.gui import run

sys.exit(run())
