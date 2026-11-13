@echo off
cd /d "%~dp0"
where pythonw >nul 2>nul && (start "" pythonw -m safesweep gui) || (python -m safesweep gui || pause)
