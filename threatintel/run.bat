@echo off
REM Double-click launcher for the Threat Intel Toolkit GUI.
cd /d "%~dp0"
where pythonw >nul 2>nul && ( start "" pythonw "%~dp0gui.py" & goto :eof )
where python  >nul 2>nul && ( python "%~dp0gui.py" & goto :eof )
echo Python 3.8+ not found on PATH.
pause
