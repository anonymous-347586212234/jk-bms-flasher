@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    where py >nul 2>nul
    if not errorlevel 1 (
        py -3.14 -m venv .venv
    ) else (
        python -m venv .venv
    )
    if errorlevel 1 goto :error
)

".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 goto :error

".venv\Scripts\python.exe" main.py
if errorlevel 1 goto :error
exit /b 0

:error
echo JK Flash failed to set up or start. 1>&2
exit /b 1
