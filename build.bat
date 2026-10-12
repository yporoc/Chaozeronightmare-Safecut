@echo off
setlocal enabledelayedexpansion
rem safecut build script: produces dist\safecut.exe (single file, no console window)
where python >nul 2>&1
if errorlevel 1 (
  echo [x] python not found in PATH
  exit /b 2
)
echo [1/4] installing dependencies
python -m pip install --disable-pip-version-check -q -r requirements.txt
python -m pip install --disable-pip-version-check -q pyinstaller
if errorlevel 1 (
  echo [x] dependency install failed
  exit /b 1
)
echo [2/4] pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name safecut ^
  --paths . --specpath build --collect-all customtkinter --collect-all capstone ^
  --exclude-module test --exclude-module unittest --exclude-module setuptools ^
  --exclude-module pydoc_data --log-level WARN app.py
if errorlevel 1 (
  echo [x] build failed
  exit /b 1
)
if not exist dist\safecut.exe (
  echo [x] dist\safecut.exe missing
  exit /b 1
)
echo [3/4] selfcheck
dist\safecut.exe --selfcheck
if errorlevel 1 (
  echo [x] selfcheck failed
  exit /b 1
)
if exist dist\safecut-selfcheck.txt type dist\safecut-selfcheck.txt
echo [4/4] artifact
for %%F in (dist\safecut.exe) do echo file=%%~nxF size=%%~zF
certutil -hashfile dist\safecut.exe SHA256 | findstr /v /i "hash SHA256"
echo usage: dist\safecut.exe
echo        dist\safecut.exe --analyze ^<file.exe^>
echo        dist\safecut.exe --build ^<file.exe^> [out-dir]
echo done: dist\safecut.exe
