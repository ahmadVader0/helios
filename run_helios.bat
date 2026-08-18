@echo off
@chcp 65001 >nul
:: Map UNC network paths (e.g. \\wsl.localhost\...) to a temporary drive letter first
pushd "%~dp0"
title Helios Data Movement Forensic Suite

echo ============================================================
echo   HELIOS DATA MOVEMENT FORENSIC SUITE v0.1.0
echo ============================================================
echo.
echo Launching Interactive Console Menu...

set PYTHONPATH=%~dp0src;%PYTHONPATH%
python src\helios\cli.py menu

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Installing required Python dependencies...
    pip install click rich jinja2 xxhash pyyaml
    python src\helios\cli.py menu
)

popd
pause
