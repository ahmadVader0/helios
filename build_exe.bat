@echo off
@chcp 65001 >nul
pushd "%~dp0"
title Building Helios Standalone Windows Executable

echo ============================================================
echo   Helios Standalone Windows Executable Build Script
echo ============================================================
echo.
echo Installing missing build dependencies...
pip install click rich jinja2 pyyaml python-registry python-evtx pyinstaller
echo.
python build_win.py

popd
pause
