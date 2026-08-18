@echo off
@chcp 65001 >nul
pushd "%~dp0"
title Testing Helios Executable Output

echo ============================================================
echo   HELIOS EXECUTABLE DIAGNOSTIC LAUNCHER
echo ============================================================
echo.
echo Executing dist\helios.exe...
echo ------------------------------------------------------------
dist\helios.exe demo
echo ------------------------------------------------------------
echo.
echo ============================================================
echo   DIAGNOSTIC COMPLETE
echo   If an error occurred, the exact error message is shown above.
echo ============================================================
popd
pause
