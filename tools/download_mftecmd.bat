@echo off
setlocal
cd /d "%~dp0"
echo [Helios] Downloading Eric Zimmerman's MFTECmd.exe into tools directory...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://download.ericzimmerman.ch/net6/MFTECmd.zip' -OutFile 'MFTECmd.zip'; Expand-Archive -Path 'MFTECmd.zip' -DestinationPath '.' -Force; Remove-Item 'MFTECmd.zip' -Force"
if exist MFTECmd.exe (
    echo [Helios] Successfully installed MFTECmd.exe into tools directory.
) else (
    echo [Helios] Download failed. Please download MFTECmd.zip manually from https://download.ericzimmerman.ch/net6/MFTECmd.zip and copy MFTECmd.exe into this folder.
)
pause
