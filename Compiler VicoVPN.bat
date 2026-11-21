@echo off
rem Compile VicoVPN (bin\) et fabrique l installateur dist\VicoVPN-Setup-<version>.exe
cd /d "%~dp0"
echo [%date% %time%] Compilation VicoVPN > build-log.txt
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\build.ps1" -Installer >> build-log.txt 2>&1
if errorlevel 1 (echo EXIT=1 >> build-log.txt) else (echo EXIT=0 >> build-log.txt)
