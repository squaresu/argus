@echo off
rem Double-click to open Argus. After the first run, Argus is also in the Start menu and on the desktop.
start "" powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0app\launch.ps1"
