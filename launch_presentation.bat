@echo off
title MazAPI Live Presentation Launcher
echo ===================================================================
echo     MazAPI Security Suite - Live Interactive Presentation Launcher
echo ===================================================================
echo.
echo Starting Playwright presentation with on-screen HUD and element highlights...
cd /d "%~dp0api-security-project"
python present.py
pause
