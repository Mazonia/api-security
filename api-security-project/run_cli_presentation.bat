@echo off
title MazAPI Live CLI Scanner Demo
echo ===================================================
echo    MazAPI Interactive Security Scanner - LIVE CLI
echo ===================================================
echo.
echo [1/3] Running DAST API Security Scan...
python "%~dp0..\cli_entry.py" scan --target http://localhost:8000
echo.
echo [2/3] Running IoT Protocol Security Audit...
python "%~dp0..\cli_entry.py" iot-audit --target http://localhost:8000
echo.
echo [3/3] Running Model Context Protocol (MCP) Audit...
python "%~dp0..\cli_entry.py" mcp-audit scan
echo.
echo MazAPI CLI Scans Complete! You can type additional commands below:
cmd /k
