@echo off
REM  Code Vulnerability Analyzer — Windows launcher
REM  Usage: vulnscan [target] [options]
python -X utf8 "%~dp0main.py" %*
