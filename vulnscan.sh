#!/usr/bin/env bash
# Code Vulnerability Analyzer — Unix launcher
# Usage: ./vulnscan.sh [target] [options]
exec python3 -X utf8 "$(dirname "$0")/main.py" "$@"
