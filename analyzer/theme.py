"""
Temas de cores para a saída no terminal (reporter.py e tui.py).

Seleção: variável de ambiente VULNSCAN_THEME=dark|light|high-contrast,
ou flag de CLI --theme, aplicada em main.py via set_theme() antes de
qualquer print. Padrão: "dark" (paleta original do projeto).
"""
from __future__ import annotations

import os

from analyzer.models import Severity

_THEMES: dict[str, dict[Severity, str]] = {
    "dark": {
        Severity.CRITICAL: "#ff2244",
        Severity.HIGH:     "#ff6600",
        Severity.MEDIUM:   "#ffcc00",
        Severity.LOW:      "#33aaff",
        Severity.INFO:     "#888888",
    },
    "light": {
        Severity.CRITICAL: "#b3001b",
        Severity.HIGH:     "#b35900",
        Severity.MEDIUM:   "#8a6d00",
        Severity.LOW:      "#00558a",
        Severity.INFO:     "#555555",
    },
    "high-contrast": {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH:     "bold black on yellow",
        Severity.MEDIUM:   "bold black on bright_yellow",
        Severity.LOW:      "bold white on blue",
        Severity.INFO:     "bold white on grey37",
    },
}

_BG_THEMES: dict[str, dict[Severity, str]] = {
    "dark": {
        Severity.CRITICAL: "on #7a0010",
        Severity.HIGH:     "on #7a2e00",
        Severity.MEDIUM:   "on #5a4a00",
        Severity.LOW:      "on #003366",
        Severity.INFO:     "on #2a2a2a",
    },
    "light": {
        Severity.CRITICAL: "on #ffd6d6",
        Severity.HIGH:     "on #ffe6cc",
        Severity.MEDIUM:   "on #fff3cc",
        Severity.LOW:      "on #d6ecff",
        Severity.INFO:     "on #e6e6e6",
    },
    "high-contrast": {
        Severity.CRITICAL: "",
        Severity.HIGH:     "",
        Severity.MEDIUM:   "",
        Severity.LOW:      "",
        Severity.INFO:     "",
    },
}

VALID_THEMES = tuple(_THEMES.keys())

_active_theme = os.environ.get("VULNSCAN_THEME", "dark")
if _active_theme not in _THEMES:
    _active_theme = "dark"


def set_theme(name: str) -> None:
    global _active_theme
    if name in _THEMES:
        _active_theme = name


def get_theme_name() -> str:
    return _active_theme


def severity_colors() -> dict[Severity, str]:
    return _THEMES[_active_theme]


def severity_backgrounds() -> dict[Severity, str]:
    return _BG_THEMES[_active_theme]
