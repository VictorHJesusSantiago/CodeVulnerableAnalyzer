# -*- mode: python ; coding: utf-8 -*-
a = Analysis(["../main.py"], pathex=[".."], hiddenimports=["analyzer.rules"], datas=[], excludes=[])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="vulnscan", console=True)
