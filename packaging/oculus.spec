# PyInstaller spec — build a single-file `oculus` binary for endpoints without Python.
#
#   pip install pyinstaller
#   pyinstaller packaging/oculus.spec
#   dist/oculus scrape        # the standalone binary
#
# The sources.yaml data file is bundled so the default feed set ships inside the binary.

# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['../oculus/__main__.py'],
    pathex=['..'],
    binaries=[],
    datas=[('../oculus/sources.yaml', 'oculus')],
    hiddenimports=['feedparser', 'httpx', 'yaml'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='oculus',
    debug=False, strip=False, upx=True, console=True,
)
