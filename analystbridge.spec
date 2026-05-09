# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for AnalystBridge.

Build:
    pip install pyinstaller
    pyinstaller analystbridge.spec --clean --noconfirm

Output:
    dist/AnalystBridge/AnalystBridge.exe   (--onedir build, faster startup)
    or
    dist/AnalystBridge.exe                  (uncomment 'onefile' block below)

The build bundles:
  * The full ``analystbridge`` package
  * ``sample_data/ransomware_demo.json``  (so Load Demo works)
  * ``assets/icons/``                     (so user-supplied PNGs are included)

Hidden imports cover the indirect Pydantic v2 / networkx / sqlite modules
PyInstaller sometimes misses on Windows.
"""

block_cipher = None

added_files = [
    ("sample_data/*.json", "sample_data"),
    ("assets/icons/*", "assets/icons"),
]

hidden_imports = [
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "PySide6.QtSvg",
    "pydantic",
    "pydantic_core",
    "networkx",
    "numpy",
    "sqlite3",
]


a = Analysis(
    ["analystbridge/app.py"],
    pathex=["."],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "test", "unittest", "pydoc",
        "pytest", "_pytest",
    ],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)


# ---- One-folder build (recommended — faster startup, easier to ship) ------
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AnalystBridge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    console=False,                        # no terminal window pops up
    icon="assets/icons/process.png",      # used as the .exe icon if present
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="AnalystBridge",
)


# ---- Alternative: one-file build (slower startup, single .exe) ------------
# Comment out the `exe = EXE(...)` and `coll = COLLECT(...)` blocks above and
# uncomment the block below to switch.
#
# exe = EXE(
#     pyz,
#     a.scripts,
#     a.binaries,
#     a.zipfiles,
#     a.datas,
#     [],
#     name="AnalystBridge",
#     debug=False,
#     bootloader_ignore_signals=False,
#     strip=False,
#     upx=True,
#     upx_exclude=[],
#     runtime_tmpdir=None,
#     console=False,
#     icon="assets/icons/process.png",
# )
