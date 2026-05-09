# Building a one-click Windows installer

AnalystBridge ships with a [PyInstaller](https://pyinstaller.org/) spec so you
can produce a standalone `AnalystBridge.exe` for the Cyshield demo.

## Prerequisites

```powershell
python -m pip install -r requirements.txt
python -m pip install pyinstaller
```

(Optional — UPX shrinks the output ~30%):
[UPX](https://upx.github.io/) — drop `upx.exe` somewhere on `PATH`.

## Build

Always invoke PyInstaller via the same Python interpreter you use for the rest
of the project — `pyinstaller` is rarely on `PATH` on Windows.

```powershell
python -m PyInstaller analystbridge.spec --clean --noconfirm
```

> If you see `'pyinstaller' is not recognized as an internal or external command`
> that's exactly why — the bare `pyinstaller` shim wasn't added to PATH when
> pip installed the package. The `python -m PyInstaller` form sidesteps that
> entirely and is the recommended invocation on Windows.

Output lands in:

```
dist/AnalystBridge/AnalystBridge.exe   ← double-click to launch
dist/AnalystBridge/                     ← ship the whole folder
```

## What's bundled

* The complete `analystbridge` Python package (engine, GUI, exporters, importers)
* `sample_data/ransomware_demo.json` — Load Demo works out of the box
* `assets/icons/*.png` — node icons (whatever you've dropped in)
* PySide6 / Qt 6 runtime
* Pydantic v2 / networkx / numpy

## Switching to a single-file `.exe`

Slower startup, single file. Open `analystbridge.spec`, comment out the
`exe = EXE(...)` + `coll = COLLECT(...)` blocks, uncomment the alternative
block at the bottom, then re-run `pyinstaller analystbridge.spec`.

## Troubleshooting

* **"ModuleNotFoundError: pydantic_core"** — make sure you're using the same
  Python that has `pydantic` installed. `pyinstaller` follows whatever Python
  is on `PATH`.
* **App opens then closes silently** — temporarily set `console=True` in the
  spec, rebuild, run from a terminal, read the traceback.
* **Massive `.exe`** — install UPX and re-run; the spec already has `upx=True`.
