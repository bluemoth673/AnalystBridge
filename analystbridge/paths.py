"""Portable project-anchored paths.

Solves the GitHub-cloning problem: nothing in the GUI ever displays
``C:\\Users\\Omar\\...`` — paths are computed relative to the project root
detected at runtime, so the same code shows ``./exports`` to every user
regardless of where they cloned the repo.

Resolution order for ``PROJECT_ROOT``:

  1. Climb up from this file until we find a directory containing an
     ``analystbridge`` package and a sibling like ``sample_data`` /
     ``assets`` / ``requirements.txt`` (the dev / git-clone case).
  2. Fall back to two parents up — ``analystbridge/paths.py`` →
     ``<project_root>``.
  3. As a last resort use the current working directory.

Use ``display_path(p)`` whenever you show a path in the UI — it returns the
shortest sensible string: relative to PROJECT_ROOT, then to ``~``, then
absolute.
"""
from __future__ import annotations

import os
from pathlib import Path


def _find_project_root() -> Path:
    here = Path(__file__).resolve().parent  # analystbridge/
    # Walk up; project root is the first ancestor that has BOTH the package
    # dir and at least one repo marker.
    candidates = [here.parent, *here.parents]
    markers = ("requirements.txt", "pyproject.toml", "analystbridge.spec",
               "sample_data", "assets")
    for cand in candidates:
        if (cand / "analystbridge").is_dir() and any(
            (cand / m).exists() for m in markers
        ):
            return cand
    # Fallback: project root = parent of the analystbridge package dir.
    return here.parent


PROJECT_ROOT: Path = _find_project_root()
EXPORTS_ROOT: Path = PROJECT_ROOT / "exports"
NOTES_ROOT: Path = PROJECT_ROOT / "notes"
ICONS_ROOT: Path = PROJECT_ROOT / "assets" / "icons"
NAV_ICONS_ROOT: Path = ICONS_ROOT / "nav"
SAMPLE_DATA_ROOT: Path = PROJECT_ROOT / "sample_data"


def display_path(p: Path | str) -> str:
    """Render ``p`` as the shortest portable string for the UI.

    Order of preference:
      * relative to ``PROJECT_ROOT``  →  ``./exports/sample_x``
      * relative to ``~``             →  ``~/work/...``
      * absolute (last resort)
    """
    path = Path(p).resolve() if not isinstance(p, Path) else p.resolve()
    try:
        rel = path.relative_to(PROJECT_ROOT)
        s = str(rel).replace(os.sep, "/")
        return f"./{s}" if s and not s.startswith(".") else s or "."
    except ValueError:
        pass
    try:
        home = Path.home()
        rel = path.relative_to(home)
        s = str(rel).replace(os.sep, "/")
        return f"~/{s}"
    except ValueError:
        pass
    return str(path)


def project_relative(p: Path | str) -> Path:
    """Return ``p`` as a Path relative to the project root, if possible."""
    path = Path(p).resolve()
    try:
        return path.relative_to(PROJECT_ROOT)
    except ValueError:
        return path
