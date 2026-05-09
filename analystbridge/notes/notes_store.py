"""Per-sample analyst case notes — sidecar file persistence.

We deliberately keep these out of the analysis SQLite database (which the GUI
opens in `:memory:` mode for the demo) so notes survive across sessions, on
their own, with zero schema concerns. One Markdown file per sample under
`notes/<safe_sample_id>.md`.
"""
from __future__ import annotations

from pathlib import Path

from analystbridge.exports.common import safe_dir_name


class NotesStore:
    def __init__(self, root: Path | str = "notes") -> None:
        self.root = Path(root)

    def _path(self, sample_id: str) -> Path:
        safe = safe_dir_name(sample_id)
        return self.root / f"{safe}.md"

    def load(self, sample_id: str) -> str:
        path = self._path(sample_id)
        if not path.exists():
            return ""
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    def save(self, sample_id: str, text: str) -> Path:
        path = self._path(sample_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text or "", encoding="utf-8")
        return path

    def has_notes(self, sample_id: str) -> bool:
        return bool(self.load(sample_id).strip())
