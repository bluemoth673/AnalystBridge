"""Shared helpers for the SOC Action Pack exporters."""
from __future__ import annotations

import re
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_dir_name(name: str) -> str:
    """Make a string safe for use as a directory name on Windows."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return cleaned or "sample"


CONTAINMENT_RECOMMENDATIONS = [
    "Isolate the affected host from the network (block at the switch / disable Wi-Fi).",
    "Preserve a disk image and a memory capture before reboot.",
    "Remove the persistence Run-key entry once forensic data is collected.",
    "Block the C2 domain and IP at the proxy and DNS firewall.",
    "Audit other hosts for the same Run-key entry, mshta launches, and encoded PowerShell.",
    "Restore impacted files from out-of-band backups (do NOT rely on local shadow copies).",
    "Reset credentials for any accounts that were active on the host during execution.",
    "Do not pay any ransom; coordinate with IR and legal.",
]
