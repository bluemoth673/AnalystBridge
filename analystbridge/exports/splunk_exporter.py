"""Splunk SPL hunting query exporter."""
from __future__ import annotations

from pathlib import Path

from analystbridge.exports.common import utc_now_iso
from analystbridge.ui.services import AnalysisBundle


def _spl_in(values: list[str]) -> str:
    return ", ".join(f'"{v}"' for v in values)


def write_splunk_spl(bundle: AnalysisBundle, out_path: Path) -> Path:
    sample = bundle.sample
    iocs = bundle.result.iocs

    sha256 = [i.value for i in iocs if i.ioc_type == "sha256"]
    domains = [i.value for i in iocs if i.ioc_type == "domain"]
    ips = [i.value for i in iocs if i.ioc_type == "ipv4"]

    parts: list[str] = []
    parts.append(
        f"# Splunk hunting queries - AnalystBridge\n"
        f"# Sample   : {sample.get('filename')}\n"
        f"# SampleID : {sample.get('sample_id')}\n"
        f"# SHA256   : {sample.get('sha256')}\n"
        f"# Generated: {utc_now_iso()}\n"
        f"#\n"
        f"# Each block is an independent search.\n"
    )

    parts.append(
        "# ---------------- 1. Encoded PowerShell --------------------------\n"
        '(sourcetype="WinEventLog:*" OR sourcetype="XmlWinEventLog:*") '
        '(Image="*\\\\powershell.exe" OR process_path="*\\\\powershell.exe") '
        '(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" '
        'OR CommandLine="*-w hidden*" OR CommandLine="*DownloadString*")\n'
        "| stats count by host, ParentImage, Image, CommandLine\n"
    )

    parts.append(
        "# ---------------- 2. mshta usage (T1218.005) ---------------------\n"
        '(Image="*\\\\mshta.exe" OR process_path="*\\\\mshta.exe")\n'
        "| stats count by host, ParentImage, Image, CommandLine\n"
    )

    parts.append(
        "# ---------------- 3. Shadow copy deletion (T1490) ----------------\n"
        '(Image="*\\\\vssadmin.exe" OR process_path="*\\\\vssadmin.exe") '
        'CommandLine="*delete*shadow*"\n'
        "| stats count by host, ParentImage, CommandLine\n"
    )

    parts.append(
        "# ---------------- 4. Run-key persistence (T1547.001) -------------\n"
        '(EventCode=13 OR EventID=13 OR sourcetype="*Sysmon*") '
        '(TargetObject="*\\\\CurrentVersion\\\\Run\\\\*" OR '
        'TargetObject="*\\\\CurrentVersion\\\\RunOnce\\\\*")\n'
        "| stats count by host, Image, TargetObject, Details\n"
    )

    if domains or ips:
        clause = []
        if domains:
            clause.append(f"dest_domain IN ({_spl_in(domains)})")
        if ips:
            clause.append(f"dest_ip IN ({_spl_in(ips)})")
        parts.append(
            "# ---------------- 5. C2 indicators -------------------------------\n"
            f"({' OR '.join(clause)})\n"
            "| stats count by src, dest_domain, dest_ip, url\n"
        )

    if sha256:
        parts.append(
            "# ---------------- 6. Hash matches --------------------------------\n"
            f"file_hash IN ({_spl_in(sha256)})\n"
            "| stats count by host, file_name, file_path, file_hash\n"
        )

    parts.append(
        "# ---------------- 7. Mass file rename (.locked) ------------------\n"
        '(Action="rename" OR EventCode=11) file_name="*.locked"\n'
        "| stats count by host, ParentImage, file_path\n"
        "| where count >= 5\n"
    )

    out_path.write_text("\n".join(parts), encoding="utf-8")
    return out_path
