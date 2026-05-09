"""Microsoft Defender Advanced Hunting (KQL) exporter."""
from __future__ import annotations

from pathlib import Path

from analystbridge.exports.common import utc_now_iso
from analystbridge.ui.services import AnalysisBundle


def _kql_string_list(values: list[str]) -> str:
    return ", ".join(f'"{v}"' for v in values)


def write_defender_kql(bundle: AnalysisBundle, out_path: Path) -> Path:
    sample = bundle.sample
    iocs = bundle.result.iocs

    sha256 = [i.value for i in iocs if i.ioc_type == "sha256"]
    domains = [i.value for i in iocs if i.ioc_type == "domain"]
    ips = [i.value for i in iocs if i.ioc_type == "ipv4"]
    urls = [i.value for i in iocs if i.ioc_type == "url"]

    parts: list[str] = []
    parts.append(
        "// Microsoft Defender Advanced Hunting - AnalystBridge\n"
        f"// Sample   : {sample.get('filename')}\n"
        f"// SampleID : {sample.get('sample_id')}\n"
        f"// SHA256   : {sample.get('sha256')}\n"
        f"// Generated: {utc_now_iso()}\n"
        "//\n"
        "// Run each block independently (split by the '----' separators).\n"
    )

    parts.append(
        "// ---------------- 1. Encoded PowerShell launches ----------------\n"
        "DeviceProcessEvents\n"
        "| where Timestamp > ago(7d)\n"
        "| where FileName =~ \"powershell.exe\"\n"
        "| where ProcessCommandLine has_any (\"-enc\", \"-EncodedCommand\", \"-w hidden\", \"DownloadString\")\n"
        "| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, "
        "FileName, ProcessCommandLine\n"
    )

    parts.append(
        "// ---------------- 2. Mshta launches (T1218.005) -----------------\n"
        "DeviceProcessEvents\n"
        "| where Timestamp > ago(7d)\n"
        "| where FileName =~ \"mshta.exe\"\n"
        "| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine\n"
    )

    parts.append(
        "// ---------------- 3. Volume shadow copy deletion (T1490) ---------\n"
        "DeviceProcessEvents\n"
        "| where Timestamp > ago(7d)\n"
        "| where FileName =~ \"vssadmin.exe\"\n"
        "| where ProcessCommandLine has_all (\"delete\", \"shadow\")\n"
        "| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine\n"
    )

    parts.append(
        "// ---------------- 4. Run-key persistence (T1547.001) -------------\n"
        "DeviceRegistryEvents\n"
        "| where Timestamp > ago(7d)\n"
        "| where ActionType in (\"RegistryValueSet\", \"RegistryKeyCreated\")\n"
        "| where RegistryKey has_any (@\"\\CurrentVersion\\Run\", @\"\\CurrentVersion\\RunOnce\")\n"
        "| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, "
        "RegistryValueName, RegistryValueData\n"
    )

    if domains or ips or urls:
        net_clause = []
        if domains:
            net_clause.append(f"RemoteUrl has_any ({_kql_string_list(domains + urls)})")
        if ips:
            net_clause.append(f"RemoteIP in ({_kql_string_list(ips)})")
        parts.append(
            "// ---------------- 5. C2 indicators -------------------------------\n"
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(7d)\n"
            f"| where {(' or '.join(net_clause))}\n"
            "| project Timestamp, DeviceName, InitiatingProcessFileName, "
            "RemoteUrl, RemoteIP, RemotePort\n"
        )

    if sha256:
        parts.append(
            "// ---------------- 6. Hash hits -----------------------------------\n"
            "search in (DeviceFileEvents, DeviceProcessEvents)\n"
            f"    SHA256 in ({_kql_string_list(sha256)})\n"
            "| project Timestamp, DeviceName, FileName, FolderPath, SHA256\n"
        )

    parts.append(
        "// ---------------- 7. Ransomware-style rename pattern -------------\n"
        "DeviceFileEvents\n"
        "| where Timestamp > ago(7d)\n"
        "| where ActionType in (\"FileRenamed\", \"FileCreated\", \"FileModified\")\n"
        "| where FileName endswith \".locked\" or FileName endswith \".encrypted\"\n"
        "| summarize encrypted_files=count() by DeviceName, InitiatingProcessFileName\n"
        "| where encrypted_files >= 5\n"
    )

    out_path.write_text("\n".join(parts), encoding="utf-8")
    return out_path
