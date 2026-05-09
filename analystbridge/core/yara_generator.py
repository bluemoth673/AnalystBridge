"""Generate YARA rules from a loaded sample's behavioural fingerprint.

Two registries:

* ``builtin_rules()`` — the static behavioural rules AnalystBridge ships with.
  These mirror the ATT&CK rules in ``mitre_mapper.py`` so analysts can drop
  the same logic straight into a YARA scanner. They use ``yara-python``-
  compatible syntax; nothing AnalystBridge-specific.

* ``generate_rules_for_bundle(bundle)`` — IOC-derived rules built on the fly
  from whatever sample is currently loaded. One rule per file-hash IOC, plus
  a single combined network-IOC rule. Stable rule names (sample_id derived)
  so re-runs are byte-identical.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class YaraRule:
    name: str
    body: str                    # full ``rule { … }`` text
    tags: List[str] = field(default_factory=list)
    source: str = "builtin"      # "builtin" | "generated"
    summary: str = ""

    @property
    def line_count(self) -> int:
        return self.body.count("\n") + 1


# ---------------------------------------------------------------------------
# Built-in behavioural rules (mirror the MITRE detection logic)
# ---------------------------------------------------------------------------


_BUILTIN: list[YaraRule] = [
    YaraRule(
        name="AB_Suspicious_PowerShell_Downloader",
        tags=["execution", "T1059_001"],
        source="builtin",
        summary="PowerShell launched with encoded / hidden / DownloadString flags.",
        body="""rule AB_Suspicious_PowerShell_Downloader
{
    meta:
        author       = "AnalystBridge"
        description  = "PowerShell process launched with suspicious flags"
        attack       = "T1059.001"
        severity     = "high"
    strings:
        $a1 = "powershell.exe" ascii nocase
        $b1 = "-enc"            ascii nocase
        $b2 = "-EncodedCommand" ascii nocase
        $b3 = "-w hidden"       ascii nocase
        $b4 = "DownloadString"  ascii nocase
        $b5 = "IEX("            ascii nocase
    condition:
        $a1 and any of ($b*)
}""",
    ),
    YaraRule(
        name="AB_Mshta_Proxy_Execution",
        tags=["defense_evasion", "T1218_005"],
        source="builtin",
        summary="mshta.exe spawned (proxy script execution).",
        body="""rule AB_Mshta_Proxy_Execution
{
    meta:
        author       = "AnalystBridge"
        description  = "mshta.exe used to proxy script execution"
        attack       = "T1218.005"
        severity     = "high"
    strings:
        $a1 = "mshta.exe" ascii nocase
    condition:
        $a1
}""",
    ),
    YaraRule(
        name="AB_Inhibit_System_Recovery",
        tags=["impact", "T1490"],
        source="builtin",
        summary="vssadmin / wbadmin used to delete shadows or backup catalog.",
        body="""rule AB_Inhibit_System_Recovery
{
    meta:
        author       = "AnalystBridge"
        description  = "Volume shadow copies / backup catalog deleted"
        attack       = "T1490"
        severity     = "critical"
    strings:
        $vssadmin = "vssadmin"  ascii nocase
        $wbadmin  = "wbadmin"   ascii nocase
        $delete   = "delete"    ascii nocase
        $shadow   = "shadow"    ascii nocase
        $catalog  = "catalog"   ascii nocase
    condition:
        ($vssadmin and $delete and $shadow)
        or ($wbadmin and $delete and $catalog)
}""",
    ),
    YaraRule(
        name="AB_Run_Key_Persistence",
        tags=["persistence", "T1547_001"],
        source="builtin",
        summary="Autorun Run / RunOnce registry key written.",
        body=r"""rule AB_Run_Key_Persistence
{
    meta:
        author       = "AnalystBridge"
        description  = "Autorun registry key created or modified"
        attack       = "T1547.001"
        severity     = "high"
    strings:
        $run     = "\\CurrentVersion\\Run"     ascii nocase
        $runonce = "\\CurrentVersion\\RunOnce" ascii nocase
    condition:
        any of them
}""",
    ),
    YaraRule(
        name="AB_Generic_Ransom_Note",
        tags=["impact", "T1486"],
        source="builtin",
        summary="Ransom-note style file name (READ_ME / DECRYPT / RESTORE).",
        body="""rule AB_Generic_Ransom_Note
{
    meta:
        author       = "AnalystBridge"
        description  = "Ransom-note file name pattern"
        attack       = "T1486"
        severity     = "critical"
    strings:
        $a1 = "READ_ME"   ascii nocase
        $a2 = "READMETO"  ascii nocase
        $a3 = "DECRYPT"   ascii nocase
        $a4 = "RESTORE"   ascii nocase
        $a5 = "HOW_TO"    ascii nocase
    condition:
        any of them
}""",
    ),
]


def builtin_rules() -> list[YaraRule]:
    """Return the static behavioural rules AnalystBridge ships with."""
    return list(_BUILTIN)


# ---------------------------------------------------------------------------
# Sample-derived rules
# ---------------------------------------------------------------------------


_SAFE_NAME = re.compile(r"[^A-Za-z0-9_]+")


def _safe_rule_name(prefix: str, value: str, max_len: int = 24) -> str:
    cleaned = _SAFE_NAME.sub("_", value).strip("_")
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return f"{prefix}_{cleaned}".strip("_")


def generate_rules_for_bundle(bundle) -> list[YaraRule]:
    """Build IOC-derived YARA rules for the currently loaded sample."""
    sample = bundle.sample or {}
    sample_id = sample.get("sample_id") or "sample"
    iocs = bundle.result.iocs or []

    out: list[YaraRule] = []

    # ---- Hash rule: one rule per sha256 IOC ------------------------------
    sha256s = [i for i in iocs if i.ioc_type == "sha256"]
    for ioc in sha256s:
        rule_name = _safe_rule_name("AB_Sample_SHA256", ioc.value[:16])
        out.append(YaraRule(
            name=rule_name,
            tags=["sample_hash"],
            source="generated",
            summary=f"SHA256 indicator of compromise: {ioc.display_value}",
            body=f"""rule {rule_name}
{{
    meta:
        author       = "AnalystBridge"
        description  = "Hash IOC extracted from {sample.get('filename') or sample_id}"
        sample_id    = "{sample_id}"
        sha256       = "{ioc.value}"
    condition:
        hash.sha256(0, filesize) == "{ioc.value}"
}}""",
        ))

    # ---- Combined network rule: one rule for all domains/IPs/URLs --------
    domains = [i for i in iocs if i.ioc_type == "domain"]
    ips = [i for i in iocs if i.ioc_type in ("ipv4", "ipv6")]
    urls = [i for i in iocs if i.ioc_type == "url"]
    if domains or ips or urls:
        strings_block: list[str] = []
        idx = 0
        for ioc in domains:
            strings_block.append(f'        $d{idx} = "{ioc.value}" ascii nocase')
            idx += 1
        idx = 0
        for ioc in urls:
            strings_block.append(f'        $u{idx} = "{ioc.value}" ascii nocase')
            idx += 1
        idx = 0
        for ioc in ips:
            strings_block.append(f'        $i{idx} = "{ioc.value}" ascii')
            idx += 1
        rule_name = _safe_rule_name("AB_Sample_Network_IOCs", sample_id, 32)
        out.append(YaraRule(
            name=rule_name,
            tags=["network", "c2"],
            source="generated",
            summary=f"Network IOCs from {sample.get('filename') or sample_id}",
            body=f"""rule {rule_name}
{{
    meta:
        author       = "AnalystBridge"
        description  = "Network indicators extracted from sample"
        sample_id    = "{sample_id}"
    strings:
{chr(10).join(strings_block)}
    condition:
        any of them
}}""",
        ))

    # ---- Ransomware-rename rule (if the sample dropped .locked / .encrypted) -
    file_iocs = [i for i in iocs if i.ioc_type == "file_path"]
    encrypted_exts = [".locked", ".encrypted", ".crypt", ".enc"]
    if any(any(fp.value.lower().endswith(ext) for ext in encrypted_exts) for fp in file_iocs):
        rule_name = _safe_rule_name("AB_Sample_Encryption_Pattern", sample_id, 32)
        out.append(YaraRule(
            name=rule_name,
            tags=["impact", "ransomware"],
            source="generated",
            summary="Encrypted-file extension pattern observed in this sample.",
            body=f"""rule {rule_name}
{{
    meta:
        author       = "AnalystBridge"
        description  = "Mass encryption pattern observed in {sample.get('filename') or sample_id}"
        sample_id    = "{sample_id}"
        attack       = "T1486"
    strings:
        $e1 = ".locked"    ascii nocase
        $e2 = ".encrypted" ascii nocase
        $e3 = ".crypt"     ascii nocase
        $e4 = ".enc"       ascii nocase
    condition:
        2 of them
}}""",
        ))

    return out
