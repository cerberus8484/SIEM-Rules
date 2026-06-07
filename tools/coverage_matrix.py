#!/usr/bin/env python3
"""
HuntingThreats Enterprise Hunt Pack — Coverage Matrix Generator

Parses all rule files and generates:
  - Markdown coverage table (COVERAGE.md)
  - JSON data file (coverage.json)
  - MITRE ATT&CK tactic heatmap summary

Usage:
    python tools/coverage_matrix.py               # generate all outputs
    python tools/coverage_matrix.py --md-only     # markdown only
    python tools/coverage_matrix.py --json-only   # JSON only
    python tools/coverage_matrix.py --stdout      # print markdown to stdout
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).parent.parent
RULE_EXTENSIONS = {".spl", ".aql", ".udm", ".kql"}
OUTPUT_MD = BASE_DIR / "COVERAGE.md"
OUTPUT_JSON = BASE_DIR / "coverage.json"

# ── Canonical MITRE Tactic Order ──────────────────────────────────────────────
MITRE_TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Pack display names and descriptions
PACK_META: dict[str, dict] = {
    "execution":          {"name": "Windows Execution",       "icon": "⚙️"},
    "persistence":        {"name": "Windows Persistence",     "icon": "🔒"},
    "defense_evasion":    {"name": "Windows Defense Evasion", "icon": "🛡️"},
    "credential_access":  {"name": "Windows Credentials",     "icon": "🔑"},
    "c2":                 {"name": "Command & Control",        "icon": "📡"},
    "lateral_movement":   {"name": "Lateral Movement",        "icon": "↔️"},
    "discovery":          {"name": "Discovery",                "icon": "🔍"},
    "exfiltration":       {"name": "Exfiltration",             "icon": "📤"},
    "impact":             {"name": "Impact",                   "icon": "💥"},
    "privilege_escalation": {"name": "Privilege Escalation",  "icon": "⬆️"},
    "initial_access":     {"name": "Initial Access",           "icon": "🚪"},
    "cloud":              {"name": "Cloud (AWS/Azure/M365/GCP)","icon": "☁️"},
    "linux":              {"name": "Linux Hunt",               "icon": "🐧"},
    "network":            {"name": "Network Infrastructure",   "icon": "🌐"},
    "web":                {"name": "Web Application",          "icon": "🕸️"},
    "threat_intel":       {"name": "Threat Intelligence",      "icon": "🎯"},
    "identity":           {"name": "Identity / IAM",           "icon": "👤"},
    "container":          {"name": "Container / Kubernetes",   "icon": "📦"},
    "devops":             {"name": "DevOps / CI-CD",           "icon": "🔧"},
    "backup":             {"name": "Backup / Resilience",      "icon": "💾"},
    "hypervisor":         {"name": "Hypervisor / VMware",      "icon": "🖥️"},
    "email":              {"name": "Email Security",           "icon": "📧"},
    "database":           {"name": "Database",                 "icon": "🗄️"},
    "vpn":                {"name": "VPN / Remote Access",      "icon": "🔐"},
    "macos":              {"name": "macOS",                    "icon": "🍎"},
    "dlp":                {"name": "DLP / Exfiltration",       "icon": "🚨"},
    "deception":          {"name": "Deception / Canary",       "icon": "🍯"},
    "correlation":        {"name": "Correlation / Multi-Stage","icon": "🔗"},
    "playbooks":          {"name": "Analyst Playbooks",        "icon": "📋"},
    "analyst_queries":    {"name": "Analyst Queries",          "icon": "🔎"},
}

PLATFORM_META: dict[str, dict] = {
    "splunk":  {"name": "Splunk SPL",        "icon": "🟠"},
    "qradar":  {"name": "QRadar AQL",        "icon": "🔵"},
    "secops":  {"name": "Google SecOps UDM", "icon": "🟢"},
    "wazuh":   {"name": "Wazuh KQL",         "icon": "🟣"},
    "unknown": {"name": "Other",             "icon": "⚪"},
}

# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class RuleSummary:
    rule_id: str
    file: str
    platform: str
    pack: str
    tactic: Optional[str]
    technique: Optional[str]
    severity: Optional[str]
    confidence: Optional[int]


@dataclass
class PackStats:
    pack: str
    platform: str
    rule_count: int = 0
    tactics: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    severity_dist: dict[str, int] = field(default_factory=dict)
    avg_confidence: float = 0.0
    rule_ids: list[str] = field(default_factory=list)


# ── Parsing ───────────────────────────────────────────────────────────────────

RE_RULE_ID   = re.compile(r'rule_id\s*=\s*"([^"]+)"')
RE_TACTIC    = re.compile(r'tactic\s*=\s*"([^"]+)"')
RE_TECHNIQUE = re.compile(r'technique\s*=\s*"([^"]+)"')
RE_SEVERITY  = re.compile(r'severity\s*=\s*"([^"]+)"')
RE_CONFIDENCE= re.compile(r'confidence\s*=\s*([0-9]+)')
RE_COMMENT   = re.compile(r'`comment\("([^"]+)"\)`|^--\s+(SP|QR|GS|WZ)-[0-9]+|^//\s+(SP|QR|GS|WZ)-[0-9]+')


def _derive_platform(file_path: Path) -> str:
    parts = [p.lower() for p in file_path.parts]
    for p in ("splunk", "qradar", "secops", "wazuh"):
        if p in parts:
            return p
    return "unknown"


def _derive_pack(file_path: Path) -> str:
    return file_path.parent.name.lower()


def _normalize_tactic(tactic: str) -> str:
    """Map multi/custom tactic labels to canonical MITRE names where possible."""
    t = tactic.lower()
    for canonical in MITRE_TACTIC_ORDER:
        if canonical.lower() in t:
            return canonical
    return tactic


def parse_all_rules(base_dir: Path) -> list[RuleSummary]:
    rules: list[RuleSummary] = []
    files = [
        f for ext in RULE_EXTENSIONS
        for f in base_dir.rglob(f"*{ext}")
        if "tools" not in f.parts and "schema" not in f.parts
    ]

    for file_path in sorted(files):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        platform = _derive_platform(file_path)
        pack = _derive_pack(file_path)

        # Split into blocks by comment markers
        blocks: list[str] = []
        current: list[str] = []
        for line in text.splitlines():
            if RE_COMMENT.match(line.strip()):
                if current:
                    blocks.append("\n".join(current))
                current = [line]
            else:
                current.append(line)
        if current:
            blocks.append("\n".join(current))

        for block in blocks:
            for rule_id in RE_RULE_ID.findall(block):
                tactic_raw = (RE_TACTIC.search(block) or type("", (), {"group": lambda s, n: None})()).group(1)
                technique = (RE_TECHNIQUE.search(block) or type("", (), {"group": lambda s, n: None})()).group(1)
                severity = (RE_SEVERITY.search(block) or type("", (), {"group": lambda s, n: None})()).group(1)
                conf_m = RE_CONFIDENCE.search(block)
                confidence = int(conf_m.group(1)) if conf_m else None

                tactic = _normalize_tactic(tactic_raw) if tactic_raw else None

                rules.append(RuleSummary(
                    rule_id=rule_id,
                    file=str(file_path.relative_to(base_dir)),
                    platform=platform,
                    pack=pack,
                    tactic=tactic,
                    technique=technique,
                    severity=severity,
                    confidence=confidence,
                ))

    return rules


# ── Aggregation ───────────────────────────────────────────────────────────────

def aggregate(rules: list[RuleSummary]) -> dict[str, dict[str, PackStats]]:
    """Returns {pack: {platform: PackStats}}"""
    stats: dict[str, dict[str, PackStats]] = defaultdict(lambda: defaultdict(
        lambda: PackStats(pack="", platform="", severity_dist=defaultdict(int))
    ))

    confidence_acc: dict[tuple, list[int]] = defaultdict(list)

    for r in rules:
        s = stats[r.pack][r.platform]
        s.pack = r.pack
        s.platform = r.platform
        s.rule_count += 1
        s.rule_ids.append(r.rule_id)
        if r.tactic:
            s.tactics.add(r.tactic)
        if r.technique:
            for t in r.technique.split("/"):
                s.techniques.add(t.strip())
        if r.severity:
            s.severity_dist[r.severity] = s.severity_dist.get(r.severity, 0) + 1
        if r.confidence is not None:
            confidence_acc[(r.pack, r.platform)].append(r.confidence)

    for (pack, platform), conf_list in confidence_acc.items():
        if conf_list:
            stats[pack][platform].avg_confidence = round(sum(conf_list) / len(conf_list), 1)

    return stats


# ── Markdown Generation ───────────────────────────────────────────────────────

def _severity_badge(dist: dict[str, int]) -> str:
    if not dist:
        return "—"
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = dist.get(sev, 0)
        if count:
            parts.append(f"{sev[:1]}:{count}")
    return " ".join(parts)


def _tactic_badges(tactics: set[str]) -> str:
    if not tactics:
        return "—"
    ordered = [t for t in MITRE_TACTIC_ORDER if t in tactics]
    rest = sorted(tactics - set(MITRE_TACTIC_ORDER))
    return " · ".join(ordered + rest)


def generate_markdown(
    rules: list[RuleSummary],
    stats: dict[str, dict[str, PackStats]],
) -> str:
    total_rules = len(rules)
    total_files = len({r.file for r in rules})
    all_techniques = {t.strip() for r in rules if r.technique for t in r.technique.split("/")}
    all_tactics = {r.tactic for r in rules if r.tactic}
    platforms_seen = {r.platform for r in rules}

    lines = [
        "# HuntingThreats Enterprise Hunt Pack — Coverage Matrix",
        "",
        f"> Auto-generated by `tools/coverage_matrix.py`  ",
        f"> Rules: **{total_rules}** | Files: **{total_files}** | "
        f"Techniques: **{len(all_techniques)}** | Tactics: **{len(all_tactics)}**",
        "",
        "## Platform Coverage",
        "",
        "| Platform | Rules | Files |",
        "|---|---|---|",
    ]

    for plat in ("splunk", "qradar", "secops", "wazuh"):
        plat_rules = [r for r in rules if r.platform == plat]
        plat_files = len({r.file for r in plat_rules})
        meta = PLATFORM_META.get(plat, {"name": plat, "icon": "⚪"})
        lines.append(f"| {meta['icon']} {meta['name']} | {len(plat_rules)} | {plat_files} |")

    lines += [
        "",
        "## Pack Coverage by Platform",
        "",
        "| Pack | Description | Splunk | QRadar | SecOps | Wazuh | MITRE Tactics |",
        "|---|---|---|---|---|---|---|",
    ]

    pack_order = [
        "execution", "persistence", "defense_evasion", "credential_access", "c2",
        "lateral_movement", "discovery", "exfiltration", "impact", "privilege_escalation",
        "initial_access", "cloud", "linux", "network", "web", "threat_intel",
        "identity", "container", "devops", "backup", "hypervisor", "email",
        "database", "vpn", "macos", "dlp", "deception", "correlation",
        "playbooks", "analyst_queries",
    ]

    all_packs_found = sorted(stats.keys())
    ordered_packs = [p for p in pack_order if p in all_packs_found]
    ordered_packs += [p for p in all_packs_found if p not in ordered_packs]

    for pack in ordered_packs:
        pack_data = stats[pack]
        meta = PACK_META.get(pack, {"name": pack.replace("_", " ").title(), "icon": "📁"})

        def cell(plat: str) -> str:
            s = pack_data.get(plat)
            if not s or s.rule_count == 0:
                return "—"
            return f"**{s.rule_count}**"

        all_tactics_in_pack: set[str] = set()
        for s in pack_data.values():
            all_tactics_in_pack |= s.tactics

        tactic_str = _tactic_badges(all_tactics_in_pack)
        if len(tactic_str) > 60:
            tactic_str = tactic_str[:57] + "..."

        lines.append(
            f"| {meta['icon']} {meta['name']} | | "
            f"{cell('splunk')} | {cell('qradar')} | {cell('secops')} | {cell('wazuh')} | "
            f"{tactic_str} |"
        )

    # MITRE Tactic Heatmap
    tactic_counts: dict[str, int] = defaultdict(int)
    for r in rules:
        if r.tactic:
            tactic_counts[r.tactic] += 1

    lines += [
        "",
        "## MITRE ATT&CK Tactic Distribution",
        "",
        "| Tactic | Rules | Coverage |",
        "|---|---|---|",
    ]

    max_count = max(tactic_counts.values(), default=1)
    for tactic in MITRE_TACTIC_ORDER:
        count = tactic_counts.get(tactic, 0)
        bar_len = int((count / max_count) * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        lines.append(f"| {tactic} | {count} | `{bar}` |")

    # Additional tactics not in standard order
    extra = {t: c for t, c in tactic_counts.items() if t not in MITRE_TACTIC_ORDER and t}
    if extra:
        for tactic, count in sorted(extra.items()):
            bar_len = int((count / max_count) * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            lines.append(f"| {tactic} | {count} | `{bar}` |")

    # Severity distribution
    sev_counts: dict[str, int] = defaultdict(int)
    for r in rules:
        if r.severity:
            sev_counts[r.severity] += 1

    lines += [
        "",
        "## Severity Distribution",
        "",
        "| Severity | Count | % |",
        "|---|---|---|",
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sev_counts.get(sev, 0)
        pct = round(count / total_rules * 100, 1) if total_rules else 0
        lines.append(f"| {sev} | {count} | {pct}% |")

    # Technique coverage
    lines += [
        "",
        "## MITRE ATT&CK Technique Coverage",
        "",
        f"Total unique techniques covered: **{len(all_techniques)}**",
        "",
        "| Technique ID | Rules | Packs |",
        "|---|---|---|",
    ]

    tech_rules: dict[str, list[str]] = defaultdict(list)
    for r in rules:
        if r.technique:
            for t in r.technique.split("/"):
                tech_rules[t.strip()].append(r.pack)

    for tech, packs in sorted(tech_rules.items(), key=lambda x: -len(x[1])):
        unique_packs = sorted(set(packs))
        lines.append(f"| `{tech}` | {len(packs)} | {', '.join(unique_packs)} |")

    lines += [
        "",
        "---",
        "",
        "*Generated by [HuntingThreats Enterprise Hunt Pack](https://github.com/cerberus8484/SIEM-Rules)*",
        "",
    ]

    return "\n".join(lines)


# ── JSON Generation ───────────────────────────────────────────────────────────

def generate_json(rules: list[RuleSummary]) -> dict:
    tactic_counts: dict[str, int] = defaultdict(int)
    tech_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    platform_counts: dict[str, int] = defaultdict(int)
    pack_counts: dict[str, int] = defaultdict(int)

    for r in rules:
        if r.tactic:
            tactic_counts[r.tactic] += 1
        if r.technique:
            for t in r.technique.split("/"):
                tech_counts[t.strip()] += 1
        if r.severity:
            sev_counts[r.severity] += 1
        platform_counts[r.platform] += 1
        pack_counts[r.pack] += 1

    return {
        "total_rules": len(rules),
        "total_files": len({r.file for r in rules}),
        "total_techniques": len(tech_counts),
        "total_tactics": len(tactic_counts),
        "by_platform": dict(platform_counts),
        "by_pack": dict(pack_counts),
        "by_tactic": dict(tactic_counts),
        "by_technique": dict(sorted(tech_counts.items(), key=lambda x: -x[1])),
        "by_severity": dict(sev_counts),
        "rules": [
            {
                "rule_id": r.rule_id,
                "file": r.file,
                "platform": r.platform,
                "pack": r.pack,
                "tactic": r.tactic,
                "technique": r.technique,
                "severity": r.severity,
                "confidence": r.confidence,
            }
            for r in rules
        ],
    }


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate coverage matrix for hunt pack.")
    parser.add_argument("--md-only", action="store_true", help="Write markdown only")
    parser.add_argument("--json-only", action="store_true", help="Write JSON only")
    parser.add_argument("--stdout", action="store_true", help="Print markdown to stdout instead of file")
    args = parser.parse_args()

    print("Parsing rules...")
    rules = parse_all_rules(BASE_DIR)
    print(f"  Found {len(rules)} rules in {len({r.file for r in rules})} files")

    stats = aggregate(rules)

    if not args.json_only:
        md = generate_markdown(rules, stats)
        if args.stdout:
            print(md)
        else:
            OUTPUT_MD.write_text(md, encoding="utf-8")
            print(f"  ✔  Wrote {OUTPUT_MD}")

    if not args.md_only:
        j = generate_json(rules)
        OUTPUT_JSON.write_text(json.dumps(j, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  ✔  Wrote {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
