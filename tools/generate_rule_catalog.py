#!/usr/bin/env python3
"""
HuntingThreats Enterprise Hunt Pack — Rule Catalog Generator

Parses all rule files and generates a searchable catalog:
  - docs/data/rules.json    full rule list (id, name, pack, platform, …)
  - docs/data/packs.json    per-pack aggregates
  - docs/data/mitre.json    per-technique index
  - docs/rules/index.md     Markdown rule table for MkDocs

Reuses parse_all_rules() from coverage_matrix.py — no duplicate parsing logic.
Adds two fields not tracked by coverage_matrix: rule name and rule status.

Usage:
    python tools/generate_rule_catalog.py
    python tools/generate_rule_catalog.py --dry-run   # validate only, no writes
    python tools/generate_rule_catalog.py --stdout    # print rules.json to stdout
    python tools/generate_rule_catalog.py --md-only   # write index.md only
    python tools/generate_rule_catalog.py --json-only # write JSON files only
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Import shared constants and parser from coverage_matrix ──────────────────
_tools_dir = Path(__file__).parent
sys.path.insert(0, str(_tools_dir))
from coverage_matrix import (  # noqa: E402
    BASE_DIR,
    PACK_META,
    MITRE_TACTIC_ORDER,
    RULE_EXTENSIONS,
    parse_all_rules,
    RuleSummary,
)

# ── Output paths ──────────────────────────────────────────────────────────────
DATA_DIR      = BASE_DIR / "docs" / "data"
RULES_JSON    = DATA_DIR / "rules.json"
PACKS_JSON    = DATA_DIR / "packs.json"
MITRE_JSON    = DATA_DIR / "mitre.json"
RULES_INDEX   = BASE_DIR / "docs" / "rules" / "index.md"

# ── Additional extraction patterns ───────────────────────────────────────────
# Matches: "SP-700021 | AWS Root Account Console Login"
RE_RULE_NAME   = re.compile(r'(?:SP|QR|GS|WZ)-\d+\s*\|\s*(.+)')
RE_STATUS      = re.compile(r'\bstatus\s*=\s*(stable|testing|experimental)\b')
RE_RULE_ID_HDR = re.compile(r'\b((?:SP|QR|GS|WZ)-\d{6})\b')

# Severity sort order
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Name / status extraction (second pass over raw files) ────────────────────

_TRAILING_JUNK = re.compile(r'["\')` \t]+$')


def _clean_rule_name(raw: str) -> str:
    """Clean extracted rule name.

    - Strip trailing Splunk comment artefacts: closing quote/paren/backtick chars.
    - If the text contains a second pipe, everything before it is a category prefix
      (e.g. ``Pack-Name | Rule Title``) — drop the prefix, keep the title.
    - Strip leading/trailing whitespace.
    """
    # Strip trailing Splunk `comment("…")` closing characters
    name = _TRAILING_JUNK.sub("", raw).strip()
    # Format: "Pack-Category | Actual Rule Name"  → take the part after the last |
    if "|" in name:
        name = name.rsplit("|", 1)[-1].strip()
    return name


def _read_file_safe(file_path: Path) -> str:
    """Read a rule file, trying UTF-8 first then CP1252 (for Windows-authored files)."""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return file_path.read_text(encoding=enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return file_path.read_text(encoding="latin-1", errors="replace")


def _extract_name_status(file_path: Path) -> dict[str, tuple[str, str]]:
    """Return {rule_id: (name, status)} for all rules in the file."""
    try:
        text = _read_file_safe(file_path)
    except Exception:
        return {}

    result: dict[str, tuple[str, str]] = {}

    # Split text into comment-block sections
    # A block starts with a comment header line containing a rule ID
    blocks: list[str] = []
    current: list[str] = []
    comment_block_re = re.compile(
        r'`comment\s*\("|^/\*\s*(?:SP|QR|GS|WZ)-\d+', re.IGNORECASE
    )
    for line in text.splitlines():
        if comment_block_re.match(line.strip()):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current))

    for block in blocks:
        ids = RE_RULE_ID_HDR.findall(block)
        if not ids:
            continue
        rule_id = ids[0]

        # Name: the text after "SP-XXXXXX | " on the header line
        name_m = RE_RULE_NAME.search(block)
        name = _clean_rule_name(name_m.group(1)) if name_m else ""
        # Truncate very long names (shouldn't happen but be safe)
        if len(name) > 120:
            name = name[:117] + "..."

        status_m = RE_STATUS.search(block)
        status = status_m.group(1) if status_m else "stable"

        result[rule_id] = (name, status)

    return result


def _build_name_status_index(base_dir: Path) -> dict[str, tuple[str, str]]:
    """Parse all rule files and return a global {rule_id: (name, status)} index."""
    index: dict[str, tuple[str, str]] = {}
    files = [
        f for ext in RULE_EXTENSIONS
        for f in base_dir.rglob(f"*{ext}")
        if "tools" not in f.parts and "schema" not in f.parts
    ]
    for file_path in sorted(files):
        index.update(_extract_name_status(file_path))
    return index


# ── Catalog data structures ───────────────────────────────────────────────────

def build_rule_catalog(
    rules: list[RuleSummary],
    name_status: dict[str, tuple[str, str]],
    version: str = "0.2.0",
) -> dict:
    """Build the full rules.json catalog."""
    rule_entries = []
    for r in rules:
        name, status = name_status.get(r.rule_id, ("", "stable"))
        rule_entries.append({
            "id":         r.rule_id,
            "name":       name,
            "pack":       r.pack,
            "platform":   r.platform,
            "tactic":     r.tactic or "",
            "technique":  r.technique or "",
            "severity":   r.severity or "",
            "confidence": r.confidence if r.confidence is not None else 0,
            "status":     status,
            "file":       r.file,
        })

    # Sort: platform → pack → severity → id
    rule_entries.sort(key=lambda e: (
        e["platform"],
        e["pack"],
        SEVERITY_ORDER.get(e["severity"], 99),
        e["id"],
    ))

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version":   version,
        "count":     len(rule_entries),
        "rules":     rule_entries,
    }


def build_pack_catalog(rules: list[RuleSummary]) -> list[dict]:
    """Aggregate rules per pack → packs.json."""
    pack_data: dict[str, dict] = {}

    for r in rules:
        key = (r.pack, r.platform)
        if r.pack not in pack_data:
            meta = PACK_META.get(r.pack, {"name": r.pack.replace("_", " ").title()})
            pack_data[r.pack] = {
                "pack":         r.pack,
                "display_name": meta.get("name", r.pack),
                "platforms":    set(),
                "rule_count":   0,
                "tactics":      set(),
                "techniques":   set(),
                "severities":   defaultdict(int),
                "_conf_sum":    0,
                "_conf_count":  0,
            }

        pd = pack_data[r.pack]
        pd["platforms"].add(r.platform)
        pd["rule_count"] += 1
        if r.tactic:
            pd["tactics"].add(r.tactic)
        if r.technique:
            for t in r.technique.split("/"):
                pd["techniques"].add(t.strip())
        if r.severity:
            pd["severities"][r.severity] += 1
        if r.confidence is not None:
            pd["_conf_sum"] += r.confidence
            pd["_conf_count"] += 1

    result = []
    pack_order = [
        "execution", "persistence", "defense_evasion", "credential_access", "c2",
        "lateral_movement", "discovery", "exfiltration", "impact", "privilege_escalation",
        "initial_access", "cloud", "linux", "network", "web", "threat_intel",
        "identity", "container", "devops", "backup", "hypervisor", "email",
        "database", "vpn", "macos", "dlp", "deception", "correlation",
    ]
    ordered = [p for p in pack_order if p in pack_data]
    ordered += sorted(p for p in pack_data if p not in pack_order)

    for pack in ordered:
        pd = pack_data[pack]
        avg_conf = (
            round(pd["_conf_sum"] / pd["_conf_count"], 1)
            if pd["_conf_count"] > 0 else 0
        )
        tactic_list = [t for t in MITRE_TACTIC_ORDER if t in pd["tactics"]]
        tactic_list += sorted(pd["tactics"] - set(MITRE_TACTIC_ORDER))

        result.append({
            "pack":          pd["pack"],
            "display_name":  pd["display_name"],
            "rule_count":    pd["rule_count"],
            "platforms":     sorted(pd["platforms"]),
            "tactics":       tactic_list,
            "techniques":    sorted(pd["techniques"]),
            "severities":    dict(pd["severities"]),
            "avg_confidence": avg_conf,
        })

    return result


def build_mitre_catalog(rules: list[RuleSummary]) -> list[dict]:
    """Index by MITRE technique → mitre.json."""
    tech_data: dict[str, dict] = {}

    for r in rules:
        if not r.technique:
            continue
        for tech in r.technique.split("/"):
            tech = tech.strip()
            if not tech:
                continue
            if tech not in tech_data:
                tech_data[tech] = {
                    "technique": tech,
                    "tactic":    r.tactic or "",
                    "rule_count": 0,
                    "rule_ids":  [],
                    "packs":     set(),
                    "platforms": set(),
                }
            td = tech_data[tech]
            td["rule_count"] += 1
            td["rule_ids"].append(r.rule_id)
            td["packs"].add(r.pack)
            td["platforms"].add(r.platform)

    result = []
    for tech, td in sorted(tech_data.items(), key=lambda x: -x[1]["rule_count"]):
        result.append({
            "technique":  td["technique"],
            "tactic":     td["tactic"],
            "rule_count": td["rule_count"],
            "rule_ids":   sorted(td["rule_ids"]),
            "packs":      sorted(td["packs"]),
            "platforms":  sorted(td["platforms"]),
        })

    return result


# ── Markdown rule index ───────────────────────────────────────────────────────

def generate_rule_index_md(rules_catalog: dict, packs_catalog: list[dict]) -> str:
    """Generate docs/rules/index.md — compact searchable rule table."""
    total = rules_catalog["count"]
    version = rules_catalog["version"]
    generated = rules_catalog["generated"]

    # Pack display name lookup
    pack_display: dict[str, str] = {p["pack"]: p["display_name"] for p in packs_catalog}

    lines = [
        "# Rule Index",
        "",
        f"**{total} detection rules** — v{version} — generated `{generated}`",
        "",
        "Use your browser's search (`Ctrl+F` / `Cmd+F`) to filter by rule ID,",
        "name, pack, technique, or severity. For programmatic access, use",
        "[`docs/data/rules.json`](https://github.com/cerberus8484/SIEM-Rules/blob/main/docs/data/rules.json).",
        "",
        "---",
        "",
        "## All Rules",
        "",
        "| ID | Name | Pack | Platform | Severity | Conf | Technique |",
        "|---|---|---|---|---|---|---|",
    ]

    sev_abbr = {
        "CRITICAL": "**CRIT**",
        "HIGH":     "HIGH",
        "MEDIUM":   "MED",
        "LOW":      "LOW",
        "INFO":     "info",
    }

    prev_pack = None
    for entry in rules_catalog["rules"]:
        pack_name = pack_display.get(entry["pack"], entry["pack"])
        # Compact name: truncate at 55 chars
        name = entry["name"] if entry["name"] else "—"
        if len(name) > 55:
            name = name[:52] + "..."

        # Add visual separator between packs (empty row with pack header)
        if entry["pack"] != prev_pack:
            if prev_pack is not None:
                lines.append(
                    f"| | | | | | | |"
                )
            prev_pack = entry["pack"]

        sev = sev_abbr.get(entry["severity"], entry["severity"])
        conf = str(entry["confidence"]) if entry["confidence"] else "—"
        tech = entry["technique"] or "—"
        # For multi-technique rules, abbreviate after first
        if "/" in tech:
            parts = tech.split("/")
            tech = f"{parts[0]} +{len(parts)-1}"

        lines.append(
            f"| `{entry['id']}` | {name} | {pack_name} | {entry['platform']} "
            f"| {sev} | {conf} | `{tech}` |"
        )

    lines += [
        "",
        "---",
        "",
        "## By Platform",
        "",
    ]

    # Summary per platform
    for plat in ("splunk", "qradar", "secops", "wazuh"):
        plat_rules = [r for r in rules_catalog["rules"] if r["platform"] == plat]
        if not plat_rules:
            continue
        lines.append(f"**{plat.title()}** — {len(plat_rules)} rules")
        lines.append("")

    lines += [
        "## By Severity",
        "",
    ]
    from collections import Counter
    sev_counts = Counter(r["severity"] for r in rules_catalog["rules"] if r["severity"])
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            lines.append(f"- **{sev}**: {sev_counts[sev]}")
    lines.append("")
    lines += [
        "---",
        "",
        "*Auto-generated by `tools/generate_rule_catalog.py` — do not edit manually.*",
        "",
    ]

    return "\n".join(lines)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate rule catalog JSON + Markdown index."
    )
    parser.add_argument("--dry-run",   action="store_true",
                        help="Validate only — do not write any files")
    parser.add_argument("--stdout",    action="store_true",
                        help="Print rules.json to stdout instead of file")
    parser.add_argument("--md-only",   action="store_true",
                        help="Write docs/rules/index.md only")
    parser.add_argument("--json-only", action="store_true",
                        help="Write JSON files only (no Markdown)")
    parser.add_argument("--version",   default="0.2.0",
                        help="Release version tag (default: 0.2.0)")
    args = parser.parse_args()

    print("Parsing rules...")
    rules = parse_all_rules(BASE_DIR)
    print(f"  {len(rules)} rules in {len({r.file for r in rules})} files")

    print("Extracting names and status...")
    name_status = _build_name_status_index(BASE_DIR)
    named = sum(1 for r in rules if r.rule_id in name_status and name_status[r.rule_id][0])
    print(f"  {named}/{len(rules)} rules have names")

    rules_catalog = build_rule_catalog(rules, name_status, version=args.version)
    packs_catalog = build_pack_catalog(rules)
    mitre_catalog = build_mitre_catalog(rules)

    if args.dry_run:
        print(f"DRY RUN — would write:")
        print(f"  {RULES_JSON}  ({rules_catalog['count']} rules)")
        print(f"  {PACKS_JSON}  ({len(packs_catalog)} packs)")
        print(f"  {MITRE_JSON}  ({len(mitre_catalog)} techniques)")
        print(f"  {RULES_INDEX}")
        return

    if args.stdout:
        print(json.dumps(rules_catalog, indent=2, ensure_ascii=False))
        return

    write_json = not args.md_only
    write_md   = not args.json_only

    if write_json:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        RULES_JSON.write_text(
            json.dumps(rules_catalog, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"  OK  Wrote {RULES_JSON}")

        PACKS_JSON.write_text(
            json.dumps(packs_catalog, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"  OK  Wrote {PACKS_JSON}")

        MITRE_JSON.write_text(
            json.dumps(mitre_catalog, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"  OK  Wrote {MITRE_JSON}")

    if write_md:
        RULES_INDEX.parent.mkdir(parents=True, exist_ok=True)
        md = generate_rule_index_md(rules_catalog, packs_catalog)
        RULES_INDEX.write_text(md, encoding="utf-8")
        print(f"  OK  Wrote {RULES_INDEX}")

    print(f"\nCatalog summary:")
    print(f"  Rules:      {rules_catalog['count']}")
    print(f"  Packs:      {len(packs_catalog)}")
    print(f"  Techniques: {len(mitre_catalog)}")


if __name__ == "__main__":
    main()
