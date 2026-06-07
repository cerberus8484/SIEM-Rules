#!/usr/bin/env python3
"""
HuntingThreats Enterprise Hunt Pack — Metadata Normalizer (U2)

Two modes of operation:
  1. String-to-int confidence:  confidence="HIGH"  →  confidence=78
  2. Backfill missing:          (no confidence)    →  confidence=78  (derived from severity)

Also normalizes legacy field names:
  mitre_tactic    →  tactic    (already matches via substring — kept for completeness)
  mitre_technique →  technique (same)

Confidence mapping (string labels used in A-F packs):
  "CRITICAL" → 90
  "HIGH"     → 78
  "MEDIUM"   → 62
  "LOW"      → 45
  "INFO"     → 35

Pack-level adjustments:
  correlation     +5   deception   +7
  credential_access +3  discovery  -5

Usage:
    python tools/metadata_normalizer.py --dry-run        # preview changes
    python tools/metadata_normalizer.py                  # apply
    python tools/metadata_normalizer.py --pack execution persistence
    python tools/metadata_normalizer.py --verbose        # show per-rule detail
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

# ── Confidence Tables ─────────────────────────────────────────────────────────

SEVERITY_TO_CONFIDENCE: dict[str, int] = {
    "CRITICAL": 90,
    "HIGH":     78,
    "MEDIUM":   62,
    "LOW":      45,
    "INFO":     35,
}

# String labels used in A-F packs: confidence="HIGH"
CONF_STRING_MAP: dict[str, int] = {
    "CRITICAL": 90,
    "HIGH":     78,
    "MEDIUM":   62,
    "LOW":      45,
    "INFO":     35,
}

PACK_ADJUSTMENT: dict[str, int] = {
    "correlation":       +5,
    "deception":         +7,
    "credential_access": +3,
    "discovery":         -5,
    "web":               -3,
    "threat_intel":      -5,
}

# ── Regex ─────────────────────────────────────────────────────────────────────

# Numeric confidence (already correct)
RE_CONF_INT    = re.compile(r'\bconfidence\s*=\s*([0-9]+)\b')
# String confidence: confidence="HIGH" or confidence='HIGH'
RE_CONF_STRING = re.compile(r'\bconfidence\s*=\s*["\']([A-Z]+)["\']')
# Severity (static string only)
RE_SEVERITY    = re.compile(r'\bseverity\s*=\s*"(CRITICAL|HIGH|MEDIUM|LOW|INFO)"')
# Dynamic severity (skip these blocks for backfill)
RE_SEVERITY_CASE = re.compile(r'\bseverity\s*=\s*case\(')
# Rule ID
RE_RULE_ID     = re.compile(r'rule_id\s*=\s*"([^"]+)"')
# The eval line containing severity (used for insertion point)
RE_EVAL_WITH_SEVERITY = re.compile(
    r'(\|\s*eval\b[^\n]*?\bseverity\s*=\s*"(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)"[^\n]*)',
    re.IGNORECASE,
)


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class PatchResult:
    file: str
    converted: int    # string → int conversion
    backfilled: int   # missing → added
    skipped: int      # already had numeric confidence
    no_action: int    # no severity, dynamic case(), etc.


# ── Block Splitting ───────────────────────────────────────────────────────────

def split_blocks(text: str) -> list[tuple[int, int]]:
    """Return list of (start, end) byte offsets for each rule block in the file."""
    comment_re = re.compile(
        r'(`comment\("|^--\s+[A-Z]{2,2}-[0-9]+|^//\s+[A-Z]{2,2}-[0-9]+)',
        re.MULTILINE,
    )
    starts = [m.start() for m in comment_re.finditer(text)]
    if not starts:
        return [(0, len(text))]
    blocks = []
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else len(text)
        blocks.append((s, e))
    return blocks


def _derive_pack(file_path: Path) -> str:
    return file_path.parent.name.lower()


# ── Patching Logic ────────────────────────────────────────────────────────────

def patch_file(
    file_path: Path,
    dry_run: bool = False,
    verbose: bool = False,
) -> PatchResult:
    pack = _derive_pack(file_path)
    rel = str(file_path.relative_to(BASE_DIR))
    result = PatchResult(rel, 0, 0, 0, 0)

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  SKIP  {rel}: {e}")
        return result

    new_text = text
    offset = 0  # track shift as we do replacements

    for start, end in split_blocks(text):
        block = text[start:end]
        rule_id = (RE_RULE_ID.search(block) or type("", (), {"group": lambda *a: "?"})()).group(1)

        # Case 1: Already has numeric confidence — skip
        if RE_CONF_INT.search(block):
            result.skipped += 1
            continue

        # Case 2: Has string confidence="HIGH" — convert to integer
        str_m = RE_CONF_STRING.search(block)
        if str_m:
            label = str_m.group(1).upper()
            # Prefer severity-derived value over the string label
            # (A-F packs used confidence="HIGH" for ALL rules regardless of severity)
            sev_m2 = RE_SEVERITY.search(block)
            if sev_m2:
                numeric = SEVERITY_TO_CONFIDENCE.get(sev_m2.group(1), CONF_STRING_MAP.get(label, 65))
            else:
                numeric = CONF_STRING_MAP.get(label)
            if numeric is None:
                result.no_action += 1
                continue
            # Apply pack adjustment
            numeric = max(10, min(98, numeric + PACK_ADJUSTMENT.get(pack, 0)))
            old_snippet = str_m.group(0)          # confidence="HIGH"
            new_snippet = f"confidence={numeric}"
            adj_start = start + offset
            adj_end = end + offset
            block_in_new = new_text[adj_start:adj_end]
            if old_snippet in block_in_new:
                patched_block = block_in_new.replace(old_snippet, new_snippet, 1)
                new_text = new_text[:adj_start] + patched_block + new_text[adj_end:]
                offset += len(new_snippet) - len(old_snippet)
                result.converted += 1
                if verbose:
                    print(f"  CONV   {rule_id:16s}  {old_snippet}  ->  {new_snippet}")
            continue

        # Case 3: No confidence at all — backfill from severity
        if RE_SEVERITY_CASE.search(block):
            result.no_action += 1
            continue

        sev_m = RE_SEVERITY.search(block)
        if not sev_m:
            result.no_action += 1
            continue

        severity = sev_m.group(1)
        numeric = max(10, min(98,
            SEVERITY_TO_CONFIDENCE.get(severity, 65) + PACK_ADJUSTMENT.get(pack, 0)
        ))

        eval_m = RE_EVAL_WITH_SEVERITY.search(block)
        if not eval_m:
            result.no_action += 1
            continue

        old_eval = eval_m.group(1)
        if RE_CONF_INT.search(old_eval):
            result.skipped += 1
            continue

        new_eval = old_eval.rstrip() + f", confidence={numeric}"
        adj_start = start + offset
        adj_end = end + offset
        block_in_new = new_text[adj_start:adj_end]
        if old_eval in block_in_new:
            patched_block = block_in_new.replace(old_eval, new_eval, 1)
            new_text = new_text[:adj_start] + patched_block + new_text[adj_end:]
            offset += len(new_eval) - len(old_eval)
            result.backfilled += 1
            if verbose:
                print(f"  FILL   {rule_id:16s}  {severity} -> confidence={numeric}")
        else:
            result.no_action += 1

    changed = result.converted + result.backfilled
    if changed > 0 and not dry_run:
        file_path.write_text(new_text, encoding="utf-8")

    return result


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize rule metadata (confidence backfill).")
    parser.add_argument("--dry-run", "-n", action="store_true")
    parser.add_argument("--pack", nargs="+")
    parser.add_argument("--platform", choices=["splunk", "qradar", "secops", "wazuh"])
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    ext_map = {
        "splunk": {".spl"}, "qradar": {".aql"},
        "secops": {".udm"}, "wazuh": {".kql"},
    }
    extensions = ext_map.get(args.platform, {".spl", ".aql", ".udm", ".kql"})

    files = [
        f for ext in extensions
        for f in BASE_DIR.rglob(f"*{ext}")
        if not any(p in f.parts for p in ("tools", "schema", "dist"))
    ]

    if args.pack:
        packs = {p.lower() for p in args.pack}
        files = [f for f in files if f.parent.name.lower() in packs]

    if args.dry_run:
        print("DRY RUN — no files will be modified\n")

    totals = PatchResult("", 0, 0, 0, 0)
    files_changed = 0

    for file_path in sorted(files):
        r = patch_file(file_path, dry_run=args.dry_run, verbose=args.verbose)
        totals.converted  += r.converted
        totals.backfilled += r.backfilled
        totals.skipped    += r.skipped
        totals.no_action  += r.no_action
        changed = r.converted + r.backfilled
        if changed > 0:
            files_changed += 1
            if not args.verbose:
                tag = "(dry) " if args.dry_run else ""
                print(f"  {tag}conv={r.converted:3d} fill={r.backfilled:3d}  {r.file}")

    changed_total = totals.converted + totals.backfilled
    print()
    print(f"Files {'would be ' if args.dry_run else ''}changed   : {files_changed}")
    print(f"String->int converted : {totals.converted}")
    print(f"Backfilled (missing)  : {totals.backfilled}")
    print(f"Already numeric OK    : {totals.skipped}")
    print(f"Skipped (no sev/case) : {totals.no_action}")
    print(f"Total changes         : {changed_total}")


if __name__ == "__main__":
    main()
