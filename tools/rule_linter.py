#!/usr/bin/env python3
"""
HuntingThreats Enterprise Hunt Pack — Rule Linter
Validates all detection rules for quality, consistency and completeness.

Usage:
    python tools/rule_linter.py                    # lint all rules
    python tools/rule_linter.py --json             # JSON output
    python tools/rule_linter.py --platform splunk  # one platform only
    python tools/rule_linter.py --pack identity    # one pack only
    python tools/rule_linter.py --strict           # exit 1 on any WARNING
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.parent
RULE_EXTENSIONS = {".spl", ".aql", ".udm", ".kql"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_PLATFORMS = {"splunk", "qradar", "secops", "wazuh"}

# ID prefixes mapped to platform
ID_PREFIX_PLATFORM: dict[str, str] = {
    "SP-": "splunk",
    "QR-": "qradar",
    "GS-": "secops",
    "WZ-": "wazuh",
    "PB-": "playbook",
    "AQ-": "analyst",
}

# Intentional config placeholders — not bugs, just deployment-specific
INTENTIONAL_PLACEHOLDERS = {
    "<COMPANY_DOMAIN>",
    "<COMPANY_BUCKET>",
    "<COMPANY_S3>",
    "<INTERNAL_REGISTRY>",
    "<KNOWN_APP_SERVER>",
    "<KNOWN_APP_IP>",
    "<KNOWN_HOST1>",
    "<KNOWN_HOST2>",
    "<KNOWN_CLUSTER>",
    "<CI_RUNNER_SUBNET>",
    "<KNOWN_EXTERNAL_CIDR>",
    "<JUMP_HOST_IP>",
    "<BASTION_IP>",
    "<VPN_CLIENT_SUBNET>",
    "<HONEYPOT_RDP_IP>",
    "<HONEYPOT_SSH_IP>",
    "<HONEYPOT_HOST>",
    "<HONEYPOT_IP_RANGE>",
    "<DECEPTION_SENSOR>",
    "<CANARY_DNS_RECORD>",
    "<CANARY_BACKUP_PATH>",
    "<CANARY_CERT_PATH>",
    "<CANARY_REGKEY>",
    "<HONEY_ACCESS_KEY_ID>",
    "<COMPANY_GIT>",
    "<INTERNAL_GIT>",
    "<INTERNAL_DOMAIN>",
    "<INTERNAL_STORAGE>",
    "<COMPANY_BUCKET_PREFIX>",
    "<KNOWN_SSH_HOSTS>",
    "<OT_SUBNET>",
    "<SCADA_SUBNET>",
    "<ICS_SUBNET>",
    "<DMZ_SUBNET>",
    "<COMPANY_BUCKET_PREFIX>",
    "<CORPORATE_CIDR>",
    "<KNOWN_HOST>",
}

# Real placeholders that indicate broken/unfinished rules
BUG_PLACEHOLDERS = [
    r"\bTODO\b",
    r"\bFIXME\b",
    r"\bchangeme\b",
    r"\bexample\.com\b",
    r"\bexample\.local\b",
    r"\btest\.local\b",
    r"\bDEMO_\b",
    r"\bDUMMY_\b",
]

# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class Issue:
    file: str
    rule_id: str
    level: str  # ERROR, WARNING, INFO
    message: str

    def __str__(self) -> str:
        icon = {"ERROR": "✘", "WARNING": "⚠", "INFO": "ℹ"}.get(self.level, "?")
        return f"  {icon} [{self.level}] {self.rule_id} — {self.message}"


@dataclass
class ParsedRule:
    file: str
    rule_id: str
    tactic: Optional[str] = None
    technique: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[int] = None
    comment_title: Optional[str] = None
    platform: Optional[str] = None
    pack: Optional[str] = None
    line_number: int = 0

    @property
    def id_prefix(self) -> str:
        return self.rule_id[:3] if len(self.rule_id) >= 3 else ""


@dataclass
class LintResult:
    rules: list[ParsedRule] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "ERROR"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "WARNING"]

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)


# ── Regex Patterns ────────────────────────────────────────────────────────────

RE_RULE_ID    = re.compile(r'rule_id\s*=\s*"([^"]+)"')
RE_TACTIC     = re.compile(r'tactic\s*=\s*"([^"]+)"')
RE_TECHNIQUE  = re.compile(r'technique\s*=\s*"([^"]+)"')
# Matches static: severity="CRITICAL" or dynamic: severity=case(...,"CRITICAL",...)
RE_SEVERITY   = re.compile(r'severity\s*=\s*(?:"([^"]+)"|case\([^)]*"(CRITICAL|HIGH|MEDIUM|LOW|INFO)")')
RE_CONFIDENCE = re.compile(r'confidence\s*=\s*([0-9]+)')
RE_COMMENT    = re.compile(r'`comment\("([^"]+)"\)`|--\s*(SP-|QR-|GS-|WZ-|WZ-|AQ-|PB-)([0-9]+)[^|]*\|([^|]+)\|')
RE_VALID_ID   = re.compile(r'^(SP|QR|GS|WZ|PB|AQ)-[0-9]{3,}')
RE_TECHNIQUE_FMT = re.compile(r'^T[0-9]{4}(\.[0-9]{3})?(/T[0-9]{4}(\.[0-9]{3})?)*$')


# ── Parsing ───────────────────────────────────────────────────────────────────

def _derive_platform(file_path: Path) -> str:
    """Derive platform from directory name."""
    parts = [p.lower() for p in file_path.parts]
    for p in VALID_PLATFORMS:
        if p in parts:
            return p
    return "unknown"


def _derive_pack(file_path: Path) -> str:
    """Derive pack from parent directory name."""
    return file_path.parent.name.lower()


def _parse_comment_block(line: str) -> Optional[str]:
    """Extract title from a comment() macro or AQL/UDM comment line."""
    m = re.search(r'`comment\("([^"]+)"\)`', line)
    if m:
        return m.group(1)
    m = re.search(r'^--\s+([A-Z]{2}-[0-9]+ \|.*)', line.strip())
    if m:
        return m.group(1)
    m = re.search(r'^//\s+([A-Z]{2}-[0-9]+ \|.*)', line.strip())
    if m:
        return m.group(1)
    return None


def parse_file(file_path: Path) -> list[ParsedRule]:
    """Parse a single rule file and return all ParsedRule objects found."""
    rules: list[ParsedRule] = []
    platform = _derive_platform(file_path)
    pack = _derive_pack(file_path)

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return rules

    # Split into rule blocks by comment markers
    # A rule block starts at a comment() / -- / // comment line
    current_block_lines: list[str] = []
    current_comment: Optional[str] = None
    current_start_line = 0

    def _flush_block(lines: list[str], comment: Optional[str], start: int) -> None:
        block_text = "\n".join(lines)
        ids = RE_RULE_ID.findall(block_text)
        for rule_id in ids:
            rule = ParsedRule(
                file=str(file_path.relative_to(BASE_DIR)),
                rule_id=rule_id,
                comment_title=comment,
                platform=platform,
                pack=pack,
                line_number=start,
            )
            m = RE_TACTIC.search(block_text)
            if m:
                rule.tactic = m.group(1)
            m = RE_TECHNIQUE.search(block_text)
            if m:
                rule.technique = m.group(1)
            m = RE_SEVERITY.search(block_text)
            if m:
                # group(1) = static string match, group(2) = case() first severity value
                rule.severity = m.group(1) or m.group(2)
            m = RE_CONFIDENCE.search(block_text)
            if m:
                rule.confidence = int(m.group(1))
            rules.append(rule)

    for line_num, line in enumerate(text.splitlines(), 1):
        comment = _parse_comment_block(line)
        if comment is not None:
            if current_block_lines:
                _flush_block(current_block_lines, current_comment, current_start_line)
            current_block_lines = [line]
            current_comment = comment
            current_start_line = line_num
        else:
            current_block_lines.append(line)

    if current_block_lines:
        _flush_block(current_block_lines, current_comment, current_start_line)

    return rules


# ── Validation ────────────────────────────────────────────────────────────────

def validate_rule(rule: ParsedRule) -> list[Issue]:
    issues: list[Issue] = []

    def err(msg: str) -> None:
        issues.append(Issue(rule.file, rule.rule_id, "ERROR", msg))

    def warn(msg: str) -> None:
        issues.append(Issue(rule.file, rule.rule_id, "WARNING", msg))

    # Required: tactic
    if not rule.tactic:
        err("Missing tactic eval")

    # Required: technique
    if not rule.technique:
        err("Missing technique eval")
    elif not RE_TECHNIQUE_FMT.match(rule.technique.split("/")[0].strip()):
        warn(f"Technique '{rule.technique}' does not match T#### or T####.### format")

    # Required: severity
    if not rule.severity:
        err("Missing severity eval")
    elif rule.severity not in VALID_SEVERITIES:
        err(f"Invalid severity '{rule.severity}' — must be one of {VALID_SEVERITIES}")

    # Confidence: WARNING for legacy packs (pre-schema), ERROR when --strict
    if rule.confidence is None:
        warn("Missing confidence eval (add: eval confidence=<0-100>)")
    elif not (0 <= rule.confidence <= 100):
        err(f"Confidence {rule.confidence} out of range 0–100")

    # Rule ID format
    if not RE_VALID_ID.match(rule.rule_id):
        err(f"Rule ID '{rule.rule_id}' does not match expected format (SP|QR|GS|WZ|PB|AQ)-######")

    # Platform / ID prefix consistency
    prefix_platform = None
    for prefix, plat in ID_PREFIX_PLATFORM.items():
        if rule.rule_id.startswith(prefix):
            prefix_platform = plat
            break
    if prefix_platform and prefix_platform != "playbook" and prefix_platform != "analyst":
        if rule.platform != "unknown" and rule.platform != prefix_platform:
            warn(f"ID prefix '{rule.rule_id[:3]}' implies platform '{prefix_platform}' but file is in '{rule.platform}/' directory")

    # Comment title presence
    if not rule.comment_title:
        warn("No comment() header found for this rule block")

    # Severity / confidence consistency check
    if rule.severity == "CRITICAL" and rule.confidence is not None and rule.confidence < 80:
        warn(f"CRITICAL severity but confidence only {rule.confidence} — consider HIGH or raise confidence")
    if rule.confidence is not None and rule.confidence >= 95 and rule.severity in ("MEDIUM", "LOW"):
        warn(f"Confidence {rule.confidence} is very high but severity is {rule.severity} — verify intentional")

    return issues


def check_bug_placeholders(file_path: Path) -> list[Issue]:
    """Check file for placeholder strings that indicate unfinished rules."""
    issues: list[Issue] = []
    # analyst_queries intentionally use example.com as user-facing templates — skip
    if "analyst_queries" in file_path.parts:
        return issues
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return issues

    rel = str(file_path.relative_to(BASE_DIR))
    for pattern in BUG_PLACEHOLDERS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            issues.append(Issue(rel, "FILE", "WARNING", f"Found bug placeholder pattern '{pattern}' ({len(matches)} occurrence(s))"))

    return issues


def check_id_uniqueness(all_rules: list[ParsedRule]) -> list[Issue]:
    """Verify that all rule IDs are globally unique."""
    issues: list[Issue] = []
    seen: dict[str, list[str]] = {}
    for rule in all_rules:
        seen.setdefault(rule.rule_id, []).append(rule.file)

    for rule_id, files in seen.items():
        if len(files) > 1:
            issues.append(Issue(
                files[0],
                rule_id,
                "ERROR",
                f"Duplicate ID found in {len(files)} files: {', '.join(files)}"
            ))
    return issues


# ── Main Linter ───────────────────────────────────────────────────────────────

def run_linter(
    base_dir: Path = BASE_DIR,
    platform_filter: Optional[str] = None,
    pack_filter: Optional[str] = None,
) -> LintResult:
    result = LintResult()
    all_files: list[Path] = []

    for ext in RULE_EXTENSIONS:
        all_files.extend(base_dir.rglob(f"*{ext}"))

    # Filter tools/ and schema/ directories
    all_files = [
        f for f in all_files
        if "tools" not in f.parts and "schema" not in f.parts
    ]

    if platform_filter:
        all_files = [f for f in all_files if platform_filter.lower() in str(f).lower()]

    if pack_filter:
        all_files = [f for f in all_files if pack_filter.lower() in str(f).lower()]

    for file_path in sorted(all_files):
        rules = parse_file(file_path)
        result.rules.extend(rules)
        # File-level checks
        result.issues.extend(check_bug_placeholders(file_path))
        # Rule-level checks
        for rule in rules:
            result.issues.extend(validate_rule(rule))

    # Global checks
    result.issues.extend(check_id_uniqueness(result.rules))

    return result


# ── Output Formatters ─────────────────────────────────────────────────────────

def print_text_report(result: LintResult, verbose: bool = False) -> None:
    # Group issues by file
    by_file: dict[str, list[Issue]] = {}
    for issue in result.issues:
        by_file.setdefault(issue.file, []).append(issue)

    print(f"\n{'='*70}")
    print("  HuntingThreats Hunt Pack — Rule Linter Report")
    print(f"{'='*70}\n")
    print(f"  Scanned:  {len(result.rules):>5} rules in {len({r.file for r in result.rules})} files")
    print(f"  Errors:   {result.error_count:>5}")
    print(f"  Warnings: {result.warning_count:>5}")
    print()

    if result.error_count == 0 and result.warning_count == 0:
        print("  ✔  All rules pass validation.\n")
        return

    for file_path, issues in sorted(by_file.items()):
        errors_in_file = [i for i in issues if i.level == "ERROR"]
        warnings_in_file = [i for i in issues if i.level == "WARNING"]
        if not errors_in_file and not warnings_in_file:
            continue
        print(f"  FILE: {file_path}")
        for issue in sorted(issues, key=lambda i: (i.level, i.rule_id)):
            if issue.level in ("ERROR", "WARNING") or verbose:
                print(str(issue))
        print()

    print(f"{'─'*70}")
    status = "FAIL" if result.error_count > 0 else "PASS (with warnings)"
    print(f"  Status: {status}")
    print(f"{'─'*70}\n")


def print_json_report(result: LintResult) -> None:
    output = {
        "summary": {
            "total_rules": len(result.rules),
            "total_files": len({r.file for r in result.rules}),
            "errors": result.error_count,
            "warnings": result.warning_count,
            "status": "FAIL" if result.error_count > 0 else "PASS",
        },
        "issues": [
            {
                "file": i.file,
                "rule_id": i.rule_id,
                "level": i.level,
                "message": i.message,
            }
            for i in result.issues
            if i.level in ("ERROR", "WARNING")
        ],
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
            for r in result.rules
        ],
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lint HuntingThreats detection rules for quality and consistency."
    )
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--platform", help="Filter by platform (splunk, qradar, secops, wazuh)")
    parser.add_argument("--pack", help="Filter by pack directory name (e.g. identity, backup)")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on WARNING as well as ERROR")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show INFO issues too")
    args = parser.parse_args()

    result = run_linter(
        platform_filter=args.platform,
        pack_filter=args.pack,
    )

    if args.json:
        print_json_report(result)
    else:
        print_text_report(result, verbose=args.verbose)

    if result.error_count > 0:
        return 1
    if args.strict and result.warning_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
