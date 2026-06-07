#!/usr/bin/env python3
"""
HuntingThreats Enterprise Hunt Pack — Fixture Validator (T3)

Validates that every test fixture references a rule_id that actually exists
in the rule files. Also checks fixture schema completeness.

Exits 0 on success, 1 on any error.

Usage:
    python tools/fixture_validator.py
    python tools/fixture_validator.py --verbose
    python tools/fixture_validator.py --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).parent.parent
FIXTURES_DIR = BASE_DIR / "tests" / "fixtures"
RULE_EXTENSIONS = {".spl", ".aql", ".udm", ".kql"}

# Fields required in EVERY fixture (TP and FP)
REQUIRED_FIELDS_ALL = {"expected_result", "scenario"}
# Additional fields required only for TP (ALERT) fixtures
REQUIRED_FIELDS_TP_ONLY = {"severity", "mitre", "confidence"}
VALID_EXPECTED = {"ALERT", "NO_ALERT"}
VALID_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# Pattern for valid rule IDs
RE_RULE_ID_VAL = re.compile(r"^(SP|QR|GS|WZ|PB)-[0-9]{3,}$")
# Pattern for extracting rule_id from rule files
RE_RULE_ID_IN_FILE = re.compile(r'rule_id\s*=\s*"([^"]+)"')
# Also match comment headers like SP-700001
RE_RULE_ID_COMMENT = re.compile(r"\b(SP|QR|GS|WZ|PB)-([0-9]{3,})\b")


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class ValidationIssue:
    fixture_file: str
    level: str   # ERROR | WARNING
    message: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.fixture_file}: {self.message}"


@dataclass
class ValidationResult:
    fixtures_checked: int = 0
    rule_ids_found_in_rules: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "ERROR"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "WARNING"]

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0


# ── Rule ID Collection ────────────────────────────────────────────────────────

def collect_rule_ids(base_dir: Path) -> set[str]:
    """Collect all rule IDs defined across all rule files."""
    ids: set[str] = set()
    for ext in RULE_EXTENSIONS:
        for fpath in base_dir.rglob(f"*{ext}"):
            if "tools" in fpath.parts or "schema" in fpath.parts:
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for match in RE_RULE_ID_IN_FILE.finditer(text):
                ids.add(match.group(1))
            # Also catch IDs in comment headers (e.g. `comment("SP-700001 | ...")`)
            for match in RE_RULE_ID_COMMENT.finditer(text):
                candidate = f"{match.group(1)}-{match.group(2)}"
                ids.add(candidate)
    return ids


# ── Fixture Loading & Validation ──────────────────────────────────────────────

def _get_rule_ids_from_fixture(data: dict) -> list[str]:
    """Extract all rule IDs referenced in a fixture (handles both rule_id and rule_ids)."""
    ids: list[str] = []
    if "rule_id" in data:
        val = data["rule_id"]
        if isinstance(val, str):
            ids.append(val)
        elif isinstance(val, list):
            ids.extend(val)
    if "rule_ids" in data:
        val = data["rule_ids"]
        if isinstance(val, str):
            ids.append(val)
        elif isinstance(val, list):
            ids.extend(val)
    return ids


def validate_fixture(
    fixture_path: Path,
    known_rule_ids: set[str],
    verbose: bool = False,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    rel = str(fixture_path.relative_to(BASE_DIR))

    # Load JSON
    try:
        text = fixture_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except json.JSONDecodeError as e:
        issues.append(ValidationIssue(rel, "ERROR", f"JSON parse error: {e}"))
        return issues
    except Exception as e:
        issues.append(ValidationIssue(rel, "ERROR", f"Cannot read file: {e}"))
        return issues

    # Universal required fields
    for f in REQUIRED_FIELDS_ALL:
        if f not in data:
            issues.append(ValidationIssue(rel, "ERROR", f"Missing required field: '{f}'"))

    # TP-only required fields
    if data.get("expected_result") == "ALERT":
        for f in REQUIRED_FIELDS_TP_ONLY:
            if f not in data:
                issues.append(ValidationIssue(rel, "WARNING", f"TP fixture missing recommended field: '{f}'"))

    # expected_result valid
    if "expected_result" in data and data["expected_result"] not in VALID_EXPECTED:
        issues.append(ValidationIssue(
            rel, "ERROR",
            f"Invalid expected_result '{data['expected_result']}' — must be one of {VALID_EXPECTED}"
        ))

    # severity valid
    if "severity" in data and data["severity"] not in VALID_SEVERITY:
        issues.append(ValidationIssue(
            rel, "ERROR",
            f"Invalid severity '{data['severity']}' — must be one of {VALID_SEVERITY}"
        ))

    # confidence range
    if "confidence" in data:
        try:
            c = int(data["confidence"])
            if not 0 <= c <= 100:
                issues.append(ValidationIssue(rel, "ERROR", f"confidence {c} out of range [0, 100]"))
        except (ValueError, TypeError):
            issues.append(ValidationIssue(rel, "ERROR", "confidence must be an integer"))

    # TP should have analyst_action
    if data.get("expected_result") == "ALERT" and "analyst_action" not in data:
        issues.append(ValidationIssue(rel, "WARNING", "TP fixture missing 'analyst_action' field"))

    # FP should have tuning_recommendation
    if data.get("expected_result") == "NO_ALERT" and "tuning_recommendation" not in data:
        issues.append(ValidationIssue(
            rel, "WARNING", "FP fixture missing 'tuning_recommendation' field"
        ))

    # Rule IDs must exist in rule files
    referenced_ids = _get_rule_ids_from_fixture(data)
    if not referenced_ids:
        issues.append(ValidationIssue(rel, "ERROR", "No rule_id or rule_ids field found"))
    else:
        for rid in referenced_ids:
            if not RE_RULE_ID_VAL.match(rid):
                issues.append(ValidationIssue(
                    rel, "ERROR", f"Invalid rule_id format: '{rid}'"
                ))
            elif rid not in known_rule_ids:
                issues.append(ValidationIssue(
                    rel, "ERROR",
                    f"rule_id '{rid}' not found in any rule file — fixture references non-existent rule"
                ))
            else:
                if verbose:
                    print(f"  OK  {rid} → {rel}")

    return issues


# ── Entry Point ───────────────────────────────────────────────────────────────

def run_validation(verbose: bool = False) -> ValidationResult:
    result = ValidationResult()

    # Collect all known rule IDs from rule files
    print("Collecting rule IDs from rule files...")
    known_ids = collect_rule_ids(BASE_DIR)
    result.rule_ids_found_in_rules = len(known_ids)
    print(f"  Found {len(known_ids)} unique rule IDs across all rule files")

    # Find all fixture JSON files
    fixture_files = [
        f for f in FIXTURES_DIR.rglob("*.json")
        if f.name != "README.md"
    ]
    print(f"  Found {len(fixture_files)} fixture files in {FIXTURES_DIR}")

    if not fixture_files:
        result.issues.append(ValidationIssue(
            str(FIXTURES_DIR), "WARNING", "No fixture files found"
        ))
        return result

    # Validate each fixture
    for fixture_path in sorted(fixture_files):
        result.fixtures_checked += 1
        issues = validate_fixture(fixture_path, known_ids, verbose=verbose)
        result.issues.extend(issues)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate test fixtures against rule files.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show OK checks too")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    result = run_validation(verbose=args.verbose)

    if args.json:
        out = {
            "fixtures_checked": result.fixtures_checked,
            "rule_ids_in_rules": result.rule_ids_found_in_rules,
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "passed": result.passed,
            "issues": [
                {"file": i.fixture_file, "level": i.level, "message": i.message}
                for i in result.issues
            ],
        }
        print(json.dumps(out, indent=2))
    else:
        print()
        if result.issues:
            for issue in result.issues:
                prefix = "[ERROR]" if issue.level == "ERROR" else "[WARN] "
                print(f"  {prefix}  {issue}")
            print()

        print(f"Fixtures checked : {result.fixtures_checked}")
        print(f"Rule IDs indexed : {result.rule_ids_found_in_rules}")
        print(f"Errors           : {len(result.errors)}")
        print(f"Warnings         : {len(result.warnings)}")
        print()

        if result.passed:
            print("PASS  All fixture validations passed.")
        else:
            print(f"FAIL  {len(result.errors)} error(s) found — fix before merging.")
            sys.exit(1)


if __name__ == "__main__":
    main()
