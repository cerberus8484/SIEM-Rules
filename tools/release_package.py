#!/usr/bin/env python3
"""
HuntingThreats Enterprise Hunt Pack — Release Packager (T4)

Builds per-platform ZIP archives for GitHub Releases:
  dist/huntingthreats-splunk-v0.1.0.zip
  dist/huntingthreats-qradar-v0.1.0.zip
  dist/huntingthreats-secops-v0.1.0.zip
  dist/huntingthreats-wazuh-v0.1.0.zip
  dist/huntingthreats-all-v0.1.0.zip

Each archive contains:
  - Platform rule files (*.spl / *.aql / *.udm / *.kql)
  - schema/rule_metadata.yaml
  - COVERAGE.md + coverage.json
  - README.md
  - CHANGELOG.md

Usage:
    python tools/release_package.py --tag v0.1.0
    python tools/release_package.py --tag v0.1.0 --out dist/
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DIST_DIR = BASE_DIR / "dist"

PLATFORM_DIRS: dict[str, str] = {
    "splunk": "*.spl",
    "qradar": "*.aql",
    "secops": "*.udm",
    "wazuh":  "*.kql",
}

# Files always included in every platform package
COMMON_FILES = [
    "schema/rule_metadata.yaml",
    "COVERAGE.md",
    "README.md",
    "CHANGELOG.md",
]

# Extra files in the "all" bundle
ALL_EXTRA_FILES = [
    "coverage.json",
    "tools/rule_linter.py",
    "tools/coverage_matrix.py",
    "tools/fixture_validator.py",
    "tools/requirements.txt",
]


@dataclass
class PackageStats:
    platform: str
    tag: str
    zip_path: Path
    files_included: int
    size_bytes: int
    sha256: str


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_platform_package(
    platform: str,
    glob_ext: str,
    tag: str,
    out_dir: Path,
) -> PackageStats:
    """Build a ZIP for a single platform."""
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"huntingthreats-{platform}-{tag}.zip"
    zip_path = out_dir / zip_name

    rule_dir = BASE_DIR / platform
    if not rule_dir.is_dir():
        rule_dir = BASE_DIR / "analyst_queries" / platform

    files_added = 0

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add platform rule files
        platform_dir = BASE_DIR / platform
        if platform_dir.is_dir():
            for rule_file in sorted(platform_dir.rglob(glob_ext)):
                arcname = rule_file.relative_to(BASE_DIR)
                zf.write(rule_file, arcname)
                files_added += 1

        # Add analyst queries for this platform
        aq_dir = BASE_DIR / "analyst_queries" / platform
        if aq_dir.is_dir():
            for f in sorted(aq_dir.rglob(glob_ext)):
                arcname = f.relative_to(BASE_DIR)
                zf.write(f, arcname)
                files_added += 1

        # Add common metadata files
        for rel in COMMON_FILES:
            fpath = BASE_DIR / rel
            if fpath.exists():
                zf.write(fpath, rel)
                files_added += 1

        # Add version marker
        version_content = f"huntingthreats-enterprise-hunt-pack\nplatform: {platform}\nversion: {tag}\n"
        zf.writestr("VERSION.txt", version_content)
        files_added += 1

    size = zip_path.stat().st_size
    checksum = sha256_of(zip_path)

    # Write checksum file
    checksum_path = zip_path.with_suffix(".zip.sha256")
    checksum_path.write_text(f"{checksum}  {zip_name}\n")

    return PackageStats(
        platform=platform,
        tag=tag,
        zip_path=zip_path,
        files_included=files_added,
        size_bytes=size,
        sha256=checksum,
    )


def build_all_package(tag: str, out_dir: Path) -> PackageStats:
    """Build the combined 'all platforms' bundle."""
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"huntingthreats-all-{tag}.zip"
    zip_path = out_dir / zip_name

    files_added = 0

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add all rule files from all platforms
        for ext in ("*.spl", "*.aql", "*.udm", "*.kql"):
            for fpath in sorted(BASE_DIR.rglob(ext)):
                if "tools" in fpath.parts or "dist" in fpath.parts:
                    continue
                arcname = fpath.relative_to(BASE_DIR)
                zf.write(fpath, arcname)
                files_added += 1

        # Add fixtures
        fixtures_dir = BASE_DIR / "tests" / "fixtures"
        if fixtures_dir.is_dir():
            for fpath in sorted(fixtures_dir.rglob("*.json")):
                arcname = fpath.relative_to(BASE_DIR)
                zf.write(fpath, arcname)
                files_added += 1

        # Add schema
        schema_dir = BASE_DIR / "schema"
        if schema_dir.is_dir():
            for fpath in sorted(schema_dir.iterdir()):
                zf.write(fpath, fpath.relative_to(BASE_DIR))
                files_added += 1

        # Add common + extra files
        for rel in COMMON_FILES + ALL_EXTRA_FILES:
            fpath = BASE_DIR / rel
            if fpath.exists():
                zf.write(fpath, rel)
                files_added += 1

        # Version marker
        version_content = f"huntingthreats-enterprise-hunt-pack\nplatform: all\nversion: {tag}\n"
        zf.writestr("VERSION.txt", version_content)
        files_added += 1

    size = zip_path.stat().st_size
    checksum = sha256_of(zip_path)

    checksum_path = zip_path.with_suffix(".zip.sha256")
    checksum_path.write_text(f"{checksum}  {zip_name}\n")

    return PackageStats(
        platform="all",
        tag=tag,
        zip_path=zip_path,
        files_included=files_added,
        size_bytes=size,
        sha256=checksum,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build release packages for each SIEM platform.")
    parser.add_argument("--tag", required=True, help="Version tag, e.g. v0.1.0")
    parser.add_argument("--out", default=str(DIST_DIR), help="Output directory (default: dist/)")
    args = parser.parse_args()

    out_dir = Path(args.out)
    tag = args.tag

    # Clean existing dist for this tag
    if out_dir.exists():
        for old in out_dir.glob(f"*-{tag}.*"):
            old.unlink()

    print(f"Building release packages for {tag} → {out_dir}/")
    print()

    stats_list: list[PackageStats] = []

    for platform, glob_ext in PLATFORM_DIRS.items():
        stats = build_platform_package(platform, glob_ext, tag, out_dir)
        stats_list.append(stats)
        print(f"  ✔  {stats.zip_path.name:50s}  {stats.files_included:4d} files  "
              f"{stats.size_bytes / 1024:.0f} KB")

    # All-platforms bundle
    all_stats = build_all_package(tag, out_dir)
    stats_list.append(all_stats)
    print(f"  ✔  {all_stats.zip_path.name:50s}  {all_stats.files_included:4d} files  "
          f"{all_stats.size_bytes / 1024:.0f} KB")

    print()
    print("SHA-256 checksums:")
    for s in stats_list:
        print(f"  {s.sha256}  {s.zip_path.name}")

    print()
    print(f"Release {tag} packaged. Upload dist/ artifacts to GitHub Release.")


if __name__ == "__main__":
    main()
