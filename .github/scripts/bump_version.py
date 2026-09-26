"""
Version bump helper script for this adapter repo.

Updates the version string of the adapter crate and the files that must
stay in sync with it:
- Cargo.toml ([package].version)
- examples/*/Cargo.toml (path dependency pins on the adapter, path = "../..")
- Cargo.lock ([[package]] version entry for the adapter crate)
- CHANGELOG.md (inserts a version scaffold at the top for manual editing)

Usage:
    python .github/scripts/bump_version.py <version>
    make bump-version VERSION=x.y.z

No external dependencies required - stdlib only.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Resolve project root relative to this script's location
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

# Example apps pin the adapter as a path dependency pointing at the repo root
EXAMPLE_PIN_PATTERN = re.compile(
    r'^(?P<name>[a-z0-9-]+)\s*=\s*\{\s*path\s*=\s*"\.\./\.\.",\s*'
    r'version\s*=\s*"(?P<version>[^"]+)"\s*\}',
    re.MULTILINE,
)


def crate_name() -> str:
    """Read the adapter crate name from the root Cargo.toml."""
    content = (PROJECT_ROOT / "Cargo.toml").read_text()
    match = re.search(r'^name\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        raise RuntimeError("no [package] name found in Cargo.toml")
    return match.group(1)


def update_root_manifest(version: str) -> bool:
    """Update [package].version in the root Cargo.toml."""
    path = PROJECT_ROOT / "Cargo.toml"
    content = path.read_text()
    pattern = re.compile(r'^version\s*=\s*"[^"]*"', re.MULTILINE)
    match = pattern.search(content)
    if not match:
        print("  ERROR: no [package] version field in Cargo.toml")
        return False
    current = re.search(r'"([^"]*)"', match.group(0))
    if current and current.group(1) == version:
        print(f"  Cargo.toml: already set to {version}")
        return True
    path.write_text(
        pattern.sub(lambda m: re.sub(r'"[^"]*"', f'"{version}"', m.group(0)), content, count=1)
    )
    print(f"  Cargo.toml: updated to {version}")
    return True


def update_example_pins(version: str) -> bool:
    """Update the adapter path+version pins in examples/*/Cargo.toml."""
    ok = True
    examples_dir = PROJECT_ROOT / "examples"
    manifests = sorted(examples_dir.glob("*/Cargo.toml")) if examples_dir.exists() else []
    if not manifests:
        print("  examples/: no example manifests found (skipping)")
        return True
    for manifest in manifests:
        content = manifest.read_text()
        changed = False

        def repl(match: re.Match[str]) -> str:
            nonlocal changed
            if match.group("version") != version:
                changed = True
            return f'{match.group("name")} = {{ path = "../..", version = "{version}" }}'

        new_content = EXAMPLE_PIN_PATTERN.sub(repl, content)
        if changed:
            manifest.write_text(new_content)
            print(f"  {manifest.relative_to(PROJECT_ROOT)}: adapter pin updated to {version}")
        else:
            print(f"  {manifest.relative_to(PROJECT_ROOT)}: adapter pin already up to date")
    return ok


def update_cargo_lock(crate: str, version: str) -> bool:
    """Update the [[package]] version entry of the adapter crate in Cargo.lock."""
    path = PROJECT_ROOT / "Cargo.lock"
    if not path.exists():
        print("  ERROR: Cargo.lock not found")
        return False
    content = path.read_text()
    pattern = re.compile(
        r'(\[\[package\]\]\nname = "%s"\nversion = )"[^"]*"' % re.escape(crate)
    )
    new_content, n = pattern.subn(r'\1"%s"' % version, content)
    if n == 0:
        print(f"  WARNING: no Cargo.lock entry found for crate {crate}")
        return True
    if new_content != content:
        path.write_text(new_content)
        print(f"  Cargo.lock: {crate} updated to {version}")
    else:
        print(f"  Cargo.lock: {crate} already at {version}")
    return True


def insert_changelog_scaffold(version: str) -> bool:
    """Insert a version scaffold block at the top of CHANGELOG.md.

    Mirrors guard-core-rs's bump_version.py scaffold behavior, adapted to
    this repo's keep-a-changelog style.
    """
    path = PROJECT_ROOT / "CHANGELOG.md"
    if not path.exists():
        print("  ERROR: CHANGELOG.md not found")
        return False
    content = path.read_text()
    today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    if f"## [{version}]" in content:
        print(f"  CHANGELOG.md: {version} entry already exists")
        return True

    scaffold = (
        f"## [{version}] - {today}\n"
        f"\n"
        f"### Added\n"
        f"\n"
        f"- (v{version}) describe additions here\n"
        f"\n"
        f"### Changed\n"
        f"\n"
        f"- (v{version}) describe changes here\n"
        f"\n"
    )

    # Insert before the first existing version heading ([Unreleased] included)
    heading_pattern = re.compile(r"^## \[", re.MULTILINE)
    match = heading_pattern.search(content)
    if match:
        insert_pos = match.start()
        new_content = content[:insert_pos] + scaffold + content[insert_pos:]
    else:
        new_content = content.rstrip() + "\n\n" + scaffold

    path.write_text(new_content)
    print(f"  CHANGELOG.md: added v{version} scaffold")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: bump_version.py <version>")
        print("  version must be in X.Y.Z format")
        return 1

    version = sys.argv[1]

    if not VERSION_PATTERN.match(version):
        print(f"Error: '{version}' is not a valid version. Expected format: X.Y.Z")
        return 1

    crate = crate_name()
    print(f"Bumping {crate} to {version}...\n")

    ok = True
    for name, updater in [
        ("Cargo.toml", update_root_manifest),
        ("example pins", update_example_pins),
        ("Cargo.lock", lambda v: update_cargo_lock(crate, v)),
        ("CHANGELOG.md scaffold", insert_changelog_scaffold),
    ]:
        try:
            if not updater(version):
                print(f"\n  FAILED: {name}")
                ok = False
        except Exception as e:
            print(f"\n  ERROR updating {name}: {e}")
            ok = False

    print()
    if ok:
        print("Version bump complete.")
        print("Next steps: edit the CHANGELOG.md scaffold, then commit and tag.")
    else:
        print("Version bump completed with errors.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
