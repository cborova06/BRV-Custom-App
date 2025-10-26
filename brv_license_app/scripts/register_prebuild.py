#!/usr/bin/env python3
"""Register prebuild script in a package.json to call the prebuild wrapper

This script is intended to live inside the custom app `brv_license_app` and will
add a `prebuild` entry into a target `package.json` (idempotent). It will:

- compute a relative path from the package.json to the wrapper `prebuild_i18n.sh`
- backup the original package.json to `package.json.<sha1>.bak`
- write the updated package.json atomically

Usage:
    python3 register_prebuild.py --package /path/to/package.json

If no package path is provided the script will attempt to find `apps/helpdesk/desk/package.json`
relative to this script's parent directories.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import tempfile


def sha1_of_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def atomic_replace(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8", newline="\n") as tf:
        tf.write(data)
        tf.flush()
        os.fsync(tf.fileno())
        tmp_name = tf.name
    os.replace(tmp_name, str(path))


def find_default_package_json() -> pathlib.Path:
    # This script lives at apps/brv_license_app/brv_license_app/scripts/register_prebuild.py
    # Default target: apps/helpdesk/desk/package.json
    here = pathlib.Path(__file__).resolve()
    repo_apps = here.parents[3]  # .../apps
    default = repo_apps / "helpdesk" / "desk" / "package.json"
    return default


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", "-p", help="Path to package.json to modify")
    ap.add_argument("--wrapper", "-w", help="Path to prebuild wrapper script (optional)")
    args = ap.parse_args(argv)

    pkg_path = pathlib.Path(args.package) if args.package else find_default_package_json()
    pkg_path = pkg_path.resolve()

    if not pkg_path.exists():
        print(f"package.json not found: {pkg_path}", file=sys.stderr)
        return 2

    wrapper = pathlib.Path(args.wrapper) if args.wrapper else (pathlib.Path(__file__).resolve().parent / "prebuild_i18n.sh")
    if not wrapper.exists():
        print(f"wrapper not found: {wrapper}", file=sys.stderr)
        return 2

    # compute relative path from package.json directory to wrapper
    rel = os.path.relpath(str(wrapper), start=str(pkg_path.parent))
    # Use bash to ensure bash-specific options (pipefail) in wrapper work as intended
    prebuild_cmd = f"bash {rel}"

    orig_bytes = pkg_path.read_bytes()
    try:
        data = json.loads(orig_bytes)
    except Exception as e:
        print(f"Failed to parse {pkg_path}: {e}", file=sys.stderr)
        return 2

    scripts = data.get("scripts")
    if scripts is None:
        scripts = {}
        data["scripts"] = scripts

    existing = scripts.get("prebuild")
    if existing == prebuild_cmd:
        print(f"prebuild already set to: {prebuild_cmd}")
        return 0

    # backup original package.json
    bak_name = f"{pkg_path.name}.{sha1_of_bytes(orig_bytes)[:8]}.bak"
    bak_path = pkg_path.with_name(bak_name)
    if not bak_path.exists():
        bak_path.write_bytes(orig_bytes)
        print(f"Wrote backup: {bak_path}")
    else:
        print(f"Backup already exists: {bak_path}")

    # set prebuild
    scripts["prebuild"] = prebuild_cmd

    new_text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    atomic_replace(pkg_path, new_text)
    print(f"Updated {pkg_path} -> scripts.prebuild = {prebuild_cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
