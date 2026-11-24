#!/usr/bin/env python3
"""Detect which languages are present so the action only runs matching scanners."""

import argparse
import os
import sys
from pathlib import Path

SKIP_DIRS = {"node_modules", "vendor", "target", "dist", ".git"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    args = parser.parse_args()
    root = Path(args.path)
    if not root.exists():
        print(f"scan path does not exist: {root}", file=sys.stderr)
        return 2
    found = {"go": False, "js": False, "rust": False}
    if root.is_file():
        mark(root, found)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")]
            for name in filenames:
                mark(Path(dirpath) / name, found)
    print(f"go={'true' if found['go'] else 'false'}")
    print(f"js={'true' if found['js'] else 'false'}")
    print(f"rust={'true' if found['rust'] else 'false'}")
    return 0


def mark(path: Path, found: dict[str, bool]) -> None:
    name = path.name
    if name.endswith(".go"):
        found["go"] = True
    elif name.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
        found["js"] = True
    elif name.endswith(".rs"):
        found["rust"] = True


if __name__ == "__main__":
    raise SystemExit(main())
