#!/usr/bin/env python3
"""Check that docs/README.md indexes every document and has no broken links."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=None, help="Repository root.")
    args = parser.parse_args()

    repo = (args.repo or Path(__file__).resolve().parents[4]).resolve()
    docs = repo / "docs"
    index = docs / "README.md"
    if not index.is_file():
        raise SystemExit(f"missing {index}")

    text = index.read_text(encoding="utf-8")
    linked = set(re.findall(r"^\| \[`([^`]+\.md)`\]", text, re.M))
    present = {path.name for path in docs.glob("*.md") if path.name != "README.md"}

    missing = sorted(present - linked)
    broken = []
    for target in re.findall(r"\]\(([^)]+)\)", text):
        target = target.split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        if not (index.parent / target).exists():
            broken.append(target)

    if missing:
        print("documents missing from the index:", file=sys.stderr)
        for name in missing:
            print(f"  docs/{name}", file=sys.stderr)
    if broken:
        print("broken links in the index:", file=sys.stderr)
        for target in sorted(set(broken)):
            print(f"  {target}", file=sys.stderr)
    if missing or broken:
        return 1
    print(f"docs index ok: {len(present)} documents, {len(linked)} linked entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
