#!/usr/bin/env python3
"""Install or verify the Claude Code skill link.

The canonical skill lives in .agents/skills/psycho. Claude Code reads
.claude/skills/psycho. The default is a symlink. Use --copy on systems where
symlinks are unavailable, such as a Windows clone without Developer Mode.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def current_target(dst: Path):
    if dst.is_symlink():
        return dst.resolve()
    if dst.is_dir():
        return dst.resolve()
    if dst.exists():
        return None
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=None, help="Repository root.")
    parser.add_argument("--copy", action="store_true", help="Install a real copy instead of a symlink.")
    parser.add_argument("--check", action="store_true", help="Verify only.")
    parser.add_argument("--force", action="store_true", help="Replace an existing real directory.")
    args = parser.parse_args()

    repo = (args.repo or repo_root()).resolve()
    src = repo / ".agents/skills/psycho"
    dst = repo / ".claude/skills/psycho"
    if not (src / "SKILL.md").is_file():
        raise SystemExit(f"missing canonical skill: {src}")

    if args.check:
        if not dst.exists():
            raise SystemExit(f"missing {dst}")
        if dst.is_symlink():
            state = dst.resolve()
            if state != src.resolve():
                raise SystemExit(f"{dst} resolves to {state}, expected {src.resolve()}")
            print(f"ok: {dst} -> {state}")
            return 0
        if dst.is_dir():
            if not (dst / "SKILL.md").is_file():
                raise SystemExit(f"{dst} is a directory without SKILL.md")
            print(f"ok: {dst} is a copy; symlink is preferred")
            return 0
        raise SystemExit(f"{dst} exists but is not a skill directory or symlink")

    dst.parent.mkdir(parents=True, exist_ok=True)
    state = current_target(dst)
    if state is not False:
        if state == src.resolve():
            print(f"ok: {dst} already resolves to the canonical skill")
            return 0
        if dst.is_symlink() or (dst.is_dir() and args.force):
            if dst.is_symlink():
                dst.unlink()
            else:
                shutil.rmtree(dst)
        else:
            raise SystemExit(f"{dst} exists and is not the canonical skill; use --force to replace")

    if not args.copy:
        try:
            dst.symlink_to(Path("../../.agents/skills/psycho"), target_is_directory=True)
            print(f"linked {dst}")
            return 0
        except OSError as error:
            print(f"symlink failed ({error}); installing a copy instead", file=sys.stderr)

    shutil.copytree(src, dst)
    print(f"copied {src} to {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
