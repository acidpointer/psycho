#!/usr/bin/env python3
"""Query the supported executable with radare2 and capture evidence.

r2mcp is optional. This helper keeps the CLI path high quality: relocations are
applied, colour is disabled, cross-references use `aar`, and r2ghidra `pdg` is
used when available. `pdc` is never used as an authority.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

import psycho_env


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def resolve_binary(args: argparse.Namespace, repo: Path, data: dict) -> Path:
    if args.bin:
        return Path(args.bin).expanduser().resolve()
    configured = os.environ.get("PSYCHO_FNV_EXE")
    if configured:
        return Path(configured).expanduser().resolve()
    path = data["fnv_exe"]["path"]
    if path:
        return Path(path).resolve()
    raise SystemExit(
        "No supported executable found. Set PSYCHO_FNV_EXE, pass --bin, or set "
        "fnv_exe in .psycho.local.toml."
    )


def resolve_r2(args: argparse.Namespace, data: dict) -> str:
    if args.r2:
        candidate = shutil.which(args.r2) or args.r2
        return candidate
    path = data["r2"]["path"]
    if path:
        return path
    located = shutil.which("r2")
    if located:
        return located
    raise SystemExit("radare2 not found. Set PSYCHO_R2 or install r2.")


def run_capture(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )


def plugin_list(r2: str, binary: Path, timeout: int) -> str:
    result = run_capture([r2, "-q", "-c", "Lc", "-c", "q", str(binary)], timeout)
    return result.stdout or ""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def r2_version(r2: str) -> str:
    try:
        result = subprocess.run(
            [r2, "-v"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20, check=False
        )
        return (result.stdout or "").splitlines()[0] if result.stdout else "unknown"
    except Exception:
        return "unknown"


def validate_target(target: str) -> str:
    if not target:
        raise SystemExit("A target address, symbol, or string is required.")
    if any(character.isspace() for character in target):
        raise SystemExit("Target must not contain whitespace.")
    return target


def build_commands(args: argparse.Namespace, has_pdg: bool) -> list[str]:
    commands: list[str] = []
    if args.command == "info":
        commands = ["iI", "iS", "iE", "ii"]
    elif args.command == "func":
        target = validate_target(args.target)
        commands = ["s " + target, "af", "afi", "pdf"]
        if args.decomp:
            if has_pdg:
                commands.append("pdg")
            else:
                print("warning: r2ghidra/pdg unavailable; returning disassembly only", file=sys.stderr)
    elif args.command == "callers":
        target = validate_target(args.target)
        commands = ["aar", "axt " + target]
    elif args.command == "bytes":
        target = validate_target(args.target)
        commands = [f"p8 {args.count} @ {target}"]
    elif args.command == "string":
        commands = ["izz~" + args.target]
    elif args.command == "rtti":
        target = validate_target(args.target)
        commands = ["s " + target, "avr"]
    elif args.command == "disasm":
        target = validate_target(args.target)
        commands = [f"pd {args.count} @ {target}"]
    elif args.command == "search-hex":
        commands = ["/x " + args.target]
    else:
        raise SystemExit(f"unknown command: {args.command}")
    return commands


def sanitize_topic(topic: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", topic.strip())
    return cleaned.strip("-") or "evidence"


def evidence_dir(repo: Path, data: dict) -> Path:
    analysis = repo / "analysis/radare2/output"
    if analysis.is_dir():
        return analysis
    reports = data["reports_dir"]["path"]
    if reports:
        path = Path(reports)
        path.mkdir(parents=True, exist_ok=True)
        return path
    raise SystemExit(
        "No evidence directory. Create analysis/radare2/output or set "
        "PSYCHO_REPORTS_DIR."
    )


def write_evidence(
    repo: Path,
    data: dict,
    topic: str,
    binary: Path,
    r2: str,
    command: list[str],
    commands: list[str],
    output: str,
) -> Path:
    directory = evidence_dir(repo, data)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    path = directory / f"{sanitize_topic(topic)}_{stamp}.txt"
    header = [
        "Psycho radare2 evidence",
        "UTC: " + datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "Binary: " + str(binary),
        "SHA-256: " + sha256(binary),
        "radare2: " + r2_version(r2),
        "Command: " + " ".join(command),
        "r2 commands: " + " | ".join(commands),
        "Note: decompiler output is a hypothesis. Disassembly, bytes, caller",
        "coverage, and runtime signature checks are the authority.",
        "This file is not patch authority.",
        "",
    ]
    path.write_text("\n".join(header) + output, encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=["info", "func", "callers", "bytes", "string", "rtti", "disasm", "search-hex"],
    )
    parser.add_argument("target", nargs="?", default="", help="Address, symbol, or search text.")
    parser.add_argument("count", nargs="?", type=int, default=16, help="Byte or instruction count.")
    parser.add_argument("--bin", default=None, help="Executable path override.")
    parser.add_argument("--r2", default=None, help="radare2 binary override.")
    parser.add_argument("--timeout", type=int, default=300, help="radare2 timeout in seconds.")
    parser.add_argument("--decomp", action="store_true", help="Add pdg when r2ghidra is available.")
    parser.add_argument("--evidence-topic", default=None, help="Write raw output to analysis evidence.")
    parser.add_argument("--repo", type=Path, default=None, help="Repository root.")
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("count must be positive")

    repo = (args.repo or repo_root()).resolve()
    data = psycho_env.resolve(repo)
    binary = resolve_binary(args, repo, data)
    if not binary.is_file():
        raise SystemExit(f"executable does not exist: {binary}")
    r2 = resolve_r2(args, data)

    plugins = plugin_list(r2, binary, args.timeout)
    has_pdg = "r2ghidra" in plugins
    has_r2mcp = "r2mcp" in plugins
    if args.command == "info":
        print("radare2 plugin note: r2ghidra=" + ("yes" if has_pdg else "no") + ", r2mcp=" + ("yes" if has_r2mcp else "no"), file=sys.stderr)
        if has_r2mcp:
            print("r2mcp is available as a plugin; use it only if the host exposes its MCP tools.", file=sys.stderr)

    commands = build_commands(args, has_pdg)
    command = [
        r2,
        "-q",
        "-e",
        "scr.color=0",
        "-e",
        "scr.html=false",
        "-e",
        "bin.relocs.apply=true",
        "-e",
        f"anal.timeout={args.timeout}",
    ]
    for item in commands:
        command.extend(["-c", item])
    command.extend(["-c", "q", str(binary)])

    try:
        result = run_capture(command, args.timeout)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"radare2 timed out after {args.timeout}s; raise --timeout")

    output = result.stdout or ""
    if output:
        print(output, end="")
    if args.evidence_topic:
        path = write_evidence(
            repo,
            data,
            args.evidence_topic,
            binary,
            r2,
            command,
            commands,
            output,
        )
        print(f"\nEvidence written to {path}", file=sys.stderr)

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
