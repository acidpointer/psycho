#!/usr/bin/env python3
"""Locate optional Psycho repository inputs without hardcoded developer paths.

The script reads `.psycho.local.toml` and `PSYCHO_*` environment variables, then
performs bounded discovery. It never writes files and never scans the whole
filesystem. Missing optional inputs are reported, not guessed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

CONFIG_NAME = ".psycho.local.toml"
ENV_MAP = {
    "fnv_exe": "PSYCHO_FNV_EXE",
    "game_dir": "PSYCHO_GAME_DIR",
    "log_dir": "PSYCHO_LOG_DIR",
    "reports_dir": "PSYCHO_REPORTS_DIR",
    "r2_bin": "PSYCHO_R2",
    "r2mcp_url": "PSYCHO_R2MCP_URL",
}
LOG_NAMES = {
    "psycho": "psycho-engine-fixes-latest.log",
    "crash": "CrashLogger.log",
    "omv": "omv-latest.log",
    "atom": "atom-latest.log",
}
TEMPLATE = """# Optional local paths for the Psycho repository. Do not commit.
# fnv_exe = "/path/to/FalloutNV.exe"
# game_dir = "/path/to/FalloutNV"
# log_dir = "/path/to/logs"
# reports_dir = "/path/to/reports"
# r2_bin = "r2"
# r2mcp_url = "http://127.0.0.1:1234"
"""


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def load_config(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        import tomllib  # Python 3.11+

        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except Exception:
        data = {}
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if key:
                data[key] = value
    return {key: str(value) for key, value in data.items() if isinstance(value, (str, int, float))}


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.is_file() or path.is_dir():
            return path
    return None


def ancestors(start: Path) -> list[Path]:
    result = []
    current = start.resolve()
    while True:
        result.append(current)
        if current.parent == current:
            break
        current = current.parent
    return result


def find_game_dir(repo: Path) -> tuple[Path | None, str]:
    configured = os.environ.get("PSYCHO_GAME_DIR")
    if configured:
        return Path(configured).expanduser(), "env"
    config = load_config(repo / CONFIG_NAME)
    if config.get("game_dir"):
        return Path(config["game_dir"]).expanduser(), "config"

    for base in [Path.cwd(), repo]:
        for directory in ancestors(base):
            if (directory / "FalloutNV.exe").is_file() or (
                directory / "FalloutNVLauncher.exe"
            ).is_file():
                return directory, "discovered"

    home = Path.home()
    candidates = [
        home / ".steam/steam/steamapps/common/Fallout New Vegas",
        home / ".local/share/Steam/steamapps/common/Fallout New Vegas",
        home / ".steam/steam/steamapps/common/FalloutNV",
        home / ".local/share/Steam/steamapps/common/FalloutNV",
        home / "Games/FalloutNV",
        home / "Games/Fallout New Vegas",
    ]
    found = first_existing(candidates)
    return (found, "discovered") if found else (None, "missing")


def find_fnv_exe(repo: Path, game_dir: Path | None) -> tuple[Path | None, str]:
    configured = os.environ.get("PSYCHO_FNV_EXE")
    if configured:
        return Path(configured).expanduser(), "env"
    config = load_config(repo / CONFIG_NAME)
    if config.get("fnv_exe"):
        return Path(config["fnv_exe"]).expanduser(), "config"

    candidate = repo / "fnv_reverse/FalloutNV.exe"
    if candidate.is_file():
        return candidate, "discovered"
    if game_dir is not None and (game_dir / "FalloutNV.exe").is_file():
        return game_dir / "FalloutNV.exe", "discovered"
    return None, "missing"


def find_logs(repo: Path, game_dir: Path | None, log_dir: Path | None) -> dict[str, dict]:
    roots: list[Path] = []
    for candidate in [log_dir, game_dir, Path.cwd(), repo, repo / "psycho-engine-fixes"]:
        if candidate is not None:
            roots.append(candidate)
    if game_dir is not None:
        roots.append(game_dir / "overwrite")

    result = {}
    for key, name in LOG_NAMES.items():
        found = None
        source = "missing"
        for root in roots:
            candidate = root / name
            if candidate.is_file():
                found = candidate
                source = "discovered"
                break
        result[key] = {"path": str(found) if found else None, "source": source, "exists": bool(found)}
    return result


def entry(path: Path | None, source: str) -> dict:
    if path is None:
        return {"path": None, "source": source, "exists": False}
    return {"path": str(path), "source": source, "exists": path.exists()}


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def resolve(repo: Path) -> dict:
    config = load_config(repo / CONFIG_NAME)
    game_dir, game_source = find_game_dir(repo)
    fnv_exe, fnv_source = find_fnv_exe(repo, game_dir)

    log_dir_value = os.environ.get("PSYCHO_LOG_DIR")
    log_source = "env"
    if not log_dir_value:
        log_dir_value = config.get("log_dir")
        log_source = "config" if log_dir_value else "missing"
    log_dir = Path(log_dir_value).expanduser() if log_dir_value else None

    reports_value = os.environ.get("PSYCHO_REPORTS_DIR") or config.get("reports_dir")
    reports_source = "env" if os.environ.get("PSYCHO_REPORTS_DIR") else "config"
    reports_dir = Path(reports_value).expanduser() if reports_value else None
    if reports_dir is None and (repo / ".reports").is_dir():
        reports_dir = repo / ".reports"
        reports_source = "discovered"

    r2_value = os.environ.get("PSYCHO_R2") or config.get("r2_bin")
    r2_source = "env" if os.environ.get("PSYCHO_R2") else "config" if config.get("r2_bin") else "discovered"
    r2_path = Path(r2_value).expanduser() if r2_value else None
    if r2_path is None:
        located = shutil.which("r2")
        r2_path = Path(located) if located else None
    if r2_path is None:
        r2_source = "missing"

    r2mcp_value = os.environ.get("PSYCHO_R2MCP_URL") or config.get("r2mcp_url")
    r2mcp_source = "env" if os.environ.get("PSYCHO_R2MCP_URL") else "config" if config.get("r2mcp_url") else "missing"

    research = repo / ".research"
    analysis = repo / "analysis/radare2/output"

    hints = []
    if fnv_exe is None:
        hints.append("Set PSYCHO_FNV_EXE or fnv_exe in .psycho.local.toml.")
    if game_dir is None:
        hints.append("Set PSYCHO_GAME_DIR or game_dir in .psycho.local.toml.")
    if reports_dir is None:
        hints.append(
            "Set PSYCHO_REPORTS_DIR or reports_dir; otherwise use "
            + str(Path(tempfile.gettempdir()) / "psycho-reports")
            + "."
        )
    if log_dir is None and all(item["path"] is None for item in find_logs(repo, game_dir, None).values()):
        hints.append("Set PSYCHO_LOG_DIR or provide the exact log path.")

    fnv_entry = entry(fnv_exe, fnv_source)
    fnv_entry["sha256"] = sha256(fnv_exe) if fnv_exe else None

    return {
        "repo_root": str(repo),
        "config_file": str(repo / CONFIG_NAME),
        "fnv_exe": fnv_entry,
        "game_dir": entry(game_dir, game_source),
        "log_dir": entry(log_dir, log_source),
        "reports_dir": entry(reports_dir, reports_source),
        "research_dir": entry(research if research.is_dir() else None, "discovered" if research.is_dir() else "missing"),
        "analysis_dir": entry(analysis if analysis.is_dir() else None, "discovered" if analysis.is_dir() else "missing"),
        "logs": find_logs(repo, game_dir, log_dir),
        "r2": entry(r2_path, r2_source),
        "r2mcp_url": {"value": r2mcp_value, "source": r2mcp_source},
        "hints": hints,
    }


def shell_output(data: dict) -> str:
    lines = []
    for key in ["fnv_exe", "game_dir", "log_dir", "reports_dir"]:
        value = data[key]["path"]
        if value:
            lines.append(f"export PSYCHO_{key.upper()}={shlex.quote(value)}")
    if data["r2"]["path"]:
        lines.append(f"export PSYCHO_R2={shlex.quote(data['r2']['path'])}")
    for key, item in data["logs"].items():
        if item["path"]:
            lines.append(f"export PSYCHO_{key.upper()}_LOG={shlex.quote(item['path'])}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=None, help="Repository root.")
    parser.add_argument("--json", action="store_true", help="Print JSON (default).")
    parser.add_argument("--shell", action="store_true", help="Print shell exports.")
    parser.add_argument("--template", action="store_true", help="Print a config template.")
    args = parser.parse_args()

    if args.template:
        print(TEMPLATE, end="")
        return 0

    repo = (args.repo or default_repo_root()).resolve()
    data = resolve(repo)
    if args.shell:
        print(shell_output(data))
    else:
        print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
