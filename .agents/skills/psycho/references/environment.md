# Environment and paths

No clone is required to have another developer's directory layout. `.reports/`,
`.research/`, `fnv_reverse/`, the game directory, and every log path are
optional. Resolve paths, or ask; never infer them.

## Local configuration

Create `.psycho.local.toml` at the repository root. It is ignored by git.

```toml
# Optional local paths. Do not commit.
fnv_exe = "/path/to/FalloutNV.exe"
game_dir = "/path/to/FalloutNV"
log_dir = "/path/to/logs"
reports_dir = "/path/to/reports"
r2_bin = "r2"
r2mcp_url = "http://127.0.0.1:1234"
```

Environment variables override the file:

| Variable | Meaning |
|---|---|
| `PSYCHO_FNV_EXE` | Supported executable to analyze. |
| `PSYCHO_GAME_DIR` | Game root containing `FalloutNV.exe` or `syringe/`. |
| `PSYCHO_LOG_DIR` | Directory containing the runtime logs. |
| `PSYCHO_REPORTS_DIR` | Directory for supplied problem logs and reports. |
| `PSYCHO_R2` | radare2 binary. |
| `PSYCHO_R2MCP_URL` | Optional r2mcp endpoint, when the host is configured. |
| `PSYCHO_REPO_ROOT` | Repository root for Ghidra scripts and evidence paths. |

Precedence: environment, local config, bounded discovery, then ask.

## Discovery

```bash
python3 .agents/skills/psycho/scripts/psycho_env.py --json
python3 .agents/skills/psycho/scripts/psycho_env.py --shell
python3 .agents/skills/psycho/scripts/psycho_env.py --template
```

The script reports the source of each path (`env`, `config`, `discovered`,
`missing`). It never writes files.

Discovery order:

1. Environment.
2. `.psycho.local.toml`.
3. Current directory and ancestors containing `FalloutNV.exe` or
   `FalloutNVLauncher.exe`.
4. Common Steam roots:
   - `~/.steam/steam/steamapps/common/Fallout New Vegas`
   - `~/.local/share/Steam/steamapps/common/Fallout New Vegas`
5. Common user game roots, shallow only:
   - `~/Games/FalloutNV`, `~/Games/Fallout New Vegas`
6. Repository convenience paths:
   - `fnv_reverse/FalloutNV.exe`
   - `.reports/`, `.research/`, `analysis/radare2/output/`

Discovery does not scan the whole home directory or filesystem.

## Supported executable

`fnv_reverse/FalloutNV.exe` is a convenience default and is gitignored. A clone
may not have it. Use `PSYCHO_FNV_EXE`, the local config, or the game directory.

Compute and report the SHA-256 when identity matters. The documented supported
binary is Fallout: New Vegas `1.4.0.525`, PE32 x86, image base `0x00400000`.
If the discovered executable has a different hash, say so; do not reuse fixed
addresses without reverification.

## Logs

Filenames are stable; locations are not.

| Log | Typical location |
|---|---|
| `psycho-engine-fixes-latest.log` | Game root, repository symlink, configured log directory. |
| `CrashLogger.log` | Game root, MO2 overwrite. |
| `omv-latest.log` | Game root or process working directory. |
| `atom-latest.log` | Game root or process working directory. |

The script checks the game root, current directory, repository root,
`psycho-engine-fixes/`, and an `overwrite/` directory. If a log is missing, ask
for its path or ask the user to run once and provide the file.

Do not assume a developer-specific absolute path, a particular Steam library, or
a fixed mod-manager layout.

## Optional directories

| Directory | Status | Use |
|---|---|---|
| `.reports/` | Optional, gitignored | Supplied problem logs and investigation notes. |
| `.research/` | Optional, gitignored | Read-only third-party reference source. Never patch or build it. |
| `fnv_reverse/` | Optional, gitignored | Local supported executable and analysis cache. |
| `analysis/` | Tracked | Durable radare2/Ghidra evidence. |
| `analysis/radare2/output/` | Tracked | Raw radare2 evidence. |
| `analysis/ghidra/output/` | Tracked | Retained Ghidra evidence. |

If `.reports/` is absent, use `PSYCHO_REPORTS_DIR` or a temporary directory and
tell the user. Do not create `.reports/` silently in another developer's clone
unless the user asks.

If `.research/` is absent, continue with `docs/` and `analysis/`. Do not try to
download another mod's source.

## Deployment is user-only

`build_fnv.sh`, `build.sh`, `release.sh`, packaging, and installation are run
only by the user. Agents must not run them, copy artifacts into a game or
mod-manager directory, or create log symlinks. Agents build and test locally
only.

`psycho-engine-fixes/ln_logs.sh` is also user-run.

## MO2 and Proton

- The game may run through Mod Organizer 2 and a Proton prefix. The mods
  directory and the game directory can be different.
- Logs may appear in the game root, the process working directory, or MO2's
  `overwrite`.
- If a path cannot be proven, ask the user for the exact path. Do not parse or
  guess a Windows path.

## Claude Code skill link

Claude Code reads `.claude/skills/psycho`. The repository commits a symlink to
`.agents/skills/psycho`. If a Windows clone checks the symlink out as a text file,
install a real copy:

```bash
python3 .agents/skills/psycho/scripts/install_claude_skill.py --copy
```

Use `--check` to verify either form. A copy must be refreshed after skill edits.

## radare2

`PSYCHO_R2` or the local config selects the binary. The helper checks `PATH`.
`r2mcp` may be installed as a radare2 plugin without being configured as an MCP
server. That is normal. Use the CLI when the host does not expose r2mcp tools.

## Reporting

State the path and source for every environment value used. Mark missing
optional inputs as missing, not as failures of the repository.
