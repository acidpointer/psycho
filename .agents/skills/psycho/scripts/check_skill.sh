#!/usr/bin/env bash
# Validate the portable Psycho Agent Skill layout and links.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
SKILL="$ROOT/.agents/skills/psycho"
status=0

fail() {
    echo "FAIL: $*" >&2
    status=1
}

ok() {
    echo "ok: $*"
}

[[ -f "$SKILL/SKILL.md" ]] && ok "SKILL.md exists" || fail "missing $SKILL/SKILL.md"
[[ -f "$ROOT/CLAUDE.md" ]] && ok "CLAUDE.md exists" || fail "missing $ROOT/CLAUDE.md"
[[ -f "$ROOT/AGENTS.md" ]] && ok "AGENTS.md exists" || fail "missing $ROOT/AGENTS.md"

if python3 "$SKILL/scripts/install_claude_skill.py" --check --repo "$ROOT" >/dev/null 2>&1; then
    ok "Claude skill resolves to the canonical skill or a valid copy"
else
    fail "Claude skill is missing or does not resolve to the canonical skill"
fi

if grep -q '^@AGENTS.md[[:space:]]*$' "$ROOT/CLAUDE.md"; then
    ok "CLAUDE.md imports AGENTS.md"
else
    fail "CLAUDE.md must contain @AGENTS.md"
fi

if python3 - "$SKILL/SKILL.md" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if not text.startswith("---\n"):
    raise SystemExit("SKILL.md must start with YAML frontmatter")
end = text.find("\n---\n", 4)
if end < 0:
    raise SystemExit("SKILL.md frontmatter is not closed")
front = text[4:end]
values = {}
for line in front.splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip().strip('"')
if values.get("name") != "psycho":
    raise SystemExit("frontmatter name must be psycho")
description = values.get("description", "")
if not description:
    raise SystemExit("frontmatter description is required")
if len(description) > 1024:
    raise SystemExit("frontmatter description exceeds 1024 characters")
if not text.split("---\n", 2)[2].strip():
    raise SystemExit("SKILL.md body is empty")
PY
then
    ok "frontmatter is valid"
else
    fail "frontmatter validation failed"
fi

if python3 - "$SKILL" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
text = (root / "SKILL.md").read_text(encoding="utf-8")
missing = []
for target in re.findall(r"\]\(([^)]+)\)", text):
    target = target.split("#", 1)[0]
    if not target or target.startswith(("http://", "https://", "mailto:")):
        continue
    if not (root / target).exists():
        missing.append(target)
if missing:
    raise SystemExit("missing skill links: " + ", ".join(missing))
PY
then
    ok "skill links resolve"
else
    fail "skill link validation failed"
fi

if grep -RIn --exclude-dir=.git --exclude='*.pyc' '/data/storage[0-9]' "$ROOT/AGENTS.md" "$ROOT/CLAUDE.md" "$SKILL"; then
    fail "hardcoded /data/storage path found"
else
    ok "no hardcoded developer storage path"
fi

python3 - "$SKILL/scripts/psycho_env.py" "$SKILL/scripts/r2q.py" "$SKILL/scripts/docs_index.py" "$SKILL/scripts/install_claude_skill.py" <<'PY'
import sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        compile(handle.read(), path, "exec")
PY
ok "Python scripts compile"

python3 "$SKILL/scripts/docs_index.py" --repo "$ROOT"
ok "documentation index"

bash -n "$SKILL/scripts/check.sh" "$SKILL/scripts/check_skill.sh"
ok "shell scripts parse"

chain_bytes=$(cat \
    "$ROOT/AGENTS.md" \
    "$ROOT/omv/AGENTS.md" \
    "$ROOT/psycho-engine-fixes/src/mods/heap_replacer/gheap/AGENTS.md" | wc -c)
if (( chain_bytes < 28672 )); then
    ok "instruction chain is ${chain_bytes} bytes (below 28 KiB)"
else
    fail "instruction chain is ${chain_bytes} bytes (28 KiB limit)"
fi

exit "$status"
