# gheap rules

These are only the gheap-specific deltas to the repository root rules; all root
acceptance, testing, commit, research, documentation, code-quality, safety, and
performance rules remain inherited.

The inherited no-guessing and fail-first behavioral gates apply to every gheap
feature, crash, OOM, UAF, and performance change without exception.

## Current risk model

- `memory.allocator = 1` uses only scrap heap. It has less performance benefit but is the safest practical mode for broad use.
- Full gheap works on lighter modpacks but large modpacks may fail immediately or later from VAS/OOM pressure.
- Location-specific full-gheap crashes remain unexplained. VAS exhaustion and UAF/reuse races are both unproven; do not select either as a cause until direct evidence proves the failing path.
- Full gheap is not broadly stable. Possible RAM/VRAM texture duplication is unproven and must not drive a fix without engine evidence.

## Non-negotiable invariants

- Mimalloc is CRT-only. Game objects use the slab allocator.
- Acquire Havok Lock before cleanup stages 0-6; AI threads can access freed Havok objects.
- Keep the IO barrier on every OOM path through stages 0, 4, and 5.
- Do not add routine per-allocation logging, allocation, broad locking, scanning, or other hot-path overhead.
- Preserve readable freed memory where the zombie-safety contract requires it.

## Three-way acceptance gate

Every decision must account for:

1. OOM recovery: cleanup, pressure handling, commit/VAS accounting, and quarantine.
2. UAF protection: zombie readability, safe reuse timing, Havok locking, and IO barriers.
3. Performance: sharded hot paths, bounded metadata work, and minimal synchronization.

State explicitly which dimension a change improves and its cost or risk to the other two. Do not call a gheap change complete if it silently worsens one dimension.

For crash fixes, first reproduce the reported crash through its real runtime
boundary and preserve the fail-first evidence. Then follow the root engine-
research rule: search durable feature documents and existing analysis, use the
radare2 MCP as the mandatory primary tool, and use Ghidra only when that MCP is
unavailable. Prove the exact caller, ownership, layout, lifetime, concurrency,
ABI, and intervention point before patching. Run the identical behavioral test
afterward. Create or update the detailed feature document under `docs/`,
including the three-way acceptance tradeoff and evidence paths, then run
focused supporting checks and the supported 32-bit release build.
