# gheap rules

These are gheap-specific deltas to the root rules. All inherited acceptance,
testing, commit, research, documentation, code-quality, safety, and performance
rules remain. The no-guessing and fail-first behavioral gates apply to every
gheap feature, crash, OOM, UAF, and performance change.

## Current risk model

- `memory.allocator = 1` uses only scrap heap. It has less performance benefit
  but is the safest practical mode for broad use.
- Full gheap works on lighter modpacks but large modpacks may fail immediately
  or later from VAS/OOM pressure.
- Location-specific full-gheap crashes remain unexplained. VAS exhaustion and
  UAF/reuse races are both unproven; do not select either without direct
  evidence.
- Full gheap is not broadly stable. Possible RAM/VRAM texture duplication is
  unproven and must not drive a fix without engine evidence.

## Non-negotiable invariants

- Mimalloc is CRT-only. Game objects use the slab allocator.
- Acquire Havok Lock before cleanup stages 0-6; AI threads can access freed
  Havok objects.
- Keep the IO barrier on every OOM path through stages 0, 4, and 5.
- No routine per-allocation logging, allocation, broad locking, scanning, or
  other hot-path overhead.
- Preserve readable freed memory where the zombie-safety contract requires it.

## Three-way acceptance gate

Every decision accounts for OOM recovery (cleanup, pressure, commit/VAS,
quarantine), UAF protection (zombie readability, reuse timing, Havok lock, IO
barrier), and performance (sharded hot paths, bounded metadata, minimal
synchronization). State which dimension improves and the cost or risk to the
other two. A change that silently worsens one dimension is not complete.

For crash fixes, reproduce through the real runtime boundary and preserve
fail-first evidence. Then follow the root research rule: search durable docs and
analysis, use radare2 (MCP or CLI), and prove caller, ownership, layout,
lifetime, concurrency, ABI, and intervention point before patching. Run the same
test afterward. Create or update the owning `docs/` feature document with the
three-way tradeoff and evidence paths, then run focused checks and the supported
32-bit release build.
