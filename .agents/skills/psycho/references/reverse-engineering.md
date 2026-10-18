# Reverse engineering

## Purpose

Use native research only to close a material contract the repository cannot
prove from existing code, docs, logs, or analysis. Reuse proven contracts for
the same executable and reverify only address-sensitive facts.

## Binary identity

Before trusting an address, record:

- path;
- SHA-256;
- PE class, architecture, image base;
- section and import facts only when the contract depends on them;
- whether relocations were applied.

The repository's documented supported binary is Fallout: New Vegas
`1.4.0.525`, PE32 x86, image base `0x00400000`, with the identity recorded in
the owning contract and `docs/fnv_location_performance_static_audit.md`.
`fnv_reverse/FalloutNV.exe` is a convenience default, not a required path.
Other clones may use a configured or discovered executable.

```bash
python3 .agents/skills/psycho/scripts/r2q.py info
```

If the hash does not match the documented supported executable, say so. Do not
silently reuse addresses.

## Tool order

1. Existing durable evidence: `docs/`, `analysis/radare2/output/`, and
   historical `analysis/ghidra/output/`.
2. r2mcp, when the host exposes its tools.
3. radare2 CLI, with `pdg` when `r2ghidra` is installed and `pdf` otherwise.

Ghidra script authoring and execution are deprecated and not effective. Do not
create, edit, run, or request Ghidra scripts. Existing Ghidra output is
historical evidence only, not current patch authority.

r2mcp is optional. The CLI path must produce the same quality.

## r2mcp to CLI mapping

| r2mcp tool | CLI equivalent |
|---|---|
| `open_file` | `r2 -q -e bin.relocs.apply=true <binary>` |
| `show_info` | `iI` |
| `list_sections` | `iS` |
| `list_imports` | `ii` |
| `list_exports` | `iE` |
| `list_functions` | `afl` |
| `analyze` | `aa`, then `aar` for references |
| `decompile_function` | `s ADDR; af; pdg` |
| `disassemble_function` | `s ADDR; af; pdf` |
| `xrefs_to` | `aar; axt ADDR` |
| `get_function_prototype` | `afi` |
| `hexdump` | `px N @ ADDR` |
| `search` | `/x PATTERN`, `izz~TEXT` |
| `lookup_symbol` | `is~NAME`, `afl~NAME` |

If r2mcp is available, select the r2ghidra `pdg` backend before decompiling.
Its default `pdc` backend is experimental and unreliable.

## Tool probe

```bash
r2 -v
r2 -q -c 'Lc' -c 'q' "$FNV_EXE" | grep -E 'r2ghidra|r2mcp'
r2 -q -c 'r2mcp status' -c 'q' "$FNV_EXE"
```

- `r2ghidra` enables `pdg`.
- `r2mcp` is a radare2 plugin. Its presence does not mean the host has an MCP
  server or MCP tools.
- `r2mcp status` reports whether the plugin server is running.
- Use r2mcp only when the host exposes its tools. Starting or configuring a
  server is a host action; do not do it silently.
- If r2mcp is absent or unconfigured, use the CLI below.

## Tested CLI cookbook

Always set `bin.relocs.apply=true`; the executable otherwise warns that
relocations were not applied. Use color-free output for evidence.

```bash
FNV_EXE="${PSYCHO_FNV_EXE:-fnv_reverse/FalloutNV.exe}"

# Identity
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'iI' -c 'iS' -c 'iE' -c 'ii' -c 'q' "$FNV_EXE"

# Function metadata and disassembly
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 's 0x00567D20' -c 'af' -c 'afi' -c 'pdf' -c 'q' "$FNV_EXE"

# r2ghidra decompilation
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 's 0x00567D20' -c 'af' -c 'pdg' -c 'q' "$FNV_EXE"

# Callers. af alone does not discover references; aar does.
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'aar' -c 'axt 0x00567D20' -c 'q' "$FNV_EXE"

# Exact signature bytes
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'p8 16 @ 0x00567D20' -c 'q' "$FNV_EXE"

# Strings
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'izz~AddOcclusionPlane' -c 'q' "$FNV_EXE"

# RTTI and vtable identity
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 's 0x0102CBBC' -c 'avr' -c 'q' "$FNV_EXE"

# Raw function metadata as JSON
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 's 0x00567D20' -c 'af' -c 'afij' -c 'q' "$FNV_EXE"
```

Observed smoke-test results on the documented binary:

- `0x00567D20` is a 106-byte function with 35 instructions.
- `aar; axt 0x00567D20` finds 9 callers, matching the documented encounter-zone
  contract.
- Bytes at `0x00567D20`: `558bec83ec08894df88b4df8e88fc606`.
- `AddOcclusionPlane` is at `0x01042170`.
- `avr @ 0x0102CBBC` identifies `.?AVBGSEncounterZone@@`.

The documented executable emits `WARN: Invalid certificate table` during
radare2 loading. It is benign for static analysis. Keep it in raw evidence and
do not treat it as a fault.

The `r2mcp` plugin can be installed inside radare2 without being configured as
an MCP server for the host. Plugin presence is not proof that MCP tools are
available. Check the host, then fall back to the CLI.

Use `scripts/r2q.py` to avoid shell quoting and to capture evidence:

```bash
python3 .agents/skills/psycho/scripts/r2q.py info
python3 .agents/skills/psycho/scripts/r2q.py func 0x00567D20 --decomp
python3 .agents/skills/psycho/scripts/r2q.py callers 0x00567D20
python3 .agents/skills/psycho/scripts/r2q.py bytes 0x00567D20 16
python3 .agents/skills/psycho/scripts/r2q.py string AddOcclusionPlane
python3 .agents/skills/psycho/scripts/r2q.py rtti 0x0102CBBC
```

## Quality rubric

Before claiming an engine contract or patch authority, prove all applicable
items:

1. **Binary identity** - supported executable and address space.
2. **Exact instructions** - disassembly and bytes for the path; decompiler
   output alone is a hypothesis.
3. **Caller coverage** - every caller found, classified, and counted. Note
   callers that could not be classified.
4. **ABI** - calling convention, argument order, `this`/`ecx`, stack cleanup
   (`ret N`), return type, and structure offsets.
5. **Ownership and lifetime** - allocator, refcounts, vtables, containers,
   destructor path, and who may free or replace the object.
6. **Concurrency** - thread ownership, locks, atomics, and the quiescent
   intervention point.
7. **Intervention choice** - prefer a callsite or pointer-slot chain over a
   prologue patch when the contract allows it.
8. **Runtime reverification** - exact `CodeSignature` checks before any write.
9. **Evidence** - exact commands, raw output, hash, date, and unresolved facts.

## Decompiler caveats

- `pdg` is r2ghidra and is the highest-quality option when installed.
- `pdc` is radare2's own experimental pseudo-decompiler. Use it only as a last
  resort and mark the result low confidence.
- Decompilers frequently mislabel calling conventions. `pdg` reported
  `fcn.00567D20` as `__fastcall` even though the disassembly uses `ecx`
  thiscall convention. Confirm ABI from `pdf`, prologue/epilogue, and callers.
- Decompiler variable names and types are not structure layout proof. Confirm
  offsets with `px`, `pf`, callers, and the engine's own accessors.
- Do not use a decompiler's guessed function prototype as patch authority.

## Evidence

Store raw output under `analysis/radare2/output/` when the directory exists:

```text
analysis/radare2/output/<topic>_<YYYYMMDD>.txt
```

The evidence header must include:

- date and tool version;
- binary path and SHA-256;
- exact commands or script;
- whether r2mcp or CLI was used;
- known tool warnings;
- scope and what was not covered;
- the statement that the file is not patch authority.

Link the raw file from the owning document. Do not paste hundreds of lines of
disassembly into a contract document.

## Ghidra scripts are deprecated

Ghidra script authoring and execution are deprecated and not effective for this
repository. The scripts and the structural validator have been removed. Do not
add, edit, run, or request Ghidra scripts.

Existing `analysis/ghidra/output/` files are historical evidence only. They are
not current patch authority. Reverify any fact with radare2 before
implementation. `r2ghidra`'s `pdg` command is a radare2 plugin, not a Ghidra
script, and remains part of the CLI workflow.

## Address hygiene

- Fixed addresses belong to one exact executable. Treat them as untrusted on
  any other binary or patch level.
- Use exact signatures for patch authority. Wildcards may identify a candidate,
  but not authorize a write.
- Verify the signature again at runtime before the first call or patch.
- Prefer capability probes over module names, hashes, or file versions.
- Do not patch another mod. Do not add mod-specific compatibility paths.
- Reconfirm image base and relocation assumptions before reusing an address
  from an old analysis file.

## Research output checklist

Before implementation, the research must answer:

- What fails, at which instruction, with which inputs?
- Which native owner and callers are involved?
- What are the object layout, lifetime, and concurrency rules?
- What is the safe intervention point?
- What valid-input behavior must remain unchanged?
- What invalid input is rejected, and what does the caller already tolerate?
- What remains unproven?
