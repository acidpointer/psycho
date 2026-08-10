# Fallout installation-path registry repair

## Purpose and user-visible behavior

Psycho repairs the two legacy Bethesda installation-path values required by
Fallout: New Vegas, Fallout 3, their stock launchers, and tools that follow the
same discovery convention:

```text
HKLM\Software\Bethesda Softworks\FalloutNV\Installed Path
HKLM\Software\Bethesda Softworks\Fallout3\Installed Path
```

Both are 32-bit-view `REG_SZ` values. On a 64-bit Windows or Wine registry
export they appear beneath `Wow6432Node`; Psycho uses the logical paths and an
explicit 32-bit-view access flag instead of addressing that reserved physical
node.

`engine_fixes.install_path_registry_repair` defaults on. New Vegas always uses
the directory containing the running `FalloutNV.exe`. Fallout 3 is repaired
only when `engine_fixes.fallout3_install_path` is nonempty. Correct values are
left untouched, while a missing key, missing value, wrong type, malformed
string, or stale path is replaced.

Registry access is one-shot during startup. Failure to read or write either key
is logged for that game and never aborts the other repair or game startup.

## Configuration and path rules

The deployed configuration is `syringe/psycho_engine_fixes.toml`:

```toml
[engine_fixes]
install_path_registry_repair = true

# Sibling of the directory containing FalloutNV.exe:
fallout3_install_path = '..\Fallout 3'
```

The Fallout 3 option accepts:

- a fully qualified Windows drive path such as `D:\Games\Fallout 3`;
- a fully qualified UNC path such as `\\server\share\Fallout 3`;
- a normal relative path resolved against the `FalloutNV.exe` directory.

It does not use the process working directory, the TOML directory, or
`syringe\` as the relative base. This makes `..\Fallout 3` stable when Steam,
xNVSE, a mod manager, Wine, or an overlay changes the working directory.

Wine and Proton users must provide a Windows-visible absolute path such as
`Z:\games\Fallout 3`, not a host path such as `/games/Fallout 3`. Psycho does
not guess drive mappings. Drive-relative `C:Fallout 3`, root-only `\Fallout 3`,
Win32 device namespaces, and verbatim namespaces are rejected because their
meaning depends on ambient drive state or exceeds the vanilla consumer
contract.

Resolution is lexical: separators are normalized, `.` is removed, `..` is
collapsed without traversing above the volume root, and one trailing backslash
is added. Psycho does not call filesystem canonicalization and does not check
the Fallout 3 directory, `Fallout3.exe`, version, distribution, or TTW setup.
The configured text remains the sole Fallout 3 authority.

The resulting directory plus the appropriate launcher and terminator must fit
both the vanilla 260-byte ANSI buffer under the active system code page and the
stock launcher's 260-wide-character buffer. Psycho round-trips the ANSI
conversion through Windows and rejects a path if the active code page would
substitute or best-fit any character. An overlong or lossy value is logged and
rejected rather than publishing data the consumers cannot use safely.

## Architecture and startup ownership

- `psycho-engine-fixes/src/mods/engine_fixes/install_paths.rs` owns path
  resolution, validation against the proven vanilla buffers, repair decisions,
  logging, and the one-shot startup entrypoint.
- `psycho-engine-fixes/src/config.rs` and the packaged TOML own the default-on
  gate and optional Fallout 3 text.
- `psycho-engine-fixes/src/startup.rs` calls the repair immediately after the
  logger is available and before display, allocator, and engine-hook setup.
- `libpsycho/src/os/windows/registry.rs` owns the safe registry boundary. Its
  `RegistryKey` closes handles through RAII, explicitly selects the 32-bit
  view, bounds registry-controlled allocations, rejects malformed UTF-16 and
  unterminated strings, verifies exact legacy ANSI representability, and writes
  null-terminated UTF-16 `REG_SZ` data.
- The registry boundary remains isolated from the broad `winapi` module so the
  xNVSE helper cannot inherit core-only registry imports during plugin load.
  Its FFI-bearing functions are inline specifically to preserve that final PE
  ownership when `libpsycho` is statically linked into multiple DLLs.
- `psycho-engine-fixes-helper/src/dashboard_config.rs` and `dashboard.rs` edit
  only the next-launch configuration. They never access the registry or load,
  initialize, or call the core DLL.

Syringe invokes core activation in its pre-CRT barrier. The repair therefore
finishes before FalloutNV's researched startup call at `0x0086ACA4` can consume
the value. No hook, polling thread, filesystem scan, persistent allocation, or
per-frame work is involved.

## Registry transaction and failure behavior

Each game follows the same independent sequence:

1. Open the existing key with `KEY_QUERY_VALUE | KEY_WOW64_32KEY`.
2. Query the type and byte length, then read a bounded value only when it can be
   a valid `REG_SZ`.
3. Return without requesting write access when the exact expected value is
   already present.
4. Otherwise create or reopen the key with only query, set-value, and 32-bit
   view rights, then replace `Installed Path`.
5. Close every obtained key handle through `RegistryKey::drop`.

This ordering lets a correct read-only installation continue without an
unnecessary access-denied warning. A native Windows ACL can still deny a needed
HKLM repair; Psycho does not elevate, change permissions, virtualize the key,
or make startup fail. Wine and Proton normally store the result in the active
prefix's `system.reg`.

The two writes are intentionally not presented as one transaction. If New
Vegas succeeds and Fallout 3 fails, the valid New Vegas repair remains useful.
No GOG, Steam, uninstall, AppCompat, file-association, DirectX, runtime, or
generic engine-settings records are created or changed.

## Proven executable contract

The focused primary-tool output is
[`analysis/radare2/output/install_path_registry_contract.txt`](../analysis/radare2/output/install_path_registry_contract.txt).

### Fallout: New Vegas

The supported `fnv_reverse/FalloutNV.exe` is PE32 x86 version 1.4.0.525, size
16,084,808 bytes, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

Function `0x00876A70` opens
`Software\Bethesda Softworks\FalloutNV` under HKLM with query access and reads
`Installed Path` into the caller's 260-byte buffer. Its only caller is startup
function `0x0086A850`, at `0x0086ACA4`. That caller appends
`FalloutNVLauncher.exe` and passes the result to `ShellExecuteA`.

The researched stock launcher probes and retrieves the same value with wide
registry APIs and a 260-wide-character buffer. It contains no GOG game-catalog
registry reference.

### Fallout 3

The researched `Fallout3.exe` is PE32 x86 version 1.7.0.3, SHA-256
`df9f0e1ec2c5413a9cef2db2dde6d926b99707d528049af4eb15538587d55f99`.

Function `0x006E4BE0` reads `Installed Path` from
`Software\Bethesda Softworks\Fallout3`. Startup calls it at `0x006EE5E8`, then
appends `FalloutLauncher.exe` and invokes it. The stock launcher probes at
`0x0040E965`/`0x0040E97D` and retrieves the same value at
`0x0040EA6B`/`0x0040EA8D`. It also contains no GOG game-catalog registry
reference.

These are direct binary facts. It is a reasoned compatibility conclusion that
other tools following Bethesda's documented-by-behavior install discovery will
benefit from the same values; Psycho does not claim or synthesize their private
metadata.

## Compatibility boundary

Neither stock launcher imports DirectInput or otherwise loads Psycho's
`dinput8.dll` proxy. In a completely fresh prefix, starting a stock launcher
directly cannot execute this repair because the core DLL is not present in that
process. Starting through xNVSE or `FalloutNV.exe` performs the repair; later
stock-launcher invocations can then consume it. Covering a launcher before any
game/xNVSE start would require a separate bootstrap or a different launcher
injection mechanism.

## Tests and acceptance criteria

Automated tests cover default and explicit configuration, dashboard
round-tripping, fully qualified drive and UNC paths, FalloutNV-relative paths,
lexical traversal, nonexistent paths, ambiguous path rejection, and the
260-element buffer limit. The helper suite also parses its own PE image and
rejects any inherited core-only registry imports. The full affected suites run
as 32-bit Windows tests under Wine.

Runtime acceptance requires a disposable or backed-up Wine/Proton prefix:

1. Remove or corrupt only the two Bethesda values.
2. Test an empty Fallout 3 option, an absolute path, and a relative sibling
   path.
3. Start through xNVSE or `FalloutNV.exe` and confirm the expected `REG_SZ`
   values appear in the 32-bit view.
4. Restart and confirm both are reported already correct with no write.
5. Confirm GOG, Steam, uninstall, AppCompat, and GECK records remain unchanged.
6. Confirm both games/tools can consume their repaired path where applicable.

Native Windows acceptance additionally checks that a denied HKLM write logs one
warning and leaves startup operational. Direct stock-launcher-first recovery
remains outside the architecture as described above.

Validation on 2026-08-10 used the required explicit
`i686-pc-windows-gnu` target. The affected library suites passed under
Wine-staging 11.14: 28 `libpsycho` tests, 170 core tests, and 15 helper tests.
The optimized 32-bit release build also completed for
`psycho-engine-fixes` and `psycho-engine-fixes-helper`. Actual registry mutation
and consumption in a disposable prefix still require the runtime acceptance
sequence above; automated tests do not claim that playtest evidence.
