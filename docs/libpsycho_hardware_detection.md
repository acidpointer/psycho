# libpsycho hardware detection

Status: implemented; automated i686 Windows/Wine validation complete, native
Windows and live renderer acceptance pending.

Date: 2026-07-29.

## Purpose

libpsycho needs a reusable hardware profile for later compatibility,
optimization, and diagnostic decisions. The supported program is a 32-bit x86
Windows process and normally runs either on native Windows or through
Wine/Proton.

The detector must be:

- precise about the distinction between physical hardware, operating-system
  policy, and features exposed by a graphics compatibility layer;
- fast enough for startup and constant-time after the first query;
- reliable when optional firmware or graphics metadata is unavailable;
- safe to call from an injected DLL without spawning processes, initializing
  COM, using WMI, reading arbitrary host files, or starting a worker;
- explicit about the active D3D9 device rather than assuming adapter zero is
  the GPU used by the game.

This document records the implemented contract, its evidence, automated
validation, and the runtime acceptance work that still requires real hardware.

## Executive decisions

1. Add a public `libpsycho::hardware` module. Keep raw Windows calls behind
   `libpsycho::os::windows` wrappers.
2. Split detection into three cost and lifetime classes:
   - a cached core profile for CPU, OS-visible memory, and runtime;
   - lazy cached SMBIOS memory-device metadata;
   - an on-demand GPU profile bound to a caller-provided D3D9 device.
3. Expose CPU features twice:
   - `advertised_features` records raw CPUID capability;
   - `usable_features` records instructions safe for application dispatch,
     including OS extended-state support for AVX-family instructions.
4. Treat `GlobalMemoryStatusEx` as the authority for memory visible to the
   running OS. Treat SMBIOS installed capacity, type, speed, and ECC as
   optional firmware metadata.
5. Treat D3D9 caps and format probes from the game's actual device as the
   authority for features usable by this process. Do not substitute Vulkan
   capabilities or a newly created D3D11 feature level.
6. Detect Wine by the Wine-owned `ntdll.dll` exports. Classify Proton only when
   Wine is proven and the Proton launch environment is also present.
7. Return unknown or a typed component error instead of inventing a value.
   Failure to read SMBIOS or DXGI metadata must not discard valid CPU, memory,
   runtime, or D3D9 results.

## Why one monolithic `detect_all` call is wrong

The information has different owners and different validity periods.

- CPU identity and instruction support are immutable for this process.
- total OS-visible memory is effectively static, but available physical,
  page-file, and virtual memory are live values.
- DIMM details come from firmware and may be missing, stale, or synthetic.
- the active GPU is not known until the host has created its D3D9 device.
- D3D9 capabilities describe the effective driver or translation layer, not
  necessarily every feature in the physical GPU.
- available texture memory and DXGI memory budgets are live estimates.

A single cached structure would either cache dynamic values incorrectly or
perform expensive and unnecessary graphics/firmware work for callers that only
need CPU dispatch.

## Public API

The implemented entry points preserve the different ownership and validity
periods:

```rust
/// Return the process-wide immutable CPU, memory, and runtime profile.
pub fn system_profile() -> &'static SystemProfile;

/// Query current OS-visible memory pressure without rebuilding the profile.
pub fn memory_status() -> Result<MemoryStatus, HardwareError>;

/// Return lazily parsed SMBIOS memory-array and memory-device metadata.
pub fn memory_device_profile()
    -> Result<&'static MemoryDeviceProfile, HardwareError>;

/// Describe the adapter and effective features used by an existing D3D9 device.
pub fn d3d9_device_profile(
    device: &Device9Ref<'_>,
) -> Result<D3d9DeviceProfile, HardwareError>;

/// Enumerate D3D9 adapters without claiming that any one is the active device.
pub fn d3d9_adapter_profiles()
    -> Result<Vec<D3d9AdapterProfile>, HardwareError>;
```

`system_profile()` uses `OnceLock` and never retries after it publishes a
complete core profile. Optional component failures are stored as typed issues
inside the profile. A transient live-memory or D3D call returns its own error.

The public types should contain owned Rust strings and normalized enums or
bitflags. They must not expose pointers, packed firmware records, unions,
Windows binding types, or references into a temporary API buffer.

## Source and authority matrix

| Information | Primary source | Authority and fallback |
|---|---|---|
| CPU vendor, brand, family, model, stepping | `CPUID` leaves 0, 1, and `0x80000002..4` | Direct architectural report. Preserve unknown vendors and absent leaves. |
| CPU instruction support | Bounded CPUID leaves and subleaves | Raw hardware/virtual-machine advertisement. Never query beyond the reported maximum leaf. |
| CPU instructions safe to execute | CPUID plus OSXSAVE/XCR0 rules | Application dispatch authority. AVX descendants require their parent state to be OS-enabled. |
| Cores, packages, NUMA nodes, and caches | `GetLogicalProcessorInformationEx` | OS-visible topology. Fall back to logical count and leave richer topology unknown. |
| Parallelism available to this process | `std::thread::available_parallelism` | Scheduling hint, separate from physical/logical topology. |
| OS-visible physical/page-file/virtual memory | `GlobalMemoryStatusEx` | Required Windows/Wine view for this process. Dynamic availability is queried live. |
| Physically installed memory | `GetPhysicallyInstalledSystemMemory` | Optional SMBIOS-derived capacity. It must not replace OS-visible capacity. |
| DIMM type, size, speed, rank, and ECC | `GetSystemFirmwareTable('RSMB')`, SMBIOS Types 16 and 17 | Optional firmware report. Parse defensively; never infer missing fields. |
| Active GPU identity | `IDirect3DDevice9::GetCreationParameters`, then the same device's `GetDirect3D` and adapter ordinal | Exact D3D9 device owner. No default-adapter substitution. |
| Active GPU features | `IDirect3DDevice9::GetDeviceCaps` and matching `IDirect3D9::CheckDeviceFormat` probes | Effective features available to the game through the native driver, wined3d, or DXVK. |
| System graphics inventory and static memory descriptions | Deferred; not part of the implemented D3D9 profile | DXGI cannot identify the active base-D3D9 device reliably and 32-bit `SIZE_T` cannot represent all modern VRAM capacities exactly. |
| Wine | `ntdll.dll!wine_get_version` | A present Wine-owned export proves Wine. Environment variables alone do not. |
| Wine build and host kernel | `wine_get_build_id` and `wine_get_host_version` when exported | Optional Wine-owned metadata. |
| Proton launch | Wine proof plus `STEAM_COMPAT_DATA_PATH` | Strong launch-environment evidence: current Proton exits if this value is absent. It is not an exact Proton version API. |

## CPU contract

### Identity

`CpuInfo` exposes:

- raw vendor string and a normalized `CpuVendor` enum;
- trimmed brand string when extended brand leaves exist;
- display family, model, and stepping decoded according to CPUID leaf 1;
- maximum basic and extended leaves;
- whether a hypervisor is advertised and its vendor string when present;
- OS-visible logical processor, active core, package, and NUMA-node counts;
- cache records with level, kind, size, line size, and sharing count;
- process-available parallelism;
- advertised and usable feature sets.

Brand text is display metadata, not a stable identity key. Family/model/stepping
and vendor are kept separately.

Frequency is deliberately excluded from the first contract. Brand strings are
not machine-readable frequency data, CPUID leaf 16 is optional nominal data,
and a one-shot timing benchmark is distorted by power management, scheduling,
virtualization, and Wine. A later frequency feature would need a separate
sampling contract.

### Feature set

The first normalized feature set should cover instructions likely to affect
library dispatch or compatibility:

- MMX, SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, and SSE4a;
- AVX, AVX2, F16C, and FMA;
- AVX-512F, AVX-512BW, AVX-512DQ, AVX-512CD, and AVX-512VL;
- AES, PCLMULQDQ, SHA, POPCNT, LZCNT/ABM, BMI1, BMI2, and ADX;
- MOVBE, ERMS, RDTSCP, RDRAND, RDSEED, CLFLUSHOPT, and CLWB.

Unknown future CPUID bits do not become named features automatically. The
profile may retain a small raw-leaf snapshot for diagnostics, but callers must
use normalized features for dispatch.

### Advertised versus usable

Raw CPUID AVX bits are insufficient for safe execution. The usable set applies
these dependencies:

- AVX, F16C, and FMA require CPUID XSAVE, OSXSAVE, and XCR0 bits 1 and 2;
- AVX2 additionally requires usable AVX;
- AVX-512 features require usable AVX plus XCR0 bits 5, 6, and 7;
- a descendant is cleared when its required parent is not usable, even if a
  malformed virtual CPU advertises the descendant bit.

Rust's standard x86 detector follows this model and is a useful implementation
reference. The implementation may use its stable
`is_x86_feature_detected!` checks or equivalent audited CPUID/XGETBV logic, but
must test the dependency reduction as pure logic.

CPUID is executed only for leaves reported by leaf 0 or `0x80000000`. This
avoids the architectural behavior where an out-of-range query can alias the
highest supported basic leaf.

### Topology semantics

`GetLogicalProcessorInformationEx` describes topology exposed by Windows or
Wine. This is the right view for a Windows process, including a deliberately
restricted `WINE_CPU_TOPOLOGY`, but it is not guaranteed to reveal every host
CPU.

The detector must not derive physical core count by dividing logical count by
two. It counts `RelationProcessorCore` records. It must walk the variable-size
buffer by each record's `Size`, reject a zero or undersized record, and stop on
overflow or truncation.

Efficiency classes are optional. Older Windows versions and Wine may return
zero or no CPU-set data. Their absence is not an error and must not collapse
ordinary topology.

## Memory contract

### Fast OS-visible memory

`SystemMemoryInfo` in the core profile records:

- a startup `MemoryStatus` snapshot containing OS-visible physical, commit, and
  process virtual-address-space totals and availability;
- system page size and allocation granularity;
- optional physically installed bytes;
- any installed-memory failure in the enclosing `SystemProfile::issues`.

`memory_status()` records the current:

- memory load percentage;
- available physical bytes;
- available page-file bytes;
- available process virtual-address-space bytes.

The live query is one `GlobalMemoryStatusEx` call and performs no heap
allocation. Callers that need exact 32-bit VAS holes must continue to use a
`VirtualQuery` walk; existing project evidence shows that Wine's
`ullAvailVirtual` can diverge from the actual region map.

### SMBIOS memory features

The lazy firmware path reads the raw SMBIOS provider with the documented
two-call size/query sequence. It validates the `RawSMBIOSData` header and
bounded table length before scanning structures.

The first parser covers:

- Type 16 Physical Memory Array:
  - location and use;
  - maximum capacity;
  - memory error-correction mode;
  - declared device count.
- Type 17 Memory Device:
  - populated versus empty slot;
  - device size, including extended-size encoding;
  - form factor;
  - memory type and memory technology;
  - type-detail flags such as registered, unbuffered, and LRDIMM;
  - advertised and configured speed in MT/s, including extended speeds;
  - rank;
  - minimum, maximum, and configured voltage;
  - manufacturer, part number, device locator, and bank locator.

The parser selects fields by the SMBIOS structure length, not only by the table
version. Every integer conversion and byte multiplication is checked. String
indices are resolved only inside the structure's double-NUL-terminated string
area. A malformed structure produces a component error and never an
out-of-bounds read or infinite scan.

Serial numbers and asset tags are intentionally omitted. They add no
optimization value and create an unnecessary stable-machine identifier.

### What RAM detection cannot promise

SMBIOS is supplied by firmware or a compatibility layer. Fields can be absent,
unknown, stale, or synthetic. Therefore:

- configured speed is reported as firmware metadata, not measured bandwidth;
- channel count is not inferred from locator names or populated-slot count;
- primary timings, XMP/EXPO profiles, memory-controller ratios, and current
  training state are not claimed;
- on-die DDR5 ECC is not labeled as platform error-correcting memory unless the
  SMBIOS array reports an applicable correction mode;
- an unavailable RSMB table returns unknown memory-device features while the
  valid OS-visible capacity remains usable.

Reading SPD accurately would require platform-specific privileged SMBus access
and is outside a safe user-mode library.

## GPU contract

### The active-device rule

The precise path starts with the host's `IDirect3DDevice9`:

1. call `GetCreationParameters` to obtain `AdapterOrdinal` and `DeviceType`;
2. call `GetDirect3D` on that device;
3. use the returned object's matching ordinal for `GetAdapterIdentifier`;
4. call the device's `GetDeviceCaps`;
5. issue selected `CheckDeviceFormat` probes through the same Direct3D object,
   ordinal, device type, and adapter display format.

Microsoft explicitly warns that adapter ordinals are meaningful only inside
the Direct3D instance that created the device. This sequence also handles
hybrid laptops, adapter reordering, Wine, DXVK device filtering, and external
renderer selection without guessing.

`GetAdapterIdentifier` must use flags zero. Requesting
`D3DENUM_WHQL_LEVEL` can initiate a network lookup on affected native Windows
versions and violates the detector's cost and side-effect contract.

### D3D9 identity

`D3d9DeviceProfile` exposes the adapter ordinal and device type, while its
`GpuIdentity` exposes:

- description, driver display name, and GDI device name;
- the packed native driver version;
- vendor, device, subsystem, and revision IDs;
- the D3D driver/chip-set GUID.

Strings are presentation metadata. The PCI tuple and device GUID remain
separate so later policy does not key off a localized or compatibility-layer
description.

### Effective GPU features

`D3d9Capabilities` and `D3d9FeatureFlags` normalize:

- vertex and pixel shader versions;
- maximum texture dimensions, volume extent, and anisotropy;
- maximum simultaneous textures, texture blend stages, streams, and stream
  stride;
- maximum simultaneous render targets;
- independent MRT bit-depth support;
- hardware transform-and-lighting and pure-device support;
- non-power-of-two and conditional-NPOT texture semantics;
- cube and volume texture support;
- anisotropic minification and magnification;
- vertex texture-fetch support where represented by D3D9 caps.

Format support is not inferred from broad caps. A compact
`D3d9FormatFeatures` section records explicit probes needed by current or
planned consumers, such as:

- FP16 and FP32 render-target textures;
- render-target blending for those formats;
- INTZ and RESZ compatibility-layer extensions;
- sRGB reads and render-target writes for ARGB textures;
- any future format only after a real consumer defines its usage and resource
  type.

These are effective D3D9 features. Under DXVK they intentionally describe what
DXVK exposes to this game, which is more useful and safer than raw Vulkan
feature bits for D3D9 code.

### GPU memory and DXGI

`IDirect3DDevice9::GetAvailableTextureMem` is an approximate, dynamic value
rounded to megabytes. It may be exposed as a live estimate, but it must never
be named total VRAM or used for small allocation decisions.

DXGI enumeration can provide dedicated, dedicated-system, and shared-system
memory descriptions plus an adapter LUID. It is deliberately not implemented
in this version because base D3D9 does not expose an adapter LUID. Adding it
later requires a separate inventory API and must not change active-device
selection.

There is an additional 32-bit limitation: DXGI adapter description capacities
use `SIZE_T`. Values at or above the representable 32-bit ceiling cannot be
treated as exact physical VRAM. The public type must preserve a
reported/truncated-or-at-least state instead of widening a capped value and
calling it precise. Newer DXGI video-memory budget APIs use 64-bit fields, but
their budget and current usage are dynamic process policy, not physical
capacity.

The implementation does not create a D3D11 device merely to obtain a
feature level. That can load another driver path, has startup cost, and answers
a different question from the D3D9 device used by Fallout New Vegas.

### Enumeration without a device

`d3d9_adapter_profiles()` is useful for diagnostics before the renderer
exists, but its result is an inventory. Adapter zero is labeled the D3D9
default, not "active GPU." The detector creates at most one temporary
`IDirect3D9` object, enumerates its stable snapshot, releases it, and caches
nothing that is later presented as the host device.

## Wine and Proton contract

### Wine proof

The detector obtains the already loaded `ntdll.dll` and checks
`wine_get_version` with `GetProcAddress`. It does not load a new DLL.

If the export exists, the runtime is Wine-compatible. Optional exports provide:

- Wine version;
- Wine build ID;
- host kernel system name and release.

The C functions use Wine's exported cdecl ABI on x86. Returned static C strings
are copied into owned strings during detection. A missing optional export does
not invalidate the primary Wine result.

No registry key, DLL filename, username, path, or environment variable alone
is accepted as proof of Wine.

### Proton classification

Proton is a Wine distribution launched by Valve's wrapper, not a distinct
Windows kernel API. Current Proton requires `STEAM_COMPAT_DATA_PATH` before it
constructs the session and passes that environment into Wine. The classification
rule is therefore:

- no Wine export: `NativeWindows`, even if a Steam variable exists;
- Wine export without Proton launch evidence: `Wine`;
- Wine export plus non-empty `STEAM_COMPAT_DATA_PATH`: `Proton`.

Additional markers such as `STEAM_COMPAT_CLIENT_INSTALL_PATH`, `SteamGameId`,
and `SteamAppId` may be recorded as corroborating evidence but are not required
for Wine proof.

The result means "launched through a Proton-compatible environment." It does
not guarantee an exact Valve release: custom Proton builds and a manually
constructed environment can look the same. Exact Proton version remains
optional. `wine_get_build_id` is retained verbatim but is not relabeled as the
Proton version unless its format proves that claim.

Host paths from Proton environment variables are not exposed in the public
profile. They are unnecessary for detection and may contain user information.

## Failure and compatibility behavior

- Core CPU identity failure is impossible on the supported x86/x64
  architecture unless the execution environment violates the CPUID contract.
  Unexpected leaf data becomes unknown, not a panic.
- A topology query failure preserves CPUID identity and the process-available
  parallelism hint.
- A live memory-status failure is returned to the caller and never replaced
  with zero; the cached startup query records the failure as an issue.
- A physical-installed-memory or SMBIOS failure preserves OS-visible memory.
- A malformed SMBIOS table fails the firmware component as a whole. Partial
  untrusted module results are not published.
- A D3D identity failure does not fabricate adapter zero. The device profile
  call returns an error.
- A failed optional format probe records unsupported only when the HRESULT
  specifically means unsupported; unexpected device/runtime failures remain
  errors.
- A Wine optional export failure leaves the runtime classified as Wine once
  `wine_get_version` has proved it.
- SMBIOS strings are bounded by their structure's string area and sanitized
  before publication. Wine strings are copied only from the proven Wine-owned
  static export contract.

The initial implementation supports both `target_arch = "x86"` and
`target_arch = "x86_64"` because libpsycho already declares both, while all
repository validation uses `i686-pc-windows-gnu`.

## Performance and allocation contract

The fast core profile performs:

- a bounded set of CPUID calls;
- one process-parallelism query;
- the two-call topology size/read sequence;
- one `GlobalMemoryStatusEx`;
- one optional installed-memory call;
- three `GetProcAddress` lookups after one non-loading module lookup.

It performs no WMI/COM work, registry enumeration, filesystem access, process
creation, sleep, network access, worker creation, or global polling. The first
call allocates only owned strings and bounded topology vectors. Later calls are
one `OnceLock` load.

SMBIOS and GPU work are lazy. SMBIOS allocates one firmware buffer and the
result vectors once. D3D9 device profiling performs no device creation and no
resource allocation. System adapter enumeration may initialize D3D9 and must
never run automatically from `system_profile()`.

Hard wall-clock assertions do not belong in unit tests because Wine startup,
driver cold state, and CI scheduling make them flaky. Runtime acceptance should
measure:

- cold and cached core-profile latency;
- cold and cached SMBIOS latency;
- active-device D3D9 profile latency;
- allocation counts or a documented upper bound.

The target is sub-millisecond cached access and no recurring allocation. Cold
budgets will be fixed only after measurement on native Windows and the
supported Proton/DXVK setup.

## Psycho Engine Fixes startup report

`psycho-engine-fixes/src/hardware_report.rs` consumes the libpsycho profile
after allocator selection and runtime-hook initialization and writes one
aligned INFO-level block to `psycho-engine-fixes-latest.log`. Running after
allocator selection is intentional: owned profile data remains cached for the
process lifetime, while temporary strings used only for presentation are
allocated and freed by the allocator retained for the session.

The report contains:

- explicit native Windows, Wine, or Proton classification, including Wine
  version/build and host kernel when those exports are available;
- CPU brand, vendor ID, family/model/stepping, hypervisor evidence, physical
  and logical topology, process parallelism, grouped cache geometry, and
  ordered OS-usable instruction features;
- OS-visible, installed, and available physical memory with startup load;
- page size and allocation granularity;
- SMBIOS version, populated/declared slot counts, described capacity, array ECC
  mode, and one concise line per populated system-memory device containing
  capacity, type, speed, form factor, width, ranks, buffering, voltage, and
  manufacturer/part metadata.

Type 16 arrays that explicitly describe system memory select the Type 17
devices included in the report. If firmware omits those associations, all Type
17 devices remain visible rather than producing an empty report. Serial
numbers and asset tags are neither collected nor logged. Long firmware slot
names are bounded only for the aligned display label; the hardware profile
itself retains the complete sanitized locator.

This report is diagnostic only. A missing topology field, installed-memory
query, or SMBIOS table is rendered as `unknown` or `unavailable` at INFO level.
It never changes allocator selection, feature installation, or engine policy.
It performs no recurring work after startup.

## Tests and validation

### Implemented automated coverage

- Family/model/stepping decoding.
- AVX-family parent dependency clearing.
- Valid variable-size topology records, efficiency classes, cache sharing
  masks, and zero-size rejection.
- SMBIOS Type 16 and Type 17 base and extended-size records.
- Missing double-NUL rejection and KiB/extended module-size decoding.
- D3D9 caps, shader versions, and unknown device-type normalization.
- Native-versus-Proton environment classification and the requirement for
  proven Wine.
- A real Windows/Wine cached-profile integration test covering CPUID, native
  system layout, memory invariants, topology, and Wine exports.

### Windows/Wine integration tests

- actual CPUID identity is non-empty and usable features are a subset of
  advertised features;
- process parallelism and OS-visible memory are nonzero;
- live available values do not exceed corresponding totals;
- Wine classification matches the presence of the Wine export in the test
  process.

### Required repository validation

```bash
cargo test --target i686-pc-windows-gnu -p libpsycho
cargo build --release --target i686-pc-windows-gnu -p libpsycho
```

Any consumer changed in the same implementation must run its affected tests
and release build as required by the repository guide. `git diff --check` and
targeted formatting remain mandatory.

Implementation evidence from 2026-07-29:

- `cargo test --target i686-pc-windows-gnu -p libpsycho --lib`: 24 tests
  passed under Wine 11.14, including the real cached-profile integration path;
- `cargo build --release --target i686-pc-windows-gnu -p libpsycho`: passed;
- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
  --lib`: 120 tests passed, including the startup-report format fixtures;
- `cargo build --release --target i686-pc-windows-gnu
  -p psycho-engine-fixes`: passed with the repository's existing MinGW stdcall
  fixup warnings;
- the unfiltered command ran all 24 library tests successfully, then
  encountered a pre-existing logger doctest whose untyped
  `0xDEADBEEF` example overflows `i32` on the 32-bit target. The hardware
  implementation does not touch that logger example.

### Runtime acceptance

Before a consumer makes policy decisions from this API, capture and compare:

- native Windows on Intel and AMD;
- Proton/DXVK on Intel, AMD, and NVIDIA where available;
- a hybrid-GPU system proving that the device-bound profile follows the game
  device rather than adapter zero;
- missing or synthetic SMBIOS, including Wine behavior;
- a CPU with AVX2 and, if available, AVX-512 OS-state gating;
- repeated call latency and zero recurring allocation.

## Implemented source ownership

Ownership:

- `libpsycho/src/hardware/mod.rs`: module documentation, public entry points,
  shared errors, source/status types, and cached profile ownership;
- `libpsycho/src/hardware/cpu.rs`: CPUID acquisition, feature normalization,
  and topology normalization;
- `libpsycho/src/hardware/memory.rs`: OS memory normalization and defensive
  SMBIOS parser;
- `libpsycho/src/hardware/runtime.rs`: Wine exports and Proton evidence;
- `libpsycho/src/hardware/gpu.rs`: device-bound D3D9 identity and feature
  profile plus independent D3D9 adapter inventory;
- `libpsycho/src/os/windows/winapi.rs`: small safe wrappers for system topology,
  physical memory, memory status, and raw firmware tables;
- `libpsycho/src/os/windows/directx9.rs`: creation-parameter, adapter identity,
  device caps, adapter count, and format-probe wrappers;
- `libpsycho/src/lib.rs`: public module export.
- `psycho-engine-fixes/src/hardware_report.rs`: stable INFO-level formatting
  and startup log publication.

Every public type and function requires a docstring. Each source module
requires module-level technical documentation. Complex parsing, ABI, lifetime,
and feature-dependency decisions require in-code comments explaining the
reason for the boundary.

## Explicitly rejected approaches

- WMI, `wmic`, PowerShell, or subprocess-based detection;
- registry CPU brand strings as the CPU identity source;
- reading `/proc`, `/sys`, or Proton files through Wine drive mappings;
- environment-only Wine detection;
- using the default D3D9 or DXGI adapter as the active game GPU;
- creating a D3D11 device solely to infer D3D9 features;
- using raw Vulkan features for D3D9 dispatch;
- treating `GetAvailableTextureMem` as total or exact VRAM;
- widening a 32-bit DXGI `SIZE_T` value and calling it exact;
- inferring RAM channels, timings, or measured speed from SMBIOS locator text;
- collecting hardware serial numbers;
- periodic refresh, background threads, or hot-path logging.

## Evidence and sources

Repository evidence:

- `libpsycho/src/os/windows/winapi.rs` already owns memory-status, module, and
  procedure-address wrappers;
- `libpsycho/src/os/windows/directx9.rs` already owns borrowed D3D9 device
  lifetime and selected capability/format wrappers;
- `docs/gheap_large_modlist_compatibility.md` records the proven
  `GlobalMemoryStatusEx::ullAvailVirtual` divergence under Proton/Wine.

Primary external sources:

- Microsoft `GetLogicalProcessorInformationEx`:
  <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex>
- Microsoft `GetPhysicallyInstalledSystemMemory`:
  <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory>
- Microsoft `MEMORYSTATUSEX`:
  <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex>
- Microsoft `GetSystemFirmwareTable`:
  <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable>
- DMTF SMBIOS 3.8.0:
  <https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.8.0.pdf>
- Rust `__cpuid_count`:
  <https://doc.rust-lang.org/core/arch/x86/fn.__cpuid_count.html>
- Rust x86 runtime feature detection implementation:
  <https://doc.rust-lang.org/src/std_detect/detect/os/x86.rs.html>
- Intel architecture manuals:
  <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- AMD64 Architecture Programmer's Manual, Volume 3:
  <https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24594.pdf>
- Microsoft D3D9 creation parameters:
  <https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3ddevice-creation-parameters>
- Microsoft `GetAdapterIdentifier`:
  <https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3d9-getadapteridentifier>
- Microsoft D3D9 adapter identifier:
  <https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dadapter-identifier9>
- Microsoft `GetAvailableTextureMem`:
  <https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-getavailabletexturemem>
- Microsoft DXGI adapter description:
  <https://learn.microsoft.com/en-us/windows/win32/api/dxgi/ns-dxgi-dxgi_adapter_desc>
- Wine `ntdll` version exports:
  <https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/version.c>
- Valve Proton launcher:
  <https://github.com/ValveSoftware/Proton/blob/proton_11.0/proton>
- DXVK configuration, including D3D9 available-memory overrides:
  <https://github.com/doitsujin/dxvk/blob/master/dxvk.conf>

## Evidence classification

Proven by public API or source contracts:

- CPUID is the architectural CPU identity/feature source and has maximum-leaf
  bounds;
- AVX-family execution requires OS-managed extended state;
- Windows exposes OS memory, raw SMBIOS, processor relationships, and D3D9
  device/adapter contracts through the selected APIs;
- a D3D9 adapter ordinal must be used with the same Direct3D object;
- `GetAvailableTextureMem` is approximate;
- Wine exports its version entry points from `ntdll`;
- current Proton requires `STEAM_COMPAT_DATA_PATH`.

Reasoned design conclusions:

- device-bound D3D9 caps are the safest authority for later FNV graphics
  policy;
- SMBIOS must be optional under Wine/Proton;
- lazy firmware and graphics stages are necessary to keep the common path fast;
- a Wine export plus Proton's required launch marker is the strongest
  low-cost classification available without host file access;
- DXGI memory cannot always be correlated precisely with a base D3D9 device.

Still awaiting runtime observation:

- actual cold and cached latency;
- allocation counts;
- exact SMBIOS behavior in the supported Proton version;
- active D3D9 identity and feature results under the user's DXVK setup;
- native Windows and hybrid-GPU acceptance.
