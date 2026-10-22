# OMV versioned graphics presets

## Purpose and user-visible behavior

OMV presets are versioned, shareable snapshots of the live visual
configuration. They allow an arbitrary practical number of installed presets,
fast in-game switching, and creation of named and versioned user presets.
Activation copies a preset into the automatically persisted Current Look; it
never mounts the preset as a live configuration layer. Only the explicit
**Update Preset** publication action updates an existing preset file.

The Presets and Customize tabs both show the current preset, its version and
whether its visual settings have been edited. **Update Preset** and
**Create a New Preset** remain visible beside that status:

- **Update Preset** opens the version form for an active user preset. A
  pristine preset explains that no visual changes need publication. A changed,
  missing, or conflicting source file explains why reactivation or a new
  preset is needed. An edited user preset can publish a strictly newer semantic
  version while preserving its UUID, name, author, description, and exact path.
  The replacement is atomic; the filename stays unchanged.
- On OMV Default, **Update Preset** explains the read-only family and opens
  the user-copy form. A custom look without preset provenance also opens the
  new-preset form. Neither route can overwrite the default family.
- **Create a New Preset** captures the live look under a newly generated UUID,
  independently of the preset it started from. Names and authors permit 80
  Unicode characters; descriptions permit 512 characters including line breaks.
  Native input preserves non-BMP codepoints, and render-owned buffers allow
  the complete UTF-8 representation of these character limits.

The built-in OMV Default family is read-only. An edited built-in preset can be
saved only as a new user preset. These rules prevent publishing a user-owned
version under OMV's built-in identity.

`Data/NVSE/plugins/omv/omv.toml` remains the authoritative working
configuration. Presets are optional. A user who never opens the Presets tab
keeps the existing configuration and manual-edit workflow. Every in-game
change is visible immediately and is automatically written to `omv.toml`
after a 750 ms trailing-edge debounce. Rapid slider changes therefore
coalesce into one snapshot, while preset activation queues an immediate
snapshot. External shader settings are persisted to their existing TOML
sidecars in the same background operation. There is no normal Save or Undo
button and no hidden second working configuration.

Activating a preset validates the complete snapshot and its dependencies,
migrates it to the current schema, and then replaces only the live visual
settings. That result becomes the Current Look and is queued for persistence
immediately. Selecting the active preset after edits is labeled **Reset to
Preset** and performs the same validated copy. Preset files are never edited
by activation, reset, or Current Look autosave.

OMV fingerprints `omv.toml` and every installed external shader sidecar on
the background persistence worker. If a tracked file changes outside the
game, autosave pauses instead of silently overwriting it. Only then does the
header show an advanced conflict card:

- **Reload Files from Disk** loads the externally edited working config and
  shader sidecars as the new live Current Look.
- **Keep In-Game Look** explicitly authorizes one overwrite with the look
  currently visible in game.

OMV retains whether the current session is custom, a concrete preset, or edited
from a concrete preset. This provenance appears beside the actions in Presets
and Customize. Only preset-owned visual changes affect its edited status;
local preferences and inert compatibility values do not. Returning visual
values to their preset values clears the edited status.

The library shows searchable installed presets, their versions, a description,
and **Use This Preset** or **Reset to Preset**. Versions sort by semantic
precedence within matching names. Build and file metadata remain behind
**Details**. Authoring forms can be opened directly from either tab; Manage
Presets remains an additional route to those actions.

## Files and ownership

| Path | Owner and behavior |
|---|---|
| `Data/NVSE/plugins/omv/omv.toml` | User-owned working configuration. Installer updates must not replace it; in-game edits atomically update it. |
| `Data/NVSE/plugins/omv/omv.default.toml` | Updateable distribution default used when the working file is absent. |
| `Data/NVSE/plugins/omv/omv-state.toml` | Non-behavioral active-preset identity and payload revision. |
| `Data/NVSE/plugins/omv/presets/**/*.omvpreset.toml` | Third-party and in-game-created preset documents. The workbench saves new files directly in this directory. |

The immutable OMV Default preset is compiled into `omv.dll` from
`omv/config/omv.toml`, so it remains available even if the loose default file
is removed. The installer copies the distribution default on every update but
creates `omv.toml` only when it is missing. Release archives contain
`omv.default.toml`, not an update-overwritable working configuration.
The built-in preset version and payload revision are test-locked; changing its
values requires publishing a new default-preset version deliberately.
The current built-in version is `1.6.0`, with format and config schema 1.
It retains the built-in family identity and publishes a revised visual payload:
CA `0.4`, grain `0.12` with particle size `1.743985`, Fast AO strength/floor
`0.9`/`0.4`, neutral object roughness/direct/ambient scales, dielectric terrain
with ambient and saturation scales one, and cloud transparency one. Far DOF
uses strength `0.25` and radius `24` pixels, distant blur `0.25`, sky blur
`0.05`, and motion blur uses a `180`-degree shutter. Other creative values,
including weather response, LUT, Bloom, halation, fog and vignette, remain.
Solar color now uses the native disk candidate, shared by the disk and haze;
the optional additive sunset tint is neutral on all three channels. Existing
saved presets retain their explicit solar settings. The sky horizon follows
the active exterior fog endpoint, positive analytic contrast retains deep
texture levels, and the fused first-person AA footprint includes the adjacent
pixel on each silhouette side. World TAA retains its existing settings and
phase; controlled production tests reduce thin-wire sampling error without
erasing its contrast, in both depth modes and MRT/fallback paths.
Adaptive display preferences remain machine-local Current Look settings.
The existing working configuration is never overwritten by this revision;
applying OMV Default uses the normal preset switch transaction.

`omv/src/presets.rs` owns the preset envelope, schema validation, migrations,
catalog, dependency checks, filename selection, and background worker.
`omv/src/file_io.rs` owns durable publication: fail-if-exists creation for a
new preset and write-through atomic replacement for an explicit version
update. `omv/src/current_look.rs` owns autosave debounce and retries, the
background file worker, full-content revision monitoring, conflict gating,
and reload. `omv/src/runtime.rs` owns the workbench state and the final live
apply transaction.

After the latest Current Look revision is durably written, OMV records the
active preset identity and immutable preset-payload revision in
`omv-state.toml`. On the next launch OMV verifies that the same preset
document is installed and compares the complete live state against it. A
match restores the active label; a difference restores its edited provenance.
A delayed initial restore cannot replace a later user activation or publication.
If the source is unavailable, its pending identity can be checked again on a
catalog refresh without applying graphics changes. Missing or corrupt state
never affects graphics behavior.

## Current Look persistence contract

`AutosaveCoordinator` is a pure render-thread state machine. Every ordinary UI
edit advances a monotonically increasing revision and moves a 750 ms
trailing-edge deadline. Closing the workbench ends that debounce early. Only
the newest due revision may own a snapshot; a completion for an older
in-flight revision cannot clear edits made after its capture. A failed write
retries with bounded exponential delays from 2 to 30 seconds.

`CurrentLookService` has one `omv-current-look` worker and bounded four-entry
command and event queues. A render callback never waits for the worker.
Idle/pending frames allocate no configuration snapshot. When one revision is
due, the runtime clones `GraphicsMenuConfig` and the current shader-source
list once and transfers ownership to the worker. Memory cost is therefore one
in-flight copy of the live menu/shader configuration, not a history of
revisions.

The worker checks complete file-content fingerprints once per second and
immediately before each ordinary save. Length is part of the revision, but
same-length changes are still detected. New external shader paths are
baselined when asset discovery publishes them. Missing files are revisions
too, so external creation and removal are conflicts. The fingerprint is a
change detector, not an authenticity guarantee.

Each text file is serialized and atomically replaced independently.
`omv.toml`, the launch-critical state, is published immediately after the
set-wide revision guard; external shader sidecars follow and each receives a
second last-moment revision check. The set is not a multi-file filesystem
transaction. Each successful file publication retains the revision of the exact
serialized bytes, rather than reading a potentially newer external revision
back from disk. A later failure leaves untouched baselines intact and retains
the live revision for a bounded retry. Recovery cannot absorb an intervening
external edit or misreport its own earlier writes as external changes.

Reload owns the workbench until its result arrives, so intervening UI edits or
preset actions cannot be discarded by reload completion. It verifies tracked
revisions before and after parsing and retains those verified baselines.
Invalid external TOML or a revision change during parsing rejects reload.
Detected external changes suspend normal autosaves until the explicit conflict
choice. Shader sidecar edits use this same guard and authoritative reload;
asset discovery does not authorize autosave to overwrite them.

Fingerprint guards are observations followed by atomic publication, not a
filesystem compare-and-swap. An independent editor can still replace a file
between the final guard and OMV's replacement. The guards do not promise
linearizable exclusion against arbitrary external writers. The working file
set and its provenance are also not one filesystem transaction.

## Version contract

A preset has three independent versions:

```toml
format = "omv-preset"
preset_format_version = 1
config_schema_version = 1

[settings]
omv_enabled = true

[preset]
id = "canonical UUID"
name = "Mojave Cinema"
version = "1.2.0"

[preset.created_with]
omv_version = "0.1.0"
git_commit = "full Git object ID"
git_tag = ""
git_branch = "master"
git_dirty = false
```

- `preset_format_version` versions the envelope and metadata representation.
- `config_schema_version` versions visual-setting semantics.
- `preset.version` is the preset author's strict semantic version. Precedence
  follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html),
  ignoring build metadata. Numeric components retain the established format's
  complete 64-byte version-string domain instead of narrowing to machine
  integers during updates or suggestions.
- `settings.omv_enabled` is the preset-owned master switch for all OMV visual
  systems. It maps to the legacy working-config key
  `graphics.screen_space_shaders`; that `omv.toml` key remains unchanged for
  backward compatibility.
- `preset.id` is an internal preset-family identity. It is generated as a
  random version-4 UUID, stays inside the document, and is never added to the
  filename. Every published version of the same preset preserves this UUID;
  Create a New Preset generates a different one.
- `preset.created_with` identifies the exact OMV build that wrote the file.
  The full commit is authoritative; branch and exact tag provide human context.
  An empty tag means the commit was not tagged. Detached or source-archive
  builds report that state rather than inventing a branch. `git_dirty` records
  whether the build contained uncommitted source changes when Git could answer.

The current unversioned `omv.toml` format is permanently recognized as legacy
config schema 0. New saves publish the explicit current schema.

Schema 1 retains
`settings.embedded_effects.motion_blur.first_person_strength` as inert
compatibility data. World-only first-person rendering does not consume it, but
working-config saves and preset snapshots round-trip it. This preserves the
released shape and avoids adding a preset migration to the catalog worker that
starts during `NVSEPlugin_Load`; removing an inactive field alone is not a
reason to publish a new schema or built-in preset version.

Versioned preset settings are complete and strict. Missing settings, unknown
settings, wrong value types, non-finite numbers, finite values outside the
public runtime control ranges, malformed metadata, and unsupported future
versions reject the preset. Values are never silently clamped, and invalid
documents never fall through to the latest Rust defaults.

Every future schema change must:

1. increment `config_schema_version`;
2. retain the complete decoder/shape contract for every released schema;
3. add one deterministic migration step from the previous schema;
4. supply the old semantic value explicitly when a new field replaces an old
   default;
5. add a golden old-preset fixture and its expected current result;
6. leave source preset files unchanged.

The compatibility promise is directional: every older valid preset remains
loadable by newer OMV versions. A newer preset in an older OMV fails closed
without changing live or disk state.

## Snapshot scope

A preset owns:

- the master visual enable state;
- all embedded-effect enable states and parameters;
- native PBR visual parameters;
- native sky visual parameters;
- all installed external shader enable states, phases, pass counts, and option
  values;
- the selected LUT dependency.

The following remain local and survive shared-preset activation:

- menu toggle key;
- shader scan cadence;
- depth-provider selection;
- logging and frame-pacing diagnostics;
- native PBR draw diagnostics.

Explicit activation of the compiled **OMV Default** additionally turns off
global, native-PBR, and native-shadow debug logging and ends session profiling.
The logger ceiling changes to Info immediately, and Current Look autosave
persists the disabled logging switches. Embedded debug views are already zero
or false in the default payload. This reset preserves shadow appearance
settings and does not apply to other presets or passive provenance restoration.

External shaders installed on the destination but absent from the preset are
disabled during activation. This prevents an unrelated local shader from
silently changing a shared look.

## External dependencies

Preset files contain data only. They cannot embed shader source, DLLs,
commands, or arbitrary paths.

An external shader sidecar may declare:

```toml
[shader]
id = "author-controlled canonical UUID"
version = "1.0.0"
```

OMV also fingerprints the exact shader file content. A preset dependency with
a stable shader ID must match both that ID and the content revision. A legacy
shader without an ID matches by normalized filename plus exact content
revision. Every option key, type, and range must still match before any source
is changed. Dependency resolution must also be one-to-one: an ID declaration
and a legacy filename declaration cannot both target the same installation.

A selected LUT is recorded by filename and exact content revision. If the
required LUT or shader is absent, changed, duplicated, or ambiguous, the whole
activation is rejected. OMV does not silently apply a partial look or select a
fallback LUT.

FNV-1a 64-bit revisions are compatibility fingerprints, not authenticity or
security signatures. Presets are configuration data and do not establish
publisher trust.

## Catalog and identity

Preset identity is `(preset.id, preset.version)`, never filename or scan order.
UUID hexadecimal case is normalized for identity comparisons without rewriting
installed document spellings or their payload revisions. The OMV Default UUID
remains read-only even when a loose file supplies a different version.

- Identical duplicate identity and content is deduplicated.
- Conflicting content with the same identity is marked incompatible; no file
  wins by load order.
- Symlinks are ignored.
- Scanning is bounded to four directory levels. Directory failures are visible
  catalog issues; they do not discard the compiled default or unrelated valid
  entries. Publication fails closed when a scan cannot establish that its
  destination identity is free.
- Each preset is limited to 1 MiB and all user-facing strings have explicit
  limits.
- There is no fixed preset slot count. The UI searches the complete dynamic
  catalog and displays it in bounded pages of 100 entries.

Catalog scanning and user-preset publication run on the `omv-presets` worker.
The render callback only polls already completed messages. Both publication
paths write and flush a same-directory temporary file. Create a New Preset
moves it into place with fail-if-exists semantics. Update Preset uses a
write-through atomic replacement of the exact existing path. OMV never passes
a preset path to a remove operation; only an unpublished hidden temporary file
may be removed after a failed publication.

## Runtime apply and failure behavior

Activation constructs candidate copies of the menu configuration and shader
source list. It validates LUTs, resolves every external shader, verifies every
option, and applies to the candidates. Only a fully successful candidate is
committed to the runtime.

After commit, OMV rebuilds embedded sources and LUT choices, invalidates
compiled screen-shader passes, republishes world/PBR/sky configuration through
the existing runtime path, and queues the complete Current Look for immediate
background persistence.

There is no file I/O, shader compilation, blocking worker wait, or unbounded
catalog rendering in the activation callback. Snapshot cloning happens only
after the debounce state machine grants one revision; all serialization,
revision checks, reads, flushes, and atomic file replacements run on the
`omv-current-look` worker. GPU resource rebuilding follows the existing lazy
effect paths.

Create a New Preset captures the current live settings, validates name and
strict semantic version, generates a version-4 UUID, and queues publication to
the worker. Update Preset instead requires a non-built-in active preset
and a semantic version whose precedence is strictly greater than the active
version. Build metadata alone does not make a version newer. It preserves the
family UUID, descriptive metadata, and exact source path. Before replacement,
the worker checks that the destination UUID/version is not installed elsewhere,
then rechecks the exact source identity and content fingerprint. Catalog refresh
cannot silently rebase an active session's overwrite authority onto a changed
file. An observed external change rejects publication.

In both workflows, the preset becomes the current in-session identity only
after durable publication and catalog verification succeed, and only if a later
activation or reload has not superseded that intent. Completion compares the
published snapshot with the current live look, so later edits remain marked
edited. A missing or conflicting publication result is a terminal error with
pending controls released; a later refresh cannot resurrect its activation.
Errors distinguish publication, catalog, and provenance operations.

Provenance waits until the newest working revision is durable and conflict-free.
The existing preset worker acknowledges state writes; failures retry without a
new user edit. Publication does not schedule a redundant working-config write
or silently rewrite the Current Look.

Transaction bookkeeping and full-size UTF-8 authoring buffers are allocated only
from the Present-owned profile service. A compatibility slot reuses the former
pending-key storage, and explicit field order preserves the startup-owned UI
and runtime layouts. Existing worker startup, bounded channel capacities,
configuration schema, serialized payload, and built-in version are retained.

Workbench-created filenames are deliberately human-readable and stable:
`<normalized-name>.omvpreset.toml`. Neither preset version nor UUID appears in
the filename; both remain inside the document. A version update atomically
replaces that same path without a preliminary delete or rename. Create New
Preset never overwrites an existing path: name collisions receive readable `-2`,
`-3`, and later numeric suffixes, and the final fail-if-exists publication also
rejects an external race.

Existing third-party filenames are treated as opaque and preserved during an
update, including legacy filenames that happen to contain a version. The
Presets tab exposes the creator OMV version, full Git commit, branch, exact
tag, and dirty-build state recorded in the selected document only when the
user opens Technical Details.

## Validation evidence and acceptance

Offline qualification executes the production preset parser, activation,
publication and persistence workers against real files. Native workbench tests
execute the shipped Dear ImGui widgets with actual mouse and text events and
commit results through the same Present-owned handler. Their test-only native
support is excluded from release builds. Source-string assertions do not prove
profile workflow behavior.

Required behavior includes:

- visible and actionable Update controls in Presets and Customize;
- default-family copy creation and user-preset update eligibility;
- visual edit/revert detection independent of local and shadow preferences;
- Unicode and multiline input preserved through native entry and publication;
- update-in-place path, UUID, descriptive metadata, and restart restoration;
- preservation of edits or activations made after publication capture;
- restoration superseded by newer user intent;
- terminal publication/catalog errors and independent provenance errors;
- rejection of conflicting installed versions and changed update targets;
- provenance gated by durable working revisions and retry after state errors;
- strict schema-one compatibility, complete dependencies, and monotonic versions;
- working-file conflicts, partial-write recovery, and authoritative reload.

Qualification uses the affected OMV and ImGui suites, production shader variants
and budgets, the supported `i686-pc-windows-gnu` release build, formatting,
document checks, and diff review. A game run is not an OMV qualification gate.
Native UI layout and file-state tests do not establish game-only image,
integration, startup, or performance behavior; owner playtesting remains the
owner's choice.
