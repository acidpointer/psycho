# OMV versioned graphics presets

## Purpose and user-visible behavior

OMV presets are versioned, shareable snapshots of the live visual
configuration. They allow an arbitrary practical number of installed presets,
fast in-game switching, and creation of named and versioned user presets.
Activation copies a preset into the automatically persisted Current Look; it
never mounts the preset as a live configuration layer. Only the explicit
**Update Current Preset** action updates an existing preset file.

The Manage Presets view exposes two deliberately different creator actions:

- **Update Current Preset** is available after a user preset is active and its
  visual settings have been edited. The user supplies a strictly newer
  semantic version. OMV preserves the preset UUID, name, author, and
  description, captures the current live payload, atomically replaces the
  contents of that exact preset path, and switches the current session to the
  new version. The filename stays unchanged and OMV never explicitly deletes
  the preset file.
- **Create a New Preset** captures the same live settings under a newly
  generated UUID. It starts an independent preset family even when the
  current settings originated from another preset.

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

OMV still retains whether the current session is custom, a concrete preset, or
edited from a concrete preset, but that provenance is not placed in the global
header. The preset library marks the preset currently in use; creator
eligibility uses the retained provenance internally.

The ordinary Presets view is intentionally a library rather than an authoring
form. It shows searchable installed presets, a clean preview, and one primary
**Use This Preset** action. Version and file/build metadata are hidden behind
**Details**. Every version update and new-preset metadata field is isolated in
the separate **Manage Presets** view, so users who only switch looks do not
need to understand UUIDs, schema versions, payload revisions, Git identifiers,
or publication rules.

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
The current built-in version remains `1.0.0`.

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
match restores the active label; a difference reports Modified from. Missing
or corrupt state never affects graphics behavior.

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
transaction. If a later file fails, the worker rebases files it already wrote
and retains the live revision for a bounded retry. It never misreports its own
partial publication as an external edit. Invalid external TOML fails reload
without changing the live look, while a detected external revision suspends
all normal autosaves until the user makes the conflict choice.

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
- `preset.version` is the preset author's strict semantic version.
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

The following remain local and survive every activation:

- menu toggle key;
- shader scan cadence;
- depth-provider selection;
- logging and frame-pacing diagnostics;
- native PBR draw diagnostics.

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
is changed.

A selected LUT is recorded by filename and exact content revision. If the
required LUT or shader is absent, changed, duplicated, or ambiguous, the whole
activation is rejected. OMV does not silently apply a partial look or select a
fallback LUT.

FNV-1a 64-bit revisions are compatibility fingerprints, not authenticity or
security signatures. Presets are configuration data and do not establish
publisher trust.

## Catalog and identity

Preset identity is `(preset.id, preset.version)`, never filename or scan order.

- Identical duplicate identity and content is deduplicated.
- Conflicting content with the same identity is marked incompatible; no file
  wins by load order.
- Symlinks are ignored.
- Scanning is bounded to four directory levels.
- Each preset is limited to 1 MiB and all user-facing strings have explicit
  limits.
- There is no fixed preset slot count. The UI searches the complete dynamic
  catalog and displays it in bounded pages of 100 entries.

Catalog scanning and user-preset publication run on the `omv-presets` worker.
The render callback only polls already completed messages. Both publication
paths write and flush a same-directory temporary file. Create a New Preset
moves it into place with fail-if-exists semantics. Update Current Preset uses a
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
the worker. Update Current Preset instead requires a non-built-in active preset
and a semantic version whose precedence is strictly greater than the active
version. Build metadata alone does not make a version newer. It preserves the
family UUID, descriptive metadata, and exact source path. Before replacement,
the worker rechecks the source identity and content fingerprint so an external
edit cannot be silently overwritten.

In both workflows, the preset becomes the current in-session identity only
after durable publication and catalog refresh succeed. The Current Look is
already autosaved independently; publication records the new preset identity
without redundantly rewriting `omv.toml`. Publication itself never silently
rewrites the working configuration.

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

Static tests cover:

- trailing-edge autosave coalescing and stale-completion rejection;
- external-change save blocking and explicit reload/overwrite resolution;
- absence of the old manual Save/Undo persistence path;
- strict built-in preset round-trip;
- missing and unknown fields;
- future schemas;
- non-finite values;
- semantic-version validation;
- strict monotonic version publication, family-UUID preservation, and current
  payload capture;
- conflicting and identical duplicate identities;
- machine-local setting preservation, including depth-provider selection;
- built-in LUT revision equality;
- path-safe version-free generated filenames and readable collision suffixes;
- fail-if-exists atomic creation and no-delete atomic version replacement;
- legacy unversioned config and future config rejection.

Release validation requires:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Validation on 2026-07-29 passed all 393 OMV tests and the supported optimized
`i686-pc-windows-gnu` OMV release build.

Ordinary game acceptance still needs:

1. open the Presets tab with no loose preset directory and activate OMV
   Default;
2. use Create a New Preset to create a named `1.0.0` preset from edited live
   values, wait one second, restart, and confirm the Current Look and active
   identity return without a Save action;
3. record its filename, edit the user preset, use Update Current Preset to
   publish `1.0.1`, and confirm the filename is unchanged, only `1.0.1`
   remains at that path, and it becomes active;
4. confirm an equal, older, malformed, or build-metadata-only version is
   rejected and that the built-in preset directs the user to Create New
   Preset;
5. install multiple third-party files and use search/page navigation;
6. edit the active preset, confirm **Reset to Preset** restores it immediately,
   then switch directly to another preset without a redundant save prompt;
7. remove or alter a required LUT and external shader and confirm activation
   is rejected with the current look unchanged;
8. edit `omv.toml` outside the game and confirm autosave pauses, the conflict
   card appears, Reload adopts the file, and Keep In-Game Look overwrites it
   only after that explicit choice;
9. update OMV over an edited `omv.toml` and confirm the file is preserved.

The static suite proves format and transaction behavior. It does not prove
visual equivalence on a real D3D9 device; normal gameplay comparison remains
the final image acceptance step.
