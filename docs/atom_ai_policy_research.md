# Atom AI policy research

## Finding and scope

The examined AI policy is implemented entirely through native game data:
88 GameSettings (`GMST`) and 30 overrides of existing combat styles (`CSTY`).
It tunes inputs to the existing decision machinery. It supplies no replacement
planner, scripts, quest loops, actor packages, navigation data, animations,
weapon records, or native hooks. This is a useful starting map of AI policy
controls, not evidence that the NPCs reason better.

All 30 styles change their maximum ranged-weapon range multiplier. Additional
edits distinguish cover, waiting, firing, and maneuver decisions for selected
styles. Of the 88 settings, 79 differ from the comparison baseline, eight are
unchanged, and one has no established native setting identity. None of the
30 advanced coefficient blocks changes. The complete comparison contains
81 changed style fields, including 30 range multipliers.

This is a static research baseline for Atom's future AI subsystem. No Atom AI
implementation, game execution, gameplay improvement, frame-time result, or
runtime acceptance is claimed. The full supplied record set was examined;
other data and runtime overrides are outside this comparison.

The intended Atom system consists of many small developer-authored Rust
strategy modules, centrally composed into runtime AI tuning. Strategy code is
compiled into Atom; runtime reconfiguration changes validated settings and
enabled strategies. An interpreter, another strategy language, external code
loading, and hot replacement of compiled Rust are outside the requested scope.
The runtime-ownership continuation below establishes the most important native
constraints for that design.

## Evidence and how to read it

The reference executable is Fallout: New Vegas 1.4.0.525, PE32 x86, image base
`0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Every address below refers to that executable.

The baseline uses the supplied `FalloutNV.esm` where it defines a setting or
style. For a setting absent from that master, it uses the verified executable's
initializer. This distinction matters: for example, the executable initializes
`fCombatCurrentWeaponAbsoluteMaxRangeMult` to `4`, but the master sets it to
`1.25`. The comparison uses `1.25`. The master's identity is retained in the
data ledger; this does not certify it as an independently authenticated pristine
master or establish the winning values in a running load order.

Evidence collected on 2026-10-20:

| Evidence | Contents |
|---|---|
| [Record ledger](../analysis/radare2/output/atom_ai_record_evidence_20261020.json) | All 88 settings, all 30 styles, record offsets, exact payload bytes, baseline bytes, decoded fields, field offsets, and every delta; also the 54 untouched base styles |
| [Initializers and loader](../analysis/radare2/output/atom_ai_initializers_and_loader_20261020.txt) | Disassembly of 87 setting initializers, constant bytes, setting constructors, and the combat-style loader |
| [Setting references](../analysis/radare2/output/atom_ai_setting_xrefs_20261020.txt) | `aar` followed by object-address `axtj` for all 87 registered settings |
| [Native consumers](../analysis/radare2/output/atom_ai_consumers_20261020.txt) | Exact reads, arithmetic, branches, timer writes, style accessors, and selected decompilation aids |
| [Record reader](../analysis/radare2/atom_ai_records.py) | Reproducible read-only extraction with explicit input arguments; no embedded private input locations |
| [Runtime ownership](../analysis/radare2/output/atom_ai_runtime_ownership_20261020.txt) | Effective style precedence, actor override setter, controller refresh/invalidation, constructor/destructor, and timer helpers |
| [Style sampling](../analysis/radare2/output/atom_ai_style_sampling_20261020.txt) | All 50 direct controller-style getter callsites found in the code scan, their continuations, cover sampling helpers and action bodies |
| [Range callers](../analysis/radare2/output/atom_ai_range_callers_20261020.txt) | All five direct range-helper callers found in the code scan, arguments, output storage and native continuations |
| [Threads and clock](../analysis/radare2/output/atom_ai_threads_and_clock_20261020.txt) | Worker registration and entry bodies, native combat-clock advancement, time-delta getter and main-loop join |
| [Context inputs](../analysis/radare2/output/atom_ai_context_inputs_20261020.txt) | Native calendar-hour pointer chain, weather command evaluators and controller creation/transition paths |

The ledger omits header text and input identity. It retains public engine
identifiers because they are necessary to inspect the actual settings and
base-game records. No executable address is an approved hook location.

Record decoding follows the public
[xEdit FNV definitions](https://github.com/TES5Edit/TES5Edit/blob/dev-4.1.6/Core/wbDefinitionsFNV.pas),
specifically its `GMST` and `CSTY` structures, corroborated by native loading
instructions and the vendored xNVSE layouts. The extraction supports extended
subrecord lengths and compressed records, checks container bounds, and rejects
unexpected record shapes. These checks validate the evidence extraction;
they are not engine behavioral tests.

Three evidence levels remain separate:

- **Record fact:** bytes, decoded values, and differences from the baseline.
- **Native fact:** an instruction reads a value, uses it in arithmetic or a
  comparison, or stores it in native state.
- **Proposal or unknown:** gameplay quality, final decision frequency, complete
  consumer coverage, and future Atom intervention points.

## Implementation model

The record inventory is one header, 88 `GMST`, and 30 `CSTY`, in two top-level
record groups. No other record types occur. Each setting contains only an
editor identifier and a four-byte numeric value. Each style contains its
editor identifier and three fixed-layout data blocks.

The setting names determine numeric type: the three `i*` settings are signed
32-bit integers; the other 85 values are binary32 floats. Reading all 88 as
floats would corrupt the interpretation of the combat-count limits.

The normal engine owns loading, form storage, combat controllers, timers,
random choices, packages, pathfinding, ammunition, animations, and attack
execution. There is no additional scheduler or per-actor persistent state in
this data set. It can still change how much work the native systems perform.
The exact time at which every consumer samples or caches a changed value is
not established by record inspection.

There are two distinct scopes:

1. GameSettings are global policy inputs. Their effects are not intrinsically
   limited to the 30 edited styles or even to NPC combat.
2. Combat styles are shared forms. An override affects consumers resolving
   that form, subject to templates, runtime style overrides, and later data
   providers. It does not directly assign a new style to an actor.

The base master contains 84 styles. Thirty are edited and 54 are untouched.
There are 2,144 NPC/creature base records with direct `ZNAM` references to the
edited styles. That is a record-reference count, not a runtime actor count,
spawn count, or coverage percentage. Template inheritance, default fallback,
scripts, added content, and winning overrides can change effective coverage.

## Native data contracts

### Settings and default values

The verified float constructor `0x0040E0B0` forwards its name and float
arguments to `0x0040E130`, which writes the name at object `+0x08` and value at
`+0x04`. The integer constructor is `0x0040C150`, forwarding to
`0x00404920`. The initializers provide `ECX = setting object`, push the numeric
argument and name, then call the matching constructor. The float path consumes
eight argument bytes on return.

For example, initializer `0x00F63660` reads float `0.25` from `0x0101622C`,
pushes `fCombatLineOfSightTimer`, and constructs the object at `0x011CF450`.
This proves its registered identity and default. It does not prove that a
gameplay consumer reads it.

`0x00403E20` returns the float value address at setting object `+0x04`;
`0x0043D4D0` provides the corresponding integer address. Native consumers
typically load the setting object into `ECX` and call an accessor. Searching
only for direct references to the value address therefore misses these reads.
The retained xref ledger searches the objects after scanning the code section.

### Combat-style storage

The constructor at `0x00505010` installs vtable `0x010266E4` and form type
`0x4A`. The loader at `0x00505180` recognizes the three block signatures and
reads their bytes into the following object ranges:

| Record block | Size | Runtime offset | Ownership |
|---|---:|---:|---|
| `CSSD` | 64 | `0x18` | Cover, wait/fire intervals, range multipliers, restrictions, targeting FOV, combat radius, semi-auto delay |
| `CSTD` | 92 | `0x58` | Maneuver chances/timers, melee decisions, power attacks, flags, rush attacks |
| `CSAD` | 84 | `0xB4` | Fatigue, encumbrance, skill and attack-state coefficients |

The resulting `TESCombatStyle` size is `0x108`. The full offset/field map is
in the ledger, with corroborating names in
[GameForms.h](../libnvse/xnvse/nvse/nvse/GameForms.h).
Record padding is retained as raw bytes; no changed byte falls outside the
decoded fields. The standard block's acrobatic and rush chances are at decimal
84 and 85 respectively; sequential field widths and runtime offsets resolve
the duplicated offset annotation in the public definition.

The loader also handles shorter historical simple blocks and a record-version
branch below version 12. The examined simple blocks are all the full 64 bytes.
Their stored values are reported as record values, without inventing a new
runtime structure or treating an editor label as a hook contract.

`0x00980070` reads the current combat controller's style pointer at `+0xF4`.
The range helper `0x009A9180` uses that style. Accessors `0x009A9350` and
`0x00508050` return its minimum and maximum range multipliers from `+0x38`
and `+0x44`. These reads independently corroborate the simple-block map.

### What the focused consumers establish

| Consumer or exact site | Proven operation | Limit of the evidence |
|---|---|---|
| `0x009A9180` | Combines native range inputs with style range multipliers; multiplies an upper output by `fCombatAbsoluteMaxRangeMult` | Different weapon/projectile branches constrain outputs; one setting is not final attack distance |
| `0x00999D55` onward | Calls that range helper; on the current-weapon match, multiplies the absolute-range result by `fCombatCurrentWeaponAbsoluteMaxRangeMult`, then squares it for a distance comparison | Does not change projectile flight, actor detection, or guarantee an attack at that distance |
| `0x0099A231` | Reads `fCombatInventoryUpdateTimer` and arms native timer storage at owner `+0x21C` | The timer's enclosing inventory path still owns eligibility and updates |
| `0x0099A840` | Selects the restore/buff timer value for two native item slots and arms their native timer | Does not add consumables, change inventory, or prove successful item use |
| `0x009861C8` | Reads the group-strength update interval and arms a native timer | Does not establish complete group tactics or thread ownership |
| `0x0098A85A`, `0x0098AE21` | Read the search-area interval and feed native timer setup | Does not prove searches always occur at that cadence |
| `0x009D2A00`, `0x009D2D9F` | Compare cover reload thresholds with the ratio returned by `0x008A88F0` | Additional action, equipment, and timer conditions remain native |
| `0x008F58BD`, `0x008FF6A8` | Compare the player's native combat count with the target soft cap in two decision routes | A soft cap is not a guarantee of that many simultaneous attacks |
| `0x00916AE6` | Compares the native count with `iNumberActorsInCombatPlayer`; the limit branch rejects this admission path | The surrounding bypasses remain; the value is not a total-world actor limit |
| `0x00644A70` | Uses dodge settings in randomized, conditionally weighted score comparisons | Neither global base nor style dodge chance alone determines observed dodge frequency |
| View-cone sites in the consumer ledger | Read `fDetectionViewCone` across several actor/detection routes | The setting does not establish LOS, hearing, or a complete stealth model |
| `0x00524024`, `0x008B1026` | Read `fNPCMaxGunWobbleAngle` in weapon/actor calculations | A larger maximum is not evidence of more accurate shooting |

The clip-ratio helper obtains process ammo and weapon information, divides the
current ammunition count by a weapon-capacity result when valid, and returns
`1.0` for missing/invalid capacity paths. The vendored `BaseProcess` vtable
identifies weapon/ammo accessors at `0x148`/`0x14C`. In the cover-wait branch,
a threshold greater than the current ratio reaches `0x008A8840`, which
requests process action `2` through vtable offset `0x614`. A threshold of
`1.0` admits that request below a full clip, subject to the preceding checks.
The setting names associate this path with reloading; the complete action
implementation and observed reload frequency remain unverified.

The native timer setter `0x008D7F40` stores a time value from `0x00435DD0`
and the supplied interval in adjacent fields. This supports treating the
inventory/search/item changes as timer policy. It does not establish wall-clock
units and pause/time-scale behavior for every subsystem.

### Consumer gaps that must remain explicit

`fCombatRangedWeaponRangeBaseMult = 20` has no matching null-terminated name
in the supported executable and no entry in the base master's settings. No
native registered object, default, or consumer was established. Its stored
value is preserved, but no effect is attributed to it. This does not prove
that an arbitrary external runtime provider could never recognize the name.

Ten other names have verified registered defaults but no direct non-lifecycle
object references in the retained code scan:

- `fCombatLineOfSightTimer`;
- `fCombatSearchExteriorMaxRadius`, `fCombatSearchExteriorMediumRadius`,
  `fCombatSearchExteriorMinRadius`;
- `fCombatSearchInteriorMaxRadius`, `fCombatSearchInteriorMediumRadius`,
  `fCombatSearchInteriorMinRadius`;
- `fCoverEvaluationLastSeenExpireTime`;
- `fCreatureCalcStealth`;
- `fCombatTargetLostRemoveDistance`.

Initialization/destruction references exist, but those are not gameplay reads.
Name lookup or other indirect access is not ruled out. In particular,
`0.25 -> 0.15` for the LOS setting is not evidence of faster LOS checks, and
the exterior/interior search radii are not established active search bounds.
The other 77 registered settings have direct non-lifecycle object references;
the xref inventory alone does not fully explain every consumer's behavior.

## Runtime policy ownership

This continuation addresses the Rust strategy design. The findings are native
static contracts; they are not a completed hook installation or gameplay test.
In particular, a readable pointer, a form identifier, and a constructor address
do not establish a lifetime pin for asynchronous use.

### Effective style has three precedence levels

`Actor` helper `0x008A7F80` resolves the effective style in this order:

1. Obtain the reference's extra-data list at actor `+0x44` through
   `0x005D43C0`. `0x0042EA20` looks up extra type `0x69` and reads its style
   pointer at extra `+0x0C`. A non-null result wins.
2. If the actor has a process at `+0x68`, call process virtual `+0x22C` to
   obtain its stable package. A non-null package's `+0x48` style is read
   through `0x006733E0`. A non-null result wins.
3. Obtain the actor's current base form through `0x004181E0` and
   `0x007AF430`, which reads actor `+0x20`. Call that form's virtual `+0x188`.
   The verified NPC getter `0x00607950` reads base `+0x1D4`; the creature
   getter `0x008D8B80` reads base `+0x140`.

The NPC and creature vtable slots and RTTI bindings are retained in the
ownership ledger. There is no template walk in this resolver or either base
getter. Template materialization before these reads has not been audited;
Atom should consume the effective native result rather than inventing an
inheritance resolver from template flags.

The stable package is a material part of the contract. The verified base,
low, middle-low, middle-high and high-process vtables all map `+0x22C` to
`0x007FA950`, which reads the package from process `+0x04` through
`0x00559450`. This matches the vendored `GetStablePackage` declaration;
`GetCurrentPackage` is a different virtual method. Selecting a style only from
an NPC base would skip package-authored behavior even without an actor
override. A null override permits the lower precedence providers to supply
the effective style.

### Style identity changes trigger native invalidation

The existing script command table maps `SetCombatStyle` to `0x005CD650`.
That handler calls actor helper `0x008A8010`, which:

- obtains the extra-data list and invokes `0x0042EA50` with the new style;
- queries actor virtual `+0x428` for a live combat controller;
- calls controller refresh `0x0097F3F0` when that query returns non-null.

The extra-list setter removes type `0x69` when passed null. Otherwise it
updates an existing extra's style pointer or allocates a 16-byte extra and
inserts it through native list ownership. This is a state-changing engine
operation, not a cheap numeric policy read.

Controller refresh saves the old style pointer at controller `+0xF4`, resolves
the owner's effective style through `0x008A7F80`, and stores the new pointer.
If the old pointer was non-null and identity changed, it sets a byte at the
controller-owned auxiliary object `+0x77` through `0x0097F450` and calls
`0x0097F200`. The latter resets the interval in the controller's timer at
`+0xB4` to `-1.0`, through `0x0097F220`.

Four direct refresh calls were found: actor setter `0x008A8048`, two paths in
`0x00980AE0` at `0x00980B99` and `0x009812C2`, and the controller path at
`0x0098232E`. The last path also refreshes the current weapon and other native
state. These calls establish that the stored style is refreshed at specific
native boundaries; they do not establish a refresh on every actor update.

Consequences for Atom:

- An actor's desired style and the controller's currently stored style are
  distinct observations. Decision policy should use the native decision's
  effective provider and context.
- Mutating fields in the same shared style does not trigger the identity-change
  branch described above. Repeatedly substituting different style objects can
  trigger that branch repeatedly.
- A configuration change should not call the style setter or reset native
  combat state merely to change a numeric decision adjustment.

The constructor at `0x0097D3A0` initializes controller `+0xF4` to null, stores
the actor at `+0xBC`, and creates its auxiliary object at `+0x9C`. Native
destructor `0x0097D770` tears down controller-owned work; the deleting wrapper
at `0x0097D740` can then release the controller. These are borrowed native
lifetimes. No cross-frame actor/controller retention contract has been proved.

### Sampling boundaries differ by parameter

| Policy surface | Native sampling | Consequence for reconfiguration |
|---|---|---|
| Effective style identity | Resolver and controller refresh paths above | Preserve the native provider and its invalidation semantics |
| Style range factors | Range helper reads controller's current style during a calculation | A new calculation can consume new policy; existing cached outputs may survive |
| Cover wait duration | Sampled from style `+0x20/+0x24`, then stored in a native timer | Apply new policy to the next sample without automatically restarting the current wait |
| Cover wait-to-fire duration | Sampled from `+0x28/+0x2C`, then stored in a different timer | Configuration publication and timer rearming are separate operations |
| Cover firing duration | Sampled from `+0x30/+0x34`, then stored in a different timer | Preserve an in-progress sample unless a separately specified transition owns its replacement |
| Inventory/item/search intervals | Read when their native timer setup paths execute | A global numeric write does not itself rearm every existing timer |
| Cover reload threshold | Read and compared during the active cover decision branch | This is a decision-time threshold rather than a sampled duration |
| Global combat-count limits | Read at native count comparisons | The scope remains global even when an individual actor reaches the comparison |

For cover, the verified functions are:

| Function | Inputs | Result and actual storage sites |
|---|---|---|
| `0x009D32E0` | `ECX = style`, waits at `+0x20/+0x24` | Sample returned in x87 `ST0`; stored by `0x009D2F61` in procedure timer `+0x3C`, also at `0x009D3094` |
| `0x009D3310` | `ECX = style`, wait-to-fire at `+0x28/+0x2C` | `ST0`; stored by `0x009D2BFC` in procedure timer `+0x44` |
| `0x009D3340` | `ECX = style`, firing at `+0x30/+0x34` | `ST0`; stored by `0x009D2C70` in procedure timer `+0x4C`; another procedure samples it at `0x009D3460` |

All three helpers are small thiscall-shaped wrappers with no stack parameters
and a plain return. They call `0x00476B70`, which forwards the two float bounds
through the native random-number helpers. A strategy must preserve native
random-state ownership; an extra sample for diagnostics or reevaluation would
change the random sequence.

The sampling helpers themselves receive a style, not an actor or controller.
The enclosing cover procedure `0x009D25B0` has the native context: procedure
`+0x04` supplies its controller, which is also passed to style getter
`0x00980070` before each sample. `0x00996DE0` obtains the actor by following
procedure `+0x04` and then the controller's `+0xBC` reader `0x0097AE90`.
Separate getter `0x00586150` reads the controller's auxiliary object at
`+0x9C`; that object is not the controller itself. A universal style-getter
replacement would lack the actor context available to its caller. No actor
lookup should be invented from the shared style pointer.

This audit found 50 direct calls to controller-style getter `0x00980070`.
Their continuations include range, cover, maneuver, inventory and other
decisions. The scan is a callsite inventory, not proof that every style read
passes through that getter: actor resolution and other direct/inline accesses
remain separate. There is no demonstrated single universal AI tuning seam.

### Range has an explicit context and three outputs

The verified ABI of `0x009A9180` is a cdecl-shaped function with five stack
arguments: controller, optional weapon, and pointers to three float outputs
for lower, upper and absolute range. It returns with a plain `RET`; all five
direct callers found clean up 20 argument bytes. The function obtains its
style through the supplied controller and applies the existing weapon and
projectile constraints described earlier.

| Caller entry | Callsite | Output storage at this call |
|---|---|---|
| `0x009993C0` | `0x00999D3E` | Caller stack locals; current-weapon multiplier and distance checks follow |
| `0x0099B8E0` | `0x0099B9A3` | Caller stack locals; additional native constraints follow |
| `0x009CAFE0` | `0x009CB147` | Caller stack locals |
| `0x009D0A30` | `0x009D0CA2` | Caller stack locals |
| `0x009D3B80` | `0x009D3C88` | Fields `+0x14/+0x18/+0x1C` in the native caller object |

This is a concrete candidate for numeric decision research because the
controller and separate output values are explicit. It is not installation
approval. A post-call adjustment could undo projectile limits, invert the
range ordering, or miss additional caller-specific constraints. The five
continuations, allowed output domains, and runtime behavior must define which
adjustment is valid. The last caller also demonstrates that a result may be
stored in an object rather than recomputed on every decision check.

### Combat time and calendar time are different inputs

Native timer storage consists of start time followed by interval.
`0x008D7F40` stores the current clock from `0x00435DD0` and its float argument.
`0x008D7F80` compares the stored interval against current clock minus start;
for finite values it reports elapsed only when the difference is strictly
greater than the interval. It does not reread the original style or setting.
Rearming the timer repeatedly replaces its start time.

The combat clock is the float at `0x011F1BF0`. `0x009915E0` advances it by an
argument supplied from `TimeGlobal::secondsPassed`: `0x00991500` uses
`0x0084D030` with object `0x011F6394`, whose delta is at `+0x0C`. This path
is gated by the update function's Boolean argument. The exact pause, loading,
time-multiplier and zero-delta behavior still needs runtime observation; the
clock must not be replaced with wall-clock time or calendar hours.

Calendar hour uses another object, `0x011DE7B8`. Native binding
`0x00867890` resolves the hour global and stores a pointer at its `+0x0C`.
The `GetCurrentTime` evaluator `0x0059C8E0` calls `0x00867DA0`, which reads
that pointer and calls `0x00526AC0` to load the global's float at `+0x24`.
If the pointer is absent, the native getter returns `12.0`.

Therefore `0x011DE7B8 + 0x0C` is a pointer slot, not a raw hour float. A future
context reader should distinguish unavailable world time from an observed noon
value if its strategy needs that distinction. Hour-of-day strategies and
combat cooldown strategies require separate typed inputs and reset rules.

### Native combat work can execute on workers

`0x008C7290` registers `0x008C7BD0` or `0x008C7DA0` as AI linear-task
thread bodies through `0x008C74D0`, depending on the processor setting. Their
captured bodies call `0x00991500` at `0x008C7C19` and `0x008C7DE9` and run
native actor/package processing. The main loop also calls `0x00991500` at
`0x0086ED55`, using an update gate derived from frame state.

The conditional main-loop join at `0x0086EE4E` calls `0x008C7990`; the
single-processor alternative invokes `0x008CA300`. The registration, body and
join evidence rules out treating all AI work as main-thread-only. It does not
establish that every candidate callsite executes on every worker or define a
safe publication boundary for a future Atom context snapshot.

An evaluator must consequently work from context whose lifetime and concurrent
read contract are explicit. A main-loop callback by itself does not prove
that workers have stopped reading the previous publication. Pointer-free
context, coherent publication and bounded evaluation are design requirements;
the storage/reclamation mechanism remains to be selected and verified.

### Weather context belongs to the native weather owner

The native `GetIsCurrentWeather` evaluator at `0x0059EBB0` obtains the weather
controller through `0x0046DD00` and calls `0x0044EDB0` to read controller
`+0x10`. It compares that form with the requested weather form.
`GetCurrentWeatherPercent` at `0x0059EB60` uses the same controller and getter
`0x006447D0`, which reads its blend value at `+0xF4`.

`0x0046DD00` uses global slot `0x011CCB78`. If absent, it allocates a
`0x138` object and calls constructor `0x00639D40`. This lazy getter is not an
appropriate arbitrary per-strategy read. The render Sky global is another
slot; whether the two slots alias at a particular runtime phase is not proved
here. The weather-command read chain does not require renderer state.

Weather update `0x0063EF20` composes current and alternate weather contributions
using the transition value and its complement. A current-weather form alone
does not describe the entire transition. A strategy context may eventually
include copied weather characteristics and transition state, but this audit
does not certify raw blend as measured rain intensity, outdoor exposure,
ambient brightness, or the conditions inside an individual actor's cell.

The source of weather/time values is now proved. Their coherent collection
phase, per-actor interior/exterior interpretation, notification/invalidation,
and lifetime-safe publication to AI workers are not yet proved. Strategies
must not query renderer state, allocate the weather controller, or retain its
raw pointers on their own.

## Complete GameSetting comparison

`M` means a base-master value; `E` means an executable initializer because the
master has no setting record. `?` means no baseline is established. Values are
displayed compactly; the ledger retains exact float values and bytes. "Same"
means identical numeric payload bytes. "Changed" does not certify that every
setting has an active native consumer.

| Setting | Baseline | Examined | Source | Difference |
|---|---:|---:|:---:|---|
| `fAICombatSlopeDifference` | 48 | 1.5 | E | Changed |
| `fAIDodgeDecisionBase` | 10 | 1 | E | Changed |
| `fAIDodgeFavorLeftRightMult` | 2 | 0.0001 | E | Changed |
| `fAIDodgeWalkChance` | 75 | 5 | E | Changed |
| `fAIIdleWaitTime` | 1 | 1 | E | Same |
| `fAIMinGreetingDistance` | 150 | 50 | E | Changed |
| `fAISocialchanceForConversation` | 25 | 45 | M | Changed |
| `fAISocialchanceForConversationInterior` | 25 | 45 | M | Changed |
| `fAITrespassWarningTimer` | 10 | 5 | E | Changed |
| `fAIUpdateMovementRestrictionsDistance` | 48 | 64 | E | Changed |
| `fAIUseWeaponDistance` | 15000 | 50000 | M | Changed |
| `fAmbushOverRideRadiusforPlayerDetection` | 1000 | 800 | E | Changed |
| `fAutoDoorActivateDistance` | 300 | 100 | E | Changed |
| `fCharacterControllerMultipleStepSpeed` | 25 | 30 | E | Changed |
| `fCharacterDefaultTurningSpeed` | 90 | 135 | E | Changed |
| `fCombatAbsoluteMaxRangeMult` | 4 | 50 | M | Changed |
| `fCombatAvoidThreatsChance` | 0.5 | 1 | E | Changed |
| `fCombatCoverMaxRangeMult` | 1.5 | 5 | E | Changed |
| `fCombatDetectionDialogueIdleMaxElapsedTime` | 15 | 30 | M | Changed |
| `fCombatDetectionDialogueMaxElapsedTime` | 3 | 15 | E | Changed |
| `fCombatDistance` | 128 | 120 | E | Changed |
| `fCombatFiringArcStationaryTurnMult` | 0.75 | 0.95 | E | Changed |
| `fCombatFleeMaxCoverDistance` | 2000 | 3000 | M | Changed |
| `fCombatFleeMinCoverDistance` | 1000 | 1500 | M | Changed |
| `fCombatFleeNormalDistance` | 1400 | 2400 | M | Changed |
| `fCombatGiantCreatureReachMult` | 2 | 1.8 | E | Changed |
| `fCombatGroupCombatStrengthUpdateTime` | 2 | 1.5 | E | Changed |
| `fCombatHitConeAngle` | 35 | 25 | E | Changed |
| `fCombatInventoryUpdateTimer` | 5 | 1 | E | Changed |
| `fCombatIronSightsDistance` | 512 | 812 | E | Changed |
| `fCombatIronSightsRangeMult` | 5 | 1.4 | E | Changed |
| `fCombatItemBuffTimer` | 45 | 35 | E | Changed |
| `fCombatItemRestoreTimer` | 3 | 1 | M | Changed |
| `fCombatLineOfSightTimer` | 0.25 | 0.15 | E | Changed |
| `fCombatLowFleeingTargetHitPercent` | 0.25 | 0.1 | E | Changed |
| `fCombatLowTargetHitPercent` | 0.5 | 0.3 | E | Changed |
| `fCombatMinEngageDistance` | 64 | 128 | E | Changed |
| `fCombatPathingLookAheadDelta` | 0.5 | 3 | E | Changed |
| `fCombatProjectileMaxRangeOptimalMult` | 0.85 | 1 | E | Changed |
| `fCombatSearchAreaUpdateTime` | 5 | 2 | E | Changed |
| `fCombatSearchBufferDistance` | 256 | 5000 | E | Changed |
| `fCombatSearchCheckDestinationMaxDistance` | 512 | 750 | E | Changed |
| `fCombatSearchCheckInvestigateMaxDistance` | 512 | 2048 | E | Changed |
| `fCombatSearchExteriorMaxRadius` | 2048 | 5000 | M | Changed |
| `fCombatSearchExteriorMediumRadius` | 1024 | 1024 | M | Same |
| `fCombatSearchExteriorMinRadius` | 512 | 512 | M | Same |
| `fCombatSearchInteriorMaxRadius` | 1024 | 3000 | M | Changed |
| `fCombatSearchInteriorMediumRadius` | 512 | 512 | M | Same |
| `fCombatSearchInteriorMinRadius` | 256 | 256 | M | Same |
| `fCombatSearchSightRadius` | 1536 | 10000 | E | Changed |
| `fCombatSearchTargetHiddenMaxTime` | 20 | 48 | E | Changed |
| `fCombatSearchTargetHiddenRemoveTime` | 10 | 45 | E | Changed |
| `fCombatSplashDamageMinRadius` | 50 | 30 | E | Changed |
| `fCombatStepAdvanceDistance` | 128 | 256 | E | Changed |
| `fCombatTargetLostRemoveTime` | 30 | 90 | E | Changed |
| `fCombatThreatAvoidCost` | 1 | 1.5 | E | Changed |
| `fCombatThreatDangerousObjectHealth` | 30 | 50 | E | Changed |
| `fCombatThreatSignificantScore` | 0.05 | 0.06 | E | Changed |
| `fConfidenceCautious` | 0.375 | 0.475 | M | Changed |
| `fCoveredAdvanceMinAdvanceDistanceMax` | 512 | 800 | E | Changed |
| `fCoveredAdvanceMinAdvanceDistanceMin` | 256 | 128 | E | Changed |
| `fCoverEvaluationLastSeenExpireTime` | 5 | 3 | E | Changed |
| `fCoverFiringReloadClipPercent` | 0.25 | 1 | E | Changed |
| `fCoverWaitReloadClipPercent` | 0.33 | 1 | E | Changed |
| `fCreatureCalcCombat` | 2 | 1.5 | E | Changed |
| `fCreatureCalcStealth` | 2 | 1.5 | E | Changed |
| `fCreatureDefaultTurningSpeed` | 45 | 45 | E | Same |
| `fDetectionViewCone` | 190 | 180 | E | Changed |
| `fDisarmedPickupWeaponDistanceMult` | 2 | 6 | E | Changed |
| `fFleeDistanceExterior` | 5000 | 6000 | M | Changed |
| `fFleeDoneDistanceExterior` | 2500 | 3000 | E | Changed |
| `fFleeDoneDistanceInterior` | 600 | 900 | E | Changed |
| `fFleeIsSafeTimer` | 30 | 45 | E | Changed |
| `fMovementNearTargetAvoidCost` | 25 | 25 | E | Same |
| `fMovementNearTargetAvoidRadius` | 64 | 50 | E | Changed |
| `fMovementTargetAvoidCost` | 25 | 25 | E | Same |
| `fMovementTargetAvoidRadius` | 512 | 67.75 | E | Changed |
| `fMovementTargetAvoidRadiusMult` | 1.25 | 3 | E | Changed |
| `fNPCMaxGunWobbleAngle` | 15 | 25 | M | Changed |
| `fPathingLargeActorRadius` | 80 | 70 | E | Changed |
| `fSneakMaxDistance` | 2500 | 3000 | M | Changed |
| `iCombatTargetLostRemoveSearchCount` | 2 | 5 | M | Changed |
| `iCombatTargetPlayerSoftCap` | 15 | 21 | E | Changed |
| `iNumberActorsInCombatPlayer` | 20 | 28 | E | Changed |
| `fCombatCurrentWeaponAbsoluteMaxRangeMult` | 1.25 | 100 | M | Changed |
| `fCombatRangedWeaponRangeBaseMult` | ? | 20 | ? | Unknown |
| `fCombatTargetLostRemoveDistanceTime` | 60 | 75 | E | Changed |
| `fCombatTargetLostRemoveDistance` | 4096 | 14336 | E | Changed |

## Complete combat-style comparison

Every row below is an existing base-game style. The identifiers establish the
comparison and must not become Atom's classification list. `Rmax` is
`rangedWeapRangeMultMax`; all other listed names are the decoded runtime fields.
Only changed fields are shown. The ledger contains every unchanged field and
both complete byte payloads as well.

| Base style / FormID | Rmax baseline -> examined | Other changed fields: baseline -> examined |
|---|---|---|
| `DefaultCombatstyle` / `0000003D` | 1 -> 2 | `CSTD.LRChance` 50 -> 65; `CSTD.idleTimerMin` 0.5 -> 0.25; `CSTD.idleTimerMax` 1.5 -> 1; `CSSD.waitTimeMin` 2 -> 1; `CSSD.waitTimeMax` 2 -> 6; `CSSD.waitToFireTimerMin` 10 -> 1; `CSSD.waitToFireTimerMax` 10 -> 2 |
| `CSSupermutantGun` / `0001D541` | 1 -> 2 | `CSSD.waitTimeMax` 3 -> 1 |
| `CSRaider` / `0002A44B` | 1 -> 2 | `CSTD.dodgeChance` 75 -> 50; `CSSD.takeCoverChance` 50 -> 45; `CSSD.waitToFireTimerMin` 5 -> 2; `CSSD.waitToFireTimerMax` 8 -> 3 |
| `CSMisterGutsy` / `0003A377` | 1 -> 2 | None |
| `CSMisterHandy` / `0003A378` | 1 -> 2 | None |
| `CSCentaur` / `0003A37D` | 1 -> 2 | None |
| `CSRoboBrain` / `0003A383` | 1 -> 2 | None |
| `CSSentrybot` / `0003A385` | 1 -> 2 | `CSSD.waitTimeMax` 2 -> 6; `CSSD.fireTimerMin` 2 -> 10; `CSSD.fireTimerMax` 2 -> 20 |
| `CSProtectron` / `0003A708` | 1 -> 2 | None |
| `CSBloatfly` / `0004713F` | 1 -> 2 | None |
| `CSTurret` / `0007B238` | 1 -> 2 | `CSSD.waitTimeMin` 0 -> 0.1; `CSSD.waitTimeMax` 0 -> 0.25; `CSSD.waitToFireTimerMin` 0 -> 0.1; `CSSD.waitToFireTimerMax` 0 -> 0.25; `CSSD.fireTimerMin` 0 -> 0.1; `CSSD.fireTimerMax` 0 -> 0.25 |
| `CSFireAnt` / `0008535D` | 1 -> 2 | None |
| `MS04FireAntWorker` / `000A01DB` | 1 -> 2 | None |
| `MS04FireAntSoldier` / `000A01DC` | 1 -> 2 | None |
| `DefaultCombatRangedstyle` / `000B2945` | 1 -> 2 | `CSSD.waitTimeMin` 2 -> 3; `CSSD.waitTimeMax` 2 -> 8; `CSSD.waitToFireTimerMin` 10 -> 1; `CSSD.waitToFireTimerMax` 10 -> 2 |
| `DefaultSniperStyle` / `000C9A00` | 3 -> 8 | `CSTD.LRChance` 50 -> 75; `CSSD.takeCoverChance` 50 -> 100; `CSSD.waitTimeMin` 1 -> 10; `CSSD.waitTimeMax` 6 -> 15; `CSSD.waitToFireTimerMax` 8 -> 2 |
| `CSSecuritron` / `0010C765` | 1 -> 2 | None |
| `CSSecuritronStreet` / `001297D1` | 1.2 -> 2.4 | None |
| `CSLegionary` / `00137AC0` | 1 -> 2 | `CSTD.dodgeChance` 75 -> 80; `CSTD.LRChance` 50 -> 65; `CSSD.waitToFireTimerMin` 10 -> 1; `CSSD.waitToFireTimerMax` 10 -> 2; `CSSD.fireTimerMax` 2 -> 6 |
| `CSNCRTrooper` / `00137AC1` | 1 -> 2 | `CSSD.waitTimeMin` 1 -> 5; `CSSD.waitTimeMax` 4 -> 8; `CSSD.waitToFireTimerMin` 1 -> 0.5; `CSSD.waitToFireTimerMax` 2 -> 1 |
| `OliverRangerRangedstyle` / `001411A1` | 1 -> 2 | `CSSD.waitTimeMax` 2 -> 6 |
| `CSNVLegateLanius` / `001438E9` | 1 -> 2 | `CSSD.fireTimerMax` 2 -> 4 |
| `CSCentaurEvolved` / `0014F434` | 1 -> 2 | None |
| `CSFireAntSoldier` / `0014F436` | 1 -> 2 | None |
| `CSFireAntWorker` / `0014F438` | 1 -> 2 | None |
| `CSNVLakelurk` / `0014F451` | 1 -> 2 | None |
| `CSNVLakelurkAlpha` / `0014F452` | 1 -> 2 | None |
| `CSNVFireGeckoRanged` / `0016294F` | 5 -> 10 | None |
| `DefaultCombatRangedstyleLargRadius` / `00168A7F` | 1 -> 3 | `CSTD.LRChance` 50 -> 60; `CSTD.idleTimerMin` 0.5 -> 0.15; `CSTD.idleTimerMax` 1.5 -> 1.25; `CSSD.waitTimeMax` 2 -> 8; `CSSD.waitToFireTimerMin` 10 -> 1; `CSSD.waitToFireTimerMax` 10 -> 2 |
| `VFactionSquadCSDefault` / `0017BA2D` | 1 -> 2 | `CSTD.LRChance` 50 -> 85; `CSTD.idleTimerMin` 0.5 -> 0.25; `CSTD.idleTimerMax` 1.5 -> 1; `CSSD.waitTimeMax` 2 -> 10 |

Across all 30 records, `CSAD`, combat-style flags, weapon restrictions, cover
search radius, minimum range multiplier, targeting FOV, combat radius,
semi-auto delays, and power-attack parameters remain unchanged. Most creature
and robot styles receive only an `Rmax` edit. It would be inaccurate to
describe them as receiving new tactical logic.

## What the policy changes, and what it cannot establish

### Range and weapon selection

There are several simultaneous range edits: `fAIUseWeaponDistance` rises from
15,000 to 50,000; the absolute-range multiplier rises from 4 to 50; the
current-weapon multiplier rises from 1.25 to 100; and every edited style raises
`Rmax`. The current-weapon branch actually composes the latter two absolute
range factors before squaring its comparison value. It is a conditional
eligibility calculation, not a change to projectile reach or damage.

The range helper also has projectile-dependent constraints. Multiplying all
the observed ratios together and publishing that as an NPC engagement range
would be unjustified. Effective weapon choice, LOS, target acquisition,
navigation, and animation remain separate. The current-weapon eligibility
comparison changes, but a better weapon-choice outcome is not proven.

The inventory timer is reduced from 5 to 1. It changes a real native timer
input, making more frequent inventory reevaluation possible when its owning
path runs. It does not improve the weapon scoring algorithm itself.

### Cover, firing cadence, and character differences

The general style changes wait-to-fire values from 10/10 to 1/2, but raises
maximum waiting from 2 to 6. The default ranged style uses 3/8 waiting and
1/2 wait-to-fire. The sniper style raises cover chance from 50 to 100, waiting
from 1/6 to 10/15, and `Rmax` from 3 to 8. These are different timing profiles;
"all enemies fire sooner and pause less" is contradicted by the record data.

The sentry style changes fire intervals from 2/2 to 10/20. The turret changes
zero wait/fire intervals into 0.1/0.25 pairs. Trooper, legionary, and special
styles have their own smaller changes. These values are policy inputs to
native actions, not observed burst lengths or guaranteed firing rates.

Global cover-reload thresholds move from 0.25 and approximately 0.33 to 1.
The actual comparison described above makes frequent top-ups a behavior to
measure. No setting here adds suppression, squad communication, new flanking
planning, a cover reservation protocol, or a new firing action.

### Maneuvering, melee, perception, and search

Only six styles change `CSTD`. Two change dodge percentage, five change
left/right chance, and three shorten their idle intervals. No style changes
blocking, attack percentage, power attacks, rush attacks, or advanced skill
and fatigue coefficients. At the global level, dodge base, left/right weighting,
and walking chance also change substantially. The randomized native score
path means their combined visible result needs observation.

The global view-cone value decreases from 190 to 180. The wobble limit grows
from 15 to 25. These facts do not support claims of broader visual awareness
or improved aim. Sneak distance, ambush radius, fleeing, cautious confidence,
threats, disarmed pickup, and search settings also change, so this policy's
scope extends beyond the exchange of gunfire.

Search retention values generally grow while the active search-area timer
shrinks. Some named search-radius and removal-distance settings lack direct
consumers, so the data does not prove the shape or duration of an actual
search. Changes to social conversation chances, greeting distance, trespass
warnings, door activation, and turning/stepping policy further show that this
is not an isolated combat-only profile.

### Cost and compatibility

Data-only implementation adds no custom update loop. However, the changes can
admit more native work: combat counts rise from 15/20 to 21/28, several native
timers shrink, and range/search policy changes. Potential cost belongs to
existing actor, inventory, pathfinding, and search work. There is no measured
performance result and no justified FPS estimate.

Global settings have shared ownership. Shared combat-style overrides also
compete with later record overrides, even when one provider intended to change
only a different field. Existing style assignment and overrides determine
which actors use the changed records. Added actors using an edited shared
style can participate; actors using independent styles do not inherit these
style edits merely because they are ranged combatants. Global settings can
still affect either group.

## Implications for Atom

### Established constraints

The [Atom combat contract](atom_combat_engine_contract.md) already separates
AI planning from common attack execution. The
[compatibility contract](atom_compatibility_contract.md) and
[Atom architecture](atom.md) require ESP-less, capability-based behavior for
arbitrary added actors and equipment. Atom has no AI module in its current
entrypoint. This research does not change that implementation state.

A direct transcription of the 30 overrides would cover a fixed identity list
and mutate shared authored data. A wholesale write of the 88 globals would
have the global scope and consumer gaps documented here. Neither establishes
the per-actor policy subsystem Atom needs.

### Proposed subsystem responsibilities

The following is a design proposal, informed by the native boundaries above.
It remains separate from verified hook installation and behavioral acceptance:

| Responsibility | Evidence motivating it | Required boundary before implementation |
|---|---|---|
| Effective actor context | Resolver precedence and controller refresh are established | Prove borrowed lifetime and concurrent access at the selected adapter; preserve package and actor overrides |
| Weapon and range policy | Five direct range callers and the three-output ABI are established | Close caller-specific output constraints, equipment capability classification, and runtime behavior |
| Cover and fire cadence | Three sampled interval families and their timer stores are established | Close procedure lifetime, all transition semantics, and safe callsite chaining; preserve native random sampling |
| Maneuver policy | Global and style terms participate in conditional randomized decisions | Prove caller arguments, allowed directions, movement constraints, and random-choice ownership |
| Search and perception | Registered setting names are not sufficient evidence of active behavior | Trace the actual detection/search boundary and memory/lifetime model before selecting controls |
| Item use | Native restore and buff timers already exist | Prove item admission, inventory ownership, and action execution without fabricating inventory or replaying use |

Keep policy calculation separate from native access and execution. A future
policy view should consume the effective native style and validated actor,
target, weapon, and action state at a proven decision boundary. It should
produce a bounded adjustment for that decision, with invalid or unsupported
contexts retaining native behavior. This proposal does not establish that a
safe seam already exists for every row.

### Rust strategy contract

The user-selected authoring model is small compiled Rust modules or functions.
The central subsystem owns context collection, strategy selection, composition,
native access and runtime configuration. An individual strategy owns one
documented policy contribution. It does not install hooks, traverse engine
objects, reset actions, or allocate a new combat style.

A strategy descriptor should declare its applicable decision phase, input
dependencies, output parameters and scope. Its calculation receives copied
or otherwise lifetime-proven values and emits typed contributions to the
central resolver. This is an interface requirement, not an implemented API.

| Concern | Design requirement grounded in the research |
|---|---|
| Parameter scope | Distinguish world/global, group, controller/actor and procedure/decision outputs. A global setting can be explicitly owned as global policy; it cannot represent different simultaneous actor values |
| Baseline | Start from the live native/predecessor result or effective authored values for this decision. Never repeatedly apply an overlay to a value containing the previous overlay |
| Composition | Specify operations and precedence per parameter. Float bounds, probabilities, enum restrictions and native safety flags need different rules; no universal multiplier composition is established |
| Publication | Capture one coherent configuration generation and one context publication for a decision. A configuration change affects the next permitted sample; it does not implicitly reset a native timer or replace a provider |
| Transition stability | Declare when an adjustment applies and when cached derived state becomes invalid. Keep thresholds and sampled durations distinct |
| Unknown input | Represent missing weather, actor state or history explicitly. A native fallback such as noon is not evidence that the world is actually at noon |
| Cost | Compile a static catalog and select applicable enabled strategies by phase/dependencies. Collect common inputs once per appropriate publication or decision; bound active work without claiming catalog size is free |
| Diagnostics | Attribute the resolved value to its baseline and contributing strategies, outside routine hot-path logging. Diagnostics must not consume another native random sample |
| Native boundary | Only the adapter owns raw pointers, ABI, provider chaining and writes. Pure Rust calculations cannot make an unproven engine pointer safe |

Examples of the intended separation are a time-of-day module contributing a
range preference, a weather module contributing cover cadence, and an actor
condition module contributing maneuver policy. These are proposed strategies,
not approved numeric behavior. They can share observations while retaining
independent code and tuning settings. Conflicting contributions are resolved
centrally with defined parameter rules, rather than through incidental module
execution order.

The existing Atom configuration path already parses one saved INI and publishes
subsystem snapshots after deferred initialization or `MCMExtUpdate`; see
[config.rs](../atom/src/config.rs). Existing input and camera configuration
stores use sequence-labelled atomic fields. This establishes a local pattern
to evaluate, not proof that a new AI snapshot can safely reuse a store without
an AI reader/writer and retirement audit. No new per-frame config parser or
Rust-code hot reload is required by the requested authoring model.

Player playstyle is a separate observation/history subsystem. The existing
[ranged-fire count wrapper](../atom/src/ballistics/hooks.rs) observes a successful
native projectile-count result and the player source, and publishes one camera
shot sequence change before projectile launch iteration. The current
[camera event](../atom/src/camera/mod.rs) carries no weapon, target, time or
historical statistics. This is an existing observation boundary to research;
it is not an implemented playstyle sensor. A history collector would need
explicit observed metrics, retention/reset rules and available hook coverage.
Individual strategies should consume its bounded summaries and must not each
reconstruct player history or gain undisclosed target-position knowledge.

Do not retain actor or combat-controller pointers beyond their proven lifetime.
Do not assume the planner runs only on the main thread. Do not modify a shared
style temporarily around a call: reader concurrency and recursive entry have
not been proved. No per-frame actor scan, new scheduler, form-name detection,
fixed FormID classification, or copying of complete form blocks follows from
this research.

The native engine should continue owning target relationships, package and
path execution, equipment/ammo commits, animation, attack admission, and
the common projectile/hit path. New policy must coexist with authored creature
restrictions and existing runtime style providers. Configuration and hook
installation remain subject to the repository's startup contract and Atom's
existing lifecycle; this document authorizes no startup change.

### Evidence still needed before production work

The record policy is fully accounted for. Native style precedence, identity
refresh, selected sampling boundaries, clock provenance, worker paths and
calendar/weather read chains are now established. The remaining gates are:

- Complete caller ownership, ABI, concurrency, liveness, and safe intervention
  for each proposed decision adjustment. Current instruction windows prove
  reads and arithmetic, not hook relocation or installation safety.
- Lifetime-safe context collection/publication across main and worker paths,
  including actor/controller/procedure replacement and reclamation. No chosen
  adapter has a complete lifetime, synchronization and intervention proof yet.
- Template materialization before the current-base getter, if a future feature
  needs to explain authored provenance rather than consume the native result.
- Meaning and valid domains of the remaining decision inputs; runtime pause,
  load and time-multiplier behavior; and complete interactions with action state.
- World-versus-actor weather interpretation, blend semantics needed by a
  particular strategy, and reliable invalidation or bounded sampling ownership.
- Playstyle metric definitions, actual observation coverage, retention and
  reset semantics. Current shot presentation events are not a history model.
- Indirect consumers of the ten registered settings without direct reads,
  and any actual consumer of the unrecognized range-base name.
- Runtime behavior across human, creature, robot, turret, companion, fleeing,
  essential, quest-controlled, and added-content contexts.
- Concrete requested behavior and balance targets. The observed numeric
  values are research inputs, not approved Atom defaults.

Direct resolver and getter disassembly supersedes the earlier header-only style
description. The native precedence proof does not by itself establish actor
lifetime, thread-exclusive access, safe code relocation, configuration
publication, or gameplay behavior.

## Acceptance for a future AI change

There is no implementation gate to pass for this documentation-only study.
Production AI work must first define the requested outcome at the actual
native gameplay boundary and establish its unchanged baseline. A useful
acceptance matrix should cover these independent observations:

| Behavior | Real boundary to observe |
|---|---|
| Weapon choice and range | Actual chosen/equipped weapon and attack admission with the same actor, target distances, equipment, and native style |
| Cover cadence | Enter/leave cover, wait/fire/reload actions, clip state, blocked firing, and completion across the same cover geometry |
| Maneuver | Actual valid movement and attack actions, including constrained directions, small interiors, and actors lacking human locomotion |
| Perception and search | Detection, loss, reacquisition, and combat exit with controlled visibility, sound, occlusion, and target movement |
| Item use | Real native inventory consumption, resulting actor values/effects, action completion, and cooldown state |
| Compatibility | Added forms, effective-style changes, inherited actors, scripted packages, and chained policy providers |
| Lifecycle | Cold Proton load-to-gameplay, save/load, cell transition, actor death/removal, and feature enable/disable behavior where supported |
| Cost | Identical encounter workload and settings, measured frame/AI time and actual work counts against an explicit approved metric |

Use a controlled encounter baseline and bounded instrumentation that observes
the shipped path without changing its decisions. Randomized behavior requires
enough repeated observations to assess its distribution; one successful action
does not prove a percentage. Source assertions, reconstructed policy models,
compilation, and the static ledger cannot substitute for these observations.

The current result is an evidence-backed policy inventory and research map.
Engine intervention and gameplay tuning remain separate future work.
