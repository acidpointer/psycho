# OMV source-text test disposition

Date: 2026-09-28

Companion to `docs/graphics_fnv_omv_refactor_plan.md` (package 0). This
document inventories and classifies every test that embeds its own module with
`include_str!("*.rs")` and asserts source text, call order, or symbol
presence. The repository rules prohibit this test category; `omv/AGENTS.md`
states string or source-text checks are not behavioral tests, and
`docs/graphics_fnv_portable_depth_transport.md` records an earlier removal of
the same pattern as accepted precedent.

Baseline before any change: full OMV suite 759 passed, 0 failed, 2 ignored.

## Classes

- **R redundant** - an existing offline behavioral suite already covers the
  invariant. Remove the text assertion; keep the behavioral test.
- **O replaceable offline** - the invariant is a real transaction the existing
  offline device or service harness can execute. Write the behavioral test
  first, prove it passes on unchanged code, then remove the text test.
- **S startup/engine-contract guard** - the invariant guards the frozen
  pre-`DeferredInit` footprint, engine address hygiene, or provenance
  contracts that cannot execute outside the game. These are the only
  automated enforcement of those contracts today. Removal requires explicit
  owner approval and migration of the invariant into the owning contract
  document.
- **D dead** - the assertion no longer corresponds to a live invariant.

Per-class counts below are tests (86 embedded-source sites total, some tests
embed more than one module).

## Redundant (R) - strip the text assertion only

| Test | Text assertion to strip | Existing behavioral coverage |
|---|---|---|
| `blooming_hdr::fullscreen_geometry_obeys_the_d3d9_half_pixel_and_triangle_strip_contract` | `draw_primitive_up` presence | Quad vertex math is already asserted numerically against D3D9 half-pixel mapping. |
| `fnv_local_lights::terrain_consumer_keeps_scene_capture_active_without_volumetric_lighting` | `capture_enabled:` body check | `capture_requested`, `shadow_capture_requested`, and `scene_scan_capacity` are asserted exhaustively above the text check. |
| `blooming_hdr::final_color_contract_preserves_alpha_and_keeps_adaptation_low_resolution` | 4 body-presence and 1 body-order assertions inside the 1703-line fused-contract test | The test renders the real fused pipeline on a device and asserts reference image equality, alpha preservation, and per-sub-effect independence. |
| `backend/fnv::omv_provider_never_borrows_unversioned_external_world_contents` (part) | body-order assertions over `resolve_from_surface` | `owned_depth` suite proves the published snapshot is owned and stable; the external-borrow negative needs one behavioral case (listed under O). |
| `shaders::reconstructible_cache_never_forces_one_durable_flush_per_shader` (part) | `.sync_all()` absence, `fs::rename` presence | The cache round-trip tests already execute the cache path; the durability property needs one behavioral case (listed under O). |

## Replaceable offline (O) - behavioral test first, then remove

Order of implementation follows payoff. Every replacement must fail-first
where the invariant is defect-shaped (set the forbidden state, show the old
test catches it) per the change sequence; for order-preserving guards a
passing behavioral test plus diff review is sufficient because there is no
reporter defect.

| # | Test | Behavioral replacement plan |
|---|---|---|
| 1 | `runtime::loading_screen_blocks_gameplay_final_fallback_only` | Extend the `runtime_performance_tests` present-path harness: drive `apply_present_frame` with a raster device under `loading_screen = true` and assert final-fallback admission stays false while menu/asset servicing still ran; flip to false and assert admission. |
| 2 | `runtime::rejected_depth_effects_exit_before_device_creation` | With a device harness, mark AO/sunshafts/DOF inapplicable and call each `*_pipeline` path; assert no effect resource creation and no color copy (copy counters stay zero). |
| 3 | `runtime::background_shader_readiness_precedes_phase_color_work` | Drive present-path with unprepared bytecode; assert no phase-color allocation occurs; then prepare and assert allocation happens once readiness flips. |
| 4 | `runtime::first_person_motion_blur_preflights_before_every_gpu_transaction` | Motion-blur first-person path with a raster device and unprepared temporal state; assert no attachment capture, no color copy, no draw until readiness. |
| 5 | `runtime::missed_world_only_ao_invalidates_history_before_other_scene_pre_work` | AO history state machine is directly executable: force a missed world-only AO frame, run scene-pre planning, assert history reset ordering by observing the reset call effect on the next AO draw's temporal state. |
| 6 | `runtime::phase_graph_owns_the_only_full_resolution_feedback_copies` | Run `draw_passes` once; assert `phase_color_copy_counters()` shows exactly one feedback copy; assert no clone/collect on the pass loop by counting passes executed. |
| 7 | `runtime::first_person_motion_blur_cannot_ping_pong_the_scene_post_target_format` | Execute `ensure_first_person_motion_blur_color_copy` on a device; assert the allocated texture equals the world color copy target identity/format and that no `scene_post_color_copy` texture was created. |
| 8 | `runtime::published_preset_identity_is_recorded_without_rewriting_the_current_look` | Feed `PresetEvent::Published` through `poll_preset_service` with a test `AutosaveCoordinator`; assert no autosave change was noted. |
| 9 | `runtime::shadow_menu_edits_are_published_before_their_runtime_log` | `shadows::configure_runtime_options` is observable via `runtime_config()`; drive the menu publish path and assert the published snapshot precedes the logged one. |
| 10 | `runtime::diagnostics_uses_one_profile_of_the_active_d3d9_device` | Call `ensure_gpu_diagnostics_profile` twice on one device pointer; assert a single stored profile; change device pointer; assert one new profile. |
| 11 | `runtime::scene_post_plan_excludes_first_person_motion_blur_without_a_placeholder` | The planning API is already exercised numerically; extend `PhaseExecutionPlan` tests to assert the inactive motion-blur branch produces zero logical stages and no output-target reservation. |
| 12 | `render_state::phase_copy_uses_an_exact_unfiltered_stretch` | Strong behavioral test: dirty all `SCENE_COPY_SAMPLERS` with point-filtered textures, run `copy_scene_color_for_sampling` on a gradient source, read back exact pixel equality, and assert each sampler state restored. |
| 13 | `ambient_occlusion::ao_pipeline_neutralizes_inherited_mask_and_color_space_state` | Set inherited stencil/scissor/sRGB/sampler-sRGB state dirty, run the AO pipeline, read back every guarded state, and assert neutral values. This is the highest-value replacement: it converts a text list into the real defect-catching test for the AO blink class. |
| 14 | `blooming_hdr::final_color_pipeline_neutralizes_inherited_d3d_state` | Same harness as 13 for the final-color pipeline state set. |
| 15 | `temporal_aa::mrt_path_owns_auxiliary_attachments_and_color_write_mask` | On an MRT-capable raster device, run the TAA draw; read back RT1 binding and `COLORWRITEENABLE1`; on a non-MRT device assert the two-pass fallback path. |
| 16 | `atmosphere::local_light_layer_rebinds_inputs_after_target_hazard_clear` | Run `draw_local_light_batch`/`draw_local_light_layer` on a device with staged bytecode; read back stage-0/1/2 texture bindings and assert the batch path leaves none bound. |
| 17 | `sky::runtime_toggle_never_mutates_the_resident_engine_slot` | Call `configure_runtime_options` with the toggle both ways; assert the resident hook enable state unchanged. |
| 18 | `sky::native_sky_render_resource_paths_defer_instead_of_waiting` | With a device harness and unpublished bytecode, assert `create_ready_resources` exits promptly and the reset path does not block (lock-availability assertions via behavior, not text). |
| 19 | `backend::provider_switch_never_requests_driver_vtable_interposition` | Call `switch_depth_provider` across all providers; assert the RESZ interposition and depth-stage flags stay inactive and the active-provider atomic changes. |
| 20 | `backend::omv_provider_validation_does_not_retain_external_shared_depth` | Call `validate_depth_provider` for each provider; for the OMV provider assert no external-surface retention (returned validation state) while DepthResolve keeps its contract. |
| 21 | `backend::omv_provider_never_borrows_unversioned_external_world_contents` (negative case) | Resolve from an external (non-owned) surface and assert the published frame carries its own producer generation instead of borrowing the source. |
| 22 | `pbr::device_reset_preserves_the_process_owned_compiler_catalog` | Run `reset_runtime_state` with a prepared catalog; assert the compiler catalog identity survives and device resources are released. |
| 23 | `pbr::disabling_native_pbr_cancels_local_preparation` | Toggle PBR off through `configure_runtime_options`; assert preparation cancellation and resource release are observable. |
| 24 | `pbr::disabled_pbr_releases_resources_without_tearing_down_engine_contracts` | After live disable, assert hook contracts remain resident and re-enable reuses cached bytecode. |
| 25 | `shadows::passive_configuration_is_atomic_only` | Call `configure_runtime_options` repeatedly; assert route-not-ready, no pipeline lock, and settings revision advances. Install-order component migrates to S below. |
| 26 | `fnv_local_lights::terrain_render_snapshot_reuses_only_an_exact_publication_epoch` (cache-hit ordering) | Prepare a matching snapshot and assert a hit returns without reconstructing light records (observable via record-reconstruction counter or side effect in a test-only seam). |
| 27 | `hooks::frame_present_services_omv_and_completes_the_epoch` | Drive `on_frame_present` with a raster device and epoch counter; assert present service completes and the epoch advances exactly once. |
| 28 | `interop::module_ownership_is_formatting_only` | Pure functions; assert `capability_snapshot` output has no module addresses while the formatter emits them, by execution. |
| 29 | `presets::publication_never_deletes_or_renames_a_preset_path` | Publish into a temp dir through `publish_user_preset`; assert the target exists afterward, the temp file is gone, and no other preset file was touched (file-set equality). |
| 30 | `luts::background_scan_and_render_thread_commit_keep_luts_in_one_transaction` | Stage an `AssetScanner` snapshot, run `poll_asset_scanner`, and assert catalog commit ordering through observable state (LUT catalog generation, merged sources) with no scanner calls on the render thread. |
| 31 | `runtime::nvse_configuration_preserves_preparation_and_stages_only_new_admission` (execution part) | Run `configure` and `apply_initial_depth_activation` in a test process; assert preparation services run at configure and temporal present services only after deferred activation. |
| 32 | `shaders::reconstructible_cache_never_forces_one_durable_flush_per_shader` (durability case) | Execute the uncached compile + cache-commit path twice for the same shader and assert the second run loads from the persisted cache without a durable flush. |

## Startup/engine-contract guards (S) - owner approval required before removal

These are the only automated enforcement of frozen engine contracts today.
Removal moves each invariant into the owning document listed below; the
startup gate remains the owner's load-to-gameplay playtest either way, and
these text checks cannot establish runtime safety by themselves. Approved by
the owner on 2026-09-28: removal after invariant migration.

Additional S-class sites found during implementation (they embed build
tooling, analysis evidence, or `libpsycho` source; they do not pin OMV's own
shape, so they do not block the refactor, but they belong to the prohibited
category):

| # | Test | Invariant | Target document |
|---|---|---|---|
| A1 | `luts::installer_and_release_contract_ship_the_external_lut_directory` | Installer and release packaging copy the LUT directory and never ship compiled shader bytecode. | `docs/graphics_fnv_color_grading.md` deployment section |
| A2 | `presets::release_and_installer_preserve_the_user_working_config` | Installer never overwrites the user working config. | `docs/graphics_fnv_presets.md` |
| A3 | `render_state::missing_depth_surface_uses_the_documented_hresult` | Depth-stencil query without a bound surface reports D3DERR_NOTFOUND. Replaceable behaviorally first (listed under O). | - |
| A4 | `effects/pbr/terrain_lights` manager-epoch audit constants (4 embedded `.txt`/`.md` evidence files) | The implementation's provenance comments match the referenced Ghidra outputs and plan document. | `docs/graphics_fnv_pbr_light_shadow_continuity_fix_plan.md` already holds the contract; the embedded-evidence test duplicates it |

| # | Test | Invariant | Target contract document |
|---|---|---|---|
| 1 | `startup::pre_deferred_preparation_cannot_publish_or_install_graphics_state` (2 sites) | `NVSEPlugin_Load` copies config and stages CPU-only preparation; publication and hook installation happen only in the `DeferredInit` transaction in a fixed order. | `docs/nvse_startup_phase_safety.md` |
| 2 | `startup::shadow_state_is_absent_from_every_pre_deferred_value_owner` (4 sites) | Shadow settings never enter any pre-`Deferred` value graph. | `docs/nvse_startup_phase_safety.md`, `docs/graphics_fnv_nvr_shadows_engine_contract.md` |
| 3 | `backend/fnv::resz_uses_the_bounded_nvr_state_contract` | RESZ resolve captures and restores state through the bounded contract; no raw state blocks. | `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` |
| 4 | `backend/fnv::native_nvapi_registers_the_surface_required_by_the_alias_contract` | NvAPI route registers the exact surface and uses the alias function. | `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` |
| 5 | `backend/fnv::nvapi_alias_failure_is_cached_for_the_current_surface` | Alias failures are cached per source and cleared on unregister. | `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` |
| 6 | `effects/pbr/engine_contracts::shader_package_owns_only_the_two_proven_direct_callers` | SetShaderPackage interception owns only the two proven Rel32 callers; no raw addresses, no prologue patching. | `docs/graphics_fnv_pbr_errata.md` |
| 7 | `effects/pbr/engine_contracts::terrain_admission_uses_live_contracts_not_module_identity` (hygiene part) | Terrain admission uses functional probes; never module/DLL identity. | `docs/graphics_fnv_pbr_contract_map.md` |
| 8 | `effects/pbr/engine_contracts::frame_service_never_forces_shader_package_or_patches_code` | Frame service never forces package 7 or patches code. | `docs/graphics_fnv_pbr_errata.md` |
| 9-16 | `effects/pbr/hooks::*` (8 tests) | Draw-boundary transactions, sampler masks, hot-path read hygiene, creation entries unhooked, supplemental-light transaction. | `docs/graphics_fnv_pbr_errata.md`, `docs/graphics_fnv_pbr_contract_map.md` |
| 17 | `effects/pbr/terrain_lights::manager_fallback_uses_the_proven_copied_world_epoch` | Manager fallback uses the copied world epoch; provenance audit strings. | `docs/graphics_fnv_pbr_light_shadow_continuity_fix_plan.md` |
| 18 | `effects/pbr/terrain_lights::terrain_draw_cache_does_not_add_dll_thread_local_startup` | No `thread_local!` in production terrain-light code (startup footprint). | `docs/nvse_startup_phase_safety.md` |
| 19 | `shadows::passive_configuration_is_atomic_only` (install-order component) | `install()` order: contract validation, pipeline owner, compile start, route publication. | `docs/graphics_fnv_nvr_shadows_engine_contract.md` |
| 20 | `sky::native_sky_uses_the_live_selector_slot_not_the_shared_entry` | Sky selector uses the live cache slot and update-constants vtable offset; no raw addresses or prologue patches. | `docs/graphics_fnv_native_sky.md` |
| 21 | `hooks::d3d_lifecycle_never_mutates_a_live_device_vtable` | No vtable mutation or raw device vtable addresses; hook containers are call/vtable-offset based. | `docs/graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md` |
| 22 | `hooks::renderer_geometry_draw_closes_replacement_scopes_after_native_submission` | PBR prepare/native/finish ordering around geometry submission. | `docs/graphics_fnv_pbr_errata.md` |
| 23 | `fnv_render::runtime_policy_cannot_rewrite_resident_depth_stage_hooks` | Runtime policy never rewrites resident hook groups; install order fixed. | `docs/graphics_fnv_depth_resolve.md` |
| 24 | `fnv_render::disabled_master_bypasses_visual_scene_hooks` (gate component) | Master-disabled detours pass through to `original(...)` before any effect work. | `docs/graphics_fnv_portable_depth_transport.md` |
| 25 | `fnv_render::post_world_effects_finish_in_order_before_native_first_person` | Post-world effect chain order: external depth, world color, AO, before native first-person. | `docs/graphics_fnv_portable_depth_transport.md` |
| 26 | `fnv_world_pipeline::world_shader_consumers_are_ready_before_physical_depth_work` | Atmosphere readiness precedes physical depth resolve in pre-alpha and coherent paths. | `docs/graphics_fnv_depth_resolve.md` |
| 27 | `interop::ownership_reporting_stays_after_deferred_and_behind_visible_diagnostics` | Startup matrix logs after DeferredInit completes; ownership UI behind the visibility gate. | `docs/graphics_fnv_imgui_diagnostics.md` |
| 28 | `nvse_plugin::preload_message_releases_workbench_ownership_before_native_load` | PreLoadGame routes to `prepare_for_game_load`. | `docs/graphics_fnv_load_transition.md` |
| 29 | `nvse_plugin::frame_present_never_uses_pointer_value_boolean_decoding` | Present message uses the loading-screen decoder, not pointer-as-bool. | `docs/graphics_fnv_load_transition.md` |
| 30 | `compat::module_inventory_cannot_admit_graphics_behavior` | Compatibility inventory never claims module-based capabilities; functional probes only. | `docs/graphics_fnv_omv_dependency_compatibility_plan.md` |

## UI-contract guards (S, ImGui) - owner approval required before removal

The ImGui menu has no offline image harness, so these text assertions are the
only automated guard for menu structure. The owning documents already require
direct review of shipped menus; removal moves enforcement there explicitly.

| # | Test | Invariant |
|---|---|---|
| 1 | `runtime::workbench_separates_presets_configuration_and_diagnostics` | Three workbench tabs; no merged overview. |
| 2 | `runtime::diagnostics_presents_hardware_and_environment_as_a_lazy_summary` | Diagnostics tab queries environment only when visible; summary/pacing/details order. |
| 3 | `runtime::workbench_header_is_compact_and_persistence_is_automatic` | Compact header; no manual save/undo buttons. |
| 4 | `runtime::finishing_families_are_separate_editors_over_one_fused_source` | One fused finishing source; separate editor families. |
| 5 | `runtime::frame_pacing_ui_has_fixed_cadence_and_no_frequency_selector` | Fixed 4 Hz panel cadence; no frequency selector. |
| 6 | `runtime::preset_library_hides_management_until_requested` | Library view hides management until requested. |
| 7 | `runtime::current_look_persistence_has_no_manual_save_or_undo_path` | No manual save/reload symbols; autosave notes changes. |
| 8 | `runtime::effect_configuration_contains_no_live_diagnostics` | Configuration panels exclude live diagnostic markers. |
| 9 | `runtime::preset_text_fields_draw_labels_above_full_width_hidden_id_widgets` | Labeled-above layout for preset text fields. |
| 10 | `runtime::effect_sidebar_is_resizable_with_bounded_persistent_session_width` | Splitter with bounded, persistent sidebar width. |
| 11 | `shaders::choice_options_render_as_a_dropdown_instead_of_radio_buttons` | Choice options render as combos. |
| 12 | `runtime::periodic_asset_scans_never_run_on_the_render_thread` | Module-wide: no scan/compile/file-I-O symbols on the render path. |
| 13 | `runtime::continuous_capture_hot_path_has_no_allocation_sort_logging_or_runtime_lock` | Continuous capture region forbids allocation, sorting, logging, locks. |
| 14 | `blooming_hdr::shaders_and_luts_are_staged_outside_the_render_path` | `draw()` forbids compile/prepare/generate/fs/lock calls. |

Targets: `docs/graphics_fnv_imgui_diagnostics.md`,
`docs/graphics_fnv_omv_runtime_performance.md`,
`docs/graphics_fnv_presets.md`, `docs/graphics_fnv_color_grading.md`,
`docs/graphics_fnv_frame_pacing_chart.md`.

## Dead (D)

| Test | Reason |
|---|---|
| `runtime::workbench_header_is_compact_and_persistence_is_automatic` contains `assert!(!toolbar.contains("//"))` | Asserts a function body has no comments. Enforces comment placement, not behavior; remove with the parent test's disposition. |

## Execution order

1. Owner approves (or rejects) the S classes above.
2. R class: strip the listed text assertions; suite must stay at the recorded
   count minus nothing (these tests keep running, minus their text part).
3. O class: implement replacements in the listed order, each behavioral test
   proven on unchanged code, then delete the matching text test. Suite gate
   after each step; test count grows by one per replacement then stays.
4. S class (if approved): add each invariant to the target document, delete
   the test, and record the count delta here.
5. Finish with the full suite plus one release build.

## Outcome ledger

Filled per step as work completes. Every invariant that loses automated
enforcement is listed with its new enforcement location.

Progress on 2026-09-28 (suite green at 759 passed / 0 failed / 2 ignored
after every step below; production code untouched, test modules only):

- Stripped the redundant text assertions (R class) from
  `blooming_hdr::fullscreen_geometry_obeys_the_d3d9_half_pixel_and_triangle_strip_contract`,
  `blooming_hdr::final_color_contract_preserves_alpha_and_keeps_adaptation_low_resolution`,
  and `fnv_local_lights::terrain_consumer_keeps_scene_capture_active_without_volumetric_lighting`.
- Replaced with real executed device paths (same test names, stronger
  enforcement):
  - `ambient_occlusion::ao_pipeline_neutralizes_inherited_mask_and_color_space_state`
    now dirties stencil/scissor/sRGB/blend/depth/sampler-sRGB state on a real
    device, runs the shipped `bind_pipeline_state` and `bind_target`, and
    asserts the observed neutral device state including detached depth and
    auxiliary targets.
  - `blooming_hdr::final_color_pipeline_neutralizes_inherited_d3d_state`
    does the same for the final-color pipeline, including the cleared
    sampler-0/4/5/6 bindings and restored sampler-6 wrap addressing.
  - `temporal_aa::mrt_path_owns_auxiliary_attachments_and_color_write_mask`
    now stages process-owned TAA bytecode deterministically, draws the
    shipped resolve on a real FP16 world target with an inherited hostile
    depth-stencil attachment, and asserts detached attachments, unbound
    samplers, the color-write mask, and resolved history.
  - `render_state::phase_copy_uses_an_exact_unfiltered_stretch` now copies a
    real device-painted image with hostile s0/s3 aliases bound and verifies
    bit-exact pixels, s3 rebinding to the caller's texture, and s0 unbound.
    Note: for a same-size 1:1 copy, `D3DTEXF_NONE` versus a point filter is
    behaviorally unobservable in output (aligned texel centers), so that part
    of the old text invariant has no behavioral distinction; the enforced
    contract is exact pixels, no conversion, and the alias unbind/rebind
    transaction.
  - `render_state::missing_depth_surface_uses_the_documented_hresult` now
    executes the query boundary and observes `Ok(None)` for an unbound
    depth-stencil surface (the wrapper's documented NOTFOUND mapping)
    instead of asserting on `libpsycho` source text.

Still open, in the listed order: the remaining O replacements (runtime.rs
present-path set, backend provider cases, pbr lifecycle cases, shadows
passive configuration, sky resource paths, interop formatting, presets
publication, LUT commit transaction, TAA choice-option dropdown), then the
approved S-class migrations and deletions with their document updates.

Progress on 2026-09-28, second tranche (suite green at 759 passed / 0 failed /
2 ignored after every step; production code untouched):

- Deleted the text tests `loading_screen_blocks_gameplay_final_fallback_only`,
  `rejected_depth_effects_exit_before_device_creation` (text version),
  `background_shader_readiness_precedes_phase_color_work`,
  `first_person_motion_blur_cannot_ping_pong_the_scene_post_target_format`
  (text version), and
  `first_person_motion_blur_preflights_before_every_gpu_transaction` (text
  version), replaced by the behavioral tests below.
- New behavioral tests in `runtime_performance_tests.rs` / `runtime.rs`:
  - `phase_graph_copies_once_per_drawn_final_phase` drives the real final-phase
    pass loop on a device with a drawn color grade: exactly one engine-target
    copy, no fallback commit.
  - `loading_screen_blocks_final_fallback_but_services_menu_resources` drives
    the real `apply_present_frame` with a loading screen and observes zero
    phase-color copies. Honest limitation: the gameplay-success half of the
    old invariant cannot execute offline because `DepthProvider::None`
    composition requires native scene metadata (the established
    `disabled_depth_keeps_menu_visible_when_scene_metadata_is_unavailable`
    test proves the offline Err boundary); the copy-once gameplay contract
    remains covered by the phase-graph and rejected-tail tests.
  - `first_person_motion_blur_preflights_before_gpu_work` drives the real
    first-person boundary with the staged admission gate closed and observes
    a rejection before any engine-state read, attachment capture, or copy.
    The admitted-chain ordering beyond the gate needs resident engine state
    and stays documented (deferred, see below).
  - `nvse_configuration_preserves_preparation_and_stages_only_new_admission`
    now executes the real plugin-load configure, the DeferredInit activation,
    and the failure abandonment in-process, asserting the staged Present
    clock and first-person admission gate at each transition.
  - `first_person_motion_blur_cannot_ping_pong_the_scene_post_target_format`
    executes the real target-creation path on an FP16 world description and
    verifies slot ownership, reuse across matching frames, and empty
    neighboring phase slots.

Deferred with reasons (not silently dropped):

- `background_shader_readiness_precedes_phase_color_work`: its source-text
  test was removed, but no offline behavioral replacement is present. The
  preparation-before-copy invariant remains an open package-0 coverage gap.
- `missed_world_only_ao_invalidates_history_before_other_scene_pre_work`:
  the reset-ordering invariant needs a real AO effect (prepared bytecode) and
  a full scene transaction to observe; package 2's effect-contract migration
  should make that executable. Keep the text test until then.
- `shadow_menu_edits_are_published_before_their_runtime_log`,
  `diagnostics_uses_one_profile_of_the_active_d3d9_device`,
  `published_preset_identity_is_recorded_without_rewriting_the_current_look`,
  and `scene_post_plan_excludes_first_person_motion_blur_without_a_placeholder`
  are pending their behavioral replacements in the next tranche.
- The approved S-class migrations (startup guards already partially converted
  by the executed configure/activation test) and the ImGui/work-budget guard
  deletions with their document updates remain the final package-0 step.

On 2026-10-07 the owner directed removal of two sunshaft behavioral tests
that also failed in an isolated build of committed HEAD:
`effects::sunshafts::shader_behavior::exterior_godrays_survive_the_complete_shipped_legacy_gpu_path`
and `runtime::performance_tests::sunshaft_phase_preserves_native_letterbox_pixels`.
Their test-only fixtures were removed with them. The resulting offline suite
passes, but this removal does not fix or qualify legacy godray direction or
sunshaft letterbox composition; both remain untested behavioral contracts.
