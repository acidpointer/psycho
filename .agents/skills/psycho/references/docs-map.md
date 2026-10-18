# Documentation map

`docs/README.md` is the complete index. This file is the routing layer: read the
owning document, not every related document.

## Authority chains

| Topic | Current authority | Historical or supporting |
|---|---|---|
| Pre-`DeferredInit` startup | `docs/nvse_startup_phase_safety.md` | `docs/graphics_fnv_atmosphere_startup_crash_errata.md`, `docs/graphics_fnv_load_transition.md` |
| OMV graphics rules | `omv/AGENTS.md` | This skill's graphics references |
| Depth providers | `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` | Older exclusive-producer and RESZ sections in `docs/graphics_fnv_depth_resolve.md`; `docs/graphics_fnv_portable_depth_transport.md` |
| Native PBR | `docs/graphics_fnv_pbr_errata.md` plus `docs/graphics_fnv_pbr_contract_map.md` | `docs/graphics_fnv_omv_real_pbr_port_plan.md`, `docs/omv_pbr_nvr_contract_gap_report.md`, `docs/nvr_reference_contract.md` |
| Shadows | `docs/graphics_fnv_nvr_shadows_engine_contract.md` | `docs/graphics_fnv_shadows_diagnostics.md`, `docs/graphics_fnv_shadows_performance_plan.md` |
| Atom gameplay | `docs/atom.md` | The feature contracts listed below |
| Save integrity | `docs/save_integrity.md` | Dated `crash_*` save post-mortems |
| Parallel IO/SpeedTree | `docs/parallel_io_engine_contract.md` | `docs/lod_streaming_handoff_engine_fix_plan.md`, `docs/radio_scan_hitch_evidence.md` |
| gheap | `psycho-engine-fixes/src/mods/heap_replacer/gheap/AGENTS.md` | `docs/gheap_large_modlist_compatibility.md` |
| zlib | `docs/zlib_stream_ownership.md` | - |
| Logger | `docs/runtime_logger.md` | - |
| Dashboard | `docs/psycho_dashboard.md` | - |
| Window/input policy | `docs/window_input_policy.md`, `docs/fnv_actor_input_contract.md` | `docs/atom_input_wrapper_design.md` |

If a document says it is superseded, do not extend the superseded design.
Extract evidence, then follow the named current authority.

## Engine fixes and infrastructure

| Document | Use when |
|---|---|
| `docs/nvse_startup_phase_safety.md` | Any change to imports, TLS, static ownership, config layout, workers, or pre-`DeferredInit` behavior. |
| `docs/psycho_engine_fix_exception.md` | Reporter-only unreleased engine-fix candidate; read completely before using the exception. |
| `docs/parallel_io_engine_contract.md` | IOManager workers, BSFile, exterior cells, SpeedTree, static vertex buffers. |
| `docs/lod_streaming_handoff_engine_fix_plan.md` | LOD demand, prefetch, handoff, retention, attachment budgets. |
| `docs/gheap_large_modlist_compatibility.md` | Allocator pressure, VAS, OOM, large modlists. |
| `docs/save_integrity.md` | Save transactions, load ownership, commit/abort, container validation. |
| `docs/zlib_stream_ownership.md` | zlib replacement, stream lifetime, deflate/inflate ownership. |
| `docs/havok_entity_batch_engine_contract.md` | Havok sparse entity consumption and batch ownership. |
| `docs/model_cache_string_key_engine_contract.md` | Model cache string keys and NULL consumers. |
| `docs/model_postprocess_serialization_engine_fix.md` | Model EditorMarker postprocess serialization. |
| `docs/source_texture_cache_publication_guard.md` | Source-texture cache publication ownership. |
| `docs/install_path_registry_repair.md` | Bethesda installation-path registry repair. |
| `docs/window_input_policy.md` | Cursor confinement, system keys, focus, display policy. |
| `docs/runtime_logger.md` | Logger queue, deferred start, flush/shutdown, performance. |
| `docs/psycho_dashboard.md` | Dashboard pages, help text, config editing, command ABI. |
| `docs/radio_music_transition_contract.md` | Radio music transitions. |
| `docs/radio_scan_hitch_evidence.md` | Radio scan hitch, path search, geometry cache. |
| `docs/fnv_location_performance_static_audit.md` | Scene lights, compound visibility, multibound, location performance. |
| `docs/fnv_extended_plugin_limit_engine_contract_and_plan.md` | Extended plugin limit research; implementation is blocked on listed evidence. |

## OMV graphics

| Document | Use when |
|---|---|
| `docs/graphics_fnv_pbr_errata.md` | Any native PBR material, selector, terrain, or lighting change. |
| `docs/graphics_fnv_pbr_contract_map.md` | Current PBR baseline and unresolved visual mapping. |
| `docs/graphics_fnv_omv_real_pbr_port_plan.md` | Object-first PBR recovery plan and ownership model. |
| `docs/omv_pbr_nvr_contract_gap_report.md` | OMV versus NVR contract gaps. |
| `docs/nvr_reference_contract.md` | NVR source contracts used as reference only. |
| `docs/graphics_fnv_pbr_light_shadow_continuity_fix_plan.md` | PBR light/shadow continuity and manager epochs. |
| `docs/graphics_fnv_pbr_object_temporal_instability_audit.md` | Object temporal instability evidence. |
| `docs/graphics_fnv_nvr_shadows_engine_contract.md` | Directional, point, and spot shadow contracts. |
| `docs/graphics_fnv_shadows_performance_plan.md` | Shadow work budgets and caster collection. |
| `docs/graphics_fnv_shadows_diagnostics.md` | Shadow runtime diagnostics. |
| `docs/graphics_fnv_depth_resolve.md` | Depth provider routes; check its authority banner first. |
| `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` | Driver-owned depth, D3D lifecycle, RESZ/NvAPI. |
| `docs/graphics_fnv_portable_depth_transport.md` | Vendor-independent depth transport and hook order. |
| `docs/graphics_fnv_native_sky.md` | Native sky replacement and selector ownership. |
| `docs/graphics_fnv_atmosphere_phase2_reliability_calibration_plan.md` | Atmosphere reliability and calibration. |
| `docs/graphics_fnv_atmosphere_phase3_directional_lighting_plan.md` | Directional volumetric lighting. |
| `docs/graphics_fnv_atmosphere_phase6_local_lighting_plan.md` | Local volumetric lighting. |
| `docs/graphics_fnv_atmosphere_debug_blink_contract_closure_plan.md` | Atmosphere debug blink and state closure. |
| `docs/graphics_fnv_volumetric_fog_lighting_plan.md` | Volumetric fog/lighting research. |
| `docs/graphics_fnv_volumetric_fog_phase2_implementation_plan.md` | Volumetric fog Phase 2 implementation. |
| `docs/graphics_fnv_omv_ao_blink_research_plan.md` | AO blinking and inherited D3D state. |
| `docs/graphics_fnv_temporal_aa_contract.md` | TAA reprojection, history, and resolve. |
| `docs/graphics_fnv_aa_performance_research.md` | AA families and performance tradeoffs. |
| `docs/graphics_fnv_motion_blur.md` | Motion blur pipeline and reprojection. |
| `docs/graphics_fnv_motion_blur_first_person_fix_plan.md` | First-person motion blur correction. |
| `docs/graphics_fnv_depth_of_field.md` | Depth of field. |
| `docs/graphics_fnv_color_grading.md` | Final color, LUTs, bloom, chromatic aberration, deband. |
| `docs/graphics_fnv_auto_exposure_and_adaptive_tone.md` | Auto exposure and adaptive tone mapping. |
| `docs/graphics_fnv_presets.md` | Versioned presets and Current Look persistence. |
| `docs/graphics_fnv_frame_pacing_chart.md` | Frame-pacing diagnostics UI. |
| `docs/graphics_fnv_imgui_diagnostics.md` | ImGui diagnostics ownership and visibility. |
| `docs/graphics_fnv_omv_runtime_performance.md` | Render-hook performance contract. |
| `docs/graphics_fnv_omv_dependency_compatibility_plan.md` | Capability-based graphics compatibility. |
| `docs/graphics_fnv_omv_nvidia_1fps_remediation_plan.md` | NVIDIA one-FPS investigation and plan. |
| `docs/graphics_fnv_omv_nvidia_remediation_implementation.md` | NVIDIA remediation implementation contract. |
| `docs/graphics_fnv_omv_nvidia_close_terrain_shader_fix_plan.md` | Superseded split-constant design. Evidence only. |
| `docs/graphics_fnv_omv_nvidia_close_terrain_shader_fix_implementation.md` | Current close-terrain texture design and compiler evidence. |
| `docs/graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md` | OMV/NVR D3D9 hook flow evidence. |
| `docs/graphics_fnv_close_terrain_portable_light_fix_plan.md` | Close-terrain portable point-light fix. |
| `docs/graphics_fnv_load_transition.md` | Load/Present/DeferredInit transition. |
| `docs/graphics_fnv_enb_depth_contract.md` | ENB depth transport reference. |
| `docs/nvr_d3d9_performance_research.md` | NVR D3D9 performance evidence. |
| `docs/omv-plan.md` | Original OMV research/implementation plan. Check status before use. |
| `docs/graphics_fnv_omv_refactor_plan.md` | OMV layering/test-architecture refactor plan. |
| `docs/graphics_fnv_omv_source_text_test_disposition.md` | Source-text test inventory and migration status. |

## Atom

| Document | Use when |
|---|---|
| `docs/atom.md` | Primary Atom architecture, lifecycle, config, and acceptance record. |
| `docs/fnv_actor_input_contract.md` | Native actor input and control ownership. |
| `docs/atom_input_wrapper_design.md` | Input wrapper, buffering, controller, MCM contract. |
| `docs/atom_first_person_camera_design.md` | First-person camera and motion. |
| `docs/atom_third_person_camera_plan.md` | Third-person camera and 360 movement. |
| `docs/atom_combat_engine_contract.md` | Native combat pipeline and data-driven policy. |
| `docs/atom_ballistics_core_plan.md` | Physical rounds and projectile policy. |
| `docs/atom_ballistics_flight_feedback_research.md` | Flight feedback and visual correlation. |
| `docs/atom_ballistics_ricochet_research.md` | Ricochet and material response. |
| `docs/atom_compatibility_contract.md` | Mod compatibility model. |

## Crash and incident records

Files named `docs/crash_*` are dated post-mortems. They preserve the failing
path, evidence, and accepted containment. They are not current policy unless a
newer contract links to them.

- `docs/crash_20260712_engine_fix_plan.md`
- `docs/crash_20260712_mod_independent_revision_plan.md`
- `docs/crash_20260717_lowprocess_save_structural_containment_plan.md`
- `docs/crash_20260802_encounter_zone_form_guard.md`
- `docs/crash_20260803_dead_corpse_cell_render_retirement.md`
- `docs/crash_20260817_controller_sequence_idtag_retirement.md`
- `docs/crash_20260819_ai_patrol_form_id_alias.md`
- `docs/crash_20260829_nipixeldata_oom_contract.md`
- `docs/crash_20260830_tile_value_contract.md`

## Plans and research

Dated `*_plan.md`, `*_research.md`, and `omv-plan.md` files are implementation
or feasibility records. Check the status line and any superseded banner before
treating them as current. Do not implement a rejected candidate from a plan.

## Updating documentation

- Extend the owning document; do not create a parallel note for the same
  contract.
- Add `Status:` and `Last updated:` to authoritative documents.
- Mark superseded material at the top with the replacement document.
- Link raw evidence instead of copying dumps.
- Record executable identity, addresses, layouts, ABI, lifecycle, intervention
  point, and evidence paths for reverse-engineered contracts.
- Keep proof, runtime observation, and unresolved facts separate.
- Do not add routine binary hashes, sizes, section inventories, or test counts
  to developer documentation unless the problem depends on artifact identity.
