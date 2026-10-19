# Documentation index

This index routes readers to the owning contract. It is not a substitute for the
document's status line. `AGENTS.md` and the owning contract are authoritative.

For task routing and authority chains, see
`.agents/skills/psycho/references/docs-map.md`.

> Ghidra script authoring is deprecated and not effective. Existing
> `analysis/ghidra/output/` is historical evidence only; use radare2 for current
> reverse engineering. See `analysis/ghidra/README.md`.

## Start here

| Document | Use when |
|---|---|
| [`nvse_startup_phase_safety.md`](nvse_startup_phase_safety.md) | Any loader-visible change before xNVSE `DeferredInit`. |
| [`parallel_io_engine_contract.md`](parallel_io_engine_contract.md) | IO workers, BSFile, exterior cells, SpeedTree, static vertex buffers. |
| [`save_integrity.md`](save_integrity.md) | Save/load transactions and container validation. |
| [`graphics_fnv_pbr_errata.md`](graphics_fnv_pbr_errata.md) | Native PBR material, selector, terrain, or light changes. |
| [`graphics_fnv_nvr_shadows_engine_contract.md`](graphics_fnv_nvr_shadows_engine_contract.md) | Shadow production and consumption contracts. |
| [`graphics_fnv_depth_resolve.md`](graphics_fnv_depth_resolve.md) | Depth routes; read its authority banner first. |
| [`atom.md`](atom.md) | Atom architecture, lifecycle, configuration, and acceptance. |
| [`runtime_logger.md`](runtime_logger.md) | Logger queuing, deferred start, and performance. |
| [`psycho_dashboard.md`](psycho_dashboard.md) | Dashboard pages, help text, config editing, ABI. |
| [`commit-rules.md`](commit-rules.md) | Immediately before any approved commit. |

## Engine fixes and infrastructure

| Document | Title | Type |
|---|---|---|
| [`nvse_startup_phase_safety.md`](nvse_startup_phase_safety.md) | Pre-DeferredInit startup compatibility and BaseObjectSwapper crash contract | contract |
| [`psycho_engine_fix_exception.md`](psycho_engine_fix_exception.md) | Reporter-only Psycho engine-fix exception | contract |
| [`parallel_io_engine_contract.md`](parallel_io_engine_contract.md) | Native parallel IO and SpeedTree engine contract | contract |
| [`lod_streaming_handoff_engine_fix_plan.md`](lod_streaming_handoff_engine_fix_plan.md) | LOD streaming and handoff engine-fix plan | plan/research |
| [`gheap_large_modlist_compatibility.md`](gheap_large_modlist_compatibility.md) | Gheap large-modlist compatibility contract | reference |
| [`save_integrity.md`](save_integrity.md) | Save integrity boundary | contract |
| [`zlib_stream_ownership.md`](zlib_stream_ownership.md) | FNV zlib replacement: ownership, correctness, and performance contract | contract |
| [`havok_entity_batch_engine_contract.md`](havok_entity_batch_engine_contract.md) | Havok sparse entity consumption contract | contract |
| [`model_cache_string_key_engine_contract.md`](model_cache_string_key_engine_contract.md) | Native model-cache string key contract | contract |
| [`model_postprocess_serialization_engine_fix.md`](model_postprocess_serialization_engine_fix.md) | Model postprocess serialization engine fix | contract |
| [`source_texture_cache_publication_guard.md`](source_texture_cache_publication_guard.md) | Source-texture cache publication guard | contract |
| [`install_path_registry_repair.md`](install_path_registry_repair.md) | Fallout installation-path registry repair | contract |
| [`window_input_policy.md`](window_input_policy.md) | Window cursor and system-key policy | contract |
| [`runtime_logger.md`](runtime_logger.md) | Runtime logger contract | contract |
| [`psycho_dashboard.md`](psycho_dashboard.md) | Psycho Engine Fixes control deck | contract |
| [`radio_music_transition_contract.md`](radio_music_transition_contract.md) | Fallout New Vegas radio music transition contract | contract |
| [`radio_scan_hitch_evidence.md`](radio_scan_hitch_evidence.md) | Fallout New Vegas Radio Scan Hitch Evidence | reference |
| [`fnv_location_performance_static_audit.md`](fnv_location_performance_static_audit.md) | Fallout New Vegas location performance static audit | reference |
| [`fnv_extended_plugin_limit_engine_contract_and_plan.md`](fnv_extended_plugin_limit_engine_contract_and_plan.md) | FNV extended plugin limit engine contract and implementation plan | contract |
| [`display_fixes_reimplementation_plan.md`](display_fixes_reimplementation_plan.md) | Display and window-mode implementation contract | plan/research |
| [`fnv_actor_input_contract.md`](fnv_actor_input_contract.md) | Fallout: New Vegas actor input contract | contract |
| [`libpsycho_hardware_detection.md`](libpsycho_hardware_detection.md) | libpsycho hardware detection | reference |
| [`fnv_runtime_visibility_injection_research.md`](fnv_runtime_visibility_injection_research.md) | Runtime visibility injection for unoptimized locations | plan/research |
| [`fnv_runtime_occlusion_plane_implementation_plan.md`](fnv_runtime_occlusion_plane_implementation_plan.md) | Runtime occlusion-plane injection: implementation plan | plan/research |

## OMV graphics

| Document | Title | Type |
|---|---|---|
| [`graphics_fnv_pbr_errata.md`](graphics_fnv_pbr_errata.md) | FNV PBR Errata | errata |
| [`graphics_fnv_pbr_contract_map.md`](graphics_fnv_pbr_contract_map.md) | FNV OMV Native PBR Contract Map | contract |
| [`graphics_fnv_omv_real_pbr_port_plan.md`](graphics_fnv_omv_real_pbr_port_plan.md) | OMV Native PBR Recovery Plan | plan/research |
| [`omv_pbr_nvr_contract_gap_report.md`](omv_pbr_nvr_contract_gap_report.md) | OMV PBR vs NVR Contract Gap Report | contract |
| [`nvr_reference_contract.md`](nvr_reference_contract.md) | NVR Reference Contract | contract |
| [`graphics_fnv_pbr_light_shadow_continuity_fix_plan.md`](graphics_fnv_pbr_light_shadow_continuity_fix_plan.md) | FNV PBR Light and Shadow Continuity Static Plan | plan/research |
| [`graphics_fnv_pbr_object_temporal_instability_audit.md`](graphics_fnv_pbr_object_temporal_instability_audit.md) | FNV Object PBR Temporal Instability Audit | graphics |
| [`graphics_fnv_nvr_shadows_engine_contract.md`](graphics_fnv_nvr_shadows_engine_contract.md) | Fallout New Vegas NVR Shadow Engine Contract | contract |
| [`graphics_fnv_shadows_performance_plan.md`](graphics_fnv_shadows_performance_plan.md) | OMV dynamic-shadow performance change plan | plan/research |
| [`graphics_fnv_shadows_diagnostics.md`](graphics_fnv_shadows_diagnostics.md) | FNV/OMV shadow diagnostics and playtest evidence | graphics |
| [`graphics_fnv_depth_resolve.md`](graphics_fnv_depth_resolve.md) | FNV depth providers and resolve routes | graphics |
| [`graphics_fnv_driver_owned_d3d_nvidia_depth.md`](graphics_fnv_driver_owned_d3d_nvidia_depth.md) | FNV engine-owned D3D lifecycle and NVIDIA depth scheduling | graphics |
| [`graphics_fnv_portable_depth_transport.md`](graphics_fnv_portable_depth_transport.md) | OMV depth transport independent of DXVK vendor profiles | graphics |
| [`graphics_fnv_native_sky.md`](graphics_fnv_native_sky.md) | FNV Native Sky Replacement | graphics |
| [`graphics_fnv_atmosphere_phase2_reliability_calibration_plan.md`](graphics_fnv_atmosphere_phase2_reliability_calibration_plan.md) | FNV atmosphere Phase 2 reliability and calibration plan | plan/research |
| [`graphics_fnv_atmosphere_phase2_slice_c_feature_plan.md`](graphics_fnv_atmosphere_phase2_slice_c_feature_plan.md) | FNV atmosphere Phase 2 Slice C feature plan | plan/research |
| [`graphics_fnv_atmosphere_phase2_slice_d_visual_composition_ui_plan.md`](graphics_fnv_atmosphere_phase2_slice_d_visual_composition_ui_plan.md) | FNV atmosphere Phase 2 Slice D visual composition and UI plan | plan/research |
| [`graphics_fnv_atmosphere_phase3_directional_lighting_plan.md`](graphics_fnv_atmosphere_phase3_directional_lighting_plan.md) | FNV atmosphere Phase 3 directional volumetric lighting plan | plan/research |
| [`graphics_fnv_atmosphere_phase6_local_lighting_plan.md`](graphics_fnv_atmosphere_phase6_local_lighting_plan.md) | FNV atmosphere Phase 6 local volumetric lighting plan | plan/research |
| [`graphics_fnv_atmosphere_debug_blink_contract_closure_plan.md`](graphics_fnv_atmosphere_debug_blink_contract_closure_plan.md) | FNV atmosphere debug blink contract-closure plan | contract |
| [`graphics_fnv_atmosphere_startup_crash_errata.md`](graphics_fnv_atmosphere_startup_crash_errata.md) | FNV atmosphere startup crash errata | errata |
| [`graphics_fnv_volumetric_fog_lighting_plan.md`](graphics_fnv_volumetric_fog_lighting_plan.md) | FNV volumetric fog and lighting research plan | plan/research |
| [`graphics_fnv_volumetric_fog_phase2_implementation_plan.md`](graphics_fnv_volumetric_fog_phase2_implementation_plan.md) | FNV volumetric fog Phase 2 implementation plan | plan/research |
| [`graphics_fnv_omv_ao_blink_research_plan.md`](graphics_fnv_omv_ao_blink_research_plan.md) | OMV ambient occlusion blinking: research and fix plan | plan/research |
| [`graphics_fnv_temporal_aa_contract.md`](graphics_fnv_temporal_aa_contract.md) | FNV Temporal AA Contract | contract |
| [`graphics_fnv_aa_performance_research.md`](graphics_fnv_aa_performance_research.md) | FNV AA performance research | plan/research |
| [`graphics_fnv_motion_blur.md`](graphics_fnv_motion_blur.md) | FNV motion blur | graphics |
| [`graphics_fnv_motion_blur_first_person_fix_plan.md`](graphics_fnv_motion_blur_first_person_fix_plan.md) | FNV first-person motion-blur correction plan | plan/research |
| [`graphics_fnv_depth_of_field.md`](graphics_fnv_depth_of_field.md) | FNV depth-of-field pipeline | graphics |
| [`graphics_fnv_color_grading.md`](graphics_fnv_color_grading.md) | OMV final color, external LUT, Bloom, and chromatic contract | graphics |
| [`graphics_fnv_auto_exposure_and_adaptive_tone.md`](graphics_fnv_auto_exposure_and_adaptive_tone.md) | OMV automatic exposure and display tone mapping | graphics |
| [`graphics_fnv_presets.md`](graphics_fnv_presets.md) | OMV versioned graphics presets | graphics |
| [`graphics_fnv_frame_pacing_chart.md`](graphics_fnv_frame_pacing_chart.md) | OMV frame-pacing diagnostics | graphics |
| [`graphics_fnv_imgui_diagnostics.md`](graphics_fnv_imgui_diagnostics.md) | OMV ImGui diagnostics ownership | graphics |
| [`graphics_fnv_omv_runtime_performance.md`](graphics_fnv_omv_runtime_performance.md) | OMV render-hook performance contract | graphics |
| [`graphics_fnv_omv_dependency_compatibility_plan.md`](graphics_fnv_omv_dependency_compatibility_plan.md) | OMV Mod-Agnostic Graphics Interoperability Plan | plan/research |
| [`graphics_fnv_omv_nvidia_1fps_remediation_plan.md`](graphics_fnv_omv_nvidia_1fps_remediation_plan.md) | OMV NVIDIA One-FPS Remediation Plan | plan/research |
| [`graphics_fnv_omv_nvidia_remediation_implementation.md`](graphics_fnv_omv_nvidia_remediation_implementation.md) | OMV NVIDIA Render-Path Remediation Implementation | graphics |
| [`graphics_fnv_omv_nvidia_close_terrain_shader_fix_plan.md`](graphics_fnv_omv_nvidia_close_terrain_shader_fix_plan.md) | OMV NVIDIA Close-Terrain Shader-Lowering Fix Plan (Superseded Design) | plan/research |
| [`graphics_fnv_omv_nvidia_close_terrain_shader_fix_implementation.md`](graphics_fnv_omv_nvidia_close_terrain_shader_fix_implementation.md) | OMV NVIDIA/AMD Close-Terrain Performance Correction | graphics |
| [`graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md`](graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md) | OMV versus NVR: D3D9 hook flow and the NVIDIA one-FPS failure | plan/research |
| [`graphics_fnv_close_terrain_portable_light_fix_plan.md`](graphics_fnv_close_terrain_portable_light_fix_plan.md) | FNV Close-Terrain Portable Point-Light Static Fix Plan | plan/research |
| [`graphics_fnv_load_transition.md`](graphics_fnv_load_transition.md) | OMV load-transition ownership | graphics |
| [`graphics_fnv_enb_depth_contract.md`](graphics_fnv_enb_depth_contract.md) | ENB reference depth transport | contract |
| [`nvr_d3d9_performance_research.md`](nvr_d3d9_performance_research.md) | NVR D3D9 Performance Research | plan/research |
| [`omv-plan.md`](omv-plan.md) | OMV Research And Implementation Plan | graphics |
| [`graphics_fnv_omv_refactor_plan.md`](graphics_fnv_omv_refactor_plan.md) | OMV code quality refactor plan | plan/research |
| [`graphics_fnv_omv_source_text_test_disposition.md`](graphics_fnv_omv_source_text_test_disposition.md) | OMV source-text test disposition | graphics |
| [`graphics_fnv_nvr_shader_contract_research.md`](graphics_fnv_nvr_shader_contract_research.md) | FNV NVR Shader Contract Research | contract |
| [`graphics_fnv_nvr_shader_portability_matrix.md`](graphics_fnv_nvr_shader_portability_matrix.md) | FNV NVR Shader Portability Matrix | graphics |

## Atom

| Document | Title | Type |
|---|---|---|
| [`atom.md`](atom.md) | Atom gameplay overhaul | atom |
| [`atom_input_wrapper_design.md`](atom_input_wrapper_design.md) | Atom input wrapper design | atom |
| [`atom_first_person_camera_design.md`](atom_first_person_camera_design.md) | Atom first-person camera design | atom |
| [`atom_camera_fov_contract.md`](atom_camera_fov_contract.md) | Atom camera FOV engine contract | contract |
| [`atom_third_person_camera_plan.md`](atom_third_person_camera_plan.md) | Atom third-person camera and 360 movement plan | plan/research |
| [`atom_combat_engine_contract.md`](atom_combat_engine_contract.md) | Atom combat engine contract | contract |
| [`atom_ballistics_core_plan.md`](atom_ballistics_core_plan.md) | Atom ballistics core implementation plan | plan/research |
| [`atom_ballistics_flight_feedback_research.md`](atom_ballistics_flight_feedback_research.md) | Atom Ballistics flight feedback research | plan/research |
| [`atom_ballistics_ricochet_research.md`](atom_ballistics_ricochet_research.md) | Atom Ballistics ricochet engine contract | plan/research |
| [`atom_compatibility_contract.md`](atom_compatibility_contract.md) | Atom mod-compatibility contract | contract |

## Crash and incident records

Dated post-mortems preserve the failing path and accepted containment. They are
not current policy unless a newer contract links to them.

| Document | Title | Type |
|---|---|---|
| [`crash_20260712_engine_fix_plan.md`](crash_20260712_engine_fix_plan.md) | 2026-07-12 crash engine-fix change set | post-mortem |
| [`crash_20260712_mod_independent_revision_plan.md`](crash_20260712_mod_independent_revision_plan.md) | Mod-independent revision plan for the 2026-07-12 crash fixes | post-mortem |
| [`crash_20260717_lowprocess_save_structural_containment_plan.md`](crash_20260717_lowprocess_save_structural_containment_plan.md) | LowProcess generic-location structural containment | post-mortem |
| [`crash_20260802_encounter_zone_form_guard.md`](crash_20260802_encounter_zone_form_guard.md) | Encounter-zone invalid form guard | post-mortem |
| [`crash_20260803_dead_corpse_cell_render_retirement.md`](crash_20260803_dead_corpse_cell_render_retirement.md) | Dead-corpse cell render-list retirement fix | post-mortem |
| [`crash_20260817_controller_sequence_idtag_retirement.md`](crash_20260817_controller_sequence_idtag_retirement.md) | Controller-sequence IDTag retirement containment | post-mortem |
| [`crash_20260819_ai_patrol_form_id_alias.md`](crash_20260819_ai_patrol_form_id_alias.md) | AI patrol retained-owner FormID containment | post-mortem |
| [`crash_20260829_nipixeldata_oom_contract.md`](crash_20260829_nipixeldata_oom_contract.md) | NiPixelData final-OOM containment contract | post-mortem |
| [`crash_20260830_tile_value_contract.md`](crash_20260830_tile_value_contract.md) | Tile value NULL-slot containment | post-mortem |
| [`crash_20261018_occlusion_link_plan.md`](crash_20261018_occlusion_link_plan.md) | Native occlusion linked-plane guard; upstream writer unresolved | plan/research |
| [`crash_20261019_vault108_fade_owner_plan.md`](crash_20261019_vault108_fade_owner_plan.md) | Vault 108 invalid fade-node owner investigation and containment | plan/research |
| [`crash_20261019_teleport_door_null_base_plan.md`](crash_20261019_teleport_door_null_base_plan.md) | Teleport-door null-base crash investigation and fix plan | plan/research |
| [`crash_20261020_corvega_exit_scene_owner_plan.md`](crash_20261020_corvega_exit_scene_owner_plan.md) | Corvega exit invalid scene-owner base-form read and fix plan | plan/research |

## Plans, research, and remaining references

| Document | Title | Type |
|---|---|---|

## Process

| Document | Title | Type |
|---|---|---|
| [`commit-rules.md`](commit-rules.md) | Git Commit Messages Guidelines | reference |

## Maintaining this index

- Add every new `docs/*.md` file here or to the owning category.
- Mark superseded documents at the top of their file and note the replacement here.
- Keep the index factual; status and acceptance belong in the document itself.
