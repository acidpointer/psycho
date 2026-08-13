use super::contract::{
    CASCADE_COUNT, CascadeDirty, CascadeScheduler, CascadeSphereSelection, CasterAdmission,
    CasterPolicy, DeferredReceiverPlan, DirectionalRootSetSignature, HookAction,
    NVR_CASCADE_RESOLUTION, NVR_POINT_DRAW_DISTANCE, NVR_POINT_LIGHT_COUNT,
    NVR_POINT_RADIUS_MULTIPLIER, PointLightCandidate, PointMapCache, PointMapSignature,
    ProducerResourcePlan, SceneKind, ShadowSettings, TransactionState,
    actor_overlay_edge_visibility, cascade_minimum_caster_radius, cascade_sphere_selection,
    composite_shadow_factor, consumer_has_shadow_work, contact_consumer_work,
    depth_sample_is_geometry, directional_actor_root_is_active, directional_caster_work,
    directional_contact_visibility, directional_form_type_is_enabled,
    directional_receiver_position, directional_root_set_dirty, dismember_partition_is_renderable,
    effective_contact_distance, evsm4_moments, evsm4_visibility, interior_shadow_factor,
    local_light_source_guard, nvr_contact_sample_offsets, point_light_distance_fade,
    point_light_influence_is_eligible, practical_cascade_splits, publication_epoch_is_usable,
    retained_cascade_refresh, select_point_lights, select_point_lights_stable,
    shadow_receiver_is_valid, skinned_position_reference, snap_shadow_center,
    source_owned_shadow_radiance, sphere_intersects_cube_face, sphere_intersects_point_light,
    terrain_lod_shadow_z,
};
use super::engine::{
    EngineCallAbi, FNV_EXE_SHA256, GeometryKind, HookSiteContract, NativeLayout,
    ShadowGenerationAbi,
};
use super::math::{
    ActorBounds, ShadowCamera, Sphere, cascade_projection, dynamic_caster_cascade_mask,
    point_cube_views, stabilize_sun_direction,
};
use super::render::{mapped_cull_mode, rebase_bone_rows};

#[test]
fn executable_identity_and_common_hook_topology_are_exact() {
    assert_eq!(
        FNV_EXE_SHA256,
        "42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c"
    );
    assert_eq!(HookSiteContract::COMMON_PREFIX, 0x0087_1290);
    assert_eq!(HookSiteContract::NATIVE_TAIL, 0x0087_1A50);
    assert_eq!(
        HookSiteContract::BRANCH_RETURNS,
        [0x0087_0856, 0x0087_0A79, 0x0087_0C41]
    );
    assert_eq!(
        HookSiteContract::ENTRY_PROLOGUE,
        [0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x9C, 0, 0, 0]
    );
    assert_eq!(
        HookSiteContract::ENTRY_ABI,
        EngineCallAbi::ThiscallReceiverEcx
    );
    assert_eq!(
        HookSiteContract::TAIL_ABI,
        EngineCallAbi::ThiscallReceiverEcx
    );
}

#[test]
fn native_scene_and_geometry_offsets_match_the_proven_32_bit_layouts() {
    assert_eq!(NativeLayout::TES_SINGLETON_PTR, 0x011D_EA10);
    assert_eq!(NativeLayout::PLAYER_SINGLETON_PTR, 0x011D_EA3C);
    assert_eq!(NativeLayout::PLAYER_FIRST_PERSON_NODE, 0x694);
    assert_eq!(NativeLayout::NIDX9_RENDERER_SINGLETON_PTR, 0x011C_73B4);
    assert_eq!(NativeLayout::TES_GRID_CELL_ARRAY, 0x08);
    assert_eq!(NativeLayout::TES_OBJECT_LOD_ROOT, 0x0C);
    assert_eq!(NativeLayout::TES_LAND_LOD_ROOT, 0x10);
    assert_eq!(NativeLayout::TES_DIRECTIONAL_LIGHT, 0x1C);
    assert_eq!(NativeLayout::TES_CURRENT_CELL, 0x34);
    assert_eq!(NativeLayout::CELL_FLAGS, 0x24);
    assert_eq!(NativeLayout::CELL_OBJECT_LIST, 0xAC);
    assert_eq!(NativeLayout::REFERENCE_BASE_FORM, 0x20);
    assert_eq!(NativeLayout::REFERENCE_PARENT_CELL, 0x40);
    assert_eq!(NativeLayout::REFERENCE_RENDER_DATA, 0x64);
    assert_eq!(NativeLayout::REFERENCE_DATA_NODE, 0x14);
    assert_eq!(NativeLayout::TES_FORM_FLAGS, 0x08);
    assert_eq!(NativeLayout::TES_FORM_TYPE, 0x04);
    assert_eq!(NativeLayout::NI_AV_OBJECT_SIZE, 0x9C);
    assert_eq!(NativeLayout::NI_AV_OBJECT_PARENT, 0x18);
    assert_eq!(NativeLayout::NI_AV_OBJECT_WORLD_BOUND, 0x20);
    assert_eq!(NativeLayout::NIDX9_RENDERER_RENDER_STATE, 0x8B8);
    assert_eq!(NativeLayout::NIDX9_RENDER_STATE_CULL_MODE_MAPPING, 0xD4);
    assert_eq!(NativeLayout::NIDX9_RENDER_STATE_LEFT_HANDED, 0xF4);
    assert_eq!(
        NativeLayout::NIDX9_RENDER_STATE_INTERNAL_NORMALIZE_NORMALS,
        0x10F5
    );
    assert_eq!(NativeLayout::NI_AV_OBJECT_FLAGS, 0x30);
    assert_eq!(NativeLayout::NI_AV_OBJECT_WORLD_TRANSFORM, 0x68);
    assert_eq!(NativeLayout::NI_NODE_SIZE, 0xAC);
    assert_eq!(NativeLayout::NI_NODE_CHILDREN, 0x9C);
    assert_eq!(NativeLayout::NI_GEOMETRY_SIZE, 0xC4);
    assert_eq!(NativeLayout::NI_GEOMETRY_PROPERTIES, 0x9C);
    assert_eq!(NativeLayout::NI_GEOMETRY_DATA, 0xB8);
    assert_eq!(NativeLayout::NI_GEOMETRY_SKIN, 0xBC);
    assert_eq!(NativeLayout::NI_GEOMETRY_SHADER, 0xC0);
    assert_eq!(NativeLayout::NI_PROPERTY_ALPHA, 0x9C);
    assert_eq!(NativeLayout::NI_PROPERTY_MATERIAL, 0xA4);
    assert_eq!(NativeLayout::NI_PROPERTY_SHADE, 0xA8);
    assert_eq!(NativeLayout::NI_PROPERTY_STENCIL, 0xAC);
    assert_eq!(NativeLayout::NI_GEOMETRY_DATA_SIZE, 0x40);
    assert_eq!(NativeLayout::NI_GEOMETRY_DATA_DIRTY_FLAGS, 0x0E);
    assert_eq!(NativeLayout::NI_GEOMETRY_DATA_BUFFER, 0x34);
    assert_eq!(NativeLayout::NI_GEOMETRY_BUFFER_SIZE, 0x54);
    assert_eq!(NativeLayout::NI_SKIN_INSTANCE_SIZE, 0x34);
    assert_eq!(NativeLayout::NI_SKIN_PARTITION, 0x0C);
    assert_eq!(NativeLayout::NI_SKIN_FRAME_ID, 0x18);
    assert_eq!(NativeLayout::NI_SKIN_BONES, 0x1C);
    assert_eq!(NativeLayout::NI_SKIN_BONE_REGISTERS, 0x20);
    assert_eq!(NativeLayout::NI_SKIN_BONE_SIZE, 0x24);
    assert_eq!(NativeLayout::NI_SKIN_BONE_MATRICES, 0x28);
    assert_eq!(NativeLayout::NI_SKIN_TO_WORLD, 0x2C);
    assert_eq!(NativeLayout::NI_SKIN_PARTITION_SIZE, 0x10);
    assert_eq!(NativeLayout::NI_SKIN_PARTITION_ENTRY_SIZE, 0x2C);
    assert_eq!(NativeLayout::NI_POINT_LIGHT_SIZE, 0xFC);
    assert_eq!(NativeLayout::NI_POINT_LIGHT_CASTS_SHADOWS, 0x9E);
    assert_eq!(NativeLayout::NI_POINT_LIGHT_SPECULAR, 0xE0);
}

#[test]
fn stencil_culling_uses_the_engine_handedness_mapping() {
    let mapping = [[3, 2], [3, 2], [2, 3], [1, 1]];
    assert_eq!(mapped_cull_mode(1, false, mapping), Some(3));
    assert_eq!(mapped_cull_mode(1, true, mapping), Some(2));
    assert_eq!(mapped_cull_mode(2, false, mapping), Some(2));
    assert_eq!(mapped_cull_mode(3, true, mapping), Some(1));
    assert_eq!(mapped_cull_mode(4, false, mapping), None);
}

#[test]
fn actor_skin_reference_matches_fnv_d3dcolor_index_and_residual_weight_order() {
    let mut bones = [[[0.0; 4]; 3]; 4];
    for (index, bone) in bones.iter_mut().enumerate() {
        bone[0] = [1.0, 0.0, 0.0, index as f32 * 10.0];
        bone[1] = [0.0, 1.0, 0.0, 0.0];
        bone[2] = [0.0, 0.0, 1.0, 0.0];
    }
    let skinned =
        skinned_position_reference([1.0, 2.0, 3.0], [0, 1, 2, 3], [0.1, 0.2, 0.3], &bones)
            .expect("valid four-bone actor vertex");
    assert!((skinned[0] - 17.0).abs() < 0.0001);
    assert_eq!(skinned[1], 2.0);
    assert_eq!(skinned[2], 3.0);
    assert!(skinned_position_reference([0.0; 3], [0; 4], [0.5; 3], &bones).is_none());
}

#[test]
fn actor_bone_upload_rebases_the_engine_camera_origin_to_the_shadow_camera() {
    let rows = [
        [1.0, 0.0, 0.0, 25.0],
        [0.0, 1.0, 0.0, -10.0],
        [0.0, 0.0, 1.0, 3.0],
    ];
    let rebased = rebase_bone_rows(rows, [100.0, 200.0, 300.0], [90.0, 230.0, 250.0])
        .expect("finite camera-origin rebase");
    assert_eq!(rebased[0][3], 35.0);
    assert_eq!(rebased[1][3], -40.0);
    assert_eq!(rebased[2][3], 53.0);
    assert!(rebase_bone_rows(rows, [f32::NAN; 3], [0.0; 3]).is_none());
}

#[test]
fn dismembered_actor_partitions_use_the_complete_fnv_extension_layout() {
    assert_eq!(NativeLayout::DISMEMBER_PARTITION_COUNT, 0x34);
    assert_eq!(NativeLayout::DISMEMBER_PARTITIONS, 0x38);
    assert_eq!(NativeLayout::DISMEMBER_RENDERABLE, 0x3C);
    assert!(dismember_partition_is_renderable(true, Some(true)));
    assert!(!dismember_partition_is_renderable(true, Some(false)));
    assert!(
        dismember_partition_is_renderable(true, None),
        "missing optional extension metadata must not erase an engine-valid body partition"
    );
    assert!(!dismember_partition_is_renderable(false, Some(true)));
}

#[test]
fn native_material_alpha_and_point_light_admission_match_modern_nvr() {
    assert_eq!(NativeLayout::NI_MATERIAL_ALPHA, 0x3C);
    assert!(point_light_influence_is_eligible(
        [0.0, 0.0, 100.0],
        256.0,
        [0.0, 0.0, 1.0],
        8_000.0,
    ));
}

#[test]
fn consumer_retains_a_complete_publication_for_the_next_scene_pre_epoch() {
    assert!(publication_epoch_is_usable(41, 41));
    assert!(
        publication_epoch_is_usable(41, 42),
        "a producer after scene-pre must remain consumable at the next scene-pre boundary"
    );
    assert!(publication_epoch_is_usable(u32::MAX, 0));
    assert!(!publication_epoch_is_usable(41, 43));
    assert!(!publication_epoch_is_usable(42, 41));
}

#[test]
fn empty_interior_publication_performs_no_depth_or_color_transaction() {
    assert!(!consumer_has_shadow_work(false, 0));
    assert!(consumer_has_shadow_work(false, 1));
    assert!(consumer_has_shadow_work(true, 0));
}

#[test]
fn expensive_receiver_visibility_is_quarter_resolution_and_never_temporal() {
    let plan = DeferredReceiverPlan::new(3_440, 1_440).expect("ultrawide receiver plan");
    let output_pixels = 3_440_u64 * 1_440;

    assert_eq!(plan.width, 1_720);
    assert_eq!(plan.height, 720);
    assert_eq!(plan.directional_pixels, output_pixels / 4);
    assert_eq!(plan.point_pixels, output_pixels / 4);
    assert_eq!(
        plan.history_pixels, 0,
        "shadow masks must not trail the camera"
    );
    assert_eq!(plan.full_resolution_shadow_map_samples, 0);
    assert!(
        plan.directional_pixels * 3 < output_pixels,
        "deferred visibility did not remove most full-resolution EVSM work"
    );
}

#[test]
fn native_shadow_scene_light_layout_and_geometry_list_lifetime_are_explicit() {
    assert_eq!(NativeLayout::SHADOW_SCENE_LIGHT_GEOMETRY_LIST, 0xE0);
    assert_eq!(NativeLayout::SHADOW_SCENE_LIGHT_POINT, 0xF4);
    assert_eq!(NativeLayout::SHADOW_SCENE_LIGHT_AMBIENT, 0xF5);
    assert_eq!(NativeLayout::SHADOW_SCENE_LIGHT_SOURCE, 0xF8);
    assert_eq!(NativeLayout::SHADOW_SCENE_LIGHT_RENDER_TARGET, 0x10C);
    assert_eq!(NativeLayout::SHADOW_SCENE_LIGHT_ENABLED, 0x110);
    assert_eq!(NativeLayout::SHADOW_SCENE_LIGHT_SIZE, 0x250);
    assert!(NativeLayout::SHADOW_GEOMETRY_LIST_VALID_ONLY_DURING_COMMON_PREFIX_EPOCH);
}

#[test]
fn generation_draw_calls_and_register_ranges_match_nvr_abi() {
    assert_eq!(GeometryKind::TriStrips.render_address(), 0x00E7_4840);
    assert_eq!(GeometryKind::TriShape.render_address(), 0x00E7_45A0);
    assert_eq!(GeometryKind::Skinned.render_address(), 0x00E6_D310);
    assert_eq!(ShadowGenerationAbi::CALCULATE_BONE_MATRICES, 0x00E6_FE30);
    assert_eq!(ShadowGenerationAbi::WORLD_ROWS, 0..4);
    assert_eq!(ShadowGenerationAbi::VIEW_PROJECTION_ROWS, 4..8);
    assert_eq!(ShadowGenerationAbi::GEOMETRY_DATA, 8);
    assert_eq!(ShadowGenerationAbi::BONE_ROWS, 9..63);
    assert_eq!(ShadowGenerationAbi::SPEEDTREE_ROWS, 63..140);
    assert_eq!(ShadowGenerationAbi::TERRAIN_LOD_ROWS, 140..146);
    assert_eq!(ShadowGenerationAbi::DIFFUSE_SAMPLER, 0);
}

#[test]
fn one_effect_keeps_interior_and_exterior_admission_independent() {
    let exterior_only = ShadowSettings {
        enabled: true,
        exterior_enabled: true,
        interior_enabled: false,
    };
    assert!(exterior_only.enabled_for(SceneKind::Exterior));
    assert!(exterior_only.enabled_for(SceneKind::BehavesLikeExterior));
    assert!(!exterior_only.enabled_for(SceneKind::Interior));

    let interior_only = ShadowSettings {
        enabled: true,
        exterior_enabled: false,
        interior_enabled: true,
    };
    assert!(!interior_only.enabled_for(SceneKind::Exterior));
    assert!(interior_only.enabled_for(SceneKind::Interior));
    assert!(
        !ShadowSettings {
            enabled: false,
            ..interior_only
        }
        .enabled_for(SceneKind::Interior)
    );
}

#[test]
fn exterior_visibility_and_interior_local_light_deficit_have_distinct_semantics() {
    let darkness = 0.75;
    let exterior = composite_shadow_factor(SceneKind::Exterior, 0.8, 0.4, darkness)
        .expect("finite exterior factor");
    assert!((exterior - 0.55).abs() < 0.000_001);
    assert_eq!(interior_shadow_factor(0.0, 0.0, darkness), Some(1.0));
    assert_eq!(interior_shadow_factor(0.75, 0.75, darkness), Some(1.0));
    assert_eq!(interior_shadow_factor(0.0, 1.0, darkness), Some(0.25));
    assert_eq!(interior_shadow_factor(0.25, 0.75, darkness), Some(0.625));
    assert!(composite_shadow_factor(SceneKind::Interior, 0.0, 0.0, darkness).is_none());
    assert!(interior_shadow_factor(f32::NAN, 1.0, darkness).is_none());
    assert!(composite_shadow_factor(SceneKind::Exterior, f32::NAN, 1.0, darkness).is_none());
}

#[test]
fn common_hook_has_exactly_one_prefix_or_one_replacement_tail_path() {
    let settings = ShadowSettings::default();
    let native = settings.hook_action(SceneKind::Exterior, false, true);
    assert_eq!(native, HookAction::NativePrefix);
    assert_eq!(native.native_prefix_calls(), 1);
    assert_eq!(native.explicit_tail_calls(), 0);

    let replacement = settings.hook_action(SceneKind::Exterior, true, true);
    assert_eq!(replacement, HookAction::ReplacementThenTail);
    assert_eq!(replacement.native_prefix_calls(), 0);
    assert_eq!(replacement.explicit_tail_calls(), 1);

    let disabled_scene = ShadowSettings {
        interior_enabled: false,
        ..settings
    }
    .hook_action(SceneKind::Interior, true, true);
    assert_eq!(disabled_scene, HookAction::TailOnly);
    assert_eq!(disabled_scene.native_prefix_calls(), 0);
    assert_eq!(disabled_scene.explicit_tail_calls(), 1);
    let disabled_while_preparing = ShadowSettings {
        interior_enabled: false,
        ..settings
    }
    .hook_action(SceneKind::Interior, true, false);
    assert_eq!(disabled_while_preparing, HookAction::TailOnly);

    let unavailable = settings.hook_action(SceneKind::Exterior, true, false);
    assert_eq!(unavailable, HookAction::NativePrefix);
    for action in [
        native,
        replacement,
        disabled_scene,
        disabled_while_preparing,
        unavailable,
    ] {
        assert_eq!(
            action.native_prefix_calls() + action.explicit_tail_calls(),
            1,
            "the native tail is already included by the native prefix"
        );
    }
}

#[test]
fn stable_main_view_refreshes_only_invalid_cascades() {
    let mut scheduler = CascadeScheduler::default();
    let first = scheduler.plan_at_millis(CascadeDirty::all(), 0);
    assert_eq!(first.render, [true; CASCADE_COUNT]);
    scheduler.commit(first);

    for now_millis in [16, 32, 33, 1_000] {
        let stable = scheduler.plan_at_millis(CascadeDirty::none(), now_millis);
        assert_eq!(stable.render, [false; CASCADE_COUNT]);
        scheduler.commit(stable);
    }

    let near_only = scheduler.plan_at_millis(CascadeDirty::from_mask(1), 100);
    assert_eq!(near_only.render, [true, false, false, false]);
    scheduler.commit(near_only);
    let lod_only = scheduler.plan_at_millis(CascadeDirty::from_mask(1 << 3), 101);
    assert_eq!(lod_only.render, [false, false, false, true]);
}

#[test]
fn late_presentations_do_not_create_wall_clock_shadow_work() {
    let mut scheduler = CascadeScheduler::default();
    let initial = scheduler.plan_at_millis(CascadeDirty::all(), 0);
    scheduler.commit(initial);

    let late = scheduler.plan_at_millis(CascadeDirty::none(), 70);
    assert_eq!(late.render, [false; CASCADE_COUNT]);
    scheduler.commit(late);
    let recovered = scheduler.plan_at_millis(CascadeDirty::from_mask(0b0100), 99);
    assert_eq!(recovered.render, [false, false, true, false]);
}

#[test]
fn directional_work_scales_with_invalidations_not_elapsed_time() {
    let mut scheduler = CascadeScheduler::default();
    let initial = scheduler.plan_at_millis(CascadeDirty::all(), 0);
    scheduler.commit(initial);
    let mut stationary_maps = 0;
    let mut animated_near_static_maps = 0;
    let mut animated_near_overlays = 0;
    for frame in 1..=120 {
        stationary_maps += scheduler
            .plan_at_millis(CascadeDirty::none(), frame * 8)
            .render
            .into_iter()
            .filter(|render| *render)
            .count();
        let work = directional_caster_work(1, 1, true);
        let near =
            scheduler.plan_at_millis(CascadeDirty::from_mask(work.static_map_mask), frame * 8);
        animated_near_static_maps += near.render.into_iter().filter(|render| *render).count();
        animated_near_overlays += usize::from(work.actor_overlay_mask & 1 != 0);
        scheduler.commit(near);
    }
    assert_eq!(stationary_maps, 0);
    assert_eq!(animated_near_static_maps, 0);
    assert_eq!(animated_near_overlays, 120);
}

#[test]
fn cascade_caster_threshold_matches_nvr_pixel_coverage_policy() {
    let radius = 2_048.0;
    assert_eq!(
        cascade_minimum_caster_radius(0, radius, NVR_CASCADE_RESOLUTION),
        Some(1.0)
    );
    assert_eq!(
        cascade_minimum_caster_radius(1, radius, NVR_CASCADE_RESOLUTION),
        Some(1.0)
    );
    assert_eq!(
        cascade_minimum_caster_radius(2, radius, NVR_CASCADE_RESOLUTION),
        Some(10.0)
    );
    assert_eq!(
        cascade_minimum_caster_radius(3, radius, NVR_CASCADE_RESOLUTION),
        Some(10.0)
    );
    assert!(cascade_minimum_caster_radius(4, radius, NVR_CASCADE_RESOLUTION).is_none());
    assert!(cascade_minimum_caster_radius(0, f32::NAN, NVR_CASCADE_RESOLUTION).is_none());
    assert!(cascade_minimum_caster_radius(0, radius, 0).is_none());
}

#[test]
fn directional_form_profiles_match_modern_nvr_defaults() {
    const ACTIVATOR: u8 = 0x15;
    const APPARATUS_COMPATIBILITY: u8 = 0xFE;
    const BOOK: u8 = 0x19;
    const CONTAINER: u8 = 0x1B;
    const DOOR: u8 = 0x1C;
    const MISC: u8 = 0x1F;
    const STATIC: u8 = 0x20;
    const STATIC_COLLECTION: u8 = 0x21;
    const MOVABLE_STATIC: u8 = 0x22;
    const TREE: u8 = 0x25;
    const FURNITURE: u8 = 0x27;
    const NPC: u8 = 0x2A;
    const CREATURE: u8 = 0x2B;
    const LEVELED_CREATURE: u8 = 0x2C;
    const LAND: u8 = 0x42;

    let exact_profiles = [
        (ACTIVATOR, [true, true, true, false]),
        (APPARATUS_COMPATIBILITY, [false; CASCADE_COUNT]),
        (BOOK, [true, true, false, false]),
        (CONTAINER, [true, true, true, false]),
        (DOOR, [true; CASCADE_COUNT]),
        (MISC, [true; CASCADE_COUNT]),
        (STATIC, [true; CASCADE_COUNT]),
        (STATIC_COLLECTION, [true; CASCADE_COUNT]),
        (MOVABLE_STATIC, [true; CASCADE_COUNT]),
        (TREE, [true; CASCADE_COUNT]),
        (FURNITURE, [true, true, true, false]),
        (NPC, [true, true, true, false]),
        (CREATURE, [true, true, true, false]),
        (LEVELED_CREATURE, [true, true, true, false]),
        (LAND, [false; CASCADE_COUNT]),
    ];
    for (form, expected) in exact_profiles {
        for (cascade, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                directional_form_type_is_enabled(cascade, form),
                expected,
                "form {form:#04x}, cascade {cascade}"
            );
        }
    }
    assert!(!directional_form_type_is_enabled(CASCADE_COUNT, STATIC));
}

#[test]
fn contact_depth_rejects_clear_endpoints_and_non_finite_samples() {
    let epsilon = 1.0 / 65_536.0;
    assert!(!depth_sample_is_geometry(0.0, epsilon));
    assert!(!depth_sample_is_geometry(1.0, epsilon));
    assert!(!depth_sample_is_geometry(f32::NAN, epsilon));
    assert!(depth_sample_is_geometry(0.25, epsilon));
    assert!(depth_sample_is_geometry(0.75, epsilon));
}

#[test]
fn contact_distance_reaches_camera_depth_independently_of_cascade_partition() {
    assert_eq!(
        effective_contact_distance(180_000.0, 28_000.0),
        Some(28_000.0)
    );
    assert_eq!(effective_contact_distance(2_000.0, 28_000.0), Some(2_000.0));
    assert!(effective_contact_distance(f32::NAN, 28_000.0).is_none());
    assert!(effective_contact_distance(2_000.0, 0.0).is_none());
}

#[test]
fn sun_stabilization_quantizes_and_smooths_only_small_motion() {
    fn direction(yaw_degrees: f32, pitch_degrees: f32) -> [f32; 3] {
        let yaw = yaw_degrees.to_radians();
        let pitch = pitch_degrees.to_radians();
        [
            pitch.cos() * yaw.cos(),
            pitch.cos() * yaw.sin(),
            pitch.sin(),
        ]
    }

    let quantized = stabilize_sun_direction(None, direction(12.49, 7.12))
        .expect("a finite sky direction is valid");
    let expected = direction(12.0, 7.0);
    assert!(
        quantized
            .into_iter()
            .zip(expected)
            .all(|(actual, expected)| (actual - expected).abs() < 0.000_001)
    );

    let previous = direction(0.0, 0.0);
    let smoothed = stabilize_sun_direction(Some(previous), direction(4.0, 0.0))
        .expect("small changes are smoothed");
    let smoothed_yaw = smoothed[1].atan2(smoothed[0]).to_degrees();
    assert!((smoothed_yaw - 0.4).abs() < 0.001);

    let jumped = stabilize_sun_direction(Some(previous), direction(10.0, 0.0))
        .expect("large changes remain valid");
    let jumped_yaw = jumped[1].atan2(jumped[0]).to_degrees();
    assert!((jumped_yaw - 10.0).abs() < 0.000_01);
    assert!(stabilize_sun_direction(None, [f32::NAN, 0.0, 0.0]).is_none());
}

#[test]
fn practical_splits_are_contiguous_monotonic_and_match_nvr_quality_defaults() {
    let splits =
        practical_cascade_splits(5.0, 28_000.0, 6_000.0, 0.9).expect("valid Fallout camera");
    assert_eq!(splits[0].near, 15.0);
    assert!((splits[CASCADE_COUNT - 1].far - 6_005.0).abs() < 0.01);
    for (index, split) in splits.iter().enumerate() {
        assert!(split.near.is_finite() && split.far.is_finite());
        assert!(split.far > split.near);
        if index > 0 {
            assert!((split.near - splits[index - 1].far).abs() < 0.001);
        }
    }
    assert!(practical_cascade_splits(0.0, f32::NAN, 6_000.0, 0.9).is_none());
    assert!(practical_cascade_splits(20.0, 10.0, 6_000.0, 0.9).is_none());
}

#[test]
fn every_shadow_distance_uses_nvrs_exact_practical_partition() {
    let short = practical_cascade_splits(5.0, 28_000.0, 1_000.0, 0.9).expect("short shadow range");
    let default =
        practical_cascade_splits(5.0, 28_000.0, 6_000.0, 0.9).expect("default shadow range");
    let extended =
        practical_cascade_splits(5.0, 28_000.0, 20_000.0, 0.9).expect("extended shadow range");

    assert!(short[0].far < default[0].far);
    assert!(
        extended[0].far > default[0].far,
        "NVR derives every split from the configured range; a private near anchor creates non-NVR cascade transitions"
    );
    assert!(
        extended[2].far > 4_000.0,
        "the actor-capable far cascade must expand instead of stranding all distant actors in the LOD-only profile"
    );
    assert!((short[3].far - 1_005.0).abs() < 0.01);
    assert!((extended[3].far - 20_005.0).abs() < 0.01);
}

#[test]
fn receiver_selection_chooses_the_smallest_current_slice_and_blends_outward() {
    let spheres = [
        [100.0, 0.0, 0.0, 100.0],
        [300.0, 0.0, 0.0, 240.0],
        [900.0, 0.0, 0.0, 700.0],
        [2_500.0, 0.0, 0.0, 2_000.0],
    ];
    assert_eq!(
        cascade_sphere_selection([50.0, 0.0, 0.0], spheres),
        Some(CascadeSphereSelection {
            cascade: 0,
            next: None,
            blend: 0.0,
        })
    );
    let overlap = cascade_sphere_selection([195.0, 0.0, 0.0], spheres)
        .expect("receiver in near-to-middle blend shell");
    assert_eq!(overlap.cascade, 0);
    assert_eq!(overlap.next, Some(1));
    assert!((overlap.blend - 0.5).abs() < 0.001);
    assert_eq!(
        cascade_sphere_selection([420.0, 120.0, 0.0], spheres)
            .expect("off-axis receiver belongs to middle sphere")
            .cascade,
        1
    );
    assert!(cascade_sphere_selection([10_000.0, 0.0, 0.0], spheres).is_none());
}

#[test]
fn contact_work_is_half_resolution_and_branch_lazy() {
    let width = 3_440_u64;
    let height = 1_440_u64;
    let full = width * height;
    let half = width.div_ceil(2) * height.div_ceil(2);
    assert_eq!(half * 4, full);
    let work = contact_consumer_work();
    assert_eq!(work.passes, 2);
    assert!(half * u64::from(work.passes) < full);
}

#[test]
fn final_shadow_composition_uses_distinct_directional_and_local_identities() {
    let source = [0.8, 0.6, 0.4];
    let clear = source_owned_shadow_radiance(source, false, 0.0, 1.0, [1.0; 3], [1.0; 3], 1.0)
        .expect("finite clear pixel");
    assert_eq!(clear, source);
    let receiver = source_owned_shadow_radiance(source, true, 0.5, 0.8, [0.1; 3], [0.1; 3], 0.5)
        .expect("finite receiver");
    // The analytic local estimate would produce [0.47, 0.35, 0.23]. That is
    // below the native surface's directional-only lower bound and therefore
    // owns ambient energy it cannot identify.
    assert!((receiver[0] - 0.48).abs() < 1.0e-6);
    assert!((receiver[1] - 0.36).abs() < 1.0e-6);
    assert!((receiver[2] - 0.24).abs() < 1.0e-6);
}

#[test]
fn interior_composition_subtracts_only_rgb_energy_proven_occluded() {
    let source = [0.8, 0.7, 0.6];
    let result = source_owned_shadow_radiance(
        source,
        true,
        1.0,
        0.0,
        [0.4, 0.2, 0.0],
        [0.4, 0.2, 0.0],
        0.5,
    )
    .expect("finite local-light receiver");
    assert_eq!(result, [0.6, 0.59999996, 0.6]);
    let emitter = [3.0, 2.0, 1.2];
    assert_eq!(
        source_owned_shadow_radiance(emitter, true, 0.0, 1.0, [1.0; 3], [1.0; 3], 1.0,),
        Some(emitter)
    );
}

#[test]
fn cascade_center_is_stable_for_sub_texel_camera_motion() {
    let radius = 512.0;
    let texel = radius * 2.0 / NVR_CASCADE_RESOLUTION as f32;
    let base = snap_shadow_center([10.21, -4.13, 80.0], radius, NVR_CASCADE_RESOLUTION)
        .expect("valid cascade");
    let moved = snap_shadow_center(
        [10.21 + texel * 0.24, -4.13 - texel * 0.24, 80.0],
        radius,
        NVR_CASCADE_RESOLUTION,
    )
    .expect("valid moved cascade");
    assert_eq!(base, moved);
    assert!(snap_shadow_center([0.0; 3], 0.0, NVR_CASCADE_RESOLUTION).is_none());
}

#[test]
fn equal_distance_point_lights_are_retained_with_a_stable_total_order() {
    let mut candidates = [PointLightCandidate::EMPTY; 16];
    for (index, candidate) in candidates.iter_mut().enumerate() {
        *candidate = PointLightCandidate {
            identity: 100 + index as u32,
            distance_squared: if index < 14 { 25.0 } else { 100.0 },
            radius: 512.0,
        };
    }
    candidates.swap(2, 11);
    let selected = select_point_lights(&candidates);
    assert_eq!(selected.len(), NVR_POINT_LIGHT_COUNT);
    assert_eq!(
        selected.identities(),
        [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111]
    );
    assert_eq!(selected.produced_count(), selected.consumer_count());
}

#[test]
fn point_admission_ignores_the_broken_native_flag_and_preserves_cube_overflow_energy() {
    let mut candidates = Vec::new();
    for identity in 1..=14 {
        candidates.push(PointLightCandidate {
            identity,
            distance_squared: identity as f32,
            radius: 512.0,
        });
    }
    candidates.extend([
        PointLightCandidate {
            identity: 101,
            distance_squared: 0.5,
            radius: 512.0,
        },
        PointLightCandidate {
            identity: 102,
            distance_squared: 13.5,
            radius: 512.0,
        },
    ]);

    let selected = select_point_lights(&candidates);
    assert_eq!(
        selected.identities(),
        [101, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    );
    assert_eq!(selected.unshadowed_len(), 4);
    assert_eq!(selected.unshadowed_identities()[..4], [12, 13, 102, 14]);
    assert_eq!(selected.produced_count(), 12);
    assert_eq!(selected.consumer_count(), 12);
}

#[test]
fn point_caster_bounds_are_tested_against_the_light_volume() {
    assert!(sphere_intersects_point_light(
        [10.0, 0.0, 0.0],
        4.0,
        [0.0; 3],
        6.0
    ));
    assert!(!sphere_intersects_point_light(
        [10.1, 0.0, 0.0],
        4.0,
        [0.0; 3],
        6.0
    ));
    assert!(!sphere_intersects_point_light(
        [f32::NAN, 0.0, 0.0],
        1.0,
        [0.0; 3],
        4.0
    ));
    assert!(!sphere_intersects_point_light(
        [0.0; 3], -1.0, [0.0; 3], 4.0
    ));
}

#[test]
fn point_caster_bounds_are_conservatively_culled_per_cube_face() {
    assert!(sphere_intersects_cube_face([10.0, 0.0, 0.0], 0.0, 0));
    assert!(!sphere_intersects_cube_face([10.0, 0.0, 0.0], 0.0, 1));
    assert!(sphere_intersects_cube_face([10.0, 10.0, 0.0], 0.0, 0));
    assert!(sphere_intersects_cube_face([10.0, 10.0, 0.0], 0.0, 2));
    assert!(!sphere_intersects_cube_face([10.0, 10.1, 0.0], 0.0, 0));
    assert!(sphere_intersects_cube_face([0.0, 0.0, -10.0], 0.0, 4));
    assert!(sphere_intersects_cube_face([0.0, 0.0, 10.0], 0.0, 5));
    // A sphere crossing the light origin belongs to every touched face.
    for face in 0..6 {
        assert!(sphere_intersects_cube_face([0.0; 3], 1.0, face));
    }
    assert!(!sphere_intersects_cube_face([f32::NAN, 0.0, 0.0], 1.0, 0));
    assert!(!sphere_intersects_cube_face([1.0, 0.0, 0.0], 1.0, 6));
}

#[test]
fn point_light_discovery_preserves_nvr_radius_and_distance_without_view_culling() {
    assert_eq!(NVR_POINT_RADIUS_MULTIPLIER, 1.5);
    assert_eq!(NVR_POINT_DRAW_DISTANCE, 8_000.0);
    let forward = [0.0, 1.0, 0.0];
    assert!(point_light_influence_is_eligible(
        [0.0, 100.0, 0.0],
        512.0,
        forward,
        8_000.0,
    ));
    assert!(point_light_influence_is_eligible(
        [0.0, -100.0, 0.0],
        512.0,
        forward,
        8_000.0,
    )); // the camera lies inside this light
    assert!(point_light_influence_is_eligible(
        [0.0, -1_000.0, 0.0],
        100.0,
        forward,
        8_000.0,
    )); // retained cubes must not inherit NVR's frame-local forward shortcut
    assert!(point_light_influence_is_eligible(
        [0.0, 7_700.0, 0.0],
        512.0,
        forward,
        8_000.0,
    )); // an influence volume overlapping the draw boundary remains relevant
    assert!(point_light_influence_is_eligible(
        [0.0, 100.0, 0.0],
        9_000.0,
        forward,
        8_000.0,
    )); // a containing room light is not rejected merely because it is large
    assert!(!point_light_influence_is_eligible(
        [0.0, 100.0, 0.0],
        10.0,
        forward,
        8_000.0,
    ));
}

#[test]
fn point_light_shadow_admission_is_invariant_under_camera_rotation() {
    let position = [0.0, 1_000.0, 0.0];
    let radius = 256.0;
    let facing = point_light_influence_is_eligible(
        position,
        radius,
        [0.0, 1.0, 0.0],
        NVR_POINT_DRAW_DISTANCE,
    );
    let turned_away = point_light_influence_is_eligible(
        position,
        radius,
        [0.0, -1.0, 0.0],
        NVR_POINT_DRAW_DISTANCE,
    );
    assert_eq!(
        facing, turned_away,
        "a camera yaw changed the selected room-light set and invalidated whole shadow groups"
    );
    assert!(facing, "the finite nearby influence must remain eligible");
}

#[test]
fn retained_shadow_maps_do_not_capture_frame_local_application_culling() {
    let candidate = CasterAdmission {
        app_culled: true,
        ..CasterAdmission::default()
    };
    assert!(
        CasterPolicy::quality_default()
            .admit_retained(candidate)
            .is_ok(),
        "a retained omnidirectional/static map omitted casters based on an unrelated camera view"
    );
}

#[test]
fn point_light_capacity_boundary_has_bounded_selection_hysteresis() {
    let mut initial = Vec::new();
    for identity in 1..=NVR_POINT_LIGHT_COUNT as u32 {
        initial.push(PointLightCandidate {
            identity,
            distance_squared: (identity as f32 * 10.0).powi(2),
            radius: 256.0,
        });
    }
    initial.push(PointLightCandidate {
        identity: 99,
        distance_squared: 120.25_f32.powi(2),
        radius: 256.0,
    });
    let previous = select_point_lights_stable(&initial, [0; NVR_POINT_LIGHT_COUNT]).identities();
    assert_eq!(previous[NVR_POINT_LIGHT_COUNT - 1], 12);

    let mut moved = initial;
    moved[NVR_POINT_LIGHT_COUNT - 1].distance_squared = 120.2_f32.powi(2);
    moved[NVR_POINT_LIGHT_COUNT].distance_squared = 120.0_f32.powi(2);
    let current = select_point_lights_stable(&moved, previous).identities();
    assert!(
        current.contains(&12),
        "a sub-unit move exchanged the twelfth cube owner and forced a six-face light blink"
    );
}

#[test]
fn point_cube_cache_pairs_metadata_and_refreshes_only_changed_lights() {
    let mut current = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    for (index, light) in current.iter_mut().enumerate() {
        *light = PointMapSignature {
            identity: index + 1,
            position: [index as f32 * 32.0, 0.0, 0.0],
            radius: 512.0,
            caster_signature: 0x1000 + index as u64,
        };
    }
    let mut dynamic_faces = [0_u8; NVR_POINT_LIGHT_COUNT];
    let first = PointMapCache::default().plan(current, dynamic_faces, NVR_POINT_LIGHT_COUNT);
    assert_eq!(first.render_faces, [0x3f; NVR_POINT_LIGHT_COUNT]);
    assert_eq!(first.static_faces, [0x3f; NVR_POINT_LIGHT_COUNT]);

    let stable = first
        .next
        .plan(current, dynamic_faces, NVR_POINT_LIGHT_COUNT);
    assert_eq!(stable.render_faces, [0; NVR_POINT_LIGHT_COUNT]);
    assert_eq!(stable.static_faces, [0; NVR_POINT_LIGHT_COUNT]);

    let periodic = stable
        .next
        .plan(current, dynamic_faces, NVR_POINT_LIGHT_COUNT);
    assert_eq!(
        periodic.render_faces, [0; NVR_POINT_LIGHT_COUNT],
        "an unchanged light/map pair must remain immutable; a timer-driven cube carousel makes static interior shadows step at a cadence unrelated to presentation"
    );

    let mut sub_threshold = current;
    sub_threshold[4].position[0] += 0.125;
    let retained = periodic
        .next
        .plan(sub_threshold, dynamic_faces, NVR_POINT_LIGHT_COUNT);
    assert_eq!(retained.render_faces[4], 0);
    assert_eq!(retained.published[4], current[4]);

    let mut moved = sub_threshold;
    moved[4].position[0] += 0.25;
    let refreshed = retained
        .next
        .plan(moved, dynamic_faces, NVR_POINT_LIGHT_COUNT);
    assert_eq!(refreshed.render_faces[4], 0x3f);
    assert_eq!(refreshed.static_faces[4], 0x3f);
    assert_eq!(refreshed.published[4], moved[4]);

    dynamic_faces[2] = 1 << 4;
    let animated = refreshed
        .next
        .plan(moved, dynamic_faces, NVR_POINT_LIGHT_COUNT);
    assert!(
        animated.render_faces[2] == 1 << 4,
        "a stationary point light containing a skinned actor must refresh at presentation cadence; otherwise the body shadow freezes or steps independently of animation"
    );
    assert_eq!(animated.static_faces[2], 0);
    assert_eq!(animated.dynamic_draw_faces[2], 1 << 4);
    assert!(
        animated.render_faces[1] == 0,
        "dynamic actor correction must not invalidate unrelated cached static cubes"
    );

    dynamic_faces[2] = 1 << 1;
    let crossed = animated
        .next
        .plan(moved, dynamic_faces, NVR_POINT_LIGHT_COUNT);
    assert_eq!(
        crossed.render_faces[2],
        (1 << 4) | (1 << 1),
        "both sides of a cube-face crossing must refresh or the old side retains an actor ghost"
    );
    assert_eq!(crossed.static_faces[2], 0);
    assert_eq!(crossed.dynamic_draw_faces[2], 1 << 1);

    let departed = crossed
        .next
        .plan(moved, [0; NVR_POINT_LIGHT_COUNT], NVR_POINT_LIGHT_COUNT);
    assert_eq!(
        departed.render_faces[2],
        1 << 1,
        "the actor's final occupied face must be restored from immutable geometry"
    );
    assert_eq!(departed.static_faces[2], 0);
    assert_eq!(
        departed.dynamic_draw_faces[2], 0,
        "an abandoned face must receive the static copy but no actor submission"
    );
}

#[test]
fn point_cube_cache_invalidates_changed_static_caster_geometry() {
    let mut signatures = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    signatures[0] = PointMapSignature {
        identity: 0x1234,
        position: [0.0; 3],
        radius: 512.0,
        caster_signature: 0xAABB,
    };
    let initial = PointMapCache::default().plan(signatures, [0; NVR_POINT_LIGHT_COUNT], 1);
    let stable = initial.next.plan(signatures, [0; NVR_POINT_LIGHT_COUNT], 1);
    assert_eq!(stable.render_faces[0], 0);

    signatures[0].caster_signature = 0xCCDD;
    let changed = stable.next.plan(signatures, [0; NVR_POINT_LIGHT_COUNT], 1);
    assert_eq!(
        changed.static_faces[0], 0x3f,
        "a moved door or streamed geometry retained a stale immutable point cube"
    );
}

#[test]
fn shadow_receivers_reject_native_sky_and_out_of_range_geometry() {
    assert!(shadow_receiver_is_valid(
        0.5,
        2_000.0,
        8_000.0,
        1.0 / 65_536.0
    ));
    assert!(!shadow_receiver_is_valid(
        0.0,
        2_000.0,
        8_000.0,
        1.0 / 65_536.0
    ));
    assert!(!shadow_receiver_is_valid(
        1.0,
        2_000.0,
        8_000.0,
        1.0 / 65_536.0
    ));
    assert!(!shadow_receiver_is_valid(
        0.5,
        8_000.0,
        8_000.0,
        1.0 / 65_536.0
    ));
    assert!(!shadow_receiver_is_valid(
        0.5,
        20_000.0,
        8_000.0,
        1.0 / 65_536.0
    ));
    assert!(!shadow_receiver_is_valid(
        0.5,
        f32::NAN,
        8_000.0,
        1.0 / 65_536.0
    ));
}

#[test]
fn contact_evidence_remains_active_beyond_the_last_directional_map() {
    let rejected = if 10_000.0 < 6_000.0 {
        0.3_f32.min(0.2)
    } else {
        1.0
    };
    assert_eq!(rejected, 1.0);
    assert_eq!(
        directional_contact_visibility(10_000.0, 6_000.0, 0.3, Some(0.2)),
        Some(0.2)
    );
    assert_eq!(
        directional_contact_visibility(2_000.0, 6_000.0, 0.3, Some(0.8)),
        Some(0.3)
    );
}

#[test]
fn contact_ray_uses_nvrs_cumulative_depth_comparison_positions() {
    let offsets = nvr_contact_sample_offsets();
    assert_eq!(offsets, [1.0, 3.0, 6.0, 10.0]);
    assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
    let total_weight = offsets.into_iter().map(|offset| 1.0 / offset).sum::<f32>();
    assert!((total_weight - 1.6).abs() < 1.0e-6);
}

#[test]
fn local_light_source_geometry_is_never_subtracted_to_black() {
    assert_eq!(local_light_source_guard(0.0), Some(0.0));
    assert_eq!(local_light_source_guard(0.02), Some(0.0));
    assert_eq!(local_light_source_guard(0.08), Some(1.0));
    let transition = local_light_source_guard(0.05).expect("finite guard");
    assert!(transition > 0.0 && transition < 1.0);
    assert!(local_light_source_guard(f32::NAN).is_none());
}

#[test]
fn animated_actors_never_redraw_static_directional_geometry() {
    let mut scheduler = CascadeScheduler::default();
    let initial = scheduler.plan_at_millis(CascadeDirty::all(), 0);
    scheduler.commit(initial);
    let work = directional_caster_work(0b0111, 0b0111, true);
    assert_eq!(work.actor_overlay_mask, 0b0111);
    assert_eq!(
        work.static_map_mask, 0,
        "a populated exterior redraws complete middle/far terrain and buildings every frame"
    );
    let plan = scheduler.plan_at_millis(CascadeDirty::from_mask(work.static_map_mask), 8);
    assert_eq!(plan.render, [false; 4]);

    let overflow = directional_caster_work(0b0111, 0b0111, false);
    assert_eq!(overflow.actor_overlay_mask, 0);
    assert_eq!(overflow.static_map_mask, 0b0111);
}

#[test]
fn application_culled_player_does_not_schedule_an_empty_actor_overlay() {
    assert!(directional_actor_root_is_active(true, 0));
    assert!(
        !directional_actor_root_is_active(true, 1),
        "first-person app-culling still scheduled a 2048x2048 four-sample actor map"
    );
    assert!(!directional_actor_root_is_active(false, 0));
}

#[test]
fn actor_crossing_outer_cascades_invalidates_departed_and_arrived_maps() {
    let work = directional_caster_work(0b0010, 0b0100, true);
    assert_eq!(work.actor_overlay_mask, 0b0100);

    assert_eq!(
        work.static_map_mask, 0,
        "actor departure/arrival must clear private actor maps, not rebuild static geometry"
    );
}

#[test]
fn point_shadow_distance_retires_continuously_before_admission_ends() {
    let radius = 512.0;
    let max_distance = 8_000.0;
    let forward = [0.0, 1.0, 0.0];
    let inside = point_light_distance_fade(
        [0.0, max_distance + radius - 1.0, 0.0],
        radius,
        forward,
        max_distance,
    )
    .expect("finite inside sample");
    let outside = point_light_distance_fade(
        [0.0, max_distance + radius + 1.0, 0.0],
        radius,
        forward,
        max_distance,
    )
    .expect("finite outside sample");
    assert!(
        inside < 0.01 && outside == 0.0 && (inside - outside).abs() < 0.01,
        "one unit of camera motion changes point-shadow weight from {inside} to {outside}"
    );
}

#[test]
fn point_cube_slots_survive_distance_order_changes_without_redrawing() {
    let mut first_order = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    first_order[0] = PointMapSignature {
        identity: 0x1000,
        position: [-32.0, 0.0, 0.0],
        radius: 512.0,
        caster_signature: 1,
    };
    first_order[1] = PointMapSignature {
        identity: 0x2000,
        position: [32.0, 0.0, 0.0],
        radius: 512.0,
        caster_signature: 2,
    };
    let first = PointMapCache::default().plan(first_order, [0; NVR_POINT_LIGHT_COUNT], 2);

    // Crossing the midpoint reverses nearest-first order without changing
    // either light or either cached cube. Slot ownership, not sort position,
    // must remain stable or ordinary movement regenerates twelve cube faces.
    let mut reversed = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    reversed[0] = first_order[1];
    reversed[1] = first_order[0];
    let moved = first.next.plan(reversed, [0; NVR_POINT_LIGHT_COUNT], 2);
    assert_eq!(
        moved.render_faces[..2],
        [0, 0],
        "camera-only nearest-order changes discarded two valid static cube maps"
    );
    assert_eq!(moved.published[0].identity, first_order[0].identity);
    assert_eq!(moved.published[1].identity, first_order[1].identity);
}

#[test]
fn newly_streamed_root_invalidates_every_cached_directional_map() {
    let mut scheduler = CascadeScheduler::default();
    let initial = scheduler.plan_at_millis(CascadeDirty::all(), 0);
    scheduler.commit(initial);

    let mut previous = [DirectionalRootSetSignature::EMPTY; CASCADE_COUNT];
    for signature in &mut previous {
        signature.include(0x1000, 0x15);
    }
    let mut current = previous;
    for signature in &mut current {
        signature.include(0x2000, 0x24);
    }
    let dirty = directional_root_set_dirty(Some(previous), Some(current));
    let streamed = scheduler.plan_at_millis(dirty, 1);
    assert_eq!(
        streamed.render, [true; CASCADE_COUNT],
        "new exterior geometry remained invisible to all cached shadow maps"
    );

    assert_eq!(
        directional_root_set_dirty(Some(current), Some(current)),
        CascadeDirty::none(),
        "an unchanged root set destroyed directional-map reuse"
    );
    assert_eq!(
        directional_root_set_dirty(Some(current), None),
        CascadeDirty::all(),
        "root-cache overflow retained maps whose complete caster set is unknown"
    );
}

#[test]
fn changing_a_lod_only_root_does_not_invalidate_near_static_maps() {
    let mut previous = [DirectionalRootSetSignature::EMPTY; CASCADE_COUNT];
    let mut current = [DirectionalRootSetSignature::EMPTY; CASCADE_COUNT];
    for cascade in 0..CASCADE_COUNT {
        previous[cascade].include(0x1000, 0x15);
        current[cascade].include(0x1000, 0x15);
        if cascade >= 2 {
            previous[cascade].include(0x9000, 0x400);
            current[cascade].include(0x9000, 0x401);
        }
    }

    assert_eq!(
        directional_root_set_dirty(Some(previous), Some(current)),
        CascadeDirty::from_mask(0b1100),
        "a far-LOD transform change forced near and middle world redraws"
    );
}

#[test]
fn caster_policy_rejects_every_known_nvr_hazard_without_forcing_flags() {
    let policy = CasterPolicy::quality_default();
    let accepted = CasterAdmission::default();
    assert!(policy.admit(accepted).is_ok());

    let rejected = [
        CasterAdmission {
            form_casts_shadows: false,
            ..accepted
        },
        CasterAdmission {
            app_culled: true,
            ..accepted
        },
        CasterAdmission {
            refraction: true,
            ..accepted
        },
        CasterAdmission {
            fire_refraction: true,
            ..accepted
        },
        CasterAdmission {
            decal: true,
            ..accepted
        },
        CasterAdmission {
            dynamic_decal: true,
            ..accepted
        },
        CasterAdmission {
            fade_alpha: 0.74,
            ..accepted
        },
        CasterAdmission {
            bound_radius: 0.49,
            ..accepted
        },
        CasterAdmission {
            within_frustum: false,
            ..accepted
        },
        CasterAdmission {
            within_multibound: false,
            ..accepted
        },
    ];
    for candidate in rejected {
        assert!(policy.admit(candidate).is_err());
    }
    assert!(!policy.force_engine_cast_shadow_flag);
    assert!(!policy.first_person_player);
    assert!(policy.third_person_player);
}

#[test]
fn evsm4_reference_is_finite_bounded_and_preserves_alpha_cutout_edges() {
    let opaque_occluder = evsm4_moments(0.35, true).expect("finite opaque moments");
    let transparent = evsm4_moments(0.35, false);
    assert!(
        transparent.is_none(),
        "alpha below 0.5 must not write a caster"
    );

    let in_front =
        evsm4_visibility(opaque_occluder, 0.30, 0.01, 0.2).expect("finite front visibility");
    let behind =
        evsm4_visibility(opaque_occluder, 0.60, 0.01, 0.2).expect("finite shadow visibility");
    assert!((0.0..=1.0).contains(&in_front));
    assert!((0.0..=1.0).contains(&behind));
    assert!(in_front > 0.99);
    assert!(behind < 0.05);
    assert!(evsm4_moments(f32::NAN, true).is_none());
    assert!(evsm4_visibility(opaque_occluder, f32::INFINITY, 0.0, 0.0).is_none());
}

#[test]
fn actor_overlay_filter_preserves_subpixel_silhouette_coverage() {
    let samples = [0.0, 0.01, 0.25, 0.5, 1.0].map(|coverage| {
        actor_overlay_edge_visibility(0.35, 0.60, coverage).expect("finite actor edge sample")
    });
    assert!(
        samples[0] > 0.999,
        "an empty actor texel must be completely neutral"
    );
    assert!(
        samples[1] > 0.90,
        "one-percent actor coverage became a fully dark rectangular projection"
    );
    assert!(
        samples.windows(2).all(|pair| pair[0] + 0.001 >= pair[1]),
        "actor shadow coverage must darken monotonically instead of producing EVSM edge blocks"
    );
    assert!(samples[4] < 0.05, "a fully covered actor failed to occlude");
}

#[test]
fn terrain_lod_shadow_vertex_uses_the_native_geomorphed_height() {
    assert_eq!(
        terrain_lod_shadow_z(80.0, 20.0, 0.25, false, 15.0),
        Some(35.0),
        "the shadow caster ignored the terrain LOD morph and projected a different far silhouette"
    );
    assert_eq!(
        terrain_lod_shadow_z(80.0, 20.0, 0.25, true, 15.0),
        Some(20.0),
        "the loaded-cell land drop must be applied after geomorphing"
    );
}

#[test]
fn resource_plan_preserves_nvr_evsm_coverage_with_one_reusable_multisample_surface() {
    let exterior = ProducerResourcePlan::quality_default(SceneKind::Exterior, 1920, 1080)
        .expect("valid exterior backbuffer");
    assert_eq!(exterior.cascade_resolution, NVR_CASCADE_RESOLUTION);
    assert_eq!(exterior.cascade_count, CASCADE_COUNT as u32);
    assert_eq!(
        exterior.directional_texture_count, 4,
        "the atlas, reusable near resolve, and two outer actor maps must be included"
    );
    assert_eq!(
        exterior.actor_overlay_fullscreen_merge_draws, 0,
        "animated actors must be sampled as a separate map instead of merging every 2048x2048 texel"
    );
    assert_eq!(exterior.atlas_resolution, NVR_CASCADE_RESOLUTION * 2);
    assert_eq!(
        exterior.directional_samples, 4,
        "NVR custom quality uses four coverage samples; receiver filtering cannot recover a thin caster missed during generation"
    );
    assert_eq!(exterior.directional_channels, 4);
    assert_eq!(exterior.directional_channel_bits, 16);
    assert!(exterior.evsm4);
    assert_eq!(exterior.actor_channels, 2);
    assert_eq!(exterior.actor_samples, 4);
    assert_eq!(exterior.actor_resolution, NVR_CASCADE_RESOLUTION / 2);
    assert!(
        exterior.actor_generation_bytes <= u64::from(NVR_CASCADE_RESOLUTION / 2).pow(2) * 4 * 4,
        "presentation-rate actor generation still writes a full 2048-square 4x-MSAA target"
    );
    assert_eq!(
        exterior.actor_generation_bytes * 8,
        u64::from(NVR_CASCADE_RESOLUTION).pow(2) * 8 * 4,
        "caster fitting must cut the former full-size EVSM4 actor write traffic by eight"
    );
    assert_eq!(
        exterior.receiver_filter_samples, 3,
        "one bilinear center plus two symmetric transition-only taps bound receiver work"
    );
    assert_eq!(exterior.point_light_count, NVR_POINT_LIGHT_COUNT as u32);
    assert_eq!(
        exterior.point_cube_texture_count,
        (NVR_POINT_LIGHT_COUNT * 2) as u32,
        "each published point cube needs an immutable-static backing cube"
    );
    assert_eq!(
        exterior.estimated_bytes, 598_383_616,
        "the resource contract omitted a quality-preserving shadow resource"
    );
    assert!(exterior.estimated_bytes <= 664 * 1024 * 1024);
    assert_eq!(exterior.fallback_estimated_bytes, 627_743_744);
    assert!(exterior.fallback_estimated_bytes < exterior.nvr_equivalent_estimated_bytes);
    assert!(exterior.combined_estimated_bytes <= 664 * 1024 * 1024);
    assert!(exterior.nvr_equivalent_estimated_bytes >= 896 * 1024 * 1024);

    let interior = ProducerResourcePlan::quality_default(SceneKind::Interior, 1920, 1080)
        .expect("valid interior backbuffer");
    assert_eq!(interior.cascade_count, 0);
    assert_eq!(interior.directional_texture_count, 0);
    assert_eq!(interior.point_light_count, NVR_POINT_LIGHT_COUNT as u32);
    assert_eq!(interior.point_cube_resolution, 512);
    assert_eq!(interior.point_cube_texture_count, 24);
    assert_eq!(interior.estimated_bytes, 176_926_720);
    assert_eq!(interior.fallback_estimated_bytes, interior.estimated_bytes);
    assert!(interior.estimated_bytes <= 208 * 1024 * 1024);
    assert_eq!(
        interior.combined_estimated_bytes, exterior.combined_estimated_bytes,
        "the retained two-branch peak is independent of the current cell"
    );
}

#[test]
fn producer_transaction_restores_every_state_class_it_mutates() {
    let required = [
        TransactionState::RenderTargets,
        TransactionState::DepthStencil,
        TransactionState::Viewport,
        TransactionState::Shaders,
        TransactionState::VertexDeclarationOrFvf,
        TransactionState::Streams,
        TransactionState::Indices,
        TransactionState::Textures,
        TransactionState::Samplers,
        TransactionState::RenderStates,
        TransactionState::SkinCalculationCache,
        TransactionState::EngineRendererCache,
    ];
    let plan =
        ProducerResourcePlan::quality_default(SceneKind::Exterior, 1920, 1080).expect("plan");
    for state in required {
        assert!(
            plan.transaction.restores(state),
            "missing restoration for {state:?}"
        );
    }
    assert_eq!(plan.transaction.begin_scene_calls, 1);
    assert_eq!(plan.transaction.end_scene_calls_after_success, 1);
    assert_eq!(plan.transaction.end_scene_calls_after_begin_failure, 0);
}

#[test]
fn cascade_projection_contains_its_source_slice_and_rejects_distant_bounds() {
    let camera = ShadowCamera {
        near: 5.0,
        far: 28_000.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5625,
        frustum_top: 0.5625,
        forward: [1.0, 0.0, 0.0],
        up: [0.0, 0.0, 1.0],
        right: [0.0, 1.0, 0.0],
        translation: [12_000.0, -2_000.0, 800.0],
        fov_compensation: 1.0,
    };
    let split =
        practical_cascade_splits(camera.near, camera.far, 6_000.0, 0.9).expect("cascade splits")[1];
    let projection = cascade_projection(camera, split, [0.4, 0.3, 0.866], 2_048)
        .expect("stable cascade projection");

    let slice_midpoint = (split.near + split.far) * 0.5;
    assert!(projection.contains(Sphere {
        center: [slice_midpoint, 0.0, 0.0],
        radius: 16.0,
    }));
    assert!(!projection.contains(Sphere {
        center: [-20_000.0, 0.0, 0.0],
        radius: 1.0,
    }));
    assert!(projection.radius.is_finite() && projection.radius > 0.0);
    assert!(
        projection
            .world_to_shadow
            .iter()
            .flatten()
            .all(|value| value.is_finite())
    );
}

#[test]
fn directional_caster_upstream_of_the_receiver_is_pancaked_instead_of_culled() {
    let camera = ShadowCamera {
        near: 5.0,
        far: 28_000.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5625,
        frustum_top: 0.5625,
        forward: [1.0, 0.0, 0.0],
        up: [0.0, 0.0, 1.0],
        right: [0.0, 1.0, 0.0],
        translation: [0.0; 3],
        fov_compensation: 1.0,
    };
    let split = practical_cascade_splits(camera.near, camera.far, 6_000.0, 0.9).expect("splits")[3];
    let sun = [0.4, 0.3, 0.866_025_4];
    let projection =
        cascade_projection(camera, split, sun, NVR_CASCADE_RESOLUTION).expect("LOD projection");

    // This caster is directly upstream of the receiver along the light ray.
    // Its vertices are deliberately beyond the light camera's near plane,
    // where NVR disables plane zero and the vertex shader clamps projected Z.
    // Rejecting it on the CPU creates the hard horizon bands in the report.
    let upstream = Sphere {
        center: std::array::from_fn(|axis| {
            projection.center[axis] + sun[axis] * projection.radius * 1.5
        }),
        radius: 8.0,
    };
    assert!(
        projection.contains(upstream),
        "the CPU near plane clipped an upstream caster before vertex-depth pancaking"
    );
}

#[test]
fn rotating_the_camera_cannot_move_a_directional_cache_footprint() {
    let forward = ShadowCamera {
        near: 5.0,
        far: 28_000.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5625,
        frustum_top: 0.5625,
        forward: [1.0, 0.0, 0.0],
        up: [0.0, 0.0, 1.0],
        right: [0.0, 1.0, 0.0],
        translation: [10_000.0, -4_000.0, 300.0],
        fov_compensation: 1.0,
    };
    let yawed = ShadowCamera {
        forward: [0.0, 1.0, 0.0],
        right: [-1.0, 0.0, 0.0],
        ..forward
    };
    let split =
        practical_cascade_splits(forward.near, forward.far, 6_000.0, 0.9).expect("splits")[2];
    let sun = [0.4, 0.3, 0.866_025_4];
    let first = cascade_projection(forward, split, sun, NVR_CASCADE_RESOLUTION)
        .expect("forward projection");
    let second =
        cascade_projection(yawed, split, sun, NVR_CASCADE_RESOLUTION).expect("yawed projection");

    assert_eq!(
        first.receiver_sphere(),
        second.receiver_sphere(),
        "camera yaw moved the retained static-map footprint and forced redraw/flicker"
    );
    assert_eq!(
        first.world_to_shadow, second.world_to_shadow,
        "camera yaw moved the stable shadow texel grid"
    );
}

#[test]
fn fast_camera_yaw_schedules_zero_static_cascade_pixels() {
    let forward = ShadowCamera {
        near: 5.0,
        far: 28_000.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5625,
        frustum_top: 0.5625,
        forward: [1.0, 0.0, 0.0],
        up: [0.0, 0.0, 1.0],
        right: [0.0, 1.0, 0.0],
        translation: [10_000.0, -4_000.0, 300.0],
        fov_compensation: 1.0,
    };
    let yawed = ShadowCamera {
        forward: [-1.0, 0.0, 0.0],
        right: [0.0, -1.0, 0.0],
        ..forward
    };
    let splits = practical_cascade_splits(forward.near, forward.far, 6_000.0, 0.9)
        .expect("practical split family");
    let sun = [0.4, 0.3, 0.866_025_4];
    let mut mandatory = 0_u8;
    let mut quality = 0_u8;
    for (index, split) in splits.into_iter().enumerate() {
        let cached = cascade_projection(forward, split, sun, NVR_CASCADE_RESOLUTION)
            .expect("cached clipmap");
        let current =
            cascade_projection(yawed, split, sun, NVR_CASCADE_RESOLUTION).expect("yawed clipmap");
        let refresh = retained_cascade_refresh(
            cached.center,
            cached.radius,
            current.center,
            current.receiver_radius,
            sun,
            sun,
            NVR_CASCADE_RESOLUTION,
        );
        mandatory |= u8::from(refresh.mandatory) << index;
        quality |= u8::from(refresh.quality) << index;
    }
    let mut scheduler = CascadeScheduler::default();
    scheduler.commit(scheduler.plan_at_millis(CascadeDirty::all(), 0));
    let plan = scheduler.plan_refreshes_at_millis(
        CascadeDirty::from_mask(mandatory),
        CascadeDirty::from_mask(quality),
        1,
    );
    assert_eq!(plan.render, [false; CASCADE_COUNT]);
    let submitted_pixels = plan.render.into_iter().filter(|render| *render).count() as u64
        * u64::from(NVR_CASCADE_RESOLUTION).pow(2);
    assert_eq!(
        submitted_pixels, 0,
        "camera-only yaw submitted static shadow-map pixels"
    );
}

#[test]
fn fitted_actor_map_encloses_the_caster_and_preserves_static_texel_density() {
    let camera = ShadowCamera {
        near: 5.0,
        far: 28_000.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5625,
        frustum_top: 0.5625,
        forward: [1.0, 0.0, 0.0],
        up: [0.0, 0.0, 1.0],
        right: [0.0, 1.0, 0.0],
        translation: [0.0; 3],
        fov_compensation: 1.0,
    };
    let split = practical_cascade_splits(camera.near, camera.far, 6_000.0, 0.9).expect("splits")[0];
    let static_projection = cascade_projection(
        camera,
        split,
        [0.4, 0.3, 0.866_025_4],
        NVR_CASCADE_RESOLUTION,
    )
    .expect("static projection");
    let bounds = ActorBounds {
        min: [24.0, -12.0, -4.0],
        max: [64.0, 12.0, 84.0],
    };
    let actor_projection = static_projection
        .cropped_to_actor_bounds(bounds, NVR_CASCADE_RESOLUTION / 2)
        .expect("fitted actor projection");
    let actor_projection = actor_projection.projection;

    for x in [bounds.min[0], bounds.max[0]] {
        for y in [bounds.min[1], bounds.max[1]] {
            for z in [bounds.min[2], bounds.max[2]] {
                let point = [x, y, z, 1.0];
                let projected: [f32; 4] = std::array::from_fn(|column| {
                    point
                        .into_iter()
                        .zip(actor_projection.world_to_shadow)
                        .map(|(value, row)| value * row[column])
                        .sum()
                });
                assert!(projected[0].abs() <= projected[3] + 0.001);
                assert!(projected[1].abs() <= projected[3] + 0.001);
            }
        }
    }

    for world_axis in 0..3 {
        let static_scale = (static_projection.world_to_shadow[world_axis][0].powi(2)
            + static_projection.world_to_shadow[world_axis][1].powi(2))
        .sqrt()
            * NVR_CASCADE_RESOLUTION as f32;
        let actor_scale = (actor_projection.world_to_shadow[world_axis][0].powi(2)
            + actor_projection.world_to_shadow[world_axis][1].powi(2))
        .sqrt()
            * (NVR_CASCADE_RESOLUTION / 2) as f32;
        assert!(
            actor_scale + 0.001 >= static_scale,
            "actor fitting reduced light-space samples along world axis {world_axis}"
        );
    }
}

#[test]
fn grazing_directional_receivers_use_nvrs_world_space_normal_offset() {
    let position = [100.0, -20.0, 8.0];
    let overhead = directional_receiver_position(position, [0.0, 0.0, 1.0], [0.0, 0.0, 1.0])
        .expect("overhead receiver");
    assert_eq!(overhead, position);

    let grazing = directional_receiver_position(position, [0.0, 0.0, 1.0], [1.0, 0.0, 0.1])
        .expect("grazing receiver");
    assert!(grazing[2] - position[2] > 0.9);
    assert_eq!(grazing[0], position[0]);
    assert!(directional_receiver_position(position, [0.0; 3], [1.0, 0.0, 0.0]).is_none());
}

#[test]
fn animated_actor_bounds_invalidate_only_their_receiver_cascade_and_blend_neighbor() {
    let camera = ShadowCamera {
        near: 5.0,
        far: 28_000.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5625,
        frustum_top: 0.5625,
        forward: [1.0, 0.0, 0.0],
        up: [0.0, 0.0, 1.0],
        right: [0.0, 1.0, 0.0],
        translation: [0.0; 3],
        fov_compensation: 1.0,
    };
    let splits = practical_cascade_splits(camera.near, camera.far, 6_000.0, 0.9)
        .expect("NVR cascade partition");
    let sun = [0.4, 0.3, 0.866_025_4];
    let first = cascade_projection(camera, splits[0], sun, NVR_CASCADE_RESOLUTION)
        .expect("near projection");
    let mut projections = [first; CASCADE_COUNT];
    for index in 1..CASCADE_COUNT {
        projections[index] = cascade_projection(camera, splits[index], sun, NVR_CASCADE_RESOLUTION)
            .expect("cascade projection");
    }
    let near_actor = Sphere {
        center: projections[0].center,
        radius: 32.0,
    };
    assert_eq!(
        dynamic_caster_cascade_mask(splits, camera.forward, near_actor),
        0b0001,
        "a near actor must use its private overlay instead of rebuilding two nested outer static maps every frame"
    );
    let beyond_near_split = Sphere {
        center: [splits[0].far * 1.1, 0.0, 0.0],
        radius: 1.0,
    };
    assert_eq!(
        dynamic_caster_cascade_mask(splits, camera.forward, beyond_near_split) & 0b0001,
        0,
        "clipmap guard coverage was mistaken for view-depth cascade ownership"
    );
    let middle_actor = Sphere {
        center: [splits[1].far * 0.9, 0.0, 0.0],
        radius: 32.0,
    };
    let mask = dynamic_caster_cascade_mask(splits, camera.forward, middle_actor);
    assert_ne!(
        mask & (1 << 1),
        0,
        "a moving middle-distance actor kept its old pose"
    );
    assert_eq!(
        mask & 0b0001,
        0,
        "a middle-distance actor cannot invalidate a near map which cannot select its receiver"
    );
    assert_eq!(
        mask & (1 << 3),
        0,
        "NVR's LOD profile does not contain actors"
    );
}

#[test]
fn cascade_projection_preserves_nvr_zoom_compensation() {
    let base = ShadowCamera {
        near: 5.0,
        far: 28_000.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5625,
        frustum_top: 0.5625,
        forward: [1.0, 0.0, 0.0],
        up: [0.0, 0.0, 1.0],
        right: [0.0, 1.0, 0.0],
        translation: [0.0; 3],
        fov_compensation: 1.0,
    };
    let split = super::contract::CascadeSplit {
        near: 15.0,
        far: 1_000.0,
    };
    let sun = [0.4, 0.2, 0.894_427_2];
    let normal = cascade_projection(base, split, sun, NVR_CASCADE_RESOLUTION)
        .expect("normal FOV projection");
    let zoomed = cascade_projection(
        ShadowCamera {
            fov_compensation: 2.25,
            ..base
        },
        split,
        sun,
        NVR_CASCADE_RESOLUTION,
    )
    .expect("zoom-compensated projection");
    assert!((zoomed.receiver_radius - normal.receiver_radius).abs() < 0.001);
    assert!((zoomed.radius / normal.radius - 2.25).abs() < 0.001);
}

#[test]
fn point_cube_views_cover_all_six_axes_with_non_degenerate_up_vectors() {
    let views = point_cube_views([10.0, -3.0, 5.0], 512.0).expect("cube views");
    let directions = views.map(|view| view.direction);
    assert_eq!(
        directions,
        [
            [1.0, 0.0, 0.0],
            [-1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            [0.0, -1.0, 0.0],
            [0.0, 0.0, -1.0],
            [0.0, 0.0, 1.0],
        ]
    );
    for view in views {
        let dot = view.direction[0] * view.up[0]
            + view.direction[1] * view.up[1]
            + view.direction[2] * view.up[2];
        assert!(dot.abs() < 0.0001);
        assert!(
            view.world_to_shadow
                .iter()
                .flatten()
                .all(|value| value.is_finite())
        );
    }
    assert!(point_cube_views([0.0; 3], 0.05).is_none());
}
