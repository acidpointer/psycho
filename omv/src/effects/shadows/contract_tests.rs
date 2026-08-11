use super::contract::{
    CASCADE_COUNT, CascadeDirty, CascadeScheduler, CasterAdmission, CasterPolicy, HookAction,
    InvocationContext, NVR_CASCADE_RESOLUTION, NVR_POINT_DRAW_DISTANCE, NVR_POINT_LIGHT_COUNT,
    NVR_POINT_RADIUS_MULTIPLIER, PointLightCandidate, ProducerResourcePlan, SceneKind,
    ShadowSettings, TransactionState, composite_shadow_factor, evsm4_moments, evsm4_visibility,
    point_light_influence_is_eligible, practical_cascade_splits, select_point_lights,
    snap_shadow_center, sphere_intersects_point_light,
};
use super::engine::{
    EngineCallAbi, FNV_EXE_SHA256, GeometryKind, HookSiteContract, NativeLayout,
    ShadowGenerationAbi,
};
use super::math::{
    ShadowCamera, Sphere, cascade_projection, point_cube_views, stabilize_sun_direction,
};

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
    assert_eq!(NativeLayout::NI_AV_OBJECT_SIZE, 0x9C);
    assert_eq!(NativeLayout::NI_AV_OBJECT_PARENT, 0x18);
    assert_eq!(NativeLayout::NI_AV_OBJECT_WORLD_BOUND, 0x20);
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
    assert_eq!(NativeLayout::NI_SKIN_PARTITION_SIZE, 0x10);
    assert_eq!(NativeLayout::NI_SKIN_PARTITION_ENTRY_SIZE, 0x2C);
    assert_eq!(NativeLayout::NI_POINT_LIGHT_SIZE, 0xFC);
    assert_eq!(NativeLayout::NI_POINT_LIGHT_CASTS_SHADOWS, 0x9E);
    assert_eq!(NativeLayout::NI_POINT_LIGHT_SPECULAR, 0xE0);
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
fn exterior_visibility_and_interior_illumination_have_distinct_nvr_semantics() {
    let darkness = 0.75;
    let exterior = composite_shadow_factor(SceneKind::Exterior, 0.8, 0.4, darkness)
        .expect("finite exterior factor");
    assert!((exterior - 0.55).abs() < 0.000_001);
    assert_eq!(
        composite_shadow_factor(SceneKind::Interior, 1.0, 0.0, darkness),
        Some(0.25)
    );
    assert_eq!(
        composite_shadow_factor(SceneKind::Interior, 0.0, 1.0, darkness),
        Some(1.0)
    );
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
fn special_and_screenshot_renders_never_advance_gameplay_cadence() {
    let mut scheduler = CascadeScheduler::default();
    let initial = scheduler.plan(InvocationContext::Main, CascadeDirty::all());
    assert_eq!(initial.render, [true; CASCADE_COUNT]);
    assert!(initial.commit_gameplay_epoch);
    scheduler.commit(initial);
    let epoch = scheduler.gameplay_epoch();

    for context in [InvocationContext::Special, InvocationContext::Screenshot] {
        let transient = scheduler.plan(context, CascadeDirty::all());
        assert_eq!(transient.render, [true; CASCADE_COUNT]);
        assert!(!transient.commit_gameplay_epoch);
        assert!(transient.invalidate_gameplay_maps);
        scheduler.commit(transient);
        assert_eq!(scheduler.gameplay_epoch(), epoch);
    }

    let recovery = scheduler.plan(InvocationContext::Main, CascadeDirty::none());
    assert_eq!(recovery.render, [true; CASCADE_COUNT]);
    assert!(recovery.commit_gameplay_epoch);
}

#[test]
fn stable_main_view_preserves_near_animation_and_bounds_distant_refresh() {
    let mut scheduler = CascadeScheduler::default();
    let first = scheduler.plan(InvocationContext::Main, CascadeDirty::all());
    scheduler.commit(first);

    let cadence = [
        [true, false, false, false],
        [true, true, false, false],
        [true, false, true, false],
        [true, true, false, true],
        [true, false, false, false],
        [true, true, true, false],
    ];
    for expected in cadence {
        let stable = scheduler.plan(InvocationContext::Main, CascadeDirty::none());
        assert_eq!(stable.render, expected);
        scheduler.commit(stable);
    }
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
            casts_shadows: true,
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
fn point_admission_preserves_nonshadow_and_cube_overflow_light_energy() {
    let mut candidates = Vec::new();
    for identity in 1..=14 {
        candidates.push(PointLightCandidate {
            identity,
            distance_squared: identity as f32,
            radius: 512.0,
            casts_shadows: true,
        });
    }
    candidates.extend([
        PointLightCandidate {
            identity: 101,
            distance_squared: 0.5,
            radius: 512.0,
            casts_shadows: false,
        },
        PointLightCandidate {
            identity: 102,
            distance_squared: 13.5,
            radius: 512.0,
            casts_shadows: false,
        },
    ]);

    let selected = select_point_lights(&candidates);
    assert_eq!(
        selected.identities(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    );
    assert_eq!(selected.unshadowed_len(), 4);
    assert_eq!(selected.unshadowed_identities()[..4], [101, 13, 102, 14]);
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
fn point_light_discovery_matches_nvr_front_radius_and_distance_admission() {
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
    assert!(!point_light_influence_is_eligible(
        [0.0, -1_000.0, 0.0],
        100.0,
        forward,
        8_000.0,
    ));
    assert!(!point_light_influence_is_eligible(
        [0.0, 7_700.0, 0.0],
        512.0,
        forward,
        8_000.0,
    ));
    assert!(!point_light_influence_is_eligible(
        [0.0, 100.0, 0.0],
        10.0,
        forward,
        8_000.0,
    ));
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
        evsm4_visibility(opaque_occluder, 0.30, 0.00002, 0.2).expect("finite front visibility");
    let behind =
        evsm4_visibility(opaque_occluder, 0.60, 0.00002, 0.2).expect("finite shadow visibility");
    assert!((0.0..=1.0).contains(&in_front));
    assert!((0.0..=1.0).contains(&behind));
    assert!(in_front > 0.99);
    assert!(behind < 0.05);
    assert!(evsm4_moments(f32::NAN, true).is_none());
    assert!(evsm4_visibility(opaque_occluder, f32::INFINITY, 0.0, 0.0).is_none());
}

#[test]
fn resource_plan_preserves_nvr_sampling_quality_without_the_giant_msaa_atlas() {
    let plan = ProducerResourcePlan::quality_default(1920, 1080).expect("valid backbuffer");
    assert_eq!(plan.cascade_resolution, NVR_CASCADE_RESOLUTION);
    assert_eq!(plan.cascade_count, CASCADE_COUNT as u32);
    assert_eq!(plan.directional_texture_count, 1);
    assert_eq!(plan.atlas_resolution, NVR_CASCADE_RESOLUTION * 2);
    assert_eq!(plan.directional_samples, 4);
    assert_eq!(plan.directional_channels, 4);
    assert_eq!(plan.directional_channel_bits, 16);
    assert!(plan.evsm4);
    assert!(plan.prefilter);
    assert_ne!(plan.blur_source_identity, plan.blur_target_identity);
    assert_eq!(plan.point_light_count, NVR_POINT_LIGHT_COUNT as u32);
    assert_eq!(plan.point_cube_resolution, 512);
    assert!(plan.estimated_bytes <= 512 * 1024 * 1024);
    assert!(plan.nvr_equivalent_estimated_bytes >= 896 * 1024 * 1024);
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
    ];
    let plan = ProducerResourcePlan::quality_default(1920, 1080).expect("plan");
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
