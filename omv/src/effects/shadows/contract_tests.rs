use super::contract::{
    CASCADE_COUNT, CascadeDirty, CascadeScheduler, CasterAdmission, CasterPolicy, HookAction,
    NVR_CASCADE_RESOLUTION, NVR_POINT_DRAW_DISTANCE, NVR_POINT_LIGHT_COUNT,
    NVR_POINT_RADIUS_MULTIPLIER, PointLightCandidate, ProducerResourcePlan, SceneKind,
    ShadowSettings, TransactionState, cascade_minimum_caster_radius, composite_shadow_factor,
    directional_form_type_is_enabled, evsm4_moments, evsm4_visibility,
    point_light_influence_is_eligible, practical_cascade_splits, publication_epoch_is_usable,
    select_point_lights, snap_shadow_center, sphere_intersects_cube_face,
    sphere_intersects_point_light,
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
    assert_eq!(NativeLayout::TES_FORM_TYPE, 0x04);
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
fn native_material_alpha_and_point_light_admission_match_modern_nvr() {
    let render = include_str!("render.rs");
    assert!(
        render.contains("const MATERIAL_ALPHA: usize = 0x3C;"),
        "NiMaterialProperty::fAlpha is at 0x3C; 0x40 is fEmitMult"
    );

    let native = include_str!("native.rs");
    assert!(
        !native.contains("NATIVE_LIGHT_CASTS_SHADOWS"),
        "modern NVR must not trust Fallout/JIP's broken point-light cast-shadow flag"
    );
}

#[test]
fn first_valid_invocation_reaches_generation_after_resource_creation() {
    let pipeline = include_str!("pipeline.rs");
    let produce = pipeline
        .split_once("pub(super) unsafe fn produce(")
        .and_then(|(_, tail)| tail.split_once("fn produce_transaction("))
        .map(|(body, _)| body)
        .expect("shadow producer body");
    let camera_snapshot = produce
        .find("fnv_world_camera_frame_fast")
        .expect("world-camera POD snapshot");
    let shared_creation = produce
        .find("ShadowResources::create")
        .expect("shared shadow resource creation");
    let transaction = produce
        .find("self.produce_transaction")
        .expect("map generation transaction");
    assert!(
        camera_snapshot < shared_creation,
        "snapshot coherent camera POD before a potentially stalling D3D allocation"
    );
    assert!(
        shared_creation < transaction,
        "the invocation that creates resources must continue to map generation"
    );
    assert!(
        !produce.contains("resources_warmed"),
        "resource creation must not defer production to an unproven future engine invocation"
    );
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
fn validated_common_entry_reaches_generation_without_caller_ancestry() {
    let source = include_str!("mod.rs");
    let handler = source
        .split_once("pub(crate) unsafe fn handle_common_entry(")
        .and_then(|(_, tail)| tail.split_once("pub(crate) unsafe fn apply_scene_pre("))
        .map(|(body, _)| body)
        .expect("common-entry handler body");
    assert!(
        handler.starts_with(") -> CommonEntryOutcome"),
        "NVR replaces the validated common entry itself; caller ancestry is not a producer input"
    );
    assert!(
        !handler.contains("CommonInvocationContext") && !handler.contains("context !="),
        "only the later outer scene-pre consumer is destination-specific"
    );
    let route_gate = handler
        .find("!ROUTE_READY.load(Ordering::Acquire)")
        .expect("deferred route gate");
    let scene_read = handler
        .find("native::current_scene()")
        .expect("native scene read");
    assert!(
        route_gate < scene_read,
        "the common entry must stay native until DeferredInit publishes the route"
    );
}

#[test]
fn resource_ownership_is_branch_lazy_and_msaa_resolve_is_full_surface() {
    let pipeline = include_str!("pipeline.rs");
    assert!(
        pipeline.contains("directional: Option<DirectionalResources>"),
        "exterior resources must not be allocated for an interior-only frame"
    );
    assert!(
        pipeline.contains("points: Option<PointResources>"),
        "the twelve cube maps must not be allocated for an exterior-only frame"
    );
    assert!(
        !pipeline.contains("self.directional = None;") && !pipeline.contains("self.points = None;"),
        "completed branch resources must survive cell transitions instead of hitching on every door"
    );
    assert!(
        pipeline.contains("directional_resolve_surface"),
        "the MSAA workspace needs a same-size single-sample resolve surface"
    );
    assert!(
        pipeline.contains("&directional.directional_resolve_surface,\n            None,"),
        "MSAA downsampling must copy the complete 2048 surface before filtering"
    );
    assert!(
        !pipeline.contains(
            "&directional.atlas_surface,\n            Some(&quadrant),\n            D3DTEXF_NONE"
        ),
        "D3D9 does not define a multisample resolve directly into an atlas sub-rectangle"
    );
}

#[test]
fn fullscreen_shadow_passes_cannot_inherit_native_pixel_rejection_state() {
    let pipeline = include_str!("pipeline.rs");
    let state = pipeline
        .split_once("fn bind_fullscreen_state(")
        .and_then(|(_, tail)| tail.split_once("fn clear_auxiliary_targets("))
        .map(|(body, _)| body)
        .expect("shadow fullscreen state binding");

    // The common shadow producer runs inside several native renderer routes,
    // and the consumer runs at an image-space boundary. Both may inherit
    // alpha/stencil predicates or a restricted channel mask. A successful
    // DrawPrimitiveUP then consumes the full GPU budget while writing no
    // visible pixels, so these are correctness requirements rather than
    // optional cleanup state.
    for required in [
        "device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?",
        "device.set_render_state(D3DRS_ALPHAREF, 0)?",
        "device.set_render_state(D3DRS_ALPHAFUNC, D3DCMP_ALWAYS.0 as u32)?",
        "device.set_render_state(D3DRS_STENCILENABLE, 0)?",
        "device.set_render_state(D3DRS_COLORWRITEENABLE, 0xF)?",
    ] {
        assert!(
            state.contains(required),
            "shadow fullscreen passes must establish `{required}`"
        );
    }
}

#[test]
fn generation_passes_own_multisample_and_alpha_coverage_state() {
    let render = include_str!("render.rs");
    let state = render
        .split_once("pub(super) fn configure_generation_state(")
        .and_then(|(_, tail)| tail.split_once("/// Bind one directional map transform"))
        .map(|(body, _)| body)
        .expect("shadow generation state binding");
    for required in [
        "device.set_render_state(D3DRS_MULTISAMPLEANTIALIAS, 1)?",
        "device.set_render_state(D3DRS_MULTISAMPLEMASK, u32::MAX)?",
        "crate::backend::AlphaCoverageMode::Nvidia",
        "crate::backend::AlphaCoverageMode::Amd",
    ] {
        assert!(
            state.contains(required),
            "shadow generation must establish `{required}`"
        );
    }
}

#[test]
fn cached_cascade_projection_remains_paired_with_its_atlas_quadrant() {
    let pipeline = include_str!("pipeline.rs");
    let loop_start = pipeline
        .find("for index in 0..CASCADE_COUNT {")
        .expect("directional cascade loop");
    let loop_source = &pipeline[loop_start..];
    let guard_start = loop_source
        .find("if plan.render[index] {")
        .expect("cascade refresh guard");
    let guard_source = &loop_source[guard_start..];
    let open = guard_source.find('{').expect("refresh block");
    let mut depth = 0usize;
    let mut close = None;
    for (offset, byte) in guard_source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &guard_source[open..=close.expect("complete refresh block")];
    for metadata in [
        "self.cascade_matrices[index] = projection.world_to_shadow;",
        "self.cascade_origins[index] = camera.world_transform.translation;",
        "self.cascade_splits[index] = splits[index];",
    ] {
        assert!(
            body.contains(metadata),
            "cached atlas data and `{metadata}` must refresh atomically"
        );
    }
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
fn stable_main_view_preserves_near_animation_and_bounds_distant_refresh() {
    let mut scheduler = CascadeScheduler::default();
    let first = scheduler.plan(CascadeDirty::all());
    assert_eq!(first.render, [true; CASCADE_COUNT]);
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
        let stable = scheduler.plan(CascadeDirty::none());
        assert_eq!(stable.render, expected);
        scheduler.commit(stable);
    }
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
        (BOOK, [false; CASCADE_COUNT]),
        (CONTAINER, [true, true, true, false]),
        (DOOR, [true; CASCADE_COUNT]),
        (MISC, [true, true, true, false]),
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
    let exterior = ProducerResourcePlan::quality_default(SceneKind::Exterior, 1920, 1080)
        .expect("valid exterior backbuffer");
    assert_eq!(exterior.cascade_resolution, NVR_CASCADE_RESOLUTION);
    assert_eq!(exterior.cascade_count, CASCADE_COUNT as u32);
    assert_eq!(exterior.directional_texture_count, 1);
    assert_eq!(exterior.atlas_resolution, NVR_CASCADE_RESOLUTION * 2);
    assert_eq!(exterior.directional_samples, 4);
    assert_eq!(exterior.directional_channels, 4);
    assert_eq!(exterior.directional_channel_bits, 16);
    assert!(exterior.evsm4);
    assert!(exterior.prefilter);
    assert_ne!(exterior.blur_source_identity, exterior.blur_target_identity);
    assert_eq!(exterior.point_light_count, 0);
    assert!(exterior.estimated_bytes <= 448 * 1024 * 1024);
    assert!(exterior.combined_estimated_bytes <= 512 * 1024 * 1024);
    assert!(exterior.nvr_equivalent_estimated_bytes >= 896 * 1024 * 1024);

    let interior = ProducerResourcePlan::quality_default(SceneKind::Interior, 1920, 1080)
        .expect("valid interior backbuffer");
    assert_eq!(interior.cascade_count, 0);
    assert_eq!(interior.directional_texture_count, 0);
    assert_eq!(interior.point_light_count, NVR_POINT_LIGHT_COUNT as u32);
    assert_eq!(interior.point_cube_resolution, 512);
    assert!(interior.estimated_bytes <= 128 * 1024 * 1024);
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
