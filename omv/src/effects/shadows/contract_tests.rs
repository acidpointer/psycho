use super::contract::{
    ActorOverlayProjectionPlan, AlphaCasterMode, CASCADE_COUNT, CascadeDirty, CascadeScheduler,
    CascadeSphereSelection, CasterAdmission, CasterPolicy, DeferredReceiverPlan,
    DirectionalRootSetSignature, HookAction, LightScissorRect, NVR_CASCADE_RESOLUTION,
    NVR_POINT_DRAW_DISTANCE, NVR_POINT_LIGHT_COUNT, NVR_POINT_RADIUS_MULTIPLIER,
    PointFaceOperation, PointLightCandidate, PointMapCache, PointMapSignature,
    PointStaticFaceCache, ProducerResourcePlan, SceneKind, ShadowConsumerWorkPlan, ShadowFramePlan,
    ShadowMapUpdate, ShadowPublicationIdentity, ShadowSettings, SkinIndexEncoding, SunCompetition,
    TransactionState, TraversalBudget, actor_overlay_edge_visibility,
    actor_overlay_projection_plan, alpha_caster_mode, cascade_minimum_caster_radius,
    cascade_sphere_selection, clipmap_texel_delta, complete_bounded_count, composite_shadow_factor,
    consumer_has_shadow_work, contact_consumer_work, depth_sample_is_geometry,
    directional_actor_root_is_active, directional_caster_work, directional_contact_visibility,
    directional_form_type_is_enabled, directional_receiver_position, directional_root_set_dirty,
    dismember_partition_is_renderable, effective_contact_distance, evsm4_moments, evsm4_visibility,
    exterior_point_shadow_radiance, interior_shadow_factor, local_light_clear_coverage,
    local_light_shadow_energy, local_light_shadow_weight, local_light_source_guard,
    manager_light_chain_is_complete, nvr_contact_sample_offsets, point_caster_depth,
    point_caster_inventory_is_complete, point_consumer_plan, point_light_distance_fade,
    point_light_influence_is_eligible, point_light_radii, point_only_shadow_radiance,
    point_shadow_presentation_weight, point_shadow_transition, point_shadow_visibility,
    practical_cascade_splits, publication_epoch_is_usable, publication_identity_is_usable,
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
use super::pipeline::ShadowPipeline;
use super::render::{mapped_cull_mode, rebase_bone_rows};

#[test]
fn retained_shadow_frame_has_a_literal_zero_work_transcript() {
    let plan = ShadowFramePlan::from_updates([ShadowMapUpdate::Reuse; CASCADE_COUNT], 0, 0);

    assert!(!plan.requires_d3d_transaction());
    assert_eq!(plan.map_draw_count(), 0);
    assert_eq!(plan.clear_count(), 0);
    assert_eq!(plan.resolve_count(), 0);
    assert_eq!(plan.copy_count(), 0);
    assert_eq!(plan.sampler_unbind_count(), 0);
}

#[test]
fn directional_translation_is_strip_bounded_and_preserves_every_texel_owner() {
    let update = ShadowMapUpdate::scroll(37, -23, NVR_CASCADE_RESOLUTION)
        .expect("bounded clipmap translation");
    let ShadowMapUpdate::Scroll(scroll) = update else {
        panic!("translation must select scrolling work");
    };

    assert_eq!(scroll.overlap().area(), 2_011 * 2_025);
    assert_eq!(
        scroll.exposed().iter().map(|rect| rect.area()).sum::<u64>(),
        u64::from(NVR_CASCADE_RESOLUTION).pow(2) - scroll.overlap().area(),
    );
    assert!(
        scroll
            .exposed()
            .iter()
            .all(|rect| rect.width() <= 64 || rect.height() <= 64)
    );

    let plan = ShadowFramePlan::from_updates(
        [
            update,
            ShadowMapUpdate::Reuse,
            ShadowMapUpdate::Reuse,
            ShadowMapUpdate::Reuse,
        ],
        0,
        0,
    );
    assert!(plan.requires_d3d_transaction());
    assert_eq!(plan.map_draw_count(), scroll.exposed().len() as u32);
    assert_eq!(plan.resolve_count(), scroll.exposed().len() as u32);
    assert_eq!(plan.copy_count(), 2 + scroll.exposed().len() as u32);
    assert!(plan.directional_written_pixels() < u64::from(NVR_CASCADE_RESOLUTION).pow(2) / 16);
}

#[test]
fn scrolling_overlap_and_bands_partition_every_destination_texel_exactly_once() {
    for [delta_x, delta_y] in [[3, 2], [3, -2], [-3, 2], [-3, -2], [0, 2], [-3, 0]] {
        let ShadowMapUpdate::Scroll(scroll) =
            ShadowMapUpdate::scroll(delta_x, delta_y, 8).expect("valid test scroll")
        else {
            panic!("small translation must scroll");
        };
        let source = scroll.source_overlap();
        let destination = scroll.overlap();
        assert_eq!(source.width(), destination.width());
        assert_eq!(source.height(), destination.height());
        assert_eq!(destination.left as i32 - source.left as i32, delta_x);
        assert_eq!(destination.top as i32 - source.top as i32, delta_y);

        let mut ownership = [[0_u8; 8]; 8];
        for row in ownership
            .iter_mut()
            .take(destination.bottom as usize)
            .skip(destination.top as usize)
        {
            for owner in row
                .iter_mut()
                .take(destination.right as usize)
                .skip(destination.left as usize)
            {
                *owner += 1;
            }
        }
        for rect in scroll.exposed() {
            for row in ownership
                .iter_mut()
                .take(rect.bottom as usize)
                .skip(rect.top as usize)
            {
                for owner in row
                    .iter_mut()
                    .take(rect.right as usize)
                    .skip(rect.left as usize)
                {
                    *owner += 1;
                }
            }
        }
        assert!(ownership.iter().flatten().all(|owner| *owner == 1));
    }
}

#[test]
fn oversized_or_degenerate_clipmap_motion_rebuilds_instead_of_corrupting_overlap() {
    assert_eq!(
        ShadowMapUpdate::scroll(65, 0, NVR_CASCADE_RESOLUTION),
        Some(ShadowMapUpdate::Rebuild),
    );
    assert_eq!(
        ShadowMapUpdate::scroll(0, 0, NVR_CASCADE_RESOLUTION),
        Some(ShadowMapUpdate::Reuse),
    );
    assert_eq!(ShadowMapUpdate::scroll(1, 1, 0), None);
}

#[test]
fn clipmap_delta_accepts_only_exact_same_basis_texel_motion() {
    let retained = [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 0.0, 1.0],
    ];
    let mut desired = retained;
    desired[3][0] = 37.0 / 1_024.0;
    desired[3][1] = 23.0 / 1_024.0;
    assert_eq!(
        clipmap_texel_delta(retained, desired, NVR_CASCADE_RESOLUTION),
        Some([37, -23])
    );

    desired[0][0] += 0.01;
    assert_eq!(
        clipmap_texel_delta(retained, desired, NVR_CASCADE_RESOLUTION),
        None,
        "a changed light basis cannot reinterpret retained EVSM moments"
    );
}

#[test]
fn point_sampler_unbinds_exist_only_when_a_cube_face_is_scheduled() {
    let idle = ShadowFramePlan::from_updates([ShadowMapUpdate::Reuse; CASCADE_COUNT], 0, 0);
    let one_face = ShadowFramePlan::from_updates([ShadowMapUpdate::Reuse; CASCADE_COUNT], 1, 0);

    assert_eq!(idle.sampler_unbind_count(), 0);
    assert_eq!(one_face.sampler_unbind_count(), 16);
}

#[test]
fn local_light_clear_covers_old_and_current_scissors_without_fullscreen_work() {
    let previous = LightScissorRect {
        left: 100,
        top: 200,
        right: 500,
        bottom: 600,
    };
    let current = LightScissorRect {
        left: 300,
        top: 100,
        right: 700,
        bottom: 450,
    };
    assert_eq!(
        local_light_clear_coverage(Some(previous), Some(current)),
        Some(LightScissorRect {
            left: 100,
            top: 100,
            right: 700,
            bottom: 600,
        })
    );
    assert_eq!(
        local_light_clear_coverage(Some(previous), None),
        Some(previous)
    );
    assert_eq!(local_light_clear_coverage(None, None), None);
}

#[test]
fn copied_actor_bounds_cover_each_intersected_cube_direction() {
    let bounds = [[10.0, 0.0, 0.0, 1.0], [-10.0, 0.0, 0.0, 1.0]];
    let faces = super::native::point_light_dynamic_faces_from_bounds(&bounds, [0.0; 3], 64.0);
    assert_ne!(faces & 0b00_0001, 0, "+X actor missing from cube coverage");
    assert_ne!(faces & 0b00_0010, 0, "-X actor missing from cube coverage");
}

#[test]
fn actors_outside_a_point_lights_finite_volume_schedule_no_cube_work() {
    let distant_actor = [[1_000.0, 0.0, 0.0, 1.0]];
    let faces =
        super::native::point_light_dynamic_faces_from_bounds(&distant_actor, [0.0; 3], 64.0);

    assert_eq!(
        faces, 0,
        "angular cube-face coverage admitted an actor which cannot intersect the finite light"
    );
}

#[test]
fn selected_point_lights_require_a_complete_canonical_root_inventory() {
    assert!(point_caster_inventory_is_complete(0, false));
    assert!(point_caster_inventory_is_complete(12, true));
    assert!(
        !point_caster_inventory_is_complete(1, false),
        "a partial inventory could cache a cube face without its occluding wall"
    );
}

#[test]
fn terminated_manager_light_chain_ignores_a_stale_cached_count() {
    assert!(
        manager_light_chain_is_complete(2, 1, false, 2),
        "a terminating native chain was rejected only because its cached count lagged"
    );
    assert!(
        manager_light_chain_is_complete(1, 2, false, 2),
        "a terminating native chain was rejected only because its cached count led"
    );
    assert!(
        !manager_light_chain_is_complete(2, 2, true, 2),
        "an over-limit or cyclic chain was certified from a bounded prefix"
    );
}

#[test]
fn native_traversal_limits_reject_the_first_unvisited_element() {
    let mut budget = TraversalBudget::new(2);
    assert!(budget.claim());
    assert!(budget.claim());
    assert!(
        !budget.claim(),
        "a bounded walk certified an unvisited native element as complete"
    );

    assert_eq!(complete_bounded_count(2, 2), Some(2));
    assert_eq!(
        complete_bounded_count(3, 2),
        None,
        "a native array count was truncated instead of rejecting partial shadow work"
    );
}

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
    assert_eq!(NativeLayout::NI_MATERIAL_ALPHA, 0x3C);
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
    let skinned = skinned_position_reference(
        [1.0, 2.0, 3.0],
        [0, 1, 2, 3],
        [0.1, 0.2, 0.3],
        &bones,
        SkinIndexEncoding::D3dColor,
    )
    .expect("valid four-bone actor vertex");
    assert!((skinned[0] - 17.0).abs() < 0.0001);
    assert_eq!(skinned[1], 2.0);
    assert_eq!(skinned[2], 3.0);
    assert!(
        skinned_position_reference(
            [0.0; 3],
            [0; 4],
            [0.5; 3],
            &bones,
            SkinIndexEncoding::D3dColor,
        )
        .is_none()
    );
}

#[test]
fn modded_skin_index_encodings_select_the_declared_bones() {
    assert_eq!(
        SkinIndexEncoding::from_declaration_element(4, 2, 0),
        Some(SkinIndexEncoding::D3dColor)
    );
    assert_eq!(
        SkinIndexEncoding::from_declaration_element(8, 2, 0),
        Some(SkinIndexEncoding::UByte4N)
    );
    assert_eq!(
        SkinIndexEncoding::from_declaration_element(5, 2, 0),
        Some(SkinIndexEncoding::UByte4)
    );
    assert_eq!(SkinIndexEncoding::from_declaration_element(2, 2, 0), None);
    assert_eq!(SkinIndexEncoding::from_declaration_element(4, 5, 0), None);
    assert_eq!(SkinIndexEncoding::from_declaration_element(4, 2, 1), None);

    let mut bones = [[[0.0; 4]; 3]; 4];
    for (index, bone) in bones.iter_mut().enumerate() {
        bone[0] = [1.0, 0.0, 0.0, index as f32 * 10.0];
        bone[1] = [0.0, 1.0, 0.0, 0.0];
        bone[2] = [0.0, 0.0, 1.0, 0.0];
    }
    let position = [1.0, 0.0, 0.0];
    let indices = [0, 1, 2, 3];
    let first_weight_only = [1.0, 0.0, 0.0];

    let d3d_color = skinned_position_reference(
        position,
        indices,
        first_weight_only,
        &bones,
        SkinIndexEncoding::D3dColor,
    )
    .expect("D3DCOLOR skin");
    assert_eq!(d3d_color[0], 21.0, "D3DCOLOR did not apply BGRA order");

    for encoding in [SkinIndexEncoding::UByte4N, SkinIndexEncoding::UByte4] {
        let vertex =
            skinned_position_reference(position, indices, first_weight_only, &bones, encoding)
                .expect("byte-order skin");
        assert_eq!(vertex[0], 1.0, "{encoding:?} reordered blend indices");
    }
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
fn blend_only_light_cards_never_become_binary_shadow_casters() {
    assert_eq!(alpha_caster_mode(false, false), AlphaCasterMode::Opaque);
    assert_eq!(alpha_caster_mode(false, true), AlphaCasterMode::Cutout);
    assert_eq!(alpha_caster_mode(true, true), AlphaCasterMode::Cutout);
    assert_eq!(
        alpha_caster_mode(true, false),
        AlphaCasterMode::Translucent,
        "a blend-only lamp card was promoted to a face-spanning hard caster"
    );

    let blend_enabled = true;
    let test_enabled = false;
    let old_combined_flag_test = blend_enabled || test_enabled;
    assert!(
        old_combined_flag_test,
        "negative control no longer models the buggy blend-or-test admission"
    );
}

#[test]
fn consumer_retains_a_complete_publication_for_the_next_scene_pre_epoch() {
    assert!(publication_epoch_is_usable(41, 41));
    assert!(
        publication_epoch_is_usable(41, 42),
        "the common shadow producer runs before the outer world transaction and must remain consumable at its next pre-alpha boundary"
    );
    assert!(publication_epoch_is_usable(u32::MAX, 0));
    assert!(!publication_epoch_is_usable(41, 43));
    assert!(!publication_epoch_is_usable(42, 41));
}

#[test]
fn common_producer_does_not_require_the_later_world_context() {
    let pipeline = ShadowPipeline::default();
    let identity = pipeline
        .current_publication_identity(SceneKind::Exterior, 0)
        .expect("the common producer precedes RenderWorldSceneGraph");
    assert_eq!(identity.transaction, 0);
    assert_eq!(identity.scene, SceneKind::Exterior);
}

#[test]
fn nonzero_receiver_transaction_requires_every_exact_owner() {
    let publication = ShadowPublicationIdentity {
        render_epoch: 41,
        transaction: 9,
        scene: SceneKind::Exterior,
        invocation: 0,
        color_surface: 0x1111,
        depth_surface: 0x2222,
        device_generation: 3,
    };
    assert!(publication_identity_is_usable(publication, publication));
    assert!(!publication_identity_is_usable(
        ShadowPublicationIdentity {
            transaction: 0,
            ..publication
        },
        publication,
    ));
    for consumer in [
        ShadowPublicationIdentity {
            transaction: 10,
            ..publication
        },
        ShadowPublicationIdentity {
            invocation: 1,
            ..publication
        },
        ShadowPublicationIdentity {
            color_surface: 0x3333,
            ..publication
        },
        ShadowPublicationIdentity {
            depth_surface: 0x4444,
            ..publication
        },
        ShadowPublicationIdentity {
            device_generation: 4,
            ..publication
        },
    ] {
        assert!(!publication_identity_is_usable(publication, consumer));
    }
}

#[test]
fn nested_world_context_restores_the_exact_outer_receiver() {
    let mut pipeline = ShadowPipeline::default();
    let camera = crate::backend::CameraFrame::default();
    let outer = pipeline.begin_world_context(0x1000, 0x2000, 0x3000, camera, camera);
    let outer_identity = pipeline
        .current_publication_identity(SceneKind::Exterior, 0)
        .expect("outer world context");
    let inner = pipeline.begin_world_context(0x4000, 0x5000, 0x6000, camera, camera);
    let inner_identity = pipeline
        .current_publication_identity(SceneKind::Exterior, 0)
        .expect("inner world context");
    assert_ne!(inner_identity.transaction, outer_identity.transaction);
    assert_eq!(inner_identity.color_surface, 0x4000);
    pipeline.end_world_context(inner);
    assert_eq!(
        pipeline.current_publication_identity(SceneKind::Exterior, 0),
        Some(outer_identity),
    );
    pipeline.end_world_context(outer);
    assert_eq!(
        pipeline
            .current_publication_identity(SceneKind::Exterior, 0)
            .expect("producer identity after receiver closes")
            .transaction,
        0,
    );
}

#[test]
fn receiver_workload_is_full_resolution_and_non_temporal() {
    let plan = DeferredReceiverPlan::new(3_440, 1_440).expect("ultrawide receiver plan");
    let output_pixels = 3_440_u64 * 1_440;
    assert_eq!((plan.width, plan.height), (3_440, 1_440));
    assert_eq!(plan.directional_pixels, output_pixels);
    assert_eq!(plan.point_pixels, output_pixels);
    assert_eq!(plan.history_pixels, 0);
}

#[test]
fn actor_crop_optimization_never_fails_the_shadow_transaction() {
    assert_eq!(
        actor_overlay_projection_plan(false, false, false, false),
        ActorOverlayProjectionPlan::NoWork,
    );
    assert_eq!(
        actor_overlay_projection_plan(true, false, true, true),
        ActorOverlayProjectionPlan::NoWork,
        "a depth-scheduled actor outside the retained projection has no overlay work",
    );
    for (bounds_valid, crop_valid) in [(false, false), (true, false)] {
        assert_eq!(
            actor_overlay_projection_plan(true, true, bounds_valid, crop_valid),
            ActorOverlayProjectionPlan::FullProjection,
            "invalid optional crop data must fall back to the complete cascade projection",
        );
    }
    assert_eq!(
        actor_overlay_projection_plan(true, true, true, true),
        ActorOverlayProjectionPlan::Cropped,
    );
}

#[test]
fn empty_interior_publication_performs_no_depth_or_color_transaction() {
    assert!(!consumer_has_shadow_work(false, 0));
    assert!(consumer_has_shadow_work(false, 1));
    assert!(consumer_has_shadow_work(true, 0));

    let no_visible_points = point_consumer_plan([None; NVR_POINT_LIGHT_COUNT], 12);
    assert!(no_visible_points.is_empty());
    assert_eq!(
        ShadowConsumerWorkPlan::new(false, no_visible_points),
        None,
        "selected but fully offscreen point lights admitted a color transaction"
    );
    let directional = ShadowConsumerWorkPlan::new(true, no_visible_points)
        .expect("directional composition remains visible without local lights");
    assert!(directional.has_directional_work());
    assert!(!directional.has_point_work());
}

#[test]
fn expensive_receiver_visibility_is_full_resolution_and_never_temporal() {
    let plan = DeferredReceiverPlan::new(3_440, 1_440).expect("ultrawide receiver plan");
    let output_pixels = 3_440_u64 * 1_440;

    assert_eq!(plan.width, 3_440);
    assert_eq!(plan.height, 1_440);
    assert_eq!(plan.directional_pixels, output_pixels);
    assert_eq!(plan.point_pixels, output_pixels);
    assert_eq!(
        plan.history_pixels, 0,
        "shadow masks must not trail the camera"
    );
    assert_eq!(plan.full_resolution_shadow_map_samples, output_pixels);
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
fn dynamic_and_experimental_sun_admission_are_independent() {
    let dynamic_exterior_only = ShadowSettings {
        enabled: true,
        exterior_enabled: true,
        interior_enabled: false,
        sun_shadows: false,
    };
    assert!(dynamic_exterior_only.point_enabled_for(SceneKind::Exterior));
    assert!(!dynamic_exterior_only.directional_enabled_for(SceneKind::Exterior));
    assert!(dynamic_exterior_only.enabled_for(SceneKind::BehavesLikeExterior));
    assert!(!dynamic_exterior_only.enabled_for(SceneKind::Interior));

    let interior_only = ShadowSettings {
        enabled: true,
        exterior_enabled: false,
        interior_enabled: true,
        sun_shadows: false,
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

    let sun_only = ShadowSettings {
        enabled: true,
        exterior_enabled: false,
        interior_enabled: false,
        sun_shadows: true,
    };
    assert!(!sun_only.point_enabled_for(SceneKind::Exterior));
    assert!(sun_only.directional_enabled_for(SceneKind::Exterior));
    assert!(sun_only.directional_enabled_for(SceneKind::BehavesLikeExterior));
    assert!(!sun_only.directional_enabled_for(SceneKind::Interior));
    assert!(sun_only.enabled_for(SceneKind::Exterior));
    assert!(!sun_only.enabled_for(SceneKind::Interior));
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
fn contact_filter_is_fused_into_the_existing_compositor() {
    let work = contact_consumer_work();
    assert_eq!(work.passes, 1);
    assert_eq!(work.texture_samples, 7);
}

#[test]
fn final_shadow_composition_uses_distinct_directional_and_local_identities() {
    let source = [0.8, 0.6, 0.4];
    let clear = source_owned_shadow_radiance(
        source,
        false,
        SceneKind::Exterior,
        0.0,
        1.0,
        [1.0; 3],
        [1.0; 3],
        1.0,
    )
    .expect("finite clear pixel");
    assert_eq!(clear, source);
    let receiver = source_owned_shadow_radiance(
        source,
        true,
        SceneKind::Exterior,
        0.5,
        0.8,
        [0.1; 3],
        [0.1; 3],
        0.5,
    )
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
        SceneKind::Interior,
        1.0,
        0.0,
        [0.4, 0.2, 0.0],
        [0.4, 0.2, 0.0],
        0.5,
    )
    .expect("finite local-light receiver");
    assert_eq!(result, [0.4, 0.35, 0.6]);
    let emitter = [3.0, 2.0, 1.2];
    assert_eq!(
        source_owned_shadow_radiance(
            emitter,
            true,
            SceneKind::Interior,
            0.0,
            1.0,
            [1.0; 3],
            [1.0; 3],
            1.0,
        ),
        Some(emitter)
    );
}

#[test]
fn nighttime_exterior_uses_the_same_full_range_as_interior_dynamic_shadows() {
    let source = [0.8, 0.7, 0.6];
    let fully_occluded = exterior_point_shadow_radiance(
        source,
        true,
        [0.0, 0.0, 1.0],
        SunCompetition::default(),
        [0.3; 3],
        [0.3; 3],
        1.0,
    )
    .expect("finite nighttime exterior receiver");
    assert_eq!(fully_occluded, [0.0; 3]);
    assert_eq!(
        exterior_point_shadow_radiance(
            source,
            true,
            [0.0, 0.0, 1.0],
            SunCompetition::default(),
            [0.3; 3],
            [0.3; 3],
            0.0,
        ),
        Some(source),
        "zero darkness must be exact identity"
    );
    assert_eq!(
        exterior_point_shadow_radiance(
            source,
            false,
            [0.0; 3],
            SunCompetition::default(),
            [0.3; 3],
            [0.3; 3],
            1.0,
        ),
        Some(source),
        "clear and sky pixels must not be darkened"
    );
}

#[test]
fn native_sun_competes_with_dynamic_occlusion_only_on_sun_facing_exteriors() {
    let source = [0.8, 0.7, 0.6];
    let total = [0.25; 3];
    let sun =
        SunCompetition::from_native([0.0, 0.0, 2.0], [1.0; 3], 1.0).expect("finite native sun");

    let rejected_global_attenuation = point_only_shadow_radiance(source, true, total, total, 1.0)
        .expect("finite rejected compositor");
    assert_eq!(rejected_global_attenuation, [0.0; 3]);

    let sun_facing =
        exterior_point_shadow_radiance(source, true, [0.0, 0.0, 1.0], sun, total, total, 1.0)
            .expect("finite sun-facing receiver");
    assert_eq!(sun_facing, source.map(|channel| channel * 0.8));
    assert!(
        sun_facing
            .into_iter()
            .zip(rejected_global_attenuation)
            .all(|(corrected, rejected)| corrected > rejected),
        "negative control did not reproduce sunlight being globally attenuated"
    );

    let back_facing =
        exterior_point_shadow_radiance(source, true, [0.0, 0.0, -1.0], sun, total, total, 1.0)
            .expect("finite back-facing receiver");
    assert_eq!(back_facing, rejected_global_attenuation);
}

#[test]
fn sunlight_competition_is_weather_colored_monotonic_and_finite() {
    let source = [1.0; 3];
    let point = [0.25; 3];
    let colored = SunCompetition::from_native([0.0, 0.0, 1.0], [1.0, 0.25, 0.0], 1.0)
        .expect("finite colored sun");
    let result =
        exterior_point_shadow_radiance(source, true, [0.0, 0.0, 1.0], colored, point, point, 1.0)
            .expect("finite colored competition");
    assert_eq!(result, [0.8, 0.5, 0.0]);
    assert!(
        result
            .into_iter()
            .all(|channel| (0.0..=1.0).contains(&channel))
    );

    let half_daylight =
        SunCompetition::from_native([0.0, 0.0, 1.0], [1.0; 3], 0.5).expect("finite sunset");
    let full_daylight =
        SunCompetition::from_native([0.0, 0.0, 1.0], [1.0; 3], 1.0).expect("finite midday");
    let sunset = exterior_point_shadow_radiance(
        source,
        true,
        [0.0, 0.0, 1.0],
        half_daylight,
        point,
        point,
        1.0,
    )
    .expect("finite sunset receiver");
    let midday = exterior_point_shadow_radiance(
        source,
        true,
        [0.0, 0.0, 1.0],
        full_daylight,
        point,
        point,
        1.0,
    )
    .expect("finite midday receiver");
    assert!(
        midday
            .into_iter()
            .zip(sunset)
            .all(|(day, dusk)| day >= dusk)
    );

    assert!(SunCompetition::from_native([0.0; 3], [1.0; 3], 1.0).is_none());
    assert!(SunCompetition::from_native([0.0, 0.0, 1.0], [f32::NAN; 3], 1.0).is_none());
}

#[test]
fn interior_darkness_controls_occluded_fraction_not_analytic_light_scale() {
    let source = [0.8, 0.7, 0.6];
    let bright_estimate = source_owned_shadow_radiance(
        source,
        true,
        SceneKind::Interior,
        1.0,
        0.0,
        [0.8, 0.6, 0.4],
        [0.4, 0.3, 0.2],
        0.5,
    )
    .expect("finite bright-light estimate");
    let dim_estimate = source_owned_shadow_radiance(
        source,
        true,
        SceneKind::Interior,
        1.0,
        0.0,
        [0.2, 0.15, 0.1],
        [0.1, 0.075, 0.05],
        0.5,
    )
    .expect("finite dim-light estimate");

    assert_eq!(
        bright_estimate, dim_estimate,
        "equal cube-proven occluded fractions must obey the same darkness setting regardless of the replacement light estimate's absolute scale"
    );
    assert_eq!(bright_estimate, [0.6, 0.525, 0.45000002]);
    let fully_occluded = source_owned_shadow_radiance(
        source,
        true,
        SceneKind::Interior,
        1.0,
        0.0,
        [0.2; 3],
        [0.2; 3],
        1.0,
    )
    .expect("finite fully occluded receiver");
    assert_eq!(
        fully_occluded, [0.0; 3],
        "maximum dynamic darkness must permit a fully occluded LDR receiver to reach black"
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
fn every_dirty_point_face_seeds_the_published_cube_from_static_depth() {
    let mut signatures = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    signatures[0] = PointMapSignature {
        identity: 0x1234,
        position: [0.0; 3],
        radius: 512.0,
        caster_signature: 1,
    };

    let initial = PointMapCache::default().plan(signatures, [0; NVR_POINT_LIGHT_COUNT], 1);
    assert_eq!(
        initial.face_operations(0, 0),
        [
            Some(PointFaceOperation::RefreshStatic),
            Some(PointFaceOperation::PublishStatic),
            None,
        ]
    );

    let mut animated_faces = [0; NVR_POINT_LIGHT_COUNT];
    animated_faces[0] = 1 << 2;
    let animated = initial.next.plan(signatures, animated_faces, 1);
    assert_eq!(
        animated.face_operations(0, 2),
        [
            None,
            Some(PointFaceOperation::PublishStatic),
            Some(PointFaceOperation::MergeAnimated),
        ],
        "animated refresh replaced the complete map instead of merging into it"
    );

    let departed = animated
        .next
        .plan(signatures, [0; NVR_POINT_LIGHT_COUNT], 1);
    assert_eq!(
        departed.face_operations(0, 2),
        [None, Some(PointFaceOperation::PublishStatic), None],
        "departed actor face was not restored to retained world depth"
    );
    assert_eq!(departed.face_operations(0, 6), [None; 3]);
    assert_eq!(
        departed.face_operations(NVR_POINT_LIGHT_COUNT, 0),
        [None; 3]
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
fn point_cube_cache_localizes_static_changes_only_with_an_exact_projection() {
    let mut signatures = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    signatures[0] = PointMapSignature {
        identity: 0x1234,
        position: [0.0; 3],
        radius: 512.0,
        caster_signature: 0xAABB,
    };
    let mut faces = [[0_u64; 6]; NVR_POINT_LIGHT_COUNT];
    faces[0] = [10, 20, 30, 40, 50, 60];

    let initial = PointMapCache::default().plan_with_static_faces(
        PointStaticFaceCache::default(),
        signatures,
        faces,
        [0; NVR_POINT_LIGHT_COUNT],
        1,
    );
    assert_eq!(initial.static_faces[0], 0x3f);

    let stable = initial.next.plan_with_static_faces(
        initial.next_static_faces,
        signatures,
        faces,
        [0; NVR_POINT_LIGHT_COUNT],
        1,
    );
    assert_eq!(stable.render_faces[0], 0);

    signatures[0].caster_signature = 0xCCDD;
    faces[0][0] += 1;
    let localized = stable.next.plan_with_static_faces(
        stable.next_static_faces,
        signatures,
        faces,
        [0; NVR_POINT_LIGHT_COUNT],
        1,
    );
    assert_eq!(localized.static_faces[0], 1);
    assert_eq!(localized.render_faces[0], 1);

    signatures[0].position[0] += 0.125;
    signatures[0].caster_signature = 0xEEFF;
    faces[0][1] += 1;
    let moved_projection = localized.next.plan_with_static_faces(
        localized.next_static_faces,
        signatures,
        faces,
        [0; NVR_POINT_LIGHT_COUNT],
        1,
    );
    assert_eq!(
        moved_projection.static_faces[0], 0x3f,
        "partial static refresh mixed two point-light projections in one cube"
    );
}

#[test]
fn point_static_face_cache_follows_physical_light_identity_across_reordering() {
    let mut current = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    current[0] = PointMapSignature {
        identity: 0x1000,
        position: [0.0; 3],
        radius: 128.0,
        caster_signature: 10,
    };
    current[1] = PointMapSignature {
        identity: 0x2000,
        position: [64.0, 0.0, 0.0],
        radius: 128.0,
        caster_signature: 20,
    };
    let mut faces = [[0_u64; 6]; NVR_POINT_LIGHT_COUNT];
    faces[0] = [1, 2, 3, 4, 5, 6];
    faces[1] = [11, 12, 13, 14, 15, 16];
    let initial = PointMapCache::default().plan_with_static_faces(
        PointStaticFaceCache::default(),
        current,
        faces,
        [0; NVR_POINT_LIGHT_COUNT],
        2,
    );

    let mut reordered = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    reordered[0] = current[1];
    reordered[1] = current[0];
    let mut reordered_faces = [[0_u64; 6]; NVR_POINT_LIGHT_COUNT];
    reordered_faces[0] = faces[1];
    reordered_faces[1] = faces[0];
    let stable = initial.next.plan_with_static_faces(
        initial.next_static_faces,
        reordered,
        reordered_faces,
        [0; NVR_POINT_LIGHT_COUNT],
        2,
    );

    assert_eq!(stable.render_faces[..2], [0, 0]);
    assert_eq!(stable.source_index(0), Some(1));
    assert_eq!(stable.source_index(1), Some(0));
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
fn point_shadow_presentation_fades_do_not_cancel_from_the_ratio() {
    assert_eq!(local_light_shadow_weight(0.0, 1.0), Some(0.0));
    assert_eq!(local_light_shadow_weight(1.0, 1.0), Some(0.0));
    assert_eq!(local_light_shadow_weight(0.5, 0.0), Some(0.0));
    let middle = local_light_shadow_weight(0.5, 0.5).expect("valid weight");
    assert!((middle - 0.5).abs() < 1.0e-6);

    let hidden = local_light_shadow_energy(0.8, 0.0, middle).expect("finite energy");
    let visible = local_light_shadow_energy(0.8, 1.0, middle).expect("finite energy");
    assert_eq!(
        hidden.0, 0.8,
        "presentation fade changed native light energy"
    );
    assert_eq!(visible.0, hidden.0);
    assert!((hidden.1 - 0.4).abs() < 1.0e-6);
    assert_eq!(visible.1, 0.0);
}

#[test]
fn point_cube_publishes_the_nearest_static_or_animated_caster() {
    let wall = 0.30;
    assert_eq!(
        point_caster_depth(wall, None),
        Some(wall),
        "a static-only face became an empty animated-only shadow map"
    );
    assert_eq!(
        point_caster_depth(wall, Some(0.50)),
        Some(wall),
        "an actor behind a wall replaced the nearer wall depth"
    );
    assert_eq!(
        point_caster_depth(wall, Some(0.20)),
        Some(0.20),
        "an actor in front of a wall failed to cast"
    );
    assert_eq!(point_caster_depth(1.0, Some(0.20)), Some(0.20));

    let far_receiver = 0.60;
    let wall_visibility =
        point_shadow_visibility(wall, far_receiver, 0.001).expect("finite wall comparison");
    assert_eq!(
        wall_visibility, 0.0,
        "a wall failed to occlude its far side"
    );
    let surface_visibility =
        point_shadow_visibility(wall, wall, 0.001).expect("finite surface comparison");
    assert_eq!(surface_visibility, 1.0, "the wall shadowed its own surface");
}

#[test]
fn replaced_point_cube_fades_in_without_restarting_each_publication() {
    let first = point_shadow_transition(0, 0, 0x1000, 10_000, 250).expect("new light");
    assert_eq!(first, (0x1000, 10_000, 0.0));
    let middle =
        point_shadow_transition(first.0, first.1, 0x1000, 10_125, 250).expect("stable light");
    assert!((middle.2 - 0.5).abs() < 1.0e-6);
    let complete =
        point_shadow_transition(middle.0, middle.1, 0x1000, 10_250, 250).expect("completed light");
    assert_eq!(complete.2, 1.0);
    let replacement = point_shadow_transition(complete.0, complete.1, 0x2000, 10_251, 250)
        .expect("replacement light");
    assert_eq!(replacement, (0x2000, 10_251, 0.0));

    let longer = point_shadow_transition(first.0, first.1, 0x1000, 10_250, 750)
        .expect("configurable transition");
    assert!(
        longer.2 < complete.2,
        "a longer configured duration must slow the same elapsed fade"
    );
    assert_eq!(
        point_shadow_transition(0, 0, 0x3000, 1, 0),
        Some((0x3000, 1, 1.0)),
        "a defensive zero duration must remain finite and immediate"
    );
}

#[test]
fn stationary_lamp_transition_advances_without_producer_republication() {
    let first = point_shadow_transition(0, 0, 0x1000, 10_000, 750).expect("new lamp");
    let consumer_weight = point_shadow_presentation_weight(
        [0.0, 0.0, 0.0],
        512.0,
        [0.0, 1.0, 0.0],
        NVR_POINT_DRAW_DISTANCE,
        first.2,
        first.1,
        10_375,
        750,
    )
    .expect("consumer weight");

    assert!(
        (consumer_weight - 0.5).abs() < 1.0e-6,
        "a stationary lamp froze at its producer weight instead of advancing on the consumer frame"
    );
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
fn point_cube_generation_never_exceeds_native_receiver_coverage() {
    assert_eq!(
        point_light_radii(400.0, 1.5),
        Some((400.0, 400.0)),
        "legacy generation headroom admitted casters outside every valid receiver ray"
    );
    assert_eq!(
        point_light_radii(400.0, 0.5),
        Some((400.0, 400.0)),
        "the compatibility multiplier may not truncate native receiver lighting"
    );
    assert!(point_light_radii(f32::NAN, 1.5).is_none());
    assert_eq!(
        point_light_radii(400.0, f32::INFINITY),
        Some((400.0, 400.0)),
        "compatibility-only radius data changed active rendering"
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
fn pip_boy_light_insertion_preserves_cube_and_metadata_ownership() {
    let mut initial = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    for (index, signature) in initial.iter_mut().enumerate() {
        *signature = PointMapSignature {
            identity: 0x1000 + index,
            position: [index as f32 * 10.0, 1.0, 2.0],
            radius: 300.0 + index as f32,
            caster_signature: 0xA000 + index as u64,
        };
    }
    let first = PointMapCache::default().plan(initial, [0; NVR_POINT_LIGHT_COUNT], 12);

    // Model a carried light entering nearest-first source order and displacing
    // only the former twelfth candidate. Retained physical slots must keep
    // their cube owners while every published metadata tuple follows the
    // source index assigned to that same slot.
    let mut with_pip_boy = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    with_pip_boy[0] = PointMapSignature {
        identity: 0xBEEF,
        position: [3.0, 4.0, 5.0],
        radius: 640.0,
        caster_signature: 0xCAFE,
    };
    with_pip_boy[1..].copy_from_slice(&initial[..NVR_POINT_LIGHT_COUNT - 1]);
    let inserted = first
        .next
        .plan(with_pip_boy, [0; NVR_POINT_LIGHT_COUNT], 12);

    let mut published_identities = [0usize; NVR_POINT_LIGHT_COUNT];
    for slot in 0..NVR_POINT_LIGHT_COUNT {
        let source = inserted
            .source_index(slot)
            .expect("occupied physical cube slot");
        assert_eq!(
            inserted.published[slot], with_pip_boy[source],
            "slot {slot} mixed one cube owner with another light's metadata"
        );
        published_identities[slot] = inserted.published[slot].identity;
        if inserted.published[slot].identity == 0xBEEF {
            assert_eq!(inserted.render_faces[slot], 0x3f);
        } else {
            assert_eq!(
                inserted.render_faces[slot], 0,
                "Pip-Boy admission unnecessarily rebuilt retained cube slot {slot}"
            );
        }
    }
    published_identities.sort_unstable();
    assert!(
        published_identities
            .windows(2)
            .all(|pair| pair[0] != pair[1]),
        "two physical slots claimed the same selected light"
    );
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
fn resource_plan_keeps_default_dynamic_exteriors_free_of_experimental_sun_work() {
    let dynamic_exterior = ProducerResourcePlan::quality_default(SceneKind::Exterior, 1920, 1080)
        .expect("valid dynamic exterior backbuffer");
    assert_eq!(dynamic_exterior.cascade_count, 0);
    assert_eq!(dynamic_exterior.directional_texture_count, 0);
    assert_eq!(dynamic_exterior.atlas_resolution, 0);
    assert_eq!(dynamic_exterior.directional_samples, 0);
    assert!(!dynamic_exterior.evsm4);
    assert_eq!(
        dynamic_exterior.point_light_count,
        NVR_POINT_LIGHT_COUNT as u32
    );
    assert_eq!(dynamic_exterior.point_cube_texture_count, 24);
    assert_eq!(dynamic_exterior.estimated_bytes, 201_809_920);

    let sun_settings = ShadowSettings {
        sun_shadows: true,
        ..ShadowSettings::default()
    };
    let exterior =
        ProducerResourcePlan::for_settings(sun_settings, SceneKind::Exterior, 1920, 1080)
            .expect("valid experimental sun backbuffer");
    assert_eq!(exterior.cascade_resolution, NVR_CASCADE_RESOLUTION);
    assert_eq!(exterior.cascade_count, CASCADE_COUNT as u32);
    assert_eq!(
        exterior.directional_texture_count, 6,
        "the atlas, full/strip resolves, and two actor maps must be included"
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
        exterior.estimated_bytes, 640_020_480,
        "the resource contract omitted a quality-preserving shadow resource"
    );
    assert!(exterior.estimated_bytes <= 664 * 1024 * 1024);
    assert_eq!(exterior.fallback_estimated_bytes, 669_380_608);
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
    assert_eq!(interior.estimated_bytes, 201_809_920);
    assert_eq!(interior.fallback_estimated_bytes, interior.estimated_bytes);
    assert!(interior.estimated_bytes <= 208 * 1024 * 1024);
    assert_eq!(
        interior.combined_estimated_bytes, dynamic_exterior.combined_estimated_bytes,
        "default dynamic-only branches retain one shared point resource family"
    );

    let sun_only = ShadowSettings {
        enabled: true,
        exterior_enabled: false,
        interior_enabled: false,
        sun_shadows: true,
    };
    let sun_only = ProducerResourcePlan::for_settings(sun_only, SceneKind::Exterior, 1920, 1080)
        .expect("valid sun-only resource plan");
    assert_eq!(sun_only.point_light_count, 0);
    assert_eq!(sun_only.point_cube_texture_count, 0);
    assert_eq!(sun_only.point_cube_resolution, 0);
    assert_eq!(sun_only.point_resource_estimated_bytes, 0);
    assert_eq!(sun_only.cascade_count, CASCADE_COUNT as u32);
}

#[test]
fn dynamic_quality_tiers_share_exact_point_resource_and_fill_contracts() {
    use crate::config::DynamicShadowQuality;

    let settings = ShadowSettings::default();
    let tiers = [
        (DynamicShadowQuality::Performance, 256, 38_010_880),
        (DynamicShadowQuality::High, 512, 152_043_520),
        (DynamicShadowQuality::Ultra, 1024, 608_174_080),
    ];
    let mut previous_face_pixels = None;
    for (quality, resolution, point_bytes) in tiers {
        let exterior = ProducerResourcePlan::for_settings_and_dynamic_quality(
            settings,
            quality,
            SceneKind::Exterior,
            1920,
            1080,
        )
        .expect("valid exterior dynamic-shadow plan");
        let interior = ProducerResourcePlan::for_settings_and_dynamic_quality(
            settings,
            quality,
            SceneKind::Interior,
            1920,
            1080,
        )
        .expect("valid interior dynamic-shadow plan");

        assert_eq!(exterior.point_cube_resolution, resolution);
        assert_eq!(interior.point_cube_resolution, resolution);
        assert_eq!(exterior.point_resource_estimated_bytes, point_bytes);
        assert_eq!(interior.point_resource_estimated_bytes, point_bytes);
        assert_eq!(exterior.point_cube_texture_count, 24);
        assert_eq!(interior.point_cube_texture_count, 24);

        let face_pixels = u64::from(resolution).pow(2);
        if let Some(previous) = previous_face_pixels {
            assert_eq!(face_pixels, previous * 4);
        }
        previous_face_pixels = Some(face_pixels);
    }
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
