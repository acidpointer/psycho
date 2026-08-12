//! Executable image and workload contracts for the shadow replacement.
//!
//! These tests deliberately operate on pixels, world-space cross sections,
//! cascade publications, and fragment counts. Source-text assertions cannot
//! detect a wrong blend identity, a camera-following occluder, a stale map, or
//! an HDR emitter that was darkened, so none of those properties are specified
//! as "this Rust/HLSL string exists" checks here.

use super::contract::{
    CascadeDirty, CascadeScheduler, NVR_CASCADE_RESOLUTION, NVR_POINT_LIGHT_COUNT, PointMapCache,
    PointMapSignature, cascade_sphere_selection, contact_depths_match, contact_history_visibility,
    depth_sample_is_geometry, first_person_caster_is_excluded, interior_shadow_factor,
    point_consumer_plan, point_geometry_plan, point_light_scissor, practical_cascade_splits,
    retained_cascade_needs_refresh, shadow_receiver_is_world_surface, skinned_position_reference,
    skinned_submission_is_available, source_owned_shadow_radiance, sun_projection_needs_refresh,
};
use super::math::{ShadowCamera, cascade_projection};
use super::pipeline::consumer_selection_spheres;

const EPSILON: f32 = 1.0e-5;

#[derive(Clone, Copy, Debug, PartialEq)]
struct Rgb([f32; 3]);

impl Rgb {
    const BLACK: Self = Self([0.0; 3]);

    fn scale(self, factor: f32) -> Self {
        Self(self.0.map(|channel| channel * factor))
    }

    fn add(self, other: Self) -> Self {
        Self(std::array::from_fn(|axis| self.0[axis] + other.0[axis]))
    }

    fn subtract_saturating(self, other: Self) -> Self {
        Self(std::array::from_fn(|axis| {
            (self.0[axis] - other.0[axis]).max(0.0)
        }))
    }

    fn max_abs_difference(self, other: Self) -> f32 {
        self.0
            .into_iter()
            .zip(other.0)
            .map(|(left, right)| (left - right).abs())
            .fold(0.0, f32::max)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiverLayer {
    Opaque,
    Emissive,
    Sky,
}

#[derive(Clone, Copy, Debug)]
struct ReferencePixel {
    layer: ReceiverLayer,
    /// Lighting which no shadow map owns: ambient, emission, and reflection.
    independent: Rgb,
    /// Direct sun energy already present in native scene color.
    sun: Rgb,
    /// Direct selected-point-light energy already present in native scene color.
    local: Rgb,
}

impl ReferencePixel {
    fn native_color(self) -> Rgb {
        self.independent.add(self.sun).add(self.local)
    }
}

/// Physically meaningful source-owned composition used as the image oracle.
fn reference_shadow_composite(
    pixel: ReferencePixel,
    sun_visibility: f32,
    local_visibility: f32,
) -> Rgb {
    if pixel.layer == ReceiverLayer::Sky {
        return pixel.native_color();
    }
    pixel
        .independent
        .add(pixel.sun.scale(sun_visibility.clamp(0.0, 1.0)))
        .add(pixel.local.scale(local_visibility.clamp(0.0, 1.0)))
}

/// Exact result of the rejected two-blend consumer for one pixel.
///
/// The directional pass emits white for non-geometry because white is neutral
/// for destination-color multiplication. The point pass currently reuses that
/// same shader result with reverse subtraction, where white is *maximum* work.
fn rejected_two_blend_composite(
    pixel: ReferencePixel,
    raw_depth: f32,
    sun_factor: Rgb,
    point_output: Rgb,
) -> Rgb {
    let geometry = depth_sample_is_geometry(raw_depth, 1.0 / 65_536.0);
    let directional_output = if geometry { sun_factor } else { Rgb([1.0; 3]) };
    // D3DBLEND_DESTCOLOR/ZERO multiplies the destination. The following
    // ONE/ONE/REVSUBTRACT computes max(destination - source, 0).
    pixel
        .native_color()
        .scale(directional_output.0[0])
        .subtract_saturating(point_output)
}

#[test]
fn clear_and_finite_sky_are_neutral_under_an_exterior_point_light() {
    let sky = ReferencePixel {
        layer: ReceiverLayer::Sky,
        independent: Rgb([0.21, 0.43, 0.86]),
        sun: Rgb::BLACK,
        local: Rgb::BLACK,
    };
    let expected = reference_shadow_composite(sky, 0.0, 0.0);

    // Clear depth is the deterministic Pip-Boy failure: the shared compositor
    // returns directional-neutral white, then reverse subtraction interprets
    // it as a full-strength local shadow.
    let clear_depth_result = rejected_two_blend_composite(sky, 1.0, Rgb([1.0; 3]), Rgb([1.0; 3]));
    assert!(clear_depth_result.max_abs_difference(expected) > 0.5);
    let clear_receiver = shadow_receiver_is_world_surface(1.0, 10_000.0, 10_000.0, 1.0 / 65_536.0);
    let fixed_clear = Rgb(source_owned_shadow_radiance(
        sky.native_color().0,
        clear_receiver,
        0.0,
        1.0,
        [1.0; 3],
        [1.0; 3],
        1.0,
    )
    .expect("finite source-owned composition"));
    assert_eq!(fixed_clear, expected);

    // Finite-depth sky is an independent negative control. A depth-only
    // receiver classifier cannot distinguish this mesh from opaque geometry;
    // composition therefore needs explicit layer/source ownership.
    let finite_depth_result =
        rejected_two_blend_composite(sky, 0.42, Rgb([0.35; 3]), Rgb([0.28; 3]));
    assert!(finite_depth_result.max_abs_difference(expected) > 0.25);
    let finite_sky_receiver =
        shadow_receiver_is_world_surface(0.42, 9_900.0, 10_000.0, 1.0 / 65_536.0);
    assert!(!finite_sky_receiver);
    assert!(shadow_receiver_is_world_surface(
        0.42,
        2_000.0,
        10_000.0,
        1.0 / 65_536.0,
    ));
    let fixed_finite = Rgb(source_owned_shadow_radiance(
        sky.native_color().0,
        finite_sky_receiver,
        0.35,
        1.0,
        [0.28; 3],
        [0.28; 3],
        1.0,
    )
    .expect("finite source-owned composition"));
    assert_eq!(fixed_finite, expected);
}

#[test]
fn interior_shadowing_preserves_emitters_and_removes_only_occluded_direct_energy() {
    let wall = ReferencePixel {
        layer: ReceiverLayer::Opaque,
        independent: Rgb([0.12, 0.10, 0.08]),
        sun: Rgb::BLACK,
        local: Rgb([0.70, 0.50, 0.30]),
    };
    let lamp = ReferencePixel {
        layer: ReceiverLayer::Emissive,
        independent: Rgb([3.5, 2.4, 1.2]),
        sun: Rgb::BLACK,
        local: Rgb::BLACK,
    };

    let shadowed_wall = reference_shadow_composite(wall, 1.0, 0.0);
    assert_eq!(shadowed_wall, wall.independent);
    let shadowed_lamp = reference_shadow_composite(lamp, 1.0, 0.0);
    assert_eq!(shadowed_lamp, lamp.independent);
    assert!(
        shadowed_lamp.0[0] > 1.0,
        "HDR emission was clipped or masked"
    );

    // The existing scalar deficit has no source-color ownership. Applying it
    // to the complete scene necessarily scales unrelated HDR emission.
    let scalar = interior_shadow_factor(0.0, 1.0, 0.8).expect("finite factor");
    let rejected_lamp = lamp.native_color().scale(scalar);
    assert!(rejected_lamp.max_abs_difference(shadowed_lamp) > 2.0);
    let fixed_lamp = Rgb(source_owned_shadow_radiance(
        lamp.native_color().0,
        true,
        1.0,
        0.0,
        [1.0; 3],
        [1.0; 3],
        0.8,
    )
    .expect("finite HDR composition"));
    assert_eq!(fixed_lamp, lamp.native_color());
}

#[test]
fn adding_a_pip_boy_light_cannot_make_an_exterior_sun_shadow_darker() {
    let without_local =
        source_owned_shadow_radiance([0.30; 3], true, 0.20, 1.0, [0.0; 3], [0.0; 3], 1.0)
            .expect("finite sun-only composition");
    let with_occluded_local =
        source_owned_shadow_radiance([0.80; 3], true, 0.20, 1.0, [0.50; 3], [0.50; 3], 1.0)
            .expect("finite mixed-light composition");

    for channel in 0..3 {
        assert!(
            with_occluded_local[channel] + EPSILON >= without_local[channel],
            "enabling a local source destroyed sun-owned energy in channel {channel}"
        );
    }
}

#[test]
fn multiple_interior_lights_cannot_subtract_unowned_ambient_energy() {
    let ambient = [0.12, 0.10, 0.08];
    let local = [0.70, 0.50, 0.30];
    let source = std::array::from_fn(|axis| ambient[axis] + local[axis]);
    // Two overlapping cube estimates can exceed the native direct-light term
    // because their analytic attenuation is not the engine material shader.
    let rejected =
        source_owned_shadow_radiance(source, true, 1.0, 0.0, local, [1.10, 0.90, 0.70], 1.0)
            .expect("finite interior composition");
    for axis in 0..3 {
        assert!(
            rejected[axis] + EPSILON >= ambient[axis],
            "local-light estimation removed ambient channel {axis}"
        );
    }
}

#[test]
fn differently_colored_lights_keep_independent_occlusion_channels() {
    let source = [0.75, 0.22, 0.65];
    let local_total = [0.60, 0.10, 0.50];
    // Only the red light is occluded. A scalar visibility reconstructed from
    // combined luminance would incorrectly subtract green and blue energy.
    let result =
        source_owned_shadow_radiance(source, true, 1.0, 0.0, local_total, [0.60, 0.0, 0.0], 1.0)
            .expect("finite colored-light composition");
    assert!((result[0] - 0.15).abs() < EPSILON);
    assert!((result[1] - source[1]).abs() < EPSILON);
    assert!((result[2] - source[2]).abs() < EPSILON);
}

#[test]
fn fog_and_volumetric_scattering_are_composed_after_surface_shadows() {
    let surface = Rgb([0.80, 0.65, 0.50]);
    let scattering = Rgb([0.22, 0.30, 0.38]);
    let transmittance = 0.35;
    let shadow = 0.25;

    let expected = surface.scale(shadow).scale(transmittance).add(scattering);
    let rejected = surface.scale(transmittance).add(scattering).scale(shadow);
    assert!(
        expected.max_abs_difference(rejected) > 0.20,
        "negative control did not darken in-scattered fog"
    );
    assert!(
        expected
            .0
            .into_iter()
            .zip(scattering.0)
            .all(|(final_channel, fog)| final_channel >= fog),
        "a surface shadow may attenuate transmitted surface radiance, never additive fog radiance"
    );
}

/// World-space 2-D visibility oracle for a receiver/light cross section.
fn ray_visibility(receiver: [f32; 2], light: [f32; 2], blockers: &[([f32; 2], [f32; 2])]) -> f32 {
    let direction = [light[0] - receiver[0], light[1] - receiver[1]];
    for &(minimum, maximum) in blockers {
        let mut enter = 0.0_f32;
        let mut exit = 1.0_f32;
        for axis in 0..2 {
            if direction[axis].abs() <= 1.0e-6 {
                if receiver[axis] < minimum[axis] || receiver[axis] > maximum[axis] {
                    enter = 1.0;
                    exit = 0.0;
                }
                continue;
            }
            let inverse = 1.0 / direction[axis];
            let first = (minimum[axis] - receiver[axis]) * inverse;
            let second = (maximum[axis] - receiver[axis]) * inverse;
            enter = enter.max(first.min(second));
            exit = exit.min(first.max(second));
        }
        if exit >= enter && exit > 0.001 && enter < 0.999 {
            return 0.0;
        }
    }
    1.0
}

fn contact_profile(camera_x: f32, blockers: &[([f32; 2], [f32; 2])]) -> [f32; 81] {
    std::array::from_fn(|index| {
        // Camera motion changes sampling phase only. Receiver/light/blocker
        // geometry remains in world space, which is the stability contract.
        let screen_x = index as f32 / 80.0 * 8.0 - 4.0;
        let receiver_x = screen_x + camera_x;
        ray_visibility([receiver_x, 0.0], [0.0, 5.0], blockers)
    })
}

#[test]
fn contact_shadow_oracle_is_empty_on_a_plane_localized_by_a_small_caster_and_camera_stable() {
    let plane = contact_profile(0.0, &[]);
    assert!(plane.into_iter().all(|visibility| visibility == 1.0));

    let blocker = [([-0.10, 0.04], [0.10, 0.55])];
    let centered = contact_profile(0.0, &blocker);
    let shifted = contact_profile(0.025, &blocker);
    let occluded = centered.into_iter().filter(|value| *value == 0.0).count();
    assert!(
        (1..=8).contains(&occluded),
        "contact evidence spread across {occluded} pixels"
    );
    let changed = centered
        .into_iter()
        .zip(shifted)
        .filter(|(left, right)| left != right)
        .count();
    assert!(
        changed <= 2,
        "sub-pixel camera motion changed {changed} contact pixels"
    );

    // The rejected map-center refinement has no screen-depth occluder input.
    // With a fully lit directional map it cannot reveal this omitted caster.
    let rejected = [1.0_f32; 81];
    assert_ne!(
        centered, rejected,
        "contact implementation is functionally invisible for small omitted casters"
    );
}

#[test]
fn contact_history_bounds_blinking_and_rejects_disocclusion_lines() {
    let stable = contact_history_visibility(0.0, 800.0, 1.0, 800.5, true)
        .expect("same-surface contact history");
    assert!(
        stable >= 0.70,
        "one screen-depth miss changed stable visibility by more than 0.30"
    );

    let disoccluded =
        contact_history_visibility(0.85, 200.0, 0.0, 900.0, true).expect("finite disocclusion");
    assert_eq!(
        disoccluded, 0.85,
        "history from a different wall produced a camera-following line"
    );
    assert!(contact_depths_match(800.0, 801.5));
    assert!(
        !contact_depths_match(800.0, 810.0),
        "a ten-unit foreground edge was treated as one filterable receiver"
    );
}

#[test]
fn skinned_partitions_do_not_depend_on_the_static_geometry_buffer() {
    assert!(
        skinned_submission_is_available(false, true),
        "an actor partition with its own prepared buffer was discarded"
    );
    assert!(!skinned_submission_is_available(true, false));
}

#[test]
fn first_person_ancestry_excludes_unflagged_hands_and_weapons() {
    assert!(first_person_caster_is_excluded(true, false));
    assert!(
        first_person_caster_is_excluded(false, true),
        "the engine does not maintain NVR's private first-person shade flag"
    );
    assert!(!first_person_caster_is_excluded(false, false));
}

#[test]
fn contact_range_does_not_collapse_to_the_two_hundred_unit_near_split() {
    let splits = practical_cascade_splits(5.0, 28_000.0, 6_000.0, 0.9).expect("NVR partition");
    assert!(splits[0].far < 300.0);
    let effective = super::contract::effective_contact_distance(180_000.0, 28_000.0)
        .expect("camera-bounded contact range");
    assert!(effective > splits[0].far * 100.0);
}

#[test]
fn actor_skinning_raster_preserves_partition_silhouette_and_world_translation() {
    let bones = [
        [
            [1.0, 0.0, 0.0, 5.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
        ],
        [
            [1.0, 0.0, 0.0, 7.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
        ],
    ];
    let vertices = [
        [-0.5, 0.0, 0.0],
        [0.5, 0.0, 0.0],
        [-0.5, 2.0, 0.0],
        [0.5, 2.0, 0.0],
    ];
    let skinned = vertices.map(|position| {
        skinned_position_reference(position, [0, 1, 0, 1], [0.5, 0.0, 0.0], &bones)
            .expect("valid actor vertex")
    });
    let minimum_x = skinned
        .into_iter()
        .map(|vertex| vertex[0])
        .fold(f32::INFINITY, f32::min);
    let maximum_x = skinned
        .into_iter()
        .map(|vertex| vertex[0])
        .fold(f32::NEG_INFINITY, f32::max);
    let minimum_y = skinned
        .into_iter()
        .map(|vertex| vertex[1])
        .fold(f32::INFINITY, f32::min);
    let maximum_y = skinned
        .into_iter()
        .map(|vertex| vertex[1])
        .fold(f32::NEG_INFINITY, f32::max);
    assert!((minimum_x - 5.5).abs() <= EPSILON);
    assert!((maximum_x - 6.5).abs() <= EPSILON);
    assert!((maximum_y - minimum_y - 2.0).abs() <= EPSILON);
}

#[test]
fn thin_caster_coverage_requires_nvrs_four_generation_samples() {
    // This projected sliver crosses only the upper-right quarter of one map
    // pixel. A center-only producer records no caster at all; filtering that
    // empty moment later cannot reconstruct the missing silhouette.
    let inside = |sample: [f32; 2]| sample[0] + sample[1] > 1.25;
    let center_coverage = inside([0.5, 0.5]) as u8 as f32;
    let nvr_samples = [
        [0.375, 0.125],
        [0.875, 0.375],
        [0.125, 0.625],
        [0.625, 0.875],
    ];
    let multisample_coverage = nvr_samples
        .into_iter()
        .map(|sample| inside(sample) as u8 as f32)
        .sum::<f32>()
        / nvr_samples.len() as f32;

    assert_eq!(
        center_coverage, 0.0,
        "negative control unexpectedly saw the sliver"
    );
    assert!(
        multisample_coverage > 0.0 && multisample_coverage < 1.0,
        "NVR coverage sampling must preserve a stable antialiased silhouette"
    );
}

#[test]
fn cascade_publication_tracks_motion_without_a_thirty_hertz_family_step() {
    let mut scheduler = CascadeScheduler::default();
    let initial = scheduler.plan_at_millis(CascadeDirty::all(), 0);
    scheduler.commit(initial);

    // A moving near actor/camera changes the receiver projection every 8.3 ms
    // at 120 FPS. Reusing all four maps until a 33 ms wall-clock deadline is
    // an observable four-frame step, not a stable cache.
    for now in [8, 16, 24] {
        let plan = scheduler.plan_at_millis(CascadeDirty::from_mask(1), now);
        assert!(plan.render[0], "near cascade was stale at {now} ms");
        assert!(
            plan.render[1..].iter().all(|render| !render),
            "near motion unnecessarily regenerated unrelated outer cascades at {now} ms"
        );
        scheduler.commit(plan);
    }

    let stationary = scheduler.plan_at_millis(CascadeDirty::none(), 1000);
    assert!(
        stationary.render.into_iter().all(|render| !render),
        "wall-clock cadence regenerated a stationary cascade family"
    );
}

#[test]
fn retained_directional_maps_never_accumulate_more_than_half_a_texel_of_sun_drift() {
    let previous = [1.0_f32, 0.0, 0.0];
    let radians = 1.0_f32.to_radians();
    let current = [radians.cos(), radians.sin(), 0.0];
    let chord = previous
        .into_iter()
        .zip(current)
        .map(|(left, right)| (left - right) * (left - right))
        .sum::<f32>()
        .sqrt();
    let projected_texels = chord * NVR_CASCADE_RESOLUTION as f32 * 0.5;

    // Negative control for the rejected dot(older, current) < 0.9998 rule.
    // It retains a one-degree-old projection even though the caster moves by
    // almost eighteen texels in that map, then replaces it in one visible
    // jump. This is the reported sun/angle-dependent shape instability.
    let rejected_refresh = previous
        .into_iter()
        .zip(current)
        .map(|(left, right)| left * right)
        .sum::<f32>()
        < 0.9998;
    assert!(!rejected_refresh, "negative control unexpectedly refreshed");
    assert!(projected_texels > 17.0);
    let refresh = sun_projection_needs_refresh(previous, current, NVR_CASCADE_RESOLUTION);
    assert!(
        refresh,
        "production retained a {projected_texels}-texel drift"
    );
    assert!(refresh || projected_texels <= 0.5);
}

#[test]
fn retained_far_map_covers_camera_translation_height_and_rotation_or_refreshes() {
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
        translation: [12_000.0, -4_000.0, 700.0],
        fov_compensation: 1.0,
    };
    let split =
        practical_cascade_splits(base.near, base.far, 6_000.0, 0.9).expect("NVR partition")[2];
    let sun = [0.4, 0.3, 0.866_025_4];
    let cached = cascade_projection(base, split, sun, NVR_CASCADE_RESOLUTION)
        .expect("cached far projection");
    let absolute_center = |camera: ShadowCamera, center: [f32; 3]| {
        std::array::from_fn(|axis| camera.translation[axis] + center[axis])
    };
    let cached_center = absolute_center(base, cached.center);

    let sub_guard = ShadowCamera {
        translation: [
            base.translation[0],
            base.translation[1],
            base.translation[2] + 1.0,
        ],
        ..base
    };
    let sub_guard_projection = cascade_projection(sub_guard, split, sun, NVR_CASCADE_RESOLUTION)
        .expect("small-height projection");
    assert!(!retained_cascade_needs_refresh(
        cached_center,
        cached.radius,
        absolute_center(sub_guard, sub_guard_projection.center),
        sub_guard_projection.receiver_radius,
        sun,
        sun,
        NVR_CASCADE_RESOLUTION,
    ));

    let raised = ShadowCamera {
        translation: [
            base.translation[0],
            base.translation[1],
            base.translation[2] + cached.receiver_radius * 0.08,
        ],
        ..base
    };
    let raised_projection =
        cascade_projection(raised, split, sun, NVR_CASCADE_RESOLUTION).expect("raised projection");
    assert!(retained_cascade_needs_refresh(
        cached_center,
        cached.radius,
        absolute_center(raised, raised_projection.center),
        raised_projection.receiver_radius,
        sun,
        sun,
        NVR_CASCADE_RESOLUTION,
    ));

    let angle = 8.0_f32.to_radians();
    let rotated = ShadowCamera {
        forward: [angle.cos(), angle.sin(), 0.0],
        right: [-angle.sin(), angle.cos(), 0.0],
        ..base
    };
    let rotated_projection = cascade_projection(rotated, split, sun, NVR_CASCADE_RESOLUTION)
        .expect("rotated projection");
    assert!(retained_cascade_needs_refresh(
        cached_center,
        cached.radius,
        absolute_center(rotated, rotated_projection.center),
        rotated_projection.receiver_radius,
        sun,
        sun,
        NVR_CASCADE_RESOLUTION,
    ));
}

#[test]
fn cascade_selection_follows_the_current_camera_slice_not_a_cached_map_center() {
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
    let splits =
        practical_cascade_splits(base.near, base.far, 6_000.0, 0.9).expect("NVR partition");
    let sun = [0.4, 0.3, 0.866_025_4];
    let base_projections = splits.map(|split| {
        cascade_projection(base, split, sun, NVR_CASCADE_RESOLUTION).expect("base cascade")
    });
    let moved = ShadowCamera {
        translation: [base_projections[0].receiver_radius * 0.035, 0.0, 0.0],
        ..base
    };
    let cached_spheres = std::array::from_fn(|index| {
        let projection = base_projections[index];
        [
            projection.center[0] - moved.translation[0],
            projection.center[1],
            projection.center[2],
            projection.radius,
        ]
    });
    let current_spheres =
        consumer_selection_spheres(moved, splits, sun).expect("consumer-camera selection spheres");

    let mut mismatch = None;
    for step in 0..=2_000 {
        let receiver = [step as f32 * splits[1].far / 2_000.0, 0.0, 0.0];
        let cached = cascade_sphere_selection(receiver, cached_spheres);
        let current = cascade_sphere_selection(receiver, current_spheres);
        if cached.map(|selection| selection.cascade) != current.map(|selection| selection.cascade) {
            mismatch = Some((receiver, cached, current));
            break;
        }
    }
    let (receiver, cached, current) =
        mismatch.expect("negative control must expose a cached-map selection boundary");
    let published = cascade_sphere_selection(receiver, current_spheres);
    assert_eq!(published, current);
    assert_ne!(published, cached);
}

#[test]
fn animated_point_casters_do_not_force_six_faces_per_light_per_frame() {
    let mut signatures = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
    signatures[0] = PointMapSignature {
        identity: 0x1234,
        position: [0.0, 0.0, 0.0],
        radius: 256.0,
    };
    let initial = PointMapCache::default().plan(signatures, [0; NVR_POINT_LIGHT_COUNT], 1);
    let mut dynamic = [0_u8; NVR_POINT_LIGHT_COUNT];
    dynamic[0] = 1 << 2;
    let animated = initial.next.plan(signatures, dynamic, 1);
    let rendered_faces = animated.render_faces[0].count_ones();

    // A compact actor bound normally touches one cube face and can straddle at
    // most a small neighboring set. Rebuilding all six faces is the rejected
    // producer lower bound; it dominates interiors before image-space work.
    assert!(
        rendered_faces <= 3,
        "one animated caster regenerated {rendered_faces} cube faces"
    );
}

#[test]
fn animated_near_actors_do_not_redraw_the_complete_static_cascade() {
    let mut scheduler = super::contract::CascadeScheduler::default();
    let initial = scheduler.plan_at_millis(super::contract::CascadeDirty::all(), 0);
    scheduler.commit(initial);

    // A changing actor silhouette affects the near map, but re-submitting the
    // terrain, buildings, and every static reference with it is exactly the
    // old NVR cost that OMV must avoid. The actor needs an independently
    // sampled overlay while the static map remains reusable.
    let work = super::contract::directional_caster_work(1, true);
    let actor_changed = scheduler.plan_at_millis(
        super::contract::CascadeDirty::from_mask(work.static_map_mask),
        1,
    );
    assert!(
        !actor_changed.render[0],
        "an animated near actor forced a complete 2048x2048 four-sample static-scene redraw"
    );
    assert!(work.near_actor_overlay);

    let overflow = super::contract::directional_caster_work(1, false);
    assert_eq!(overflow.static_map_mask, 1);
    assert!(!overflow.near_actor_overlay);
}

#[test]
fn ultrawide_point_shadow_work_is_bounded_by_light_coverage_not_light_batches() {
    let pixels = 3_440_u64 * 1_440;
    // Current maximum: two full-screen point batches plus directional and
    // point composite passes. This ignores the still more expensive cube-map
    // producer, so it is a conservative lower bound for the rejected frame.
    let rejected_fragments = pixels * 4;
    let budget = pixels * 2 + pixels / 2;
    assert!(
        rejected_fragments > budget,
        "negative control no longer exceeds the budget"
    );
    let local = point_light_scissor([0.0, 0.0, 10.0], 1.0, [-1.2, 1.2, 0.5, -0.5], 3_440, 1_440)
        .expect("visible local light")
        .pixels();
    // One combined source-owned composition plus three half-resolution
    // contact passes and the actual light rectangle.
    let optimized_fragments = pixels + 3 * pixels / 4 + local * 2;
    assert!(
        optimized_fragments <= budget,
        "coverage-bounded consumer schedules {optimized_fragments} fragments; budget is {budget}"
    );
}

#[test]
fn camera_containing_point_lights_share_depth_reconstruction_work() {
    let pixels = 3_440_u64 * 1_440;
    let frustum = [-1.2, 1.2, 0.5, -0.5];
    let rectangle = point_light_scissor([0.0, 0.0, 0.5], 256.0, frustum, 3_440, 1_440)
        .expect("camera lies inside the light");
    let per_light_fragments = rectangle.pixels() * NVR_POINT_LIGHT_COUNT as u64;
    assert_eq!(per_light_fragments, pixels * NVR_POINT_LIGHT_COUNT as u64);

    // A geometry prepass reconstructs depth/normal once, after which two
    // SM3-safe six-light batches cover all twelve cubes. Reconstructing the
    // same full-screen position six times remains a deterministic interior
    // bottleneck even when cube maps are perfectly cached.
    let plan = point_consumer_plan(
        [Some(rectangle); NVR_POINT_LIGHT_COUNT],
        NVR_POINT_LIGHT_COUNT,
    );
    assert_eq!(plan.fragment_count(), pixels * 2);
    let geometry = point_geometry_plan(
        [Some(rectangle); NVR_POINT_LIGHT_COUNT],
        NVR_POINT_LIGHT_COUNT,
    );
    assert_eq!(geometry.fragment_count(), pixels);
    let rejected_depth_fetches = pixels * 6 * 5;
    let shared_depth_and_geometry_fetches = geometry.fragment_count() * 5 + plan.fragment_count();
    assert!(
        shared_depth_and_geometry_fetches * 4 < rejected_depth_fetches,
        "shared receiver work regressed to repeated full-screen depth reconstruction"
    );
}

#[test]
fn projected_point_light_scissors_are_conservative_and_reduce_fragment_work() {
    let width = 3_440;
    let height = 1_440;
    let frustum = [-1.2, 1.2, 0.5, -0.5];
    let rectangle = point_light_scissor([0.0, 0.0, 10.0], 1.0, frustum, width, height)
        .expect("center light intersects the screen");
    assert!(rectangle.left < width / 2 && rectangle.right > width / 2);
    assert!(rectangle.top < height / 2 && rectangle.bottom > height / 2);
    assert!(rectangle.pixels() < u64::from(width) * u64::from(height) / 20);
    assert!(point_light_scissor([50.0, 0.0, 10.0], 1.0, frustum, width, height).is_none());

    let camera_inside = point_light_scissor([0.0, 0.0, 0.5], 1.0, frustum, width, height)
        .expect("camera lies inside light");
    assert_eq!(camera_inside.pixels(), u64::from(width) * u64::from(height));

    let left =
        point_light_scissor([-7.0, 0.0, 10.0], 0.5, frustum, width, height).expect("left light");
    let right =
        point_light_scissor([7.0, 0.0, 10.0], 0.5, frustum, width, height).expect("right light");
    let mut separated = [None; NVR_POINT_LIGHT_COUNT];
    separated[0] = Some(left);
    separated[1] = Some(right);
    let plan = point_consumer_plan(separated, 2);
    assert_eq!(plan.draws().count(), 2);
    assert_eq!(plan.fragment_count(), left.pixels() + right.pixels());
    let geometry = point_geometry_plan(separated, 2);
    assert_eq!(geometry.fragment_count(), left.pixels() + right.pixels());
}
