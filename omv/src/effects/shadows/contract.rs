//! Pure, deterministic contracts shared by the native shadow producer and its tests.
//!
//! This module intentionally contains no engine pointers, COM objects, locks,
//! allocation, or file I/O. Keeping policy and shadow math here makes the
//! reverse-engineered boundary executable on its own and prevents rendering
//! details from silently changing the contract.
//!
//! Several pure models are executable specifications used only by the test
//! build because the production path implements the same equations in HLSL or
//! native-pointer adapters. Retaining them is intentional contract evidence.

#![cfg_attr(not(test), allow(dead_code))]

/// Number of directional cascade maps published to the consumer.
pub(super) const CASCADE_COUNT: usize = 4;
/// NVR's highest custom-quality resolution for each cascade.
pub(super) const NVR_CASCADE_RESOLUTION: u32 = 2048;
/// Number of replacement point-light cube maps produced and sampled.
pub(super) const NVR_POINT_LIGHT_COUNT: usize = 12;
/// Bit mask containing all six D3D cube faces.
pub(super) const ALL_CUBE_FACES: u8 = 0x3f;
/// Supplied NVR custom-quality multiplier for point-light influence radius.
pub(super) const NVR_POINT_RADIUS_MULTIPLIER: f32 = 1.5;
/// Modern NVR's hard upper bound for tracked point-light influence.
pub(super) const NVR_POINT_DRAW_DISTANCE: f32 = 8_000.0;

const COMPLETE_CASCADE_MASK: u8 = (1 << CASCADE_COUNT) - 1;
const NVR_CASCADE_MIN_RADIUS_PIXELS: [f32; CASCADE_COUNT] = [1.0, 1.0, 10.0, 10.0];
const EVSM4_POSITIVE_EXPONENT_FP16: f32 = 5.54;
const EVSM4_NEGATIVE_EXPONENT: f32 = 5.0;
// A retained cube and its published light position are one transform pair.
// Sub-unit tolerance absorbs floating-point noise without allowing a carried
// Pip-Boy light to trail the player for several visible world units.
const POINT_POSITION_REFRESH_DISTANCE: f32 = 0.25;
/// Fixed linear-depth range represented by contact G16 values.
///
/// This covers the complete schema-one contact slider rather than the current
/// camera far plane, so a camera/FOV change cannot reinterpret retained data.
pub(super) const CONTACT_DEPTH_KEY_RANGE: f32 = 250_000.0;

/// Combine exterior map/contact-refined visibility with configured darkness.
///
/// Exterior directional and contact terms are both visibility values, so the
/// darker term wins before the configured darkness is applied. Interior point
/// data has different, two-channel semantics and must go through
/// [`interior_shadow_factor`]; returning `None` rejects accidental reuse of the
/// old global-darkening model.
pub(super) fn composite_shadow_factor(
    scene: SceneKind,
    directional_visibility: f32,
    contact_or_point_illumination: f32,
    darkness: f32,
) -> Option<f32> {
    if ![
        directional_visibility,
        contact_or_point_illumination,
        darkness,
    ]
    .into_iter()
    .all(f32::is_finite)
    {
        return None;
    }
    let darkness = darkness.clamp(0.0, 1.0);
    let directional_visibility = directional_visibility.clamp(0.0, 1.0);
    let local = contact_or_point_illumination.clamp(0.0, 1.0);
    let factor = match scene {
        SceneKind::Exterior | SceneKind::BehavesLikeExterior => {
            1.0 - darkness * (1.0 - directional_visibility.min(local))
        }
        SceneKind::Interior => return None,
    };
    Some(factor)
}

/// Attenuate only the point-light energy proven occluded by cube maps.
///
/// The native scene already contains ambient, emissive, and direct point-light
/// illumination. The point accumulator therefore publishes both the visible
/// contribution and the same lights' unoccluded contribution. Their positive
/// difference is the only energy the replacement may remove. In particular,
/// an unlit pixel (`0, 0`) remains unchanged instead of being globally
/// darkened merely because the interior effect is enabled.
pub(super) fn interior_shadow_factor(
    visible_local_light: f32,
    unoccluded_local_light: f32,
    darkness: f32,
) -> Option<f32> {
    if ![visible_local_light, unoccluded_local_light, darkness]
        .into_iter()
        .all(f32::is_finite)
    {
        return None;
    }
    let deficit = (unoccluded_local_light.max(0.0) - visible_local_light.max(0.0)).clamp(0.0, 1.0);
    Some(1.0 - darkness.clamp(0.0, 1.0) * deficit)
}

/// Model whether a skinned draw has the buffer which actually owns its vertices.
///
/// Kept as an executable contract because FNV stores actor vertex/index data on
/// each `NiSkinPartition::Partition`; the unrelated `NiGeometryData` buffer is
/// not a prerequisite for the NVR skinned submission route.
pub(super) const fn skinned_submission_is_available(
    _geometry_buffer_available: bool,
    partition_buffer_available: bool,
) -> bool {
    partition_buffer_available
}

/// Decide whether a caster belongs to the first-person view-model tree.
///
/// NVR publishes `NiShadeProperty::kFirstPerson` itself every fifty frames;
/// the engine does not guarantee that bit. A durable consumer must therefore
/// also honor explicit ancestry beneath `PlayerCharacter::firstPersonNiNode`.
pub(super) const fn first_person_caster_is_excluded(
    shader_flagged: bool,
    under_first_person_root: bool,
) -> bool {
    shader_flagged || under_first_person_root
}

/// Reject temporal reuse when only contact-receiver depth is available.
///
/// Equal receiver depth proves only that both frames contain the same wall or
/// ground plane. It cannot prove that the screen-depth ray hit the same
/// occluder. Blending such history leaves a dark trail after forward movement
/// or a fast yaw and delays a newly detected shadow. OMV therefore uses the
/// current ray estimate and stabilizes it spatially within the same frame.
pub(super) fn contact_history_visibility(
    current_visibility: f32,
    current_depth: f32,
    history_visibility: f32,
    history_depth: f32,
    history_valid: bool,
) -> Option<f32> {
    if ![
        current_visibility,
        current_depth,
        history_visibility,
        history_depth,
    ]
    .into_iter()
    .all(f32::is_finite)
        || current_depth <= 0.0
    {
        return None;
    }
    let current = current_visibility.clamp(0.0, 1.0);
    let _ = (history_visibility, history_depth, history_valid);
    Some(current)
}

/// Match contact evidence only when both samples own the same receiver.
///
/// The relative tolerance grows only with distance and retains a two-unit
/// floor for near geometry and FP16 depth quantization. Spatial and temporal
/// contact filtering use this same boundary so neither can bridge an edge.
pub(super) fn contact_depths_match(receiver_depth: f32, sample_depth: f32) -> bool {
    if !receiver_depth.is_finite()
        || !sample_depth.is_finite()
        || receiver_depth <= 0.0
        || sample_depth <= 0.0
    {
        return false;
    }
    let tolerance = (receiver_depth * 0.0025).max(2.0);
    (sample_depth - receiver_depth).abs() <= tolerance
}

/// Encode a linear contact-receiver depth for the half-float work targets.
///
/// The returned value is the exact scalar stored in the G channel. Keeping
/// this transform as a pure contract lets tests exercise representability and
/// reprojection at distances well beyond binary16's 65,504 finite limit.
pub(super) fn contact_depth_key(linear_depth: f32) -> Option<f32> {
    if !linear_depth.is_finite() || linear_depth <= 0.0 || linear_depth > CONTACT_DEPTH_KEY_RANGE {
        return None;
    }
    Some(linear_depth / CONTACT_DEPTH_KEY_RANGE)
}

/// Decode a contact key back to linear view depth.
pub(super) fn contact_depth_from_key(key: f32) -> Option<f32> {
    if !key.is_finite() || !(0.0..=1.0).contains(&key) || key == 0.0 {
        return None;
    }
    Some(key * CONTACT_DEPTH_KEY_RANGE)
}

/// Resolve the full-resolution scene-depth texel addressed by a point sample.
///
/// Contact generation runs at half resolution. Its interpolated UV therefore
/// often lies on a full-resolution texel boundary; reconstruction must use
/// the center of the texel whose depth value the point sampler actually read.
pub(super) fn point_sampled_texel_center(uv: [f32; 2], dimensions: [u32; 2]) -> Option<[f32; 2]> {
    if dimensions.into_iter().any(|value| value == 0)
        || !uv.into_iter().all(f32::is_finite)
        || uv.into_iter().any(|value| !(0.0..1.0).contains(&value))
    {
        return None;
    }
    Some(std::array::from_fn(|axis| {
        let extent = dimensions[axis] as f32;
        ((uv[axis] * extent).floor() + 0.5) / extent
    }))
}

/// Bound quantization error while extrapolating a rasterized receiver plane.
///
/// Device depth is affine over one triangle, but every sampled value is
/// quantized. A gradient inferred from immediate neighbours can accumulate one
/// depth level of uncertainty per extrapolated pixel. A fixed one-level test
/// consequently classifies distant planar walls as detached occluders. The
/// returned bound grows only with the sampled footprint and the actual depth
/// precision reported by the provider.
pub(super) fn contact_plane_raw_epsilon(
    geometric_epsilon: f32,
    sample_offset_pixels: [f32; 2],
    depth_levels: f32,
) -> Option<f32> {
    if !geometric_epsilon.is_finite()
        || geometric_epsilon < 0.0
        || !sample_offset_pixels.into_iter().all(f32::is_finite)
        || !depth_levels.is_finite()
        || depth_levels < 1.0
    {
        return None;
    }
    let quantization =
        (2.0 + sample_offset_pixels[0].abs() + sample_offset_pixels[1].abs()) / depth_levels;
    Some(geometric_epsilon.max(quantization))
}

/// Depth-aware contact visibility for one full-resolution receiver.
///
/// Four half-resolution texels surround a full-resolution output coordinate.
/// Only samples whose encoded depth owns that receiver may contribute. This
/// is the CPU oracle for the compositor's branch-lazy bilateral upsample.
pub(super) fn contact_bilateral_visibility(
    receiver_depth: f32,
    samples: [[f32; 3]; 4],
) -> Option<f32> {
    if !receiver_depth.is_finite()
        || receiver_depth <= 0.0
        || !samples.iter().flatten().all(|value| value.is_finite())
        || samples.iter().any(|sample| sample[2] < 0.0)
    {
        return None;
    }
    let mut weighted_visibility = 0.0;
    let mut accepted_weight = 0.0;
    for [visibility, depth, weight] in samples {
        if contact_depths_match(receiver_depth, depth) {
            weighted_visibility += visibility.clamp(0.0, 1.0) * weight;
            accepted_weight += weight;
        }
    }
    (accepted_weight > 0.0).then(|| (weighted_visibility / accepted_weight).clamp(0.0, 1.0))
}

/// NVR contact-ray scale for one reconstructed view-space receiver.
pub(super) fn contact_ray_scale(view_position: [f32; 3], camera_far: f32) -> Option<f32> {
    if !view_position.into_iter().all(f32::is_finite)
        || !camera_far.is_finite()
        || camera_far <= 0.0
        || view_position[2] <= 0.0
    {
        return None;
    }
    let radial_depth = view_position
        .into_iter()
        .map(|value| value * value)
        .sum::<f32>()
        .sqrt();
    Some((radial_depth / camera_far).clamp(0.0001, 1.0).powf(0.6))
}

/// Classify one screen-depth ray hit against its receiver plane.
///
/// A true blocker must be behind the marched point but separated from the
/// receiver plane. A depth sample from the receiver itself is self-occlusion,
/// which otherwise becomes a large camera-dependent patch on planar walls.
pub(super) fn contact_sample_is_occluder(
    receiver: [f32; 3],
    receiver_normal: [f32; 3],
    marched: [f32; 3],
    sampled_scene: [f32; 3],
    thickness: f32,
) -> bool {
    if !receiver
        .into_iter()
        .chain(receiver_normal)
        .chain(marched)
        .chain(sampled_scene)
        .chain([thickness])
        .all(f32::is_finite)
        || thickness <= 0.0
    {
        return false;
    }
    let normal_length = receiver_normal
        .into_iter()
        .map(|value| value * value)
        .sum::<f32>()
        .sqrt();
    if !normal_length.is_finite() || normal_length <= 1.0e-6 {
        return false;
    }
    let plane_distance = (0..3)
        .map(|axis| (sampled_scene[axis] - receiver[axis]) * receiver_normal[axis] / normal_length)
        .sum::<f32>()
        .abs();
    let plane_epsilon = (receiver[2].abs() * 1.0e-5).max(0.5);
    let delta = marched[2] - sampled_scene[2];
    delta > 0.01 && delta < thickness && plane_distance > plane_epsilon
}

/// Return whether a directional-map projection lies inside its complete clip volume.
pub(super) fn directional_projection_is_sampleable(ndc: [f32; 3]) -> bool {
    ndc.into_iter().all(f32::is_finite)
        && (-1.0..=1.0).contains(&ndc[0])
        && (-1.0..=1.0).contains(&ndc[1])
        && (0.0..=1.0).contains(&ndc[2])
}

/// Fixed fragment workload of the half-resolution contact consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ContactConsumerWork {
    /// Fullscreen half-resolution draw count.
    pub(super) passes: u32,
    /// Executed texture reads per half-resolution output pixel.
    pub(super) texture_samples: u32,
}

/// Return the contact pass topology paired with the embedded shaders.
pub(super) const fn contact_consumer_work() -> ContactConsumerWork {
    ContactConsumerWork {
        passes: 2,
        // Receiver depth, two light-opposed plane neighbours, four NVR ray
        // taps, then the center plus four depth-aware spatial neighbours.
        texture_samples: 12,
    }
}

/// Compose shadow-owned radiance while preserving unrelated source energy.
///
/// `receiver` is false for clear/far-sky pixels. Directional visibility owns a
/// multiplicative surface term. `point_total` identifies the source-owned
/// local-light energy, and `point_deficit` is the subset proven occluded by a
/// cube. Restoring the local term after directional attenuation prevents a
/// Pip-Boy or lamp from being shadowed by the sun. HDR energy transitions to
/// full source preservation between one and 1.15, avoiding a hard temporal
/// discontinuity while remaining stricter than NVR's "re-add values above
/// one" rule.
pub(super) fn source_owned_shadow_radiance(
    source_linear: [f32; 3],
    receiver: bool,
    directional_visibility: f32,
    directional_darkness: f32,
    point_total: [f32; 3],
    point_deficit: [f32; 3],
    point_darkness: f32,
) -> Option<[f32; 3]> {
    if !source_linear
        .into_iter()
        .chain(point_total)
        .chain(point_deficit)
        .chain([directional_visibility, directional_darkness, point_darkness])
        .all(f32::is_finite)
        || source_linear.into_iter().any(|channel| channel < 0.0)
    {
        return None;
    }
    if !receiver {
        return Some(source_linear);
    }
    let directional =
        1.0 - directional_darkness.clamp(0.0, 1.0) * (1.0 - directional_visibility.clamp(0.0, 1.0));
    let shadowed: [f32; 3] = std::array::from_fn(|axis| {
        // The native framebuffer is the authority for how much energy exists.
        // Capping both estimates prevents an approximate replacement-light
        // model from subtracting ambient or creating energy.
        let owned_local = point_total[axis].max(0.0).min(source_linear[axis]);
        let deficit = point_deficit[axis].max(0.0).min(owned_local);
        let mixed = (source_linear[axis] * directional + owned_local * (1.0 - directional)
            - deficit * point_darkness.clamp(0.0, 1.0))
        .max(0.0);
        if directional_darkness > 0.0 {
            // Analytic NVR point attenuation is an estimate, while the native
            // framebuffer is authoritative. An overestimate may remove local
            // energy down to the sun-only result, never through that result
            // into ambient/emissive ownership.
            mixed.max(source_linear[axis] * directional)
        } else {
            mixed
        }
    });
    let peak = source_linear.into_iter().fold(0.0_f32, f32::max);
    let transition = ((peak - 1.0) / 0.15).clamp(0.0, 1.0);
    let emitter = transition * transition * (3.0 - 2.0 * transition);
    Some(std::array::from_fn(|axis| {
        shadowed[axis] + (source_linear[axis] - shadowed[axis]) * emitter
    }))
}

/// Apply NVR's receiver-side normal offset before directional projection.
///
/// Grazing surfaces need a larger offset than faces aimed at the sun. This is
/// a receiver correction, not a producer depth bias: a global map-space bias
/// cannot preserve the same world-space separation across four cascade radii.
pub(super) fn directional_receiver_position(
    position: [f32; 3],
    normal: [f32; 3],
    sun_direction: [f32; 3],
) -> Option<[f32; 3]> {
    if !position.into_iter().all(f32::is_finite)
        || !normal.into_iter().all(f32::is_finite)
        || !sun_direction.into_iter().all(f32::is_finite)
    {
        return None;
    }
    let normalize = |value: [f32; 3]| {
        let length_squared = value.into_iter().map(|axis| axis * axis).sum::<f32>();
        (length_squared.is_finite() && length_squared > 1.0e-12)
            .then(|| value.map(|axis| axis / length_squared.sqrt()))
    };
    let normal = normalize(normal)?;
    let sun = normalize(sun_direction)?;
    let facing = normal
        .into_iter()
        .zip(sun)
        .map(|(left, right)| left * right)
        .sum::<f32>();
    let scale = (1.0 - facing).clamp(0.0, 1.0);
    Some(std::array::from_fn(|axis| {
        position[axis] + normal[axis] * scale
    }))
}

/// Return whether a sampled hardware depth belongs to rendered geometry.
///
/// Fallout clears ordinary and reversed world-depth targets to opposite
/// endpoints. Linearizing either endpoint fabricates a far-plane position;
/// treating that position as geometry fabricates a far-plane receiver and can
/// turn sky or disocclusion pixels into false shadows.
pub(super) fn depth_sample_is_geometry(raw_depth: f32, endpoint_epsilon: f32) -> bool {
    raw_depth.is_finite()
        && endpoint_epsilon.is_finite()
        && endpoint_epsilon > 0.0
        && endpoint_epsilon < 0.5
        && raw_depth > endpoint_epsilon
        && raw_depth < 1.0 - endpoint_epsilon
}

/// Return whether light rotation has displaced a cached projection by more
/// than half a shadow texel.
///
/// For a cascade sphere of radius `r`, the chord between two unit light
/// vectors moves an extremal caster by at most `chord * r`. One texel spans
/// `2r / resolution`, so the radius cancels and the half-texel threshold is
/// exactly `chord > 1 / resolution`. Comparing with the light direction that
/// owns each cached map prevents small per-frame changes from accumulating
/// forever against a newer, unrelated direction.
pub(super) fn sun_projection_needs_refresh(
    cached_direction: [f32; 3],
    current_direction: [f32; 3],
    resolution: u32,
) -> bool {
    if resolution == 0
        || !cached_direction.into_iter().all(f32::is_finite)
        || !current_direction.into_iter().all(f32::is_finite)
    {
        return true;
    }
    let normalize = |value: [f32; 3]| {
        let length_squared = value.into_iter().map(|axis| axis * axis).sum::<f32>();
        (length_squared.is_finite() && length_squared > 1.0e-12)
            .then(|| value.map(|axis| axis / length_squared.sqrt()))
    };
    let (Some(cached), Some(current)) = (normalize(cached_direction), normalize(current_direction))
    else {
        return true;
    };
    let chord_squared = cached
        .into_iter()
        .zip(current)
        .map(|(left, right)| (left - right) * (left - right))
        .sum::<f32>();
    chord_squared > (1.0 / resolution as f32).powi(2)
}

/// Decide whether one retained cascade can still cover the current receiver.
///
/// `cached_center` and `current_center` are absolute world-space sphere
/// centers. The cached radius includes its producer guard band, while
/// `current_receiver_radius` is the unguarded sphere containing the current
/// frustum slice. The map remains usable only when it contains that complete
/// slice and its light direction has drifted by no more than half a texel.
pub(super) fn retained_cascade_needs_refresh(
    cached_center: [f32; 3],
    cached_radius: f32,
    current_center: [f32; 3],
    current_receiver_radius: f32,
    cached_sun: [f32; 3],
    current_sun: [f32; 3],
    resolution: u32,
) -> bool {
    if !cached_center.into_iter().all(f32::is_finite)
        || !current_center.into_iter().all(f32::is_finite)
        || !cached_radius.is_finite()
        || !current_receiver_radius.is_finite()
        || cached_radius <= 0.0
        || current_receiver_radius <= 0.0
    {
        return true;
    }
    let center_delta = cached_center
        .into_iter()
        .zip(current_center)
        .map(|(cached, current)| (cached - current) * (cached - current))
        .sum::<f32>()
        .sqrt();
    // Preserve one percent of the producer guard for floating-point and
    // half-texel boundary uncertainty. It is not an extra reuse margin.
    center_delta + current_receiver_radius > cached_radius * 0.99
        || sun_projection_needs_refresh(cached_sun, current_sun, resolution)
}

/// Urgency of one retained-cascade refresh.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct RetainedCascadeRefresh {
    /// The current receiver no longer fits in the cached projection.
    pub(super) mandatory: bool,
    /// The map is still safe to sample but should be refreshed soon.
    pub(super) quality: bool,
}

/// Classify retained-map refresh work without conflating validity and quality.
///
/// Receiver containment is mandatory; approaching the guard edge and a
/// half-texel sun drift are quality work which may be distributed across
/// presentations. This preserves valid coverage while preventing camera yaw
/// from submitting four expensive maps in one frame.
#[allow(clippy::too_many_arguments)]
pub(super) fn retained_cascade_refresh(
    cached_center: [f32; 3],
    cached_radius: f32,
    current_center: [f32; 3],
    current_receiver_radius: f32,
    cached_sun: [f32; 3],
    current_sun: [f32; 3],
    resolution: u32,
) -> RetainedCascadeRefresh {
    if !cached_center.into_iter().all(f32::is_finite)
        || !current_center.into_iter().all(f32::is_finite)
        || !cached_radius.is_finite()
        || !current_receiver_radius.is_finite()
        || cached_radius <= 0.0
        || current_receiver_radius <= 0.0
    {
        return RetainedCascadeRefresh {
            mandatory: true,
            quality: false,
        };
    }
    let center_delta = cached_center
        .into_iter()
        .zip(current_center)
        .map(|(cached, current)| (cached - current) * (cached - current))
        .sum::<f32>()
        .sqrt();
    let extent = center_delta + current_receiver_radius;
    let mandatory = extent > cached_radius * 0.99;
    // Start a bounded refresh while roughly half of the six-percent producer
    // guard is still available. That gives the scheduler several presentation
    // epochs to update all four maps before any cached projection becomes
    // unsafe, even during a fast camera yaw.
    let approaches_guard = extent > cached_radius * 0.965;
    let sun_drift = sun_projection_needs_refresh(cached_sun, current_sun, resolution);
    RetainedCascadeRefresh {
        mandatory,
        quality: !mandatory && (approaches_guard || sun_drift),
    }
}

/// Admit one directional receiver only inside the published cascade range.
///
/// Native sky meshes may write a finite, non-clear depth, so rejecting depth
/// endpoints alone is insufficient. The linearized receiver must also be a
/// finite positive point strictly inside the outer cascade split.
pub(super) fn shadow_receiver_is_valid(
    raw_depth: f32,
    view_depth: f32,
    outer_cascade_far: f32,
    endpoint_epsilon: f32,
) -> bool {
    depth_sample_is_geometry(raw_depth, endpoint_epsilon)
        && view_depth.is_finite()
        && outer_cascade_far.is_finite()
        && view_depth > 0.0
        && outer_cascade_far > 0.0
        && view_depth < outer_cascade_far
}

/// Classify native opaque-world depth independently of shadow distance.
///
/// FNV sky meshes can write a finite depth at the camera far plane. The
/// shared opaque-world convention treats the last 1.5 percent of view depth
/// as sky/background, matching OMV sun visibility and keeping a Pip-Boy or
/// point light from turning finite-depth sky into a receiver.
pub(super) fn shadow_receiver_is_world_surface(
    raw_depth: f32,
    view_depth: f32,
    camera_far: f32,
    endpoint_epsilon: f32,
) -> bool {
    depth_sample_is_geometry(raw_depth, endpoint_epsilon)
        && view_depth.is_finite()
        && camera_far.is_finite()
        && view_depth > 0.0
        && camera_far > 0.0
        && view_depth < camera_far * 0.985
}

/// Bound NVR's screen-depth contact ray to the live camera depth range.
///
/// Contact evidence is independent of cascade partitioning and remains useful
/// beyond the last map. The camera far plane is the largest reconstructable
/// depth; clamping to a near split (roughly 212 units at defaults) made the
/// configured 180,000-unit effect functionally disappear.
pub(super) fn effective_contact_distance(configured_distance: f32, camera_far: f32) -> Option<f32> {
    if !configured_distance.is_finite()
        || !camera_far.is_finite()
        || configured_distance <= 0.0
        || camera_far <= 0.0
    {
        return None;
    }
    Some(configured_distance.min(camera_far))
}

/// Combine map and contact evidence without coupling their distance ranges.
pub(super) fn directional_contact_visibility(
    view_depth: f32,
    outer_map_distance: f32,
    map_visibility: f32,
    contact_visibility: Option<f32>,
) -> Option<f32> {
    if ![view_depth, outer_map_distance, map_visibility]
        .into_iter()
        .all(f32::is_finite)
        || view_depth <= 0.0
        || outer_map_distance <= 0.0
        || contact_visibility.is_some_and(|value| !value.is_finite())
    {
        return None;
    }
    let map = if view_depth < outer_map_distance {
        map_visibility.clamp(0.0, 1.0)
    } else {
        1.0
    };
    Some(contact_visibility.map_or(map, |contact| map.min(contact.clamp(0.0, 1.0))))
}

/// Cumulative screen-depth ray positions emitted by modern NVR.
///
/// NVR advances its second sample from the first, then carries that position
/// into the next pair. The four actual comparisons are therefore at one,
/// three, six, and ten base steps, not one through four. Keeping these values
/// in the native upload contract makes the shader behavior directly testable.
pub(super) const fn nvr_contact_sample_offsets() -> [f32; 4] {
    [1.0, 3.0, 6.0, 10.0]
}

/// Suppress estimated direct-light subtraction on the emitting source.
///
/// Cube depth and reconstructed normals are least reliable at the light
/// origin. More importantly, the source's emissive appearance is not direct
/// irradiance that this post-process owns. The guard reaches full strength
/// outside eight percent of the selected light radius.
pub(super) fn local_light_source_guard(normalized_distance: f32) -> Option<f32> {
    if !normalized_distance.is_finite() || normalized_distance < 0.0 {
        return None;
    }
    let t = ((normalized_distance - 0.02) / 0.06).clamp(0.0, 1.0);
    Some(t * t * (3.0 - 2.0 * t))
}

/// Inclusive-exclusive pixel bounds for one conservative local-light draw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LightScissorRect {
    /// Leftmost affected pixel.
    pub(super) left: u32,
    /// Topmost affected pixel.
    pub(super) top: u32,
    /// One past the rightmost affected pixel.
    pub(super) right: u32,
    /// One past the bottommost affected pixel.
    pub(super) bottom: u32,
}

impl LightScissorRect {
    /// Number of fragments in the conservative rectangle.
    pub(super) const fn pixels(self) -> u64 {
        (self.right - self.left) as u64 * (self.bottom - self.top) as u64
    }

    fn union(self, other: Self) -> Self {
        Self {
            left: self.left.min(other.left),
            top: self.top.min(other.top),
            right: self.right.max(other.right),
            bottom: self.bottom.max(other.bottom),
        }
    }
}

/// Maximum cube samplers evaluated with one scene-depth receiver sampler.
///
/// Pixel shader model three exposes sixteen samplers. Scene depth occupies s0,
/// so all twelve NVR-quality point maps fit in one draw without reducing the
/// configured light count or repeating full-resolution receiver work.
pub(super) const POINT_CONSUMER_BATCH_SIZE: usize = NVR_POINT_LIGHT_COUNT;

/// One coverage-bounded point-light consumer draw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PointConsumerDraw {
    /// Source cube/light indices packed into shader slots zero through count.
    pub(super) indices: [u8; POINT_CONSUMER_BATCH_SIZE],
    /// Number of populated shader slots.
    pub(super) count: u8,
    /// Conservative union of every populated light sphere.
    pub(super) scissor: LightScissorRect,
}

impl PointConsumerDraw {
    const EMPTY: Self = Self {
        indices: [0; POINT_CONSUMER_BATCH_SIZE],
        count: 0,
        scissor: LightScissorRect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
    };
}

/// Fixed-capacity point-light draw schedule with no render-thread allocation.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointConsumerPlan {
    draws: [PointConsumerDraw; NVR_POINT_LIGHT_COUNT],
    len: usize,
}

impl PointConsumerPlan {
    /// Scheduled draws in submission order.
    pub(super) fn draws(self) -> impl Iterator<Item = PointConsumerDraw> {
        self.draws.into_iter().take(self.len)
    }

    /// Total scheduled scissor fragments before shader early-outs.
    pub(super) fn fragment_count(self) -> u64 {
        self.draws().map(|draw| draw.scissor.pixels()).sum()
    }
}

/// Batch overlapping point lights while keeping separated lights scissored.
///
/// Each draw reconstructs its receiver directly from scene depth and then uses
/// the remaining samplers for up to twelve shadow cubes. A batch is profitable
/// only when saved receiver reconstruction exceeds the extra per-light work
/// over the union. Area alone is insufficient: two adjacent disjoint lights
/// have `union == sum`, yet batching makes every covered pixel evaluate both
/// lights. The constants come from the compiled one/six/twelve-light programs
/// (238 shared receiver instructions and about 107 per active light).
pub(super) fn point_consumer_plan(
    scissors: [Option<LightScissorRect>; NVR_POINT_LIGHT_COUNT],
    count: usize,
) -> PointConsumerPlan {
    let mut plan = PointConsumerPlan {
        draws: [PointConsumerDraw::EMPTY; NVR_POINT_LIGHT_COUNT],
        len: 0,
    };
    let count = count.min(NVR_POINT_LIGHT_COUNT);
    let mut visible = [u8::MAX; NVR_POINT_LIGHT_COUNT];
    let mut visible_len = 0;
    for index in 0..count {
        if scissors[index].is_some() {
            visible[visible_len] = index as u8;
            visible_len += 1;
        }
    }
    // Nearest-light order is ideal for cube ownership but unrelated to screen
    // overlap. A tiny fixed-array insertion sort groups spatial neighbors so
    // two independent clusters can each share receiver reconstruction without
    // turning the empty rectangle between them into shader work.
    for index in 1..visible_len {
        let value = visible[index];
        let rectangle = scissors[value as usize].expect("visible light");
        let key = (
            u64::from(rectangle.left) + u64::from(rectangle.right),
            u64::from(rectangle.top) + u64::from(rectangle.bottom),
        );
        let mut insertion = index;
        while insertion > 0 {
            let previous = scissors[visible[insertion - 1] as usize].expect("visible light");
            let previous_key = (
                u64::from(previous.left) + u64::from(previous.right),
                u64::from(previous.top) + u64::from(previous.bottom),
            );
            if previous_key <= key {
                break;
            }
            visible[insertion] = visible[insertion - 1];
            insertion -= 1;
        }
        visible[insertion] = value;
    }

    const RECEIVER_WORK: u64 = 238;
    const PER_LIGHT_WORK: u64 = 107;
    let work = |rectangle: LightScissorRect, lights: u8| {
        rectangle.pixels() * (RECEIVER_WORK + PER_LIGHT_WORK * u64::from(lights))
    };
    let mut current = PointConsumerDraw::EMPTY;
    for source in visible.into_iter().take(visible_len) {
        let rectangle = scissors[source as usize].expect("visible light");
        if current.count == 0 {
            current.indices[0] = source;
            current.count = 1;
            current.scissor = rectangle;
            continue;
        }
        let combined_scissor = current.scissor.union(rectangle);
        let combined_count = current.count + 1;
        let combined_work = work(combined_scissor, combined_count);
        let separate_work = work(current.scissor, current.count) + work(rectangle, 1);
        if usize::from(combined_count) <= POINT_CONSUMER_BATCH_SIZE
            && combined_work <= separate_work
        {
            current.indices[current.count as usize] = source;
            current.count = combined_count;
            current.scissor = combined_scissor;
        } else {
            plan.draws[plan.len] = current;
            plan.len += 1;
            current = PointConsumerDraw::EMPTY;
            current.indices[0] = source;
            current.count = 1;
            current.scissor = rectangle;
        }
    }
    if current.count != 0 {
        plan.draws[plan.len] = current;
        plan.len += 1;
    }
    plan
}

/// Project a view-space point-light sphere into a conservative screen scissor.
///
/// The tangent slopes are the exact perspective extrema of a circle in the
/// `(axis, depth)` plane. A sphere intersecting the eye/near plane returns the
/// full screen because no smaller rectangle is conservative. Completely
/// off-screen spheres return `None`, avoiding both the draw and its depth
/// reconstruction work.
pub(super) fn point_light_scissor(
    view_position: [f32; 3],
    radius: f32,
    frustum: [f32; 4],
    width: u32,
    height: u32,
) -> Option<LightScissorRect> {
    if width == 0
        || height == 0
        || !view_position.into_iter().all(f32::is_finite)
        || !radius.is_finite()
        || radius <= 0.0
        || !frustum.into_iter().all(f32::is_finite)
        || frustum[1] <= frustum[0]
        || frustum[2] <= frustum[3]
    {
        return None;
    }
    let [x, y, z] = view_position;
    if z + radius <= 0.0 {
        return None;
    }
    if z <= radius {
        return Some(LightScissorRect {
            left: 0,
            top: 0,
            right: width,
            bottom: height,
        });
    }

    let tangent_slopes = |axis: f32| -> Option<[f32; 2]> {
        let denominator = z * z - radius * radius;
        let radical = (axis * axis + z * z - radius * radius).max(0.0).sqrt();
        let first = (axis * z - radius * radical) / denominator;
        let second = (axis * z + radius * radical) / denominator;
        (first.is_finite() && second.is_finite()).then_some([first.min(second), first.max(second)])
    };
    let horizontal = tangent_slopes(x)?;
    let vertical = tangent_slopes(y)?;
    let uv_left = (horizontal[0] - frustum[0]) / (frustum[1] - frustum[0]);
    let uv_right = (horizontal[1] - frustum[0]) / (frustum[1] - frustum[0]);
    // Screen V grows downward while view-space Y grows toward frustum top.
    let uv_top = (frustum[2] - vertical[1]) / (frustum[2] - frustum[3]);
    let uv_bottom = (frustum[2] - vertical[0]) / (frustum[2] - frustum[3]);
    if uv_right <= 0.0 || uv_left >= 1.0 || uv_bottom <= 0.0 || uv_top >= 1.0 {
        return None;
    }
    // Two pixels cover raster-center rules, half-texel convention, and the
    // normal reconstruction's immediate depth neighbors at the sphere edge.
    let to_min = |uv: f32, extent: u32| ((uv * extent as f32).floor() as i64 - 2).max(0) as u32;
    let to_max = |uv: f32, extent: u32| {
        ((uv * extent as f32).ceil() as i64 + 2).clamp(0, i64::from(extent)) as u32
    };
    let rectangle = LightScissorRect {
        left: to_min(uv_left, width),
        top: to_min(uv_top, height),
        right: to_max(uv_right, width),
        bottom: to_max(uv_bottom, height),
    };
    (rectangle.left < rectangle.right && rectangle.top < rectangle.bottom).then_some(rectangle)
}

/// CPU reference for FNV's four-influence skinned shadow position.
///
/// `BLENDINDICES` arrives through normalized `D3DCOLOR` semantics, whose byte
/// order is z, y, x, w in the NVR generation shader. The first three explicit
/// weights correspond to those reordered slots; the fourth is their residual.
pub(super) fn skinned_position_reference(
    position: [f32; 3],
    blend_indices: [u8; 4],
    blend_weights: [f32; 3],
    bone_matrices: &[[[f32; 4]; 3]],
) -> Option<[f32; 3]> {
    if !position.into_iter().all(f32::is_finite) || !blend_weights.into_iter().all(f32::is_finite) {
        return None;
    }
    let residual = 1.0 - blend_weights.into_iter().sum::<f32>();
    if residual < 0.0 {
        return None;
    }
    let indices = [
        blend_indices[2] as usize,
        blend_indices[1] as usize,
        blend_indices[0] as usize,
        blend_indices[3] as usize,
    ];
    let weights = [
        blend_weights[0],
        blend_weights[1],
        blend_weights[2],
        residual,
    ];
    let homogeneous = [position[0], position[1], position[2], 1.0];
    let mut result = [0.0; 3];
    for (index, weight) in indices.into_iter().zip(weights) {
        let matrix = bone_matrices.get(index)?;
        for axis in 0..3 {
            result[axis] += matrix[axis]
                .into_iter()
                .zip(homogeneous)
                .map(|(left, right)| left * right)
                .sum::<f32>()
                * weight;
        }
    }
    result.into_iter().all(f32::is_finite).then_some(result)
}

/// Decide whether one BS dismember skin partition contributes geometry.
///
/// The instance-wide renderable byte owns the complete skin. When a matching
/// extension entry exists its `Enabled` byte owns that partition. Missing
/// metadata is conservative and keeps geometry: dropping a body partition is
/// a visible hole, while the ordinary skin partition remains engine-valid.
pub(super) const fn dismember_partition_is_renderable(
    instance_renderable: bool,
    partition_enabled: Option<bool>,
) -> bool {
    instance_renderable
        && match partition_enabled {
            Some(enabled) => enabled,
            None => true,
        }
}

/// Receiver-side cascade choice paired with NVR's sphere-overlap blend.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CascadeSphereSelection {
    /// First (highest-resolution) cascade containing the receiver.
    pub(super) cascade: usize,
    /// Adjacent cascade sampled only in the outer ten-percent blend shell.
    pub(super) next: Option<usize>,
    /// Smooth blend weight toward `next`, or toward neutral after the LOD map.
    pub(super) blend: f32,
}

/// Select a receiver from the exact center/radius metadata owning each map.
///
/// Depth-only selection assumes every cached map still follows the current
/// camera slice. OMV intentionally reuses distant maps; their published
/// spheres are therefore the authoritative coverage test, as in modern NVR.
pub(super) fn cascade_sphere_selection(
    receiver: [f32; 3],
    spheres: [[f32; 4]; CASCADE_COUNT],
) -> Option<CascadeSphereSelection> {
    if !receiver.into_iter().all(f32::is_finite) {
        return None;
    }
    for (cascade, sphere) in spheres.into_iter().enumerate() {
        if !sphere.into_iter().all(f32::is_finite) || sphere[3] <= 0.0 {
            continue;
        }
        let distance = receiver
            .into_iter()
            .zip(sphere)
            .take(3)
            .map(|(value, center)| {
                let delta = value - center;
                delta * delta
            })
            .sum::<f32>()
            .sqrt();
        if distance >= sphere[3] {
            continue;
        }
        let edge_start = sphere[3] * 0.9;
        let normalized = ((distance - edge_start) / (sphere[3] - edge_start)).clamp(0.0, 1.0);
        let blend = normalized * normalized * (3.0 - 2.0 * normalized);
        return Some(CascadeSphereSelection {
            cascade,
            next: (blend > 0.0 && cascade + 1 < CASCADE_COUNT).then_some(cascade + 1),
            blend,
        });
    }
    None
}

/// Coarse cell classification used by independent shadow toggles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SceneKind {
    /// A normal exterior cell.
    Exterior,
    /// An interior whose engine flag requests exterior rendering behavior.
    BehavesLikeExterior,
    /// A normal interior cell.
    Interior,
}

/// Persisted master and location controls for the single Shadows effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ShadowSettings {
    /// Enables the effect as a whole.
    pub(super) enabled: bool,
    /// Enables directional and applicable point shadows in exterior-like cells.
    pub(super) exterior_enabled: bool,
    /// Enables replacement point shadows in interior cells.
    pub(super) interior_enabled: bool,
}

impl Default for ShadowSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            exterior_enabled: true,
            interior_enabled: true,
        }
    }
}

impl ShadowSettings {
    /// Return whether the effect is active for the classified current cell.
    pub(super) fn enabled_for(self, scene: SceneKind) -> bool {
        self.enabled
            && match scene {
                SceneKind::Exterior | SceneKind::BehavesLikeExterior => self.exterior_enabled,
                SceneKind::Interior => self.interior_enabled,
            }
    }

    /// Select the only legal ownership path through the common engine hook.
    ///
    /// Calling the original prefix also calls the native tail. Once the
    /// replacement owns the entry, it must bypass that prefix and invoke the
    /// tail itself exactly once. An unavailable replacement fails safely to
    /// the complete native prefix, even if a configuration toggle is active.
    pub(super) fn hook_action(
        self,
        scene: SceneKind,
        replacement_owned: bool,
        replacement_ready: bool,
    ) -> HookAction {
        if !replacement_owned || !self.enabled {
            HookAction::NativePrefix
        } else if !self.enabled_for(scene) {
            // A location toggle suppresses both OMV and native generation. It
            // needs no shader/resource readiness, so toggles remain exact
            // while deferred bytecode preparation is still completing.
            HookAction::TailOnly
        } else if replacement_ready {
            HookAction::ReplacementThenTail
        } else {
            HookAction::NativePrefix
        }
    }
}

/// Exclusive control-flow alternatives at `FalloutNV.exe + 0x00871290`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HookAction {
    /// Call the native prefix, which internally reaches the native tail.
    NativePrefix,
    /// Run the OMV producer and then call the native tail once.
    ReplacementThenTail,
    /// Suppress shadow production for this cell and call only the native tail.
    TailOnly,
}

impl HookAction {
    /// Number of explicit native-prefix calls made by this path.
    pub(super) const fn native_prefix_calls(self) -> u8 {
        match self {
            Self::NativePrefix => 1,
            Self::ReplacementThenTail | Self::TailOnly => 0,
        }
    }

    /// Number of explicit tail calls made outside the native prefix.
    pub(super) const fn explicit_tail_calls(self) -> u8 {
        match self {
            Self::NativePrefix => 0,
            Self::ReplacementThenTail | Self::TailOnly => 1,
        }
    }
}

/// Return whether a completed map publication may feed this presentation.
///
/// Kept as a pure predicate because producer and image-space callbacks are
/// separate engine transactions. Tests must cover their exact lifetime
/// relationship instead of relying on a live rendering observation.
pub(super) const fn publication_epoch_is_usable(published_epoch: u32, current_epoch: u32) -> bool {
    current_epoch == published_epoch || current_epoch == published_epoch.wrapping_add(1)
}

/// Return whether a publication can change any scene-color pixel.
///
/// An interior with no selected cube light has neither directional nor local
/// shadow evidence. Resolving depth, copying source color, and gamma round-
/// tripping that frame would be pure overhead and could perturb lamp values.
pub(super) const fn consumer_has_shadow_work(directional: bool, point_count: usize) -> bool {
    directional || point_count > 0
}

/// Split animated caster work from persistent directional-map work.
///
/// Rebuilding an NVR-quality cascade for actor animation resubmits terrain and
/// every static reference at 2048 with four coverage samples. When root
/// collection is complete, OMV renders actors into independent near, middle,
/// and far EVSM maps and keeps all static maps immutable. An overflow preserves
/// correctness by returning to complete-map rebuilds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DirectionalCasterWork {
    /// Animated-caster invalidations that still require complete map rebuilds.
    pub(super) static_map_mask: u8,
    /// Actor-capable cascades requiring private same-frame EVSM maps.
    pub(super) actor_overlay_mask: u8,
}

/// Plan directional actor work without dropping an unclassified root.
pub(super) const fn directional_caster_work(
    previous_dynamic_cascade_mask: u8,
    current_dynamic_cascade_mask: u8,
    complete_root_cache: bool,
) -> DirectionalCasterWork {
    let previous_dynamic_cascade_mask = previous_dynamic_cascade_mask & 0b0111;
    let current_dynamic_cascade_mask = current_dynamic_cascade_mask & 0b0111;
    // A retained map contains the last submitted actor silhouette. Crossing a
    // cascade boundary therefore dirties both sides: the new map needs the
    // actor and the old map must be regenerated without it. Current bounds
    // alone cannot remove an abandoned silhouette.
    let affected_cascades = previous_dynamic_cascade_mask | current_dynamic_cascade_mask;
    if complete_root_cache {
        DirectionalCasterWork {
            // Every actor-capable cascade has an independent overlay. Actor
            // animation and ownership transitions therefore never invalidate
            // terrain, buildings, or other immutable casters.
            static_map_mask: 0,
            // Every overlay is a same-frame publication, so an actor which
            // departed a cascade needs no clearing pass: not publishing that
            // slot makes its previous contents unreachable to the compositor.
            actor_overlay_mask: current_dynamic_cascade_mask,
        }
    } else {
        DirectionalCasterWork {
            static_map_mask: affected_cascades,
            actor_overlay_mask: 0,
        }
    }
}

/// Return whether an animated root can contribute to the current view.
///
/// The native traversal rejects an application-culled root before visiting any
/// children. Dynamic invalidation must use the same predicate or first-person
/// play pays for a full actor-only map whose third-person player root submits
/// no geometry.
pub(super) const fn directional_actor_root_is_active(
    is_dynamic_actor: bool,
    ni_av_object_flags: u32,
) -> bool {
    const APP_CULLED: u32 = 1 << 0;
    is_dynamic_actor && ni_av_object_flags & APP_CULLED == 0
}

/// Dirty causes that require one or more directional maps to be rebuilt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CascadeDirty {
    mask: u8,
}

impl CascadeDirty {
    /// A fully dirty shadow graph, used for first publication and invalidation.
    pub(super) const fn all() -> Self {
        Self {
            mask: COMPLETE_CASCADE_MASK,
        }
    }

    /// An unchanged gameplay view eligible for cached-map reuse.
    pub(super) const fn none() -> Self {
        Self { mask: 0 }
    }

    /// Record the exact cached maps whose producer inputs changed.
    pub(super) const fn from_mask(mask: u8) -> Self {
        Self {
            mask: mask & COMPLETE_CASCADE_MASK,
        }
    }
}

/// Allocation-free identity of the roots submitted to directional maps.
///
/// Exterior cell streaming may add or remove geometry without changing the
/// camera, sun, or form profile. Retained maps must therefore own a root-set
/// identity as well as their projection. The two commutative accumulators keep
/// the result independent of cell-list order while making duplicate, added,
/// and removed roots materially distinct.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct DirectionalRootSetSignature {
    count: u32,
    xor: u32,
    sum: u32,
}

impl DirectionalRootSetSignature {
    /// Empty signature used only while constructing the current-frame value.
    pub(super) const EMPTY: Self = Self {
        count: 0,
        xor: 0,
        sum: 0,
    };

    /// Add one stable native root identity and its profile discriminator.
    pub(super) fn include(&mut self, identity: usize, profile: u32) {
        let mut mixed = (identity as u32) ^ profile.rotate_left(21);
        // Murmur3's 32-bit finalizer provides adequate avalanche for aligned
        // engine pointers. No cryptographic property is required: this is a
        // conservative cache invalidator, not an ownership or safety token.
        mixed ^= mixed >> 16;
        mixed = mixed.wrapping_mul(0x85eb_ca6b);
        mixed ^= mixed >> 13;
        mixed = mixed.wrapping_mul(0xc2b2_ae35);
        mixed ^= mixed >> 16;
        self.count = self.count.wrapping_add(1);
        self.xor ^= mixed;
        self.sum = self.sum.wrapping_add(mixed.rotate_left(profile));
    }
}

/// Invalidate retained maps when their borrowed scene-root set changed.
///
/// `None` means collection overflowed, so no complete identity exists and all
/// maps must use the complete visitor again. The previous signature is staged
/// beside the D3D transaction; callers publish the new value only after draw,
/// `EndScene`, and state restoration succeed.
pub(super) const fn directional_root_set_dirty(
    previous: Option<DirectionalRootSetSignature>,
    current: Option<DirectionalRootSetSignature>,
) -> CascadeDirty {
    match (previous, current) {
        (Some(previous), Some(current))
            if previous.count == current.count
                && previous.xor == current.xor
                && previous.sum == current.sum =>
        {
            CascadeDirty::none()
        }
        _ => CascadeDirty::all(),
    }
}

/// Immutable rendering decision for one common-hook invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CascadePlan {
    /// Map indices that must be produced for this invocation.
    pub(super) render: [bool; CASCADE_COUNT],
    next_quality_cursor: u8,
}

/// Allocation-free cadence state for directional map reuse.
#[derive(Clone, Copy, Debug)]
pub(super) struct CascadeScheduler {
    gameplay_maps_invalid: bool,
    valid_cascades: u8,
    quality_cursor: u8,
}

impl Default for CascadeScheduler {
    fn default() -> Self {
        Self {
            gameplay_maps_invalid: true,
            valid_cascades: 0,
            quality_cursor: 0,
        }
    }
}

impl CascadeScheduler {
    /// Plan map work without mutating cadence or publication state.
    ///
    /// Only an executable-proven gameplay producer may call this planner.
    /// This includes the nested `0x0086FF70` wrapper because generation reads
    /// only global world state; unrelated menu, reflection, and screenshot
    /// routes retain native ownership before they can mutate this cache.
    pub(super) fn plan_at_millis(self, dirty: CascadeDirty, _now_millis: u64) -> CascadePlan {
        let invalid = if self.gameplay_maps_invalid {
            COMPLETE_CASCADE_MASK
        } else {
            dirty.mask | (COMPLETE_CASCADE_MASK & !self.valid_cascades)
        };
        CascadePlan {
            render: std::array::from_fn(|index| invalid & (1 << index) != 0),
            next_quality_cursor: self.quality_cursor,
        }
    }

    /// Plan mandatory and quality-only cascade refreshes independently.
    ///
    /// Mandatory validity work is never delayed. On otherwise idle
    /// presentations, at most one still-valid quality refresh is added with
    /// rotating priority so sustained camera or sun motion cannot starve an
    /// outer map or compound an already expensive validity frame.
    pub(super) fn plan_refreshes_at_millis(
        self,
        mandatory: CascadeDirty,
        quality: CascadeDirty,
        _now_millis: u64,
    ) -> CascadePlan {
        if self.gameplay_maps_invalid {
            return self.plan_at_millis(CascadeDirty::all(), 0);
        }

        let mandatory = mandatory.mask | (COMPLETE_CASCADE_MASK & !self.valid_cascades);
        let mut render_mask = mandatory;
        // A mandatory map already consumes the frame's expensive generation
        // allowance. Quality-only work is safe to defer and must not turn a
        // one-map validity event into a two-map camera-rotation spike.
        let pending = if mandatory == 0 {
            quality.mask & COMPLETE_CASCADE_MASK
        } else {
            0
        };
        let mut selected_quality = None;
        for offset in 0..CASCADE_COUNT {
            let index = (usize::from(self.quality_cursor) + offset) % CASCADE_COUNT;
            if pending & (1 << index) != 0 {
                render_mask |= 1 << index;
                selected_quality = Some(index as u8);
                break;
            }
        }
        CascadePlan {
            render: std::array::from_fn(|index| render_mask & (1 << index) != 0),
            next_quality_cursor: selected_quality.map_or(self.quality_cursor, |index| {
                (index + 1) % CASCADE_COUNT as u8
            }),
        }
    }

    /// Commit a plan only after every requested map and state restore succeeds.
    pub(super) fn commit(&mut self, plan: CascadePlan) {
        for (index, rendered) in plan.render.into_iter().enumerate() {
            if rendered {
                self.valid_cascades |= 1 << index;
            }
        }
        self.quality_cursor = plan.next_quality_cursor;
        self.gameplay_maps_invalid = false;
    }
}

/// Map-defining point-light values paired with one cube-map slot.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct PointMapSignature {
    /// Stable native `NiPointLight*` identity.
    pub(super) identity: usize,
    /// Absolute world position used when the six faces were rendered.
    pub(super) position: [f32; 3],
    /// Effective finite influence radius used by generation and sampling.
    pub(super) radius: f32,
    /// Order-independent signature of caster identities, transforms, and bounds.
    pub(super) caster_signature: u64,
}

impl PointMapSignature {
    /// Empty signature used for an unowned cube slot.
    pub(super) const EMPTY: Self = Self {
        identity: 0,
        position: [0.0; 3],
        radius: 0.0,
        caster_signature: 0,
    };

    fn materially_matches(self, current: Self) -> bool {
        if self.identity == 0
            || self.identity != current.identity
            || !self.position.into_iter().all(f32::is_finite)
            || !current.position.into_iter().all(f32::is_finite)
            || !self.radius.is_finite()
            || !current.radius.is_finite()
            || (self.radius - current.radius).abs() > 0.01
            || self.caster_signature != current.caster_signature
            || current.caster_signature == u64::MAX
        {
            return false;
        }
        let movement_squared = (0..3)
            .map(|axis| {
                let delta = self.position[axis] - current.position[axis];
                delta * delta
            })
            .sum::<f32>();
        movement_squared < POINT_POSITION_REFRESH_DISTANCE * POINT_POSITION_REFRESH_DISTANCE
    }
}

/// Transactional cache for twelve expensive six-face point maps.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointMapCache {
    signatures: [PointMapSignature; NVR_POINT_LIGHT_COUNT],
    // The previous dynamic footprint is retained for one transaction. When a
    // moving actor crosses a cube edge, both its old and new faces must be
    // cleared and regenerated or the abandoned face keeps a ghost silhouette.
    dynamic_faces: [u8; NVR_POINT_LIGHT_COUNT],
}

impl Default for PointMapCache {
    fn default() -> Self {
        Self {
            signatures: [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT],
            dynamic_faces: [0; NVR_POINT_LIGHT_COUNT],
        }
    }
}

/// Point-map work and metadata which must commit as one D3D transaction.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointMapPlan {
    /// Face bits regenerated for each cube during this transaction.
    pub(super) render_faces: [u8; NVR_POINT_LIGHT_COUNT],
    /// Faces whose immutable geometry is resubmitted.
    pub(super) static_faces: [u8; NVR_POINT_LIGHT_COUNT],
    /// Faces receiving current animated geometry after static restoration.
    pub(super) dynamic_draw_faces: [u8; NVR_POINT_LIGHT_COUNT],
    /// Map-paired values safe for the consumer to sample.
    pub(super) published: [PointMapSignature; NVR_POINT_LIGHT_COUNT],
    /// Current nearest-order entry assigned to each stable physical cube.
    source_indices: [u8; NVR_POINT_LIGHT_COUNT],
    /// Cache state committed only after draw, EndScene, and restoration pass.
    pub(super) next: PointMapCache,
}

impl PointMapPlan {
    /// Return the current selected-light index owned by one physical cube.
    pub(super) fn source_index(self, slot: usize) -> Option<usize> {
        let index = *self.source_indices.get(slot)?;
        (index != u8::MAX).then_some(index as usize)
    }
}

impl PointMapCache {
    /// Return stable light identities currently owning physical cube slots.
    pub(super) fn identities(self) -> [usize; NVR_POINT_LIGHT_COUNT] {
        self.signatures.map(|signature| signature.identity)
    }

    /// Bound cube work while retaining complete spatial quality per map.
    ///
    /// New, replaced, or materially moved lights update all six faces
    /// synchronously. An unchanged static light retains its immutable cube.
    /// Moving skinned casters update only cube faces touched by their current
    /// or immediately previous bounds, which removes abandoned silhouettes at
    /// face crossings without paying six traversals for every affected light.
    pub(super) fn plan(
        self,
        current: [PointMapSignature; NVR_POINT_LIGHT_COUNT],
        dynamic_faces: [u8; NVR_POINT_LIGHT_COUNT],
        count: usize,
    ) -> PointMapPlan {
        let count = count.min(NVR_POINT_LIGHT_COUNT);
        let mut next = PointMapCache::default();
        let mut render_faces = [0; NVR_POINT_LIGHT_COUNT];
        let mut static_faces = [0; NVR_POINT_LIGHT_COUNT];
        let mut dynamic_draw_faces = [0; NVR_POINT_LIGHT_COUNT];
        let mut published = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
        let mut source_indices = [u8::MAX; NVR_POINT_LIGHT_COUNT];
        let mut source_claimed = [false; NVR_POINT_LIGHT_COUNT];

        // Preserve every still-selected identity in its existing physical
        // slot. Camera distance changes may reorder the input array, but they
        // do not alter the cube's contents or ownership.
        for slot in 0..count {
            let identity = self.signatures[slot].identity;
            if identity == 0 {
                continue;
            }
            if let Some(source) =
                current[..count]
                    .iter()
                    .enumerate()
                    .find_map(|(source, signature)| {
                        (!source_claimed[source] && signature.identity == identity)
                            .then_some(source)
                    })
            {
                source_indices[slot] = source as u8;
                source_claimed[source] = true;
            }
        }
        // Fill vacated slots in nearest-first input order. Replacing one light
        // invalidates one cube instead of shifting every later map.
        for source in 0..count {
            if source_claimed[source] || current[source].identity == 0 {
                continue;
            }
            let Some(slot) = source_indices[..count]
                .iter()
                .position(|index| *index == u8::MAX)
            else {
                break;
            };
            source_indices[slot] = source as u8;
            source_claimed[source] = true;
        }

        for slot in 0..count {
            let Some(source) =
                (source_indices[slot] != u8::MAX).then_some(source_indices[slot] as usize)
            else {
                continue;
            };
            if !self.signatures[slot].materially_matches(current[source]) {
                render_faces[slot] = ALL_CUBE_FACES;
                static_faces[slot] = ALL_CUBE_FACES;
                next.signatures[slot] = current[source];
            } else {
                render_faces[slot] =
                    (self.dynamic_faces[slot] | dynamic_faces[source]) & ALL_CUBE_FACES;
                // Retain exact map-defining metadata until a material move
                // causes this physical cube to be regenerated.
                next.signatures[slot] = self.signatures[slot];
            }
            next.dynamic_faces[slot] = dynamic_faces[source] & ALL_CUBE_FACES;
            dynamic_draw_faces[slot] = next.dynamic_faces[slot];
            published[slot] = next.signatures[slot];
        }
        PointMapPlan {
            render_faces,
            static_faces,
            dynamic_draw_faces,
            published,
            source_indices,
            next,
        }
    }
}

/// Convert modern NVR's per-cascade pixel threshold to a world-space radius.
///
/// NVR keeps one-pixel casters in the near and middle cascades and raises the
/// far/LOD threshold to ten pixels. The threshold scales with the stabilized
/// cascade radius, so it removes only geometry whose projected bound is below
/// the source quality profile instead of imposing an arbitrary world size.
pub(super) fn cascade_minimum_caster_radius(
    cascade: usize,
    cascade_radius: f32,
    resolution: u32,
) -> Option<f32> {
    let pixels = *NVR_CASCADE_MIN_RADIUS_PIXELS.get(cascade)?;
    if !cascade_radius.is_finite() || cascade_radius <= 0.0 || resolution == 0 {
        return None;
    }
    let radius = pixels * cascade_radius / resolution as f32;
    (radius.is_finite() && radius >= 0.0).then_some(radius)
}

/// Return whether modern NVR's default form profile admits a base form.
///
/// Near, middle, and far share the broad gameplay profile. Supplied NVR
/// defaults admit books in near/middle, keep misc objects in every map, and
/// exclude actors plus selected interactive forms only from LOD. Terrain is
/// visited through the dedicated land child and is never duplicated here.
pub(super) const fn directional_form_type_is_enabled(cascade: usize, form_type: u8) -> bool {
    const ACTIVATOR: u8 = 0x15;
    const BOOK: u8 = 0x19;
    const CONTAINER: u8 = 0x1B;
    const FURNITURE: u8 = 0x27;
    const NPC: u8 = 0x2A;
    const CREATURE: u8 = 0x2B;
    const LEVELED_CREATURE: u8 = 0x2C;
    const LAND: u8 = 0x42;
    const APPARATUS_COMPATIBILITY: u8 = 0xFE;

    if cascade >= CASCADE_COUNT || matches!(form_type, LAND | APPARATUS_COMPATIBILITY) {
        return false;
    }
    match form_type {
        BOOK => cascade < 2,
        ACTIVATOR | CONTAINER | FURNITURE | NPC | CREATURE | LEVELED_CREATURE => cascade < 3,
        // Doors, misc objects, statics, trees, and unknown compatible forms
        // remain enabled in the LOD profile exactly as in modern NVR.
        _ => true,
    }
}

/// Absolute camera-space near/far interval for one directional cascade.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CascadeSplit {
    /// Inclusive near distance used to isolate the frustum slice.
    pub(super) near: f32,
    /// Exclusive far distance and next cascade's near boundary.
    pub(super) far: f32,
}

/// Compute NVR's practical four-cascade partition exactly.
///
/// The first slice starts ten world units beyond the camera near plane. The
/// requested distance is clamped to the camera far plane, and `lambda` blends
/// uniform (`0`) with logarithmic (`1`) placement. Every boundary uses that
/// same requested range. A private fixed near boundary made lambda and distance
/// edits produce a hybrid partition which NVR never generated, leaving cached
/// neighboring projections with visibly inconsistent crop boundaries.
pub(super) fn practical_cascade_splits(
    camera_near: f32,
    camera_far: f32,
    shadow_distance: f32,
    lambda: f32,
) -> Option<[CascadeSplit; CASCADE_COUNT]> {
    if ![camera_near, camera_far, shadow_distance, lambda]
        .iter()
        .all(|value| value.is_finite())
        || camera_near < 0.0
        || camera_far <= camera_near + 10.0
        || shadow_distance <= 10.0
        || !(0.0..=1.0).contains(&lambda)
    {
        return None;
    }
    let min_z = camera_near + 10.0;
    let max_z = (camera_near + shadow_distance).min(camera_far);
    if max_z <= min_z {
        return None;
    }
    let range = max_z - min_z;
    let ratio = max_z / min_z;
    let mut near = min_z;
    let mut splits = [CascadeSplit {
        near: 0.0,
        far: 0.0,
    }; CASCADE_COUNT];
    for index in 0..CASCADE_COUNT {
        let p = (index + 1) as f32 / CASCADE_COUNT as f32;
        let logarithmic = min_z * ratio.powf(p);
        let uniform = min_z + range * p;
        let far = uniform + lambda * (logarithmic - uniform);
        if !far.is_finite() || far <= near {
            return None;
        }
        splits[index] = CascadeSplit { near, far };
        near = far;
    }
    Some(splits)
}

/// Quantize a cascade center to its shadow texel grid.
///
/// Quantizing the light-space origin removes sub-texel projection movement,
/// which is the principal source of cascade shimmer. The Z component is
/// quantized by the same rule so cached transforms are deterministic.
pub(super) fn snap_shadow_center(
    center: [f32; 3],
    radius: f32,
    resolution: u32,
) -> Option<[f32; 3]> {
    if resolution == 0
        || !radius.is_finite()
        || radius <= 0.0
        || !center.iter().all(|value| value.is_finite())
    {
        return None;
    }
    let texel = radius * 2.0 / resolution as f32;
    if !texel.is_finite() || texel <= 0.0 {
        return None;
    }
    Some(center.map(|value| (value / texel).floor() * texel))
}

/// Bounded point-light input used by deterministic admission.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct PointLightCandidate {
    /// Stable engine-object identity used to break equal-distance ties.
    pub(super) identity: u32,
    /// Squared camera distance; avoids a hot-path square root.
    pub(super) distance_squared: f32,
    /// Effective light radius in world units.
    pub(super) radius: f32,
}

impl PointLightCandidate {
    /// Empty fixed-array sentinel rejected by selection.
    pub(super) const EMPTY: Self = Self {
        identity: 0,
        distance_squared: f32::INFINITY,
        radius: 0.0,
    };

    fn valid(self) -> bool {
        self.identity != 0
            && self.distance_squared.is_finite()
            && self.distance_squared >= 0.0
            && self.radius.is_finite()
            && self.radius > 0.0
    }

    fn precedes(self, other: Self) -> bool {
        self.distance_squared < other.distance_squared
            || (self.distance_squared == other.distance_squared && self.identity < other.identity)
    }
}

/// Fixed-capacity result shared by cube production and sampling.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointLightSelection {
    shadowed: [PointLightCandidate; NVR_POINT_LIGHT_COUNT],
    shadowed_len: usize,
    unshadowed: [PointLightCandidate; NVR_POINT_LIGHT_COUNT],
    unshadowed_len: usize,
}

impl PointLightSelection {
    /// Return the number of admitted cube maps.
    pub(super) const fn len(self) -> usize {
        self.shadowed_len
    }

    /// Return cube-shadowed identities, with unused slots set to zero.
    pub(super) fn identities(self) -> [u32; NVR_POINT_LIGHT_COUNT] {
        self.shadowed.map(|value| value.identity)
    }

    /// Return the number of tracked lights that intentionally have no cube.
    pub(super) const fn unshadowed_len(self) -> usize {
        self.unshadowed_len
    }

    /// Return tracked nonshadow identities, with unused slots set to zero.
    pub(super) fn unshadowed_identities(self) -> [u32; NVR_POINT_LIGHT_COUNT] {
        self.unshadowed.map(|value| value.identity)
    }

    /// Number of cube maps the producer must update.
    pub(super) const fn produced_count(self) -> usize {
        self.shadowed_len
    }

    /// Number of cube maps the consumer is allowed to sample.
    pub(super) const fn consumer_count(self) -> usize {
        self.shadowed_len
    }
}

/// Partition nearby lights into NVR's twelve cube and twelve fallback slots.
///
/// A shadow candidate displaced from the bounded nearest-twelve cube set still
/// competes for an unshadowed slot. This preserves its local-light energy in
/// crowded rooms while keeping cube production strictly bounded. Identity is
/// a deterministic secondary key, so equal distances cannot overwrite an
/// earlier light as they do in modern NVR's integer-keyed `std::map`.
pub(super) fn select_point_lights(candidates: &[PointLightCandidate]) -> PointLightSelection {
    let mut selected = PointLightSelection {
        shadowed: [PointLightCandidate::EMPTY; NVR_POINT_LIGHT_COUNT],
        shadowed_len: 0,
        unshadowed: [PointLightCandidate::EMPTY; NVR_POINT_LIGHT_COUNT],
        unshadowed_len: 0,
    };
    for candidate in candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.valid())
    {
        if selected.shadowed[..selected.shadowed_len]
            .iter()
            .chain(&selected.unshadowed[..selected.unshadowed_len])
            .any(|current| current.identity == candidate.identity)
        {
            continue;
        }
        if let Some(fallback) = insert_point_candidate(
            &mut selected.shadowed,
            &mut selected.shadowed_len,
            candidate,
        ) {
            insert_point_candidate(
                &mut selected.unshadowed,
                &mut selected.unshadowed_len,
                fallback,
            );
        }
    }
    selected
}

/// Select point lights while preferring identities that already own cubes.
///
/// A retained identity receives a bounded ten-percent distance preference.
/// This prevents nearly equal candidates from exchanging a physical cube on
/// sub-unit camera movement while allowing a materially nearer light to win.
pub(super) fn select_point_lights_stable(
    candidates: &[PointLightCandidate],
    previous: [u32; NVR_POINT_LIGHT_COUNT],
) -> PointLightSelection {
    let mut selected = PointLightSelection {
        shadowed: [PointLightCandidate::EMPTY; NVR_POINT_LIGHT_COUNT],
        shadowed_len: 0,
        unshadowed: [PointLightCandidate::EMPTY; NVR_POINT_LIGHT_COUNT],
        unshadowed_len: 0,
    };
    for mut candidate in candidates.iter().copied() {
        if previous.contains(&candidate.identity) {
            // A retained light competes with a ten-percent distance advantage.
            // The margin is large enough to absorb sub-unit camera jitter at
            // the Nth-light boundary but bounded enough that a genuinely
            // nearer source replaces it promptly.
            candidate.distance_squared =
                stable_point_light_distance_squared(candidate.distance_squared, true);
        }
        if !candidate.valid()
            || selected.shadowed[..selected.shadowed_len]
                .iter()
                .chain(&selected.unshadowed[..selected.unshadowed_len])
                .any(|current| current.identity == candidate.identity)
        {
            continue;
        }
        if let Some(fallback) = insert_point_candidate(
            &mut selected.shadowed,
            &mut selected.shadowed_len,
            candidate,
        ) {
            insert_point_candidate(
                &mut selected.unshadowed,
                &mut selected.unshadowed_len,
                fallback,
            );
        }
    }
    selected
}

/// Rank a retained point light with bounded cube-ownership hysteresis.
pub(super) const fn stable_point_light_distance_squared(
    distance_squared: f32,
    retained: bool,
) -> f32 {
    if retained {
        distance_squared * 0.81
    } else {
        distance_squared
    }
}

/// Insert into one nearest-first fixed array, returning any rejected tail.
fn insert_point_candidate(
    values: &mut [PointLightCandidate; NVR_POINT_LIGHT_COUNT],
    len: &mut usize,
    candidate: PointLightCandidate,
) -> Option<PointLightCandidate> {
    let insertion = values[..*len]
        .iter()
        .position(|current| candidate.precedes(*current))
        .unwrap_or(*len);
    if insertion >= NVR_POINT_LIGHT_COUNT {
        return Some(candidate);
    }
    let rejected = (*len == NVR_POINT_LIGHT_COUNT).then_some(values[NVR_POINT_LIGHT_COUNT - 1]);
    let last = (*len).min(NVR_POINT_LIGHT_COUNT - 1);
    for index in (insertion..last).rev() {
        values[index + 1] = values[index];
    }
    values[insertion] = candidate;
    *len = (*len + 1).min(NVR_POINT_LIGHT_COUNT);
    rejected
}

/// Return whether a caster sphere intersects a point light's finite volume.
///
/// Both positions must use the same camera-relative origin. Comparing squared
/// distance avoids a square root for every candidate while retaining objects
/// which cross the light boundary.
pub(super) fn sphere_intersects_point_light(
    sphere_center: [f32; 3],
    sphere_radius: f32,
    light_center: [f32; 3],
    light_radius: f32,
) -> bool {
    if !sphere_center.into_iter().all(f32::is_finite)
        || !light_center.into_iter().all(f32::is_finite)
        || !sphere_radius.is_finite()
        || !light_radius.is_finite()
        || sphere_radius < 0.0
        || light_radius <= 0.0
    {
        return false;
    }
    let combined = sphere_radius + light_radius;
    let distance_squared = (0..3)
        .map(|index| {
            let delta = sphere_center[index] - light_center[index];
            delta * delta
        })
        .sum::<f32>();
    distance_squared.is_finite() && distance_squared <= combined * combined
}

/// Conservatively test a caster bound against one 90-degree cube face.
///
/// The six indices follow D3D cube-face order used by `point_cube_views`:
/// +X, -X, +Y, -Y, +Z (view direction -Z), and -Z (view direction +Z).
/// A sphere touching a side plane is retained, so this optimization cannot
/// clip geometry that contributes pixels to a neighboring face seam.
pub(super) fn sphere_intersects_cube_face(
    center_from_light: [f32; 3],
    sphere_radius: f32,
    face: usize,
) -> bool {
    if !center_from_light.into_iter().all(f32::is_finite)
        || !sphere_radius.is_finite()
        || sphere_radius < 0.0
        || face >= 6
    {
        return false;
    }
    let [x, y, z] = center_from_light;
    let (forward, side_a, side_b) = match face {
        0 => (x, y.abs(), z.abs()),
        1 => (-x, y.abs(), z.abs()),
        2 => (y, x.abs(), z.abs()),
        3 => (-y, x.abs(), z.abs()),
        // The D3D face enum and NVR's right-handed view directions are
        // intentionally inverted on Z; keep the renderer's proven ordering.
        4 => (-z, x.abs(), y.abs()),
        5 => (z, x.abs(), y.abs()),
        _ => return false,
    };
    let conservative_radius = sphere_radius * core::f32::consts::SQRT_2;
    forward + sphere_radius >= 0.1
        && side_a - forward <= conservative_radius
        && side_b - forward <= conservative_radius
}

/// Apply NVR's bounded point-light influence admission without engine access.
///
/// A light must have a useful shadow radius and overlap the fixed discovery
/// distance. Camera orientation is deliberately excluded: retained cube maps
/// describe an omnidirectional source, so a view-facing gate would invalidate
/// complete light sets as the camera rotates. Requiring the entire influence
/// sphere to fit inside the boundary would likewise reject large room lights
/// and reject more lights as the user increases the radius multiplier.
pub(super) fn point_light_influence_is_eligible(
    relative_position: [f32; 3],
    radius: f32,
    camera_forward: [f32; 3],
    max_distance: f32,
) -> bool {
    if !relative_position.into_iter().all(f32::is_finite)
        || !camera_forward.into_iter().all(f32::is_finite)
        || !radius.is_finite()
        || !max_distance.is_finite()
        || radius <= 10.0
        || max_distance <= 0.0
    {
        return false;
    }
    let distance_squared = relative_position
        .into_iter()
        .map(|component| component * component)
        .sum::<f32>();
    let forward_length_squared = camera_forward
        .into_iter()
        .map(|component| component * component)
        .sum::<f32>();
    if !distance_squared.is_finite() || forward_length_squared <= f32::EPSILON {
        return false;
    }
    let distance = distance_squared.sqrt();
    // A cube map is omnidirectional and may remain cached across many camera
    // orientations. Modern NVR's forward-dot shortcut was safe only because
    // it rebuilt the selected set every frame; retaining that shortcut made
    // complete room-light shadows pop at the instant the camera crossed 90
    // degrees. Screen-space scissoring later rejects sources with no visible
    // receiver work, so orientation is neither a correctness nor performance
    // admission criterion here.
    let _ = camera_forward;
    distance - radius <= max_distance
}

/// Evaluate one coverage-aware actor-overlay edge sample.
///
/// The actor map stores premultiplied linear depth and coverage. This reference
/// is the CPU oracle for the shader consumer and proves that resolve/filtering
/// remains neutral at zero coverage and monotonic across a silhouette.
pub(super) fn actor_overlay_edge_visibility(
    actor_depth: f32,
    receiver_depth: f32,
    coverage: f32,
) -> Option<f32> {
    if !coverage.is_finite() || !(0.0..=1.0).contains(&coverage) {
        return None;
    }
    if !actor_depth.is_finite()
        || !receiver_depth.is_finite()
        || !(0.0..=1.0).contains(&actor_depth)
        || !(0.0..=1.0).contains(&receiver_depth)
    {
        return None;
    }
    if coverage <= f32::EPSILON || receiver_depth <= actor_depth + 0.000_5 {
        return Some(1.0);
    }
    // The actor target stores premultiplied linear depth and sample coverage.
    // MSAA resolve and bilinear filtering preserve both quantities linearly;
    // uncovered samples therefore remain neutral instead of becoming an
    // invalid four-moment EVSM distribution.
    Some(1.0 - coverage)
}

/// Compute NVR's terrain-LOD shadow vertex height in the required order.
///
/// Geomorphing precedes the loaded-cell land drop. The CPU oracle is paired
/// with the compiled dedicated terrain shader route so a later simplification
/// cannot silently reintroduce a different far silhouette.
pub(super) fn terrain_lod_shadow_z(
    original_z: f32,
    morph_source_z: f32,
    morph: f32,
    inside_loaded_range: bool,
    loaded_land_drop: f32,
) -> Option<f32> {
    if ![original_z, morph_source_z, morph, loaded_land_drop]
        .into_iter()
        .all(f32::is_finite)
        || !(0.0..=1.0).contains(&morph)
    {
        return None;
    }
    let geomorphed_z = morph_source_z + (original_z - morph_source_z) * morph;
    Some(geomorphed_z - f32::from(inside_loaded_range) * loaded_land_drop)
}

/// Return the shadow contribution retained at the point-light discovery edge.
///
/// This function deliberately models the currently shipped hard admission so
/// the multi-frame regression can reject it before the production selector is
/// changed. A correct implementation must retire an otherwise valid light
/// continuously before it leaves the discovery set; returning only zero or
/// one makes a static shadow appear or disappear on a one-unit camera move.
pub(super) fn point_light_distance_fade(
    relative_position: [f32; 3],
    radius: f32,
    camera_forward: [f32; 3],
    max_distance: f32,
) -> Option<f32> {
    if !relative_position
        .into_iter()
        .chain(camera_forward)
        .chain([radius, max_distance])
        .all(f32::is_finite)
        || radius <= 10.0
        || max_distance <= 0.0
    {
        return None;
    }
    if !point_light_influence_is_eligible(relative_position, radius, camera_forward, max_distance) {
        return Some(0.0);
    }
    let distance = relative_position
        .into_iter()
        .map(|component| component * component)
        .sum::<f32>()
        .sqrt();
    let edge_distance = (distance - radius).max(0.0);
    // Five percent is long enough to hide a one-frame producer/consumer
    // handoff while remaining local to the user-owned discovery distance.
    let fade_width = (max_distance * 0.05).clamp(128.0, 1_024.0);
    let retained = ((max_distance - edge_distance) / fade_width).clamp(0.0, 1.0);
    Some(retained * retained * (3.0 - 2.0 * retained))
}

/// Observable geometry attributes used by shadow-caster policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CasterAdmission {
    /// The source form has not opted out of casting shadows.
    pub(super) form_casts_shadows: bool,
    /// Engine application culling is active.
    pub(super) app_culled: bool,
    /// Shader property uses refraction.
    pub(super) refraction: bool,
    /// Shader property uses fire refraction.
    pub(super) fire_refraction: bool,
    /// Shader property is a decal.
    pub(super) decal: bool,
    /// Shader property is a dynamic decal.
    pub(super) dynamic_decal: bool,
    /// Effective fade-node alpha.
    pub(super) fade_alpha: f32,
    /// World-bound radius.
    pub(super) bound_radius: f32,
    /// Object passed the cascade/light frustum.
    pub(super) within_frustum: bool,
    /// Object passed its owning multibound.
    pub(super) within_multibound: bool,
}

impl Default for CasterAdmission {
    fn default() -> Self {
        Self {
            form_casts_shadows: true,
            app_culled: false,
            refraction: false,
            fire_refraction: false,
            decal: false,
            dynamic_decal: false,
            fade_alpha: 1.0,
            bound_radius: 32.0,
            within_frustum: true,
            within_multibound: true,
        }
    }
}

/// Stable reason for excluding geometry from a shadow pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CasterRejection {
    /// Source form explicitly disabled casting.
    FormOptOut,
    /// Engine application culling is active.
    AppCulled,
    /// Refraction/decal shader flags are incompatible with the depth pass.
    IncompatibleShader,
    /// Fade alpha is below NVR's accepted threshold.
    Faded,
    /// Bounds are invalid or below the selected-map threshold.
    TooSmall,
    /// Bounds do not intersect the light/cascade frustum.
    OutsideFrustum,
    /// Owning multibound rejected the object.
    OutsideMultibound,
}

/// Explicit form/geometry policy shared by every producer route.
#[derive(Clone, Copy, Debug)]
pub(super) struct CasterPolicy {
    /// Minimum accepted world-bound radius.
    pub(super) minimum_radius: f32,
    /// First-person player geometry is excluded to avoid camera self-shadowing.
    pub(super) first_person_player: bool,
    /// Third-person player geometry participates normally.
    pub(super) third_person_player: bool,
    /// Must remain false: OMV observes but never rewrites native form flags.
    pub(super) force_engine_cast_shadow_flag: bool,
}

impl CasterPolicy {
    /// Return the quality-preserving default policy derived from modern NVR.
    pub(super) const fn quality_default() -> Self {
        Self {
            minimum_radius: 0.5,
            first_person_player: false,
            third_person_player: true,
            force_engine_cast_shadow_flag: false,
        }
    }

    /// Return this policy with a validated map-specific radius threshold.
    ///
    /// Directional cascades derive this value from NVR's projected-pixel
    /// coverage rule. Keeping validation here prevents a non-finite native
    /// projection from accidentally admitting or rejecting every caster.
    pub(super) fn with_minimum_radius(self, minimum_radius: f32) -> Option<Self> {
        (minimum_radius.is_finite() && minimum_radius >= 0.0).then_some(Self {
            minimum_radius,
            ..self
        })
    }

    /// Admit a caster or return its first stable rejection reason.
    pub(super) fn admit(self, candidate: CasterAdmission) -> Result<(), CasterRejection> {
        if !candidate.form_casts_shadows {
            return Err(CasterRejection::FormOptOut);
        }
        if candidate.app_culled {
            return Err(CasterRejection::AppCulled);
        }
        if candidate.refraction
            || candidate.fire_refraction
            || candidate.decal
            || candidate.dynamic_decal
        {
            return Err(CasterRejection::IncompatibleShader);
        }
        if !candidate.fade_alpha.is_finite() || candidate.fade_alpha < 0.75 {
            return Err(CasterRejection::Faded);
        }
        if !candidate.bound_radius.is_finite() || candidate.bound_radius < self.minimum_radius {
            return Err(CasterRejection::TooSmall);
        }
        if !candidate.within_frustum {
            return Err(CasterRejection::OutsideFrustum);
        }
        if !candidate.within_multibound {
            return Err(CasterRejection::OutsideMultibound);
        }
        Ok(())
    }

    /// Admit a caster whose moments will outlive the current camera cull.
    ///
    /// The compatibility implementation delegates to the frame-local NVR
    /// policy. Retained-map tests require this route to ignore only the
    /// camera-owned `APP_CULLED` observation while preserving every material,
    /// bound, multibound, and form rejection.
    pub(super) fn admit_retained(
        self,
        mut candidate: CasterAdmission,
    ) -> Result<(), CasterRejection> {
        candidate.app_culled = false;
        self.admit(candidate)
    }
}

/// Encode one opaque depth sample as FP16-safe four-moment EVSM data.
///
/// `opaque` models the generation shader's alpha-test cutoff. Transparent
/// samples return `None`, which means the pre-cleared far-depth moment remains.
pub(super) fn evsm4_moments(depth: f32, opaque: bool) -> Option<[f32; 4]> {
    if !opaque || !depth.is_finite() || !(0.0..=1.0).contains(&depth) {
        return None;
    }
    let normalized = depth * 2.0 - 1.0;
    let positive = (EVSM4_POSITIVE_EXPONENT_FP16 * normalized).exp();
    let negative = -(-EVSM4_NEGATIVE_EXPONENT * normalized).exp();
    let moments = [positive, negative, positive * positive, negative * negative];
    moments
        .iter()
        .all(|value| value.is_finite())
        .then_some(moments)
}

fn reduce_light_bleeding(probability: f32, amount: f32) -> f32 {
    ((probability - amount) / (1.0 - amount)).clamp(0.0, 1.0)
}

fn chebyshev_upper_bound(
    mean: f32,
    mean_squared: f32,
    receiver: f32,
    minimum_variance: f32,
    bleed_reduction: f32,
) -> f32 {
    if receiver <= mean {
        return 1.0;
    }
    let variance = (mean_squared - mean * mean).max(minimum_variance);
    let distance = receiver - mean;
    reduce_light_bleeding(variance / (variance + distance * distance), bleed_reduction)
}

/// Evaluate FP16 EVSM4 visibility using NVR's two one-tailed bounds.
pub(super) fn evsm4_visibility(
    moments: [f32; 4],
    receiver_depth: f32,
    bias: f32,
    bleed_reduction: f32,
) -> Option<f32> {
    if !moments.iter().all(|value| value.is_finite())
        || !receiver_depth.is_finite()
        || !(0.0..=1.0).contains(&receiver_depth)
        || !bias.is_finite()
        || bias < 0.0
        || !bleed_reduction.is_finite()
        || !(0.0..1.0).contains(&bleed_reduction)
    {
        return None;
    }
    let normalized = receiver_depth * 2.0 - 1.0;
    let positive = (EVSM4_POSITIVE_EXPONENT_FP16 * normalized).exp();
    let negative = -(-EVSM4_NEGATIVE_EXPONENT * normalized).exp();
    let positive_scale = bias * EVSM4_POSITIVE_EXPONENT_FP16 * positive;
    let negative_scale = bias * EVSM4_NEGATIVE_EXPONENT * negative;
    let positive_visibility = chebyshev_upper_bound(
        moments[0],
        moments[2],
        positive,
        positive_scale * positive_scale,
        bleed_reduction,
    );
    let negative_visibility = chebyshev_upper_bound(
        moments[1],
        moments[3],
        negative,
        negative_scale * negative_scale,
        bleed_reduction,
    );
    let visibility = positive_visibility.min(negative_visibility);
    visibility.is_finite().then_some(visibility.clamp(0.0, 1.0))
}

/// Categories of D3D9 state touched by the producer transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(super) enum TransactionState {
    /// All active color attachments.
    RenderTargets = 1 << 0,
    /// Depth/stencil attachment.
    DepthStencil = 1 << 1,
    /// Complete viewport.
    Viewport = 1 << 2,
    /// Vertex and pixel shaders.
    Shaders = 1 << 3,
    /// Vertex declaration or fixed-function FVF.
    VertexDeclarationOrFvf = 1 << 4,
    /// Every mutated vertex stream.
    Streams = 1 << 5,
    /// Active index buffer.
    Indices = 1 << 6,
    /// Every mutated texture stage.
    Textures = 1 << 7,
    /// Every mutated sampler state.
    Samplers = 1 << 8,
    /// Blend, depth, cull, alpha, stencil, bias, and related states.
    RenderStates = 1 << 9,
    /// `NiSkinInstance` frame/mode stamps written by bone calculation.
    SkinCalculationCache = 1 << 10,
    /// CPU-side `NiDX9RenderState` values not captured by a D3D state block.
    EngineRendererCache = 1 << 11,
}

const COMPLETE_TRANSACTION_MASK: u16 = (1 << 12) - 1;

/// Scene-pair and restoration contract for a replacement producer.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProducerTransaction {
    restored: u16,
    /// Exactly one scene begins around all map production.
    pub(super) begin_scene_calls: u8,
    /// A successful `BeginScene` is balanced exactly once.
    pub(super) end_scene_calls_after_success: u8,
    /// Failed `BeginScene` must not be followed by invalid `EndScene`.
    pub(super) end_scene_calls_after_begin_failure: u8,
}

impl ProducerTransaction {
    /// Return whether the transaction restores the requested state category.
    pub(super) const fn restores(self, state: TransactionState) -> bool {
        self.restored & state as u16 != 0
    }

    const fn complete() -> Self {
        Self {
            restored: COMPLETE_TRANSACTION_MASK,
            begin_scene_calls: 1,
            end_scene_calls_after_success: 1,
            end_scene_calls_after_begin_failure: 0,
        }
    }
}

/// Immutable quality and memory contract for all shadow resources.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProducerResourcePlan {
    /// Resolution of each of four persistent directional maps.
    pub(super) cascade_resolution: u32,
    /// Number of directional maps.
    pub(super) cascade_count: u32,
    /// Number of persistent shader-readable directional textures.
    ///
    /// These are the four-map atlas, static resolve, packed near/middle actor
    /// map, and far actor map (also reused as the actor resolve scratch).
    pub(super) directional_texture_count: u32,
    /// Width and height of the single-sample 2-by-2 consumer atlas.
    pub(super) atlas_resolution: u32,
    /// Multisample count used by the reusable generation target.
    pub(super) directional_samples: u32,
    /// EVSM4 channel count.
    pub(super) directional_channels: u32,
    /// Bits per EVSM channel.
    pub(super) directional_channel_bits: u32,
    /// True when the consumer uses four-moment exponential variance shadows.
    pub(super) evsm4: bool,
    /// Coverage-aware actor depth channels (`depth * coverage`, `coverage`).
    pub(super) actor_channels: u32,
    /// Coverage samples retained for actor silhouettes.
    pub(super) actor_samples: u32,
    /// Bytes written by one complete actor generation target.
    pub(super) actor_generation_bytes: u64,
    /// Maximum stable atlas taps used at one visible receiver.
    pub(super) receiver_filter_samples: u32,
    /// Full-map draws required to merge an actor overlay into static moments.
    pub(super) actor_overlay_fullscreen_merge_draws: u32,
    /// Produced/sampled point-shadow count.
    pub(super) point_light_count: u32,
    /// Total cube textures: one published and one immutable-static cube per
    /// selected light. The latter removes static-scene traversal from actor
    /// animation updates without reducing cube resolution or update cadence.
    pub(super) point_cube_texture_count: u32,
    /// Resolution of every cube face.
    pub(super) point_cube_resolution: u32,
    /// Preferred G16R16F-actor peak bytes at the requested resolution.
    pub(super) estimated_bytes: u64,
    /// Peak when a device requires the quality-equivalent four-channel actor
    /// target fallback because multisampled G16R16F is unavailable.
    pub(super) fallback_estimated_bytes: u64,
    /// Peak bytes after both lazy location branches have been visited.
    ///
    /// Retaining both families prevents cell-transition allocation hitches.
    /// Both locations share one source-color copy and full-resolution RGB
    /// local-total and local-deficit targets. Receiver geometry is consumed
    /// directly from scene depth. Exterior contact adds two half-resolution
    /// G16R16F maps for raw evidence and its same-frame depth-aware filter.
    pub(super) combined_estimated_bytes: u64,
    /// Comparable lower bound for NVR's multisampled 4096 atlas path.
    pub(super) nvr_equivalent_estimated_bytes: u64,
    /// Required complete D3D transaction.
    pub(super) transaction: ProducerTransaction,
}

impl ProducerResourcePlan {
    /// Build the fixed highest-quality plan for one active location branch.
    ///
    /// OMV preserves NVR's 2048 resolution and four FP16 EVSM moments. Stable
    /// spatial filtering runs only at visible receivers; touching every map
    /// texel twice after each update is not a quality requirement.
    pub(super) fn quality_default(scene: SceneKind, width: u32, height: u32) -> Option<Self> {
        if width == 0 || height == 0 {
            return None;
        }
        let cascade_pixels = u64::from(NVR_CASCADE_RESOLUTION).pow(2);
        let persistent_cascades = cascade_pixels * 8 * CASCADE_COUNT as u64;
        let generation_moments = cascade_pixels * 8 * 4;
        let generation_depth = cascade_pixels * 4 * 4;
        let resolved_moments = cascade_pixels * 8;
        // Actor maps need coverage-aware linear depth, not EVSM4. Two FP16
        // channels are closed under MSAA resolve and bilinear filtering, halve
        // presentation-rate color bandwidth, and retain the same four raster
        // coverage samples. Near/middle remain packed; the far texture doubles
        // as the mandatory full-size resolve scratch, avoiding a fifth texture.
        let actor_generation = cascade_pixels * 4 * 4;
        let actor_moments = cascade_pixels * 4 * 3;
        let point_cubes = u64::from(512_u32.pow(2)) * 6 * 4 * NVR_POINT_LIGHT_COUNT as u64;
        let point_static_cubes = point_cubes;
        let point_depth = u64::from(512_u32.pow(2)) * 4;
        let full_resolution_pixels = u64::from(width) * u64::from(height);
        // Equal-format MRTs preserve the exact total and occluded RGB sums in
        // one scissored draw, avoiding colored-light cross-contamination.
        let point_accumulation = full_resolution_pixels * 8 * 2;
        let source_copy = full_resolution_pixels * 8;
        // Two half-resolution four-byte targets retain visibility plus its
        // normalized receiver-depth key. Round conservatively for odd sizes.
        let contact_targets = u64::from(width.div_ceil(2)) * u64::from(height.div_ceil(2)) * 4 * 2;
        let interior_consumer = source_copy + point_accumulation;
        let directional = scene != SceneKind::Interior;
        let estimated_bytes = if directional {
            persistent_cascades
                + generation_moments
                + generation_depth
                + resolved_moments
                + actor_generation
                + actor_moments
                + point_cubes
                + point_static_cubes
                + point_depth
                + interior_consumer
                + contact_targets
        } else {
            point_cubes + point_static_cubes + point_depth + interior_consumer
        };
        let combined_estimated_bytes = persistent_cascades
            + generation_moments
            + generation_depth
            + resolved_moments
            + actor_generation
            + actor_moments
            + point_cubes
            + point_static_cubes
            + point_depth
            + source_copy
            + point_accumulation
            + contact_targets;
        let actor_fallback_extra = actor_generation + actor_moments;
        let fallback_estimated_bytes = if directional {
            estimated_bytes + actor_fallback_extra
        } else {
            estimated_bytes
        };

        let atlas_pixels = u64::from((NVR_CASCADE_RESOLUTION * 2).pow(2));
        let nvr_equivalent_estimated_bytes =
            atlas_pixels * 8 + atlas_pixels * 8 * 4 + atlas_pixels * 4 * 4;
        Some(Self {
            cascade_resolution: NVR_CASCADE_RESOLUTION,
            cascade_count: if directional { CASCADE_COUNT as u32 } else { 0 },
            directional_texture_count: if directional { 4 } else { 0 },
            atlas_resolution: NVR_CASCADE_RESOLUTION * 2,
            directional_samples: 4,
            directional_channels: 4,
            directional_channel_bits: 16,
            evsm4: true,
            actor_channels: if directional { 2 } else { 0 },
            actor_samples: if directional { 4 } else { 0 },
            actor_generation_bytes: if directional { actor_generation } else { 0 },
            receiver_filter_samples: 3,
            actor_overlay_fullscreen_merge_draws: 0,
            point_light_count: NVR_POINT_LIGHT_COUNT as u32,
            point_cube_texture_count: (NVR_POINT_LIGHT_COUNT * 2) as u32,
            point_cube_resolution: 512,
            estimated_bytes,
            fallback_estimated_bytes,
            combined_estimated_bytes,
            nvr_equivalent_estimated_bytes,
            transaction: ProducerTransaction::complete(),
        })
    }
}
