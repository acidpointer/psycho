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
/// Supplied NVR custom-quality multiplier for point-light influence radius.
pub(super) const NVR_POINT_RADIUS_MULTIPLIER: f32 = 1.5;
/// Modern NVR's hard upper bound for tracked point-light influence.
pub(super) const NVR_POINT_DRAW_DISTANCE: f32 = 8_000.0;

const MID_REFRESH_PERIOD: u64 = 2;
const FAR_REFRESH_PERIOD: u64 = 3;
const LOD_REFRESH_PERIOD: u64 = 4;
const EVSM4_POSITIVE_EXPONENT_FP16: f32 = 5.54;
const EVSM4_NEGATIVE_EXPONENT: f32 = 5.0;

/// Combine raw map/contact visibility with NVR's location-specific darkness.
///
/// Exterior directional and contact terms are both visibility values, so the
/// darker term wins before the configured darkness is applied. Interior point
/// accumulation is instead a bounded illumination amount: no local light
/// leaves the configured ambient floor, while sufficient visible local-light
/// energy reaches full brightness.
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
        SceneKind::Interior => 1.0 - darkness * (1.0 - local),
    };
    Some(factor)
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

/// Dispatcher context recovered from the common hook's return address/caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InvocationContext {
    /// Normal player-visible world rendering.
    Main,
    /// An engine-owned special view or offscreen render.
    Special,
    /// The dedicated screenshot render path.
    Screenshot,
}

/// Dirty causes that require one or more directional maps to be rebuilt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CascadeDirty {
    camera: bool,
    sun: bool,
    scene: bool,
}

impl CascadeDirty {
    /// A fully dirty shadow graph, used for first publication and invalidation.
    pub(super) const fn all() -> Self {
        Self {
            camera: true,
            sun: true,
            scene: true,
        }
    }

    /// An unchanged gameplay view eligible for cached-map reuse.
    pub(super) const fn none() -> Self {
        Self {
            camera: false,
            sun: false,
            scene: false,
        }
    }

    const fn any(self) -> bool {
        self.camera || self.sun || self.scene
    }
}

/// Immutable rendering decision for one common-hook invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CascadePlan {
    /// Map indices that must be produced for this invocation.
    pub(super) render: [bool; CASCADE_COUNT],
    /// Whether completion publishes a new player-visible map epoch.
    pub(super) commit_gameplay_epoch: bool,
    /// Whether a transient view overwrites shared maps and invalidates cache.
    pub(super) invalidate_gameplay_maps: bool,
    context: InvocationContext,
    advance_main_cadence: bool,
}

/// Allocation-free cadence state for directional map reuse.
#[derive(Clone, Copy, Debug)]
pub(super) struct CascadeScheduler {
    gameplay_epoch: u64,
    main_cadence: u64,
    gameplay_maps_invalid: bool,
}

impl Default for CascadeScheduler {
    fn default() -> Self {
        Self {
            gameplay_epoch: 0,
            main_cadence: 0,
            gameplay_maps_invalid: true,
        }
    }
}

impl CascadeScheduler {
    /// Plan map work without mutating cadence or publication state.
    ///
    /// Special and screenshot views rebuild all maps because their camera may
    /// differ from gameplay, but they never consume gameplay cadence. Since
    /// the maps are shared, their completion invalidates gameplay cache and
    /// forces a complete recovery on the next main view.
    pub(super) fn plan(self, context: InvocationContext, dirty: CascadeDirty) -> CascadePlan {
        match context {
            InvocationContext::Special | InvocationContext::Screenshot => CascadePlan {
                render: [true; CASCADE_COUNT],
                commit_gameplay_epoch: false,
                invalidate_gameplay_maps: true,
                context,
                advance_main_cadence: false,
            },
            InvocationContext::Main => {
                let rebuild_all = self.gameplay_maps_invalid || dirty.any();
                let mut render = [rebuild_all; CASCADE_COUNT];
                if !rebuild_all {
                    // The near map tracks animated characters and close foliage
                    // every gameplay frame. Progressively slower updates are
                    // restricted to larger, lower-frequency world regions;
                    // this removes most of NVR's repeated distant traversal
                    // without reducing map resolution or filter quality.
                    render[0] = true;
                    render[1] = self.main_cadence % MID_REFRESH_PERIOD == 0;
                    render[2] = self.main_cadence % FAR_REFRESH_PERIOD == 0;
                    render[3] = self.main_cadence % LOD_REFRESH_PERIOD == 0;
                }
                CascadePlan {
                    render,
                    commit_gameplay_epoch: render.iter().any(|render| *render),
                    invalidate_gameplay_maps: false,
                    context,
                    advance_main_cadence: true,
                }
            }
        }
    }

    /// Commit a plan only after every requested map and state restore succeeds.
    pub(super) fn commit(&mut self, plan: CascadePlan) {
        if plan.invalidate_gameplay_maps {
            self.gameplay_maps_invalid = true;
        }
        if plan.context == InvocationContext::Main {
            if plan.commit_gameplay_epoch {
                self.gameplay_epoch = self.gameplay_epoch.wrapping_add(1);
                self.gameplay_maps_invalid = false;
            }
            if plan.advance_main_cadence {
                self.main_cadence = self.main_cadence.wrapping_add(1);
            }
        }
    }

    /// Return the last successfully published gameplay map epoch.
    pub(super) const fn gameplay_epoch(self) -> u64 {
        self.gameplay_epoch
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

/// Compute NVR's practical logarithmic/uniform four-cascade partition.
///
/// The first slice starts ten world units beyond the camera near plane. The
/// requested distance is clamped to the camera far plane, and `lambda` blends
/// uniform (`0`) with logarithmic (`1`) placement.
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
    let mut boundaries = [0.0; CASCADE_COUNT];
    for (index, boundary) in boundaries.iter_mut().enumerate() {
        let p = (index + 1) as f32 / CASCADE_COUNT as f32;
        let logarithmic = min_z * ratio.powf(p);
        let uniform = min_z + range * p;
        *boundary = uniform + lambda * (logarithmic - uniform);
    }
    let mut near = min_z;
    let mut splits = [CascadeSplit {
        near: 0.0,
        far: 0.0,
    }; CASCADE_COUNT];
    for (index, far) in boundaries.into_iter().enumerate() {
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
    /// Explicit policy result; OMV never mutates the engine cast flag.
    pub(super) casts_shadows: bool,
}

impl PointLightCandidate {
    /// Empty fixed-array sentinel rejected by selection.
    pub(super) const EMPTY: Self = Self {
        identity: 0,
        distance_squared: f32::INFINITY,
        radius: 0.0,
        casts_shadows: false,
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
        if candidate.casts_shadows {
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
        } else {
            insert_point_candidate(
                &mut selected.unshadowed,
                &mut selected.unshadowed_len,
                candidate,
            );
        }
    }
    selected
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

/// Apply NVR's bounded point-light influence admission without engine access.
///
/// A light must have a useful shadow radius, fit entirely inside the fixed
/// discovery distance, and either face the camera or contain it. The latter
/// exception prevents a surrounding room light from vanishing when its origin
/// moves behind the view plane.
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
    let in_front = (0..3)
        .map(|index| relative_position[index] * camera_forward[index])
        .sum::<f32>()
        > 0.0;
    (in_front || distance <= radius) && distance + radius <= max_distance
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
}

const COMPLETE_TRANSACTION_MASK: u16 = (1 << 10) - 1;

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
    /// True when every updated map receives separable prefiltering.
    pub(super) prefilter: bool,
    /// Logical identity of the source sampled by one blur pass.
    pub(super) blur_source_identity: u8,
    /// Distinct logical identity of the blur render target.
    pub(super) blur_target_identity: u8,
    /// Produced/sampled point-shadow count.
    pub(super) point_light_count: u32,
    /// Resolution of every cube face.
    pub(super) point_cube_resolution: u32,
    /// Conservative peak bytes for the OMV plan at the requested resolution.
    pub(super) estimated_bytes: u64,
    /// Comparable lower bound for NVR's multisampled 4096 atlas path.
    pub(super) nvr_equivalent_estimated_bytes: u64,
    /// Required complete D3D transaction.
    pub(super) transaction: ProducerTransaction,
}

impl ProducerResourcePlan {
    /// Build the fixed highest-quality plan for a nonzero backbuffer.
    ///
    /// OMV persists NVR's single-sample 4096 atlas but reuses one 2048 4x-MSAA
    /// color/depth workspace. Resolving and filtering one quadrant at a time is
    /// sampling-equivalent and avoids multisampling three empty quadrants for
    /// every cascade draw.
    pub(super) fn quality_default(width: u32, height: u32) -> Option<Self> {
        if width == 0 || height == 0 {
            return None;
        }
        let cascade_pixels = u64::from(NVR_CASCADE_RESOLUTION).pow(2);
        let persistent_cascades = cascade_pixels * 8 * CASCADE_COUNT as u64;
        let shared_msaa_color = cascade_pixels * 8 * 4;
        let shared_msaa_depth = cascade_pixels * 4 * 4;
        let shared_blur_target = cascade_pixels * 8;
        let point_cubes = u64::from(512_u32.pow(2)) * 6 * 4 * NVR_POINT_LIGHT_COUNT as u64;
        let point_depth = u64::from(512_u32.pow(2)) * 4;
        let point_accumulation = u64::from(width) * u64::from(height) * 4;
        let reconstructed_normals = u64::from(width) * u64::from(height) * 8;
        let scene_color_copy = u64::from(width) * u64::from(height) * 4;
        let estimated_bytes = persistent_cascades
            + shared_msaa_color
            + shared_msaa_depth
            + shared_blur_target
            + point_cubes
            + point_depth
            + point_accumulation
            + reconstructed_normals
            + scene_color_copy;

        let atlas_pixels = u64::from((NVR_CASCADE_RESOLUTION * 2).pow(2));
        let nvr_equivalent_estimated_bytes =
            atlas_pixels * 8 + atlas_pixels * 8 * 4 + atlas_pixels * 4 * 4;
        Some(Self {
            cascade_resolution: NVR_CASCADE_RESOLUTION,
            cascade_count: CASCADE_COUNT as u32,
            directional_texture_count: 1,
            atlas_resolution: NVR_CASCADE_RESOLUTION * 2,
            directional_samples: 4,
            directional_channels: 4,
            directional_channel_bits: 16,
            evsm4: true,
            prefilter: true,
            blur_source_identity: 1,
            blur_target_identity: 2,
            point_light_count: NVR_POINT_LIGHT_COUNT as u32,
            point_cube_resolution: 512,
            estimated_bytes,
            nvr_equivalent_estimated_bytes,
            transaction: ProducerTransaction::complete(),
        })
    }
}
