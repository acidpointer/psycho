//! Bounded access to FNV scene objects during the common shadow transaction.
//!
//! Every borrowed pointer in this module is consumed synchronously before the
//! native tail resumes. Point-map signatures and submissions share one
//! canonical root inventory; the engine's camera-owned per-light geometry list
//! is intentionally not accepted as a retained-map completeness boundary.
//! Directional maps consume the inventory's land roots, while local point
//! cubes keep landscape receiver-only to avoid hard self-shadow islands.
//! Device resources and scalar publication live in the renderer module instead.

use core::{ffi::c_void, ptr::read_unaligned};

use libpsycho::os::windows::memory::validate_memory_range;

use super::{
    contract::{
        ALL_CUBE_FACES, CASCADE_COUNT, DirectionalRootSetSignature, POINT_LIGHT_CAPACITY,
        SceneKind, TraversalBudget, directional_actor_root_is_active,
        directional_form_type_is_enabled, point_light_influence_is_eligible, point_light_radii,
        sphere_intersects_cube_face, sphere_intersects_point_light,
        stable_point_light_distance_squared,
    },
    engine::NativeLayout,
    math::{ActorBounds, CascadeProjection, Sphere, dynamic_caster_cascade_mask},
};

const MAX_GRID_SIDE: usize = 15;
const MAX_CELL_REFERENCES: usize = 4_096;
/// Preallocated root cache used to avoid rescanning every loaded cell once per
/// due cascade. Overflow falls back to the complete per-cascade visitor.
pub(super) const DIRECTIONAL_ROOT_CACHE_CAPACITY: usize = 32_768;
/// Bounded scalar actor cache shared by directional and point-light planning.
pub(super) const POINT_ACTOR_BOUND_CACHE_CAPACITY: usize = 1_024;

const GRID_SIZE: usize = 0x0C;
const GRID_CELLS: usize = 0x10;
const CELL_STRUCT: usize = 0xC4;
const CELL_STRUCT_MASTER_NODE: usize = 0x00;
const LAND_CHILD_INDEX: usize = 2;
const LIST_ITEM: usize = 0x00;
const LIST_NEXT: usize = 0x04;
const NI_TARRAY_DATA: usize = 0x04;
const NI_TARRAY_END: usize = 0x0A;

const CELL_INTERIOR: u8 = 1 << 0;
const CELL_BEHAVES_LIKE_EXTERIOR: u8 = 1 << 7;
const FORM_NOT_CAST_SHADOWS: u32 = 0x0000_0200;

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeBound {
    center: [f32; 3],
    radius: f32,
}

/// Native scene ownership recovered at the common shadow entry.
#[derive(Clone, Copy, Debug)]
pub(super) struct NativeScene {
    /// TES manager valid for this serialized call.
    pub(super) tes: *mut u8,
    /// Player reference whose third-person node is not assumed to be present
    /// in the ordinary cell reference list.
    pub(super) player: *mut u8,
    /// First-person hand/weapon scene root. It may be null while changing view
    /// or before the view model is constructed.
    pub(super) first_person_root: *mut u8,
    /// Current player cell used for independent interior/exterior policy.
    pub(super) cell: *mut u8,
    /// Renderer receiver used by native geometry submission helpers.
    pub(super) renderer: *mut c_void,
    /// Stable location classification.
    pub(super) kind: SceneKind,
}

/// One borrowed root and the profile metadata needed by all four cascades.
#[derive(Clone, Copy, Debug)]
pub(super) struct DirectionalRoot {
    // Integer identity keeps the persistent allocation `Send`; the cache is
    // populated and consumed synchronously on the render thread only.
    root: usize,
    form_type: Option<u8>,
    /// Terrain roots bypass ordinary form filtering and minimum root size.
    pub(super) is_land: bool,
    /// Object/land LOD roots are admitted only by far and LOD profiles.
    pub(super) is_lod: bool,
    /// Stable hash of the root's absolute transform and world bound.
    world_state: u32,
    /// Valid absolute bound copied with `world_state` for regional point work.
    world_bound: Option<[f32; 4]>,
}

impl DirectionalRoot {
    /// Borrow the native node only inside the active common-prefix epoch.
    pub(super) fn node(self) -> *mut u8 {
        self.root as *mut u8
    }

    /// Apply the same supplied NVR form profile previously used while walking
    /// each cell list independently for every cascade.
    pub(super) fn enabled_for(self, cascade: usize) -> bool {
        (!self.is_lod || cascade >= 2)
            && self
                .form_type
                .is_none_or(|form_type| directional_form_type_is_enabled(cascade, form_type))
    }

    /// Return whether pose/skinning changes can alter this root every frame.
    pub(super) fn is_dynamic_actor(self) -> bool {
        matches!(self.form_type, Some(0x2A..=0x2C))
    }

    /// Return whether this actor root can submit geometry in this traversal.
    ///
    /// # Safety
    ///
    /// The root must still belong to the active common-shadow transaction.
    pub(super) unsafe fn is_active_dynamic_actor(self) -> bool {
        directional_actor_root_is_active(self.is_dynamic_actor(), unsafe {
            read::<u32>(self.node(), NativeLayout::NI_AV_OBJECT_FLAGS)
        })
    }

    fn signature_profile(self) -> u32 {
        u32::from(self.form_type.unwrap_or(0))
            | (u32::from(self.form_type.is_none()) << 8)
            | (u32::from(self.is_land) << 9)
            | (u32::from(self.is_lod) << 10)
    }

    /// Return whether this root can intersect a selected point-light volume.
    ///
    /// Missing root bounds are admitted conservatively so malformed or late
    /// engine bounds cannot remove a wall from a retained cube.
    pub(super) fn intersects_point_light(
        self,
        light_position: [f32; 3],
        light_radius: f32,
    ) -> bool {
        self.world_bound.is_none_or(|bound| {
            sphere_intersects_point_light(
                [bound[0], bound[1], bound[2]],
                bound[3],
                light_position,
                light_radius,
            )
        })
    }

    /// Return whether this root can touch one selected point-cube face.
    ///
    /// Root world bounds enclose their descendants. Rejecting an unrelated
    /// face here avoids traversing and classifying the same skinned hierarchy
    /// for every other actor-owned face in a crowded light volume. Missing
    /// bounds remain conservatively admitted.
    pub(super) fn intersects_point_face(
        self,
        light_position: [f32; 3],
        light_radius: f32,
        face: usize,
    ) -> bool {
        self.world_bound.is_none_or(|bound| {
            sphere_intersects_point_light(
                [bound[0], bound[1], bound[2]],
                bound[3],
                light_position,
                light_radius,
            ) && sphere_intersects_cube_face(
                [
                    bound[0] - light_position[0],
                    bound[1] - light_position[1],
                    bound[2] - light_position[2],
                ],
                bound[3],
                face,
            )
        })
    }

    /// Whether this immutable root may cast into a local-light cube.
    ///
    /// Cell landscape remains a point-shadow receiver, so props and actors
    /// still cast onto the ground. Submitting the same landscape as a caster
    /// makes shallow depressions hard self-occluders under a carried light;
    /// native material lighting already owns that relief and its normals.
    pub(super) fn is_point_static_caster(
        self,
        light_position: [f32; 3],
        light_radius: f32,
    ) -> bool {
        !self.is_land
            && !self.is_dynamic_actor()
            && self.intersects_point_light(light_position, light_radius)
    }
}

/// Identify the borrowed static roots owned by each cascade profile.
///
/// LOD roots are absent from the near and middle signatures because those
/// maps never submit them. Keeping four independent identities prevents
/// streaming/transform churn in distant LOD roots from invalidating two
/// expensive maps whose actual producer inputs did not change.
pub(super) fn directional_root_set_signatures(
    roots: &[DirectionalRoot],
) -> [DirectionalRootSetSignature; CASCADE_COUNT] {
    let mut signatures = [DirectionalRootSetSignature::EMPTY; CASCADE_COUNT];
    for root in roots
        .iter()
        .copied()
        .filter(|root| !root.is_dynamic_actor())
    {
        for (cascade, signature) in signatures.iter_mut().enumerate() {
            if root.enabled_for(cascade) {
                signature.include(
                    root.root,
                    root.signature_profile() ^ root.world_state.rotate_left(11),
                );
            }
        }
    }
    signatures
}

/// Return gameplay maps containing actor bounds whose pose can change now.
///
/// Root bounds are engine-owned and read only during the serialized common
/// shadow call. Invalid actor bounds conservatively invalidate all three NVR
/// actor-capable maps; retaining an unknown animated silhouette is worse than
/// the exceptional extra work.
///
/// # Safety
///
/// Every root must come from [`collect_directional_roots`] in the current
/// common-shadow invocation.
pub(super) unsafe fn directional_dynamic_cascade_mask(
    roots: &[DirectionalRoot],
    splits: [super::contract::CascadeSplit; CASCADE_COUNT],
    camera_forward: [f32; 3],
    camera_translation: [f32; 3],
) -> u8 {
    let mut mask = 0_u8;
    for root in roots
        .iter()
        .copied()
        .filter(|root| unsafe { root.is_active_dynamic_actor() })
    {
        let Some(bound) = (unsafe { directional_actor_sphere(root, camera_translation) }) else {
            return 0b0111;
        };
        mask |= dynamic_caster_cascade_mask(splits, camera_forward, bound);
    }
    mask
}

/// Bound active animated casters submitted to one directional overlay.
///
/// The result is relative to the retained static map's generation origin, not
/// necessarily the current camera. That keeps the cropped actor projection in
/// the same coordinate domain as the matrix with which it is paired.
/// `None` means either no active actor belongs to the profile or an engine
/// bound was invalid; callers which expected work fail the replacement
/// transaction instead of silently publishing a clipped actor.
///
/// # Safety
///
/// Every root and its world bound must remain live for the current serialized
/// common-shadow invocation.
pub(super) enum DirectionalActorBounds {
    NoWork,
    Croppable(ActorBounds),
    FullProjection,
}

pub(super) unsafe fn directional_actor_bounds(
    roots: &[DirectionalRoot],
    cascade: usize,
    projection: CascadeProjection,
    generation_origin: [f32; 3],
) -> DirectionalActorBounds {
    let mut minimum = [f32::INFINITY; 3];
    let mut maximum = [f32::NEG_INFINITY; 3];
    let mut found = false;
    for root in roots
        .iter()
        .copied()
        .filter(|root| root.enabled_for(cascade) && unsafe { root.is_active_dynamic_actor() })
    {
        let Some(sphere) = (unsafe { directional_actor_sphere(root, generation_origin) }) else {
            return DirectionalActorBounds::FullProjection;
        };
        if !projection.contains(sphere) {
            continue;
        }
        for axis in 0..3 {
            minimum[axis] = minimum[axis].min(sphere.center[axis] - sphere.radius);
            maximum[axis] = maximum[axis].max(sphere.center[axis] + sphere.radius);
        }
        found = true;
    }
    if found {
        DirectionalActorBounds::Croppable(ActorBounds {
            min: minimum,
            max: maximum,
        })
    } else {
        DirectionalActorBounds::NoWork
    }
}

/// Read one live actor's conservative world bound in a requested origin.
///
/// # Safety
///
/// `root` must remain a live engine object for this common-shadow invocation.
unsafe fn directional_actor_sphere(root: DirectionalRoot, origin: [f32; 3]) -> Option<Sphere> {
    let bound =
        unsafe { read::<*mut NativeBound>(root.node(), NativeLayout::NI_AV_OBJECT_WORLD_BOUND) };
    if bound.is_null() {
        return None;
    }
    let bound = unsafe { read_unaligned(bound) };
    if !bound.center.into_iter().all(f32::is_finite)
        || !bound.radius.is_finite()
        || bound.radius < 0.0
    {
        return None;
    }
    Some(Sphere {
        center: std::array::from_fn(|axis| bound.center[axis] - origin[axis]),
        radius: bound.radius,
    })
}

/// Scalar and borrowed geometry ownership for one selected point light.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointLight {
    /// Stable native-light identity used to preserve ordering.
    pub(super) identity: usize,
    /// Absolute native light position.
    pub(super) position: [f32; 3],
    /// Camera-relative light position uploaded to generation/consumer shaders.
    pub(super) relative_position: [f32; 3],
    /// Effective RGB color after the native light dimmer.
    pub(super) color: [f32; 3],
    /// Native radius which owns receiver attenuation and screen coverage.
    pub(super) receiver_radius: f32,
    /// Cube-generation coverage, never smaller than the receiver radius.
    pub(super) cube_radius: f32,
    distance_squared: f32,
}

/// Fixed-capacity point-light selection shared by all six-face producers.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointLightSet {
    values: [Option<PointLight>; POINT_LIGHT_CAPACITY],
    len: usize,
}

impl Default for PointLightSet {
    fn default() -> Self {
        Self {
            values: [None; POINT_LIGHT_CAPACITY],
            len: 0,
        }
    }
}

impl PointLightSet {
    /// Number of selected lights. The consumer samples exactly this count.
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Iterate selected lights in distance/identity order.
    pub(super) fn iter(&self) -> impl Iterator<Item = &PointLight> {
        self.values[..self.len].iter().flatten()
    }

    /// Return one current nearest-order entry for stable cube-slot mapping.
    pub(super) fn get(&self, index: usize) -> Option<&PointLight> {
        self.values.get(index).and_then(Option::as_ref)
    }

    fn contains(&self, identity: usize) -> bool {
        self.iter().any(|current| current.identity == identity)
    }

    /// Insert by stable distance order and return a rejected or evicted tail.
    fn insert(&mut self, candidate: PointLight, capacity: usize) -> Option<PointLight> {
        let capacity = capacity.min(POINT_LIGHT_CAPACITY);
        if capacity == 0 {
            return Some(candidate);
        }
        let insertion = self
            .iter()
            .position(|current| point_light_precedes(candidate, *current))
            .unwrap_or(self.len);
        if insertion >= capacity {
            return Some(candidate);
        }
        let rejected = (self.len == capacity)
            .then(|| self.values[capacity - 1])
            .flatten();
        let last = self.len.min(capacity - 1);
        for index in (insertion..last).rev() {
            self.values[index + 1] = self.values[index];
        }
        self.values[insertion] = Some(candidate);
        self.len = (self.len + 1).min(capacity);
        rejected
    }
}

/// Bounded modern-NVR point-light selection for one common-entry epoch.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PointLightSelection {
    /// Lights that receive cube maps and shadow comparisons.
    shadowed: PointLightSet,
    shadow_limit: usize,
}

impl PointLightSelection {
    fn with_shadow_limit(shadow_limit: usize) -> Self {
        Self {
            shadow_limit: shadow_limit.clamp(1, POINT_LIGHT_CAPACITY),
            ..Self::default()
        }
    }

    /// Return the ordered cube-producing subset.
    pub(super) const fn shadowed(&self) -> &PointLightSet {
        &self.shadowed
    }

    fn insert(&mut self, candidate: PointLight) {
        if self.shadowed.contains(candidate.identity) {
            return;
        }
        // Modern NVR deliberately ignores the engine cast-shadow bit because
        // JIP can leave it false for valid lights. Overflow needs no OMV
        // fallback draw: native scene color already contains every light, and
        // this pipeline subtracts only energy proven occluded by a cube.
        let _ = self.shadowed.insert(candidate, self.shadow_limit);
    }
}

/// Validate process-static globals first touched at `DeferredInit`.
pub(super) fn validate_contract() -> Result<(), &'static str> {
    for (address, label) in [
        (NativeLayout::TES_SINGLETON_PTR, "TES singleton"),
        (NativeLayout::PLAYER_SINGLETON_PTR, "player singleton"),
        (
            NativeLayout::NIDX9_RENDERER_SINGLETON_PTR,
            "NiDX9Renderer singleton",
        ),
    ] {
        validate_memory_range(address as *const c_void, size_of::<usize>()).map_err(|_| label)?;
    }
    Ok(())
}

/// Recover scene classification and owners at the common shadow entry.
///
/// # Safety
///
/// Must execute on FNV's serialized render thread while the player, cell, TES,
/// and renderer singletons are live.
pub(super) unsafe fn current_scene() -> Option<NativeScene> {
    let tes = unsafe { read_global_ptr(NativeLayout::TES_SINGLETON_PTR) }?;
    let player = unsafe { read_global_ptr(NativeLayout::PLAYER_SINGLETON_PTR) }?;
    let renderer = unsafe { read_global_ptr(NativeLayout::NIDX9_RENDERER_SINGLETON_PTR) }?;
    let cell = unsafe { read::<*mut u8>(player, NativeLayout::REFERENCE_PARENT_CELL) };
    if cell.is_null() {
        return None;
    }
    let flags = unsafe { read::<u8>(cell, NativeLayout::CELL_FLAGS) };
    let kind = if flags & CELL_INTERIOR == 0 {
        SceneKind::Exterior
    } else if flags & CELL_BEHAVES_LIKE_EXTERIOR != 0 {
        SceneKind::BehavesLikeExterior
    } else {
        SceneKind::Interior
    };
    Some(NativeScene {
        tes,
        player,
        first_person_root: unsafe {
            read::<*mut u8>(player, NativeLayout::PLAYER_FIRST_PERSON_NODE)
        },
        cell,
        renderer: renderer.cast(),
        kind,
    })
}

/// Read modern NVR's zoom compensation for a directional cascade sphere.
///
/// The engine exposes the live vertical FOV on `WorldSceneGraph` and retains
/// the user's default world FOV in a process setting. NVR expands a zoomed
/// cascade by the tangent ratio so aiming cannot crop or rescale its shadow
/// coverage. Values which would shrink or unreasonably expand a map are
/// clamped; missing runtime owners select neutral compensation.
///
/// # Safety
///
/// The world scene graph must be live in the serialized common-shadow epoch.
pub(super) unsafe fn directional_fov_compensation() -> f32 {
    let Some(scene_graph) = (unsafe { read_global_ptr(NativeLayout::WORLD_SCENE_GRAPH_PTR) })
    else {
        return 1.0;
    };
    let default_fov = unsafe { read_unaligned(NativeLayout::DEFAULT_WORLD_FOV as *const f32) };
    let current_fov = unsafe { read::<f32>(scene_graph, NativeLayout::SCENE_GRAPH_CAMERA_FOV) };
    if !default_fov.is_finite()
        || !current_fov.is_finite()
        || !(1.0..179.0).contains(&default_fov)
        || !(1.0..179.0).contains(&current_fov)
    {
        return 1.0;
    }
    let ratio = (default_fov.to_radians() * 0.5).tan() / (current_fov.to_radians() * 0.5).tan();
    ratio.clamp(1.0, 4.0)
}

/// Select up to sixteen cube lights for one retained point-shadow family.
///
/// Equal-distance candidates use native pointer identity as a deterministic
/// tiebreaker, so no light is lost through the float-key collision present in
/// NVR's `std::map<float, ...>` path. Candidates beyond the configured limit
/// remain present in native scene color without growing the cube-map budget;
/// OMV never redraws or globally attenuates their illumination.
///
/// `None` rejects an over-limit or cyclic producer inventory. A bounded prefix
/// cannot prove which lights are actually nearest, so the caller preserves
/// native shadow ownership for that transaction.
pub(super) fn select_point_lights(
    scene_lights: &crate::fnv_local_lights::SceneLightFrame,
    camera_translation: [f32; 3],
    camera_forward: [f32; 3],
    retained_identities: [usize; POINT_LIGHT_CAPACITY],
    selection_lease_active: bool,
    shadow_limit: usize,
    radius_multiplier: f32,
    draw_distance: f32,
) -> Option<PointLightSelection> {
    let mut selected = PointLightSelection::with_shadow_limit(shadow_limit);
    if !camera_translation.into_iter().all(f32::is_finite) {
        return Some(selected);
    }
    if !scene_lights.is_complete() {
        return None;
    }
    for source in scene_lights.lights().iter().copied() {
        if let Some(mut candidate) = point_light(
            source,
            camera_translation,
            camera_forward,
            radius_multiplier,
            draw_distance,
        ) {
            if retained_identities.contains(&candidate.identity) {
                candidate.distance_squared = if selection_lease_active {
                    // Hold an admitted source for one short lease so candidates
                    // at the nearest-N boundary cannot exchange whole shadow
                    // groups every presentation. Missing or invalid lights are
                    // still removed immediately; expiry then recomputes the
                    // true nearest set.
                    0.0
                } else {
                    // Outside the lease, keep only the established bounded
                    // hysteresis while the fresh nearest set is chosen.
                    stable_point_light_distance_squared(candidate.distance_squared, true)
                };
            }
            selected.insert(candidate);
        }
    }
    Some(selected)
}

/// Immutable point-caster ownership for one cube and each of its six faces.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct PointStaticSignatures {
    /// Order-independent signature for every static root in the light volume.
    pub(super) cube: u64,
    /// Order-independent signatures for roots touching each D3D cube face.
    pub(super) faces: [u64; 6],
}

#[derive(Clone, Copy, Default)]
struct StaticSignatureAccumulator {
    count: u64,
    xor: u64,
    sum: u64,
}

impl StaticSignatureAccumulator {
    fn include(&mut self, mixed: u64) {
        self.count = self.count.wrapping_add(1);
        self.xor ^= mixed;
        self.sum = self.sum.wrapping_add(mixed.rotate_left(23));
    }

    fn finish(self) -> u64 {
        self.xor ^ self.sum.rotate_left(29) ^ self.count.wrapping_mul(0xD6E8_FEB8_6659_FD93)
    }
}

/// Hash immutable point-caster ownership inside one light's influence sphere.
///
/// Bounds and world-state hashes were copied by the single cell-root snapshot,
/// so this performs only scalar work. Face-local signatures let a door or
/// streamed reference invalidate only directions which could contain its old
/// or current projection. Missing bounds remain conservative and participate
/// in every face. No light rescans its native 8,192-entry geometry list.
pub(super) fn point_scene_static_signatures(
    roots: &[DirectionalRoot],
    light_position: [f32; 3],
    light_radius: f32,
) -> PointStaticSignatures {
    let mut cube = StaticSignatureAccumulator::default();
    let mut faces = [StaticSignatureAccumulator::default(); 6];
    for root in roots
        .iter()
        .copied()
        .filter(|root| root.is_point_static_caster(light_position, light_radius))
    {
        let mut mixed = root.root as u64;
        mixed ^= u64::from(root.signature_profile()).rotate_left(17);
        mixed ^= u64::from(root.world_state).wrapping_mul(0x9E37_79B1_85EB_CA87);
        mixed ^= mixed >> 33;
        mixed = mixed.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        mixed ^= mixed >> 33;
        cube.include(mixed);

        let face_mask = root.world_bound.map_or(ALL_CUBE_FACES, |bound| {
            let center_from_light = std::array::from_fn(|axis| bound[axis] - light_position[axis]);
            (0..6).fold(0_u8, |mask, face| {
                mask | (u8::from(sphere_intersects_cube_face(
                    center_from_light,
                    bound[3],
                    face,
                )) << face)
            })
        });
        for (face, accumulator) in faces.iter_mut().enumerate() {
            if face_mask & (1 << face) != 0 {
                accumulator.include(mixed);
            }
        }
    }
    PointStaticSignatures {
        cube: cube.finish(),
        faces: faces.map(StaticSignatureAccumulator::finish),
    }
}

/// Copy active actor bounds out of the borrowed root list.
///
/// The scalar spheres may be reused for every selected light. The parallel
/// actor-root list avoids scanning every static root again for each dynamic
/// face; it remains borrowed and must be discarded in this invocation.
/// `false` reports overflow or an invalid bound, requiring conservative
/// six-face dynamic work from the complete canonical root inventory.
///
/// # Safety
///
/// Every root must belong to the current serialized common-shadow epoch.
pub(super) unsafe fn collect_point_actor_bounds(
    roots: &[DirectionalRoot],
    bounds: &mut Vec<[f32; 4]>,
    actor_roots: &mut Vec<DirectionalRoot>,
) -> bool {
    bounds.clear();
    actor_roots.clear();
    for root in roots.iter().copied().filter(|root| root.is_dynamic_actor()) {
        if !unsafe { root.is_active_dynamic_actor() } {
            continue;
        }
        if bounds.len() == bounds.capacity() || actor_roots.len() == actor_roots.capacity() {
            bounds.clear();
            actor_roots.clear();
            return false;
        }
        let Some(bound) = root.world_bound else {
            bounds.clear();
            actor_roots.clear();
            return false;
        };
        bounds.push(bound);
        actor_roots.push(root);
    }
    true
}

/// Resolve cube faces touched by actor spheres inside one finite point light.
///
/// Cube-face pyramids are angular and therefore unbounded. Applying the light
/// sphere first is not merely an optimization: without it, an actor anywhere
/// in the loaded scene dirties the face pointing toward it even though the
/// generation traversal later rejects that actor from the finite light. The
/// resulting empty refresh still copies and clears a complete cube face.
pub(super) fn point_light_dynamic_faces_from_bounds(
    bounds: &[[f32; 4]],
    light_position: [f32; 3],
    light_radius: f32,
) -> u8 {
    let mut faces = 0_u8;
    for bound in bounds {
        faces |= point_actor_bound_faces(*bound, light_position, light_radius);
    }
    faces
}

fn point_actor_bound_faces(bound: [f32; 4], light_position: [f32; 3], light_radius: f32) -> u8 {
    if !sphere_intersects_point_light(
        [bound[0], bound[1], bound[2]],
        bound[3],
        light_position,
        light_radius,
    ) {
        return 0;
    }
    let center_from_light = std::array::from_fn(|axis| bound[axis] - light_position[axis]);
    (0..6).fold(0_u8, |faces, face| {
        faces | ((sphere_intersects_cube_face(center_from_light, bound[3], face) as u8) << face)
    })
}

/// Build face masks aligned with the compact actor-root inventory.
///
/// This performs the actor/light sphere and cube-face classification once per
/// transaction. Dynamic submissions then use one byte lookup instead of
/// repeating the same bound tests before walking each dirty face. Returning
/// `None` reports insufficient reusable capacity and requires the conservative
/// complete-root fallback.
pub(super) fn collect_point_actor_face_masks(
    bounds: &[[f32; 4]],
    points: &PointLightSet,
    masks: &mut Vec<[u8; POINT_LIGHT_CAPACITY]>,
) -> Option<[u8; POINT_LIGHT_CAPACITY]> {
    masks.clear();
    if bounds.len() > masks.capacity() {
        return None;
    }
    let mut dynamic_faces = [0_u8; POINT_LIGHT_CAPACITY];
    for bound in bounds.iter().copied() {
        let mut actor_faces = [0_u8; POINT_LIGHT_CAPACITY];
        for (index, point) in points.iter().enumerate() {
            let faces = point_actor_bound_faces(bound, point.position, point.cube_radius);
            actor_faces[index] = faces;
            dynamic_faces[index] |= faces;
        }
        masks.push(actor_faces);
    }
    Some(dynamic_faces)
}

/// Collect directional roots once for all maps due in this transaction.
///
/// The caller supplies a preallocated vector. Returning `false` means its
/// fixed capacity was insufficient; callers must use [`visit_directional_roots`]
/// for every map rather than render an incomplete cache.
///
/// # Safety
///
/// `scene` and every collected pointer are valid only until the native shadow
/// tail resumes. The vector must be cleared or dropped within that epoch.
pub(super) unsafe fn collect_directional_roots(
    scene: NativeScene,
    roots: &mut Vec<DirectionalRoot>,
) -> bool {
    roots.clear();
    for (offset, is_land) in [
        (NativeLayout::TES_OBJECT_LOD_ROOT, false),
        (NativeLayout::TES_LAND_LOD_ROOT, true),
    ] {
        let root = unsafe { read::<*mut u8>(scene.tes, offset) };
        if root.is_null() {
            continue;
        }
        let snapshot = unsafe { retained_object_world_snapshot(root) };
        if !push_directional_root(
            roots,
            root,
            None,
            is_land,
            true,
            snapshot.state,
            snapshot.bound,
        ) {
            roots.clear();
            return false;
        }
    }

    if scene.kind == SceneKind::Exterior {
        let grid = unsafe { read::<*mut u8>(scene.tes, NativeLayout::TES_GRID_CELL_ARRAY) };
        if !grid.is_null() {
            let side = unsafe { read::<u8>(grid, GRID_SIZE) } as usize;
            let cells = unsafe { read::<*mut *mut u8>(grid, GRID_CELLS) };
            if !(1..=MAX_GRID_SIDE).contains(&side) || cells.is_null() {
                roots.clear();
                return false;
            }
            for index in 0..side * side {
                let cell = unsafe { read_unaligned(cells.add(index)) };
                if !cell.is_null()
                    && unsafe { read::<u8>(cell, NativeLayout::CELL_FLAGS) } & CELL_INTERIOR == 0
                    && !unsafe { collect_cell_directional_roots(cell, roots) }
                {
                    roots.clear();
                    return false;
                }
            }
            return unsafe { push_player_directional_root(scene, roots) };
        }
    }

    if !unsafe { collect_cell_directional_roots(scene.cell, roots) } {
        roots.clear();
        return false;
    }
    unsafe { push_player_directional_root(scene, roots) }
}

/// Add the third-person player node through the dedicated ownership route used
/// by classic NVR's skin map. Fallout does not contractually expose the player
/// as an ordinary entry in `TESObjectCELL::objectList`; relying on that list
/// can leave only an unrelated contact-like artifact where a body shadow belongs.
unsafe fn push_player_directional_root(
    scene: NativeScene,
    roots: &mut Vec<DirectionalRoot>,
) -> bool {
    let Some(node) = (unsafe { player_directional_root(scene) }) else {
        return true;
    };
    if roots.iter().any(|root| root.node() == node) {
        return true;
    }
    // PlayerCharacter's base form is an NPC, and modern NVR enables actors in
    // the three gameplay cascades while excluding them from the LOD profile.
    // Actor pose/bounds change at presentation cadence and are owned by the
    // cropped overlay, never by retained static-map identities. Avoid hashing
    // thirteen transform floats for a value the signature deliberately drops.
    push_directional_root(
        roots,
        node,
        Some(0x2A),
        false,
        false,
        0,
        unsafe { retained_object_world_snapshot(node) }.bound,
    )
}

unsafe fn player_directional_root(scene: NativeScene) -> Option<*mut u8> {
    let render_data = unsafe { read::<*mut u8>(scene.player, NativeLayout::REFERENCE_RENDER_DATA) };
    if render_data.is_null() {
        return None;
    }
    let node = unsafe { read::<*mut u8>(render_data, NativeLayout::REFERENCE_DATA_NODE) };
    (!node.is_null()).then_some(node)
}

unsafe fn collect_cell_directional_roots(cell: *mut u8, roots: &mut Vec<DirectionalRoot>) -> bool {
    let cell_state = unsafe { read::<*mut u8>(cell, CELL_STRUCT) };
    if !cell_state.is_null() {
        let master = unsafe { read::<*mut u8>(cell_state, CELL_STRUCT_MASTER_NODE) };
        if let Some(land) = unsafe { node_child(master, LAND_CHILD_INDEX) } {
            let snapshot = unsafe { retained_object_world_snapshot(land) };
            if !push_directional_root(
                roots,
                land,
                None,
                true,
                false,
                snapshot.state,
                snapshot.bound,
            ) {
                return false;
            }
        }
    }

    let mut entry = unsafe { cell.add(NativeLayout::CELL_OBJECT_LIST) };
    let mut budget = TraversalBudget::new(MAX_CELL_REFERENCES);
    while !entry.is_null() {
        if !budget.claim() {
            return false;
        }
        let reference = unsafe { read::<*mut u8>(entry, LIST_ITEM) };
        if !reference.is_null()
            && unsafe { read::<u32>(reference, NativeLayout::TES_FORM_FLAGS) }
                & FORM_NOT_CAST_SHADOWS
                == 0
        {
            let base = unsafe { read::<*mut u8>(reference, NativeLayout::REFERENCE_BASE_FORM) };
            let render_data =
                unsafe { read::<*mut u8>(reference, NativeLayout::REFERENCE_RENDER_DATA) };
            if !base.is_null() && !render_data.is_null() {
                let node =
                    unsafe { read::<*mut u8>(render_data, NativeLayout::REFERENCE_DATA_NODE) };
                let form_type = unsafe { read::<u8>(base, NativeLayout::TES_FORM_TYPE) };
                if !node.is_null() {
                    let snapshot = unsafe { retained_object_world_snapshot(node) };
                    let world_state = if matches!(form_type, 0x2A..=0x2C) {
                        0
                    } else {
                        snapshot.state
                    };
                    if !push_directional_root(
                        roots,
                        node,
                        Some(form_type),
                        false,
                        false,
                        world_state,
                        snapshot.bound,
                    ) {
                        return false;
                    }
                }
            }
        }
        entry = unsafe { read::<*mut u8>(entry, LIST_NEXT) };
    }
    true
}

fn push_directional_root(
    roots: &mut Vec<DirectionalRoot>,
    root: *mut u8,
    form_type: Option<u8>,
    is_land: bool,
    is_lod: bool,
    world_state: u32,
    world_bound: Option<[f32; 4]>,
) -> bool {
    if roots.len() == roots.capacity() {
        return false;
    }
    roots.push(DirectionalRoot {
        root: root as usize,
        form_type,
        is_land,
        is_lod,
        world_state,
        world_bound,
    });
    true
}

#[derive(Clone, Copy)]
struct RetainedWorldSnapshot {
    state: u32,
    bound: Option<[f32; 4]>,
}

/// Copy and hash the absolute fields shared by directional and point caches.
///
/// # Safety
///
/// `object` must be a live `NiAVObject` in the current common-shadow epoch.
unsafe fn retained_object_world_snapshot(object: *mut u8) -> RetainedWorldSnapshot {
    if object.is_null() {
        return RetainedWorldSnapshot {
            state: u32::MAX,
            bound: None,
        };
    }
    let bound = unsafe { read::<*mut NativeBound>(object, NativeLayout::NI_AV_OBJECT_WORLD_BOUND) };
    let bound = (!bound.is_null()).then(|| unsafe { read_unaligned(bound) });
    let transform = unsafe {
        read_unaligned::<[f32; 13]>(
            object
                .add(NativeLayout::NI_AV_OBJECT_WORLD_TRANSFORM)
                .cast(),
        )
    };
    let valid_bound = bound.and_then(|bound| {
        (bound.center.into_iter().all(f32::is_finite)
            && bound.radius.is_finite()
            && bound.radius >= 0.0)
            .then_some([
                bound.center[0],
                bound.center[1],
                bound.center[2],
                bound.radius,
            ])
    });
    RetainedWorldSnapshot {
        state: retained_object_state_signature(bound, transform),
        bound: valid_bound,
    }
}

/// Hash the retained fields of one native object's absolute world state.
fn retained_object_state_signature(bound: Option<NativeBound>, transform: [f32; 13]) -> u32 {
    let mut state = 0x811C_9DC5_u32;
    let bound_values = bound.map_or([f32::NAN; 4], |bound| {
        [
            bound.center[0],
            bound.center[1],
            bound.center[2],
            bound.radius,
        ]
    });
    for bits in bound_values.into_iter().map(f32::to_bits) {
        state ^= bits;
        state = state.wrapping_mul(0x0100_0193);
    }
    // A bound sphere normally changes under translation, but not under a
    // rotation around its center. Hash all 3x3 rotation, translation, and
    // scale fields so a retained door or movable mesh cannot reuse geometry
    // projected from its previous orientation.
    for bits in transform.into_iter().map(f32::to_bits) {
        state ^= bits;
        state = state.wrapping_mul(0x0100_0193);
    }
    state
}

/// Visit exterior cell/reference roots admitted by one NVR cascade profile.
///
/// The callback receives `(root, is_land, is_lod)`. Reference nodes already
/// passed the `NotCastShadows` form bit and the map-specific form-category
/// switches. Object/land LOD roots are included only for far and LOD maps.
/// Root traversal remains bounded even if a corrupted list contains a cycle.
/// The return value is `false` when any cell list exceeds that bound; callers
/// must then abandon the OMV map rather than publish the visited prefix.
///
/// # Safety
///
/// `scene` must be the current result of [`current_scene`], and `visit` must
/// consume each borrowed node synchronously.
pub(super) unsafe fn visit_directional_roots(
    scene: NativeScene,
    cascade: usize,
    mut visit: impl FnMut(*mut u8, bool, bool),
) -> bool {
    if cascade >= 2 {
        for (offset, is_land) in [
            (NativeLayout::TES_OBJECT_LOD_ROOT, false),
            (NativeLayout::TES_LAND_LOD_ROOT, true),
        ] {
            let root = unsafe { read::<*mut u8>(scene.tes, offset) };
            if !root.is_null() {
                visit(root, is_land, true);
            }
        }
    }

    if scene.kind == SceneKind::Exterior {
        let grid = unsafe { read::<*mut u8>(scene.tes, NativeLayout::TES_GRID_CELL_ARRAY) };
        if !grid.is_null() {
            let side = unsafe { read::<u8>(grid, GRID_SIZE) } as usize;
            let cells = unsafe { read::<*mut *mut u8>(grid, GRID_CELLS) };
            if !(1..=MAX_GRID_SIDE).contains(&side) || cells.is_null() {
                return false;
            }
            for index in 0..side * side {
                let cell = unsafe { read_unaligned(cells.add(index)) };
                if !cell.is_null()
                    && unsafe { read::<u8>(cell, NativeLayout::CELL_FLAGS) } & CELL_INTERIOR == 0
                {
                    if !unsafe { visit_cell_roots(cell, Some(cascade), &mut visit) } {
                        return false;
                    }
                }
            }
            if directional_form_type_is_enabled(cascade, 0x2A)
                && let Some(player) = unsafe { player_directional_root(scene) }
            {
                visit(player, false, false);
            }
            return true;
        }
    }

    // Interior cells that behave like exteriors have no grid. Their current
    // cell still supplies ordinary statics/actors and a land child when one
    // exists, so the location toggle has meaningful NVR-compatible behavior.
    if !unsafe { visit_cell_roots(scene.cell, Some(cascade), &mut visit) } {
        return false;
    }
    if directional_form_type_is_enabled(cascade, 0x2A)
        && let Some(player) = unsafe { player_directional_root(scene) }
    {
        visit(player, false, false);
    }
    true
}

unsafe fn visit_cell_roots(
    cell: *mut u8,
    directional_cascade: Option<usize>,
    visit: &mut impl FnMut(*mut u8, bool, bool),
) -> bool {
    let cell_state = unsafe { read::<*mut u8>(cell, CELL_STRUCT) };
    if !cell_state.is_null() {
        let master = unsafe { read::<*mut u8>(cell_state, CELL_STRUCT_MASTER_NODE) };
        if let Some(land) = unsafe { node_child(master, LAND_CHILD_INDEX) } {
            visit(land, true, false);
        }
    }

    let mut entry = unsafe { cell.add(NativeLayout::CELL_OBJECT_LIST) };
    let mut budget = TraversalBudget::new(MAX_CELL_REFERENCES);
    while !entry.is_null() {
        if !budget.claim() {
            return false;
        }
        let reference = unsafe { read::<*mut u8>(entry, LIST_ITEM) };
        if !reference.is_null()
            && unsafe { read::<u32>(reference, NativeLayout::TES_FORM_FLAGS) }
                & FORM_NOT_CAST_SHADOWS
                == 0
            && directional_cascade.is_none_or(|cascade| {
                let base = unsafe { read::<*mut u8>(reference, NativeLayout::REFERENCE_BASE_FORM) };
                !base.is_null()
                    && directional_form_type_is_enabled(cascade, unsafe {
                        read::<u8>(base, NativeLayout::TES_FORM_TYPE)
                    })
            })
        {
            let render_data =
                unsafe { read::<*mut u8>(reference, NativeLayout::REFERENCE_RENDER_DATA) };
            if !render_data.is_null() {
                let node =
                    unsafe { read::<*mut u8>(render_data, NativeLayout::REFERENCE_DATA_NODE) };
                if !node.is_null() {
                    visit(node, false, false);
                }
            }
        }
        entry = unsafe { read::<*mut u8>(entry, LIST_NEXT) };
    }
    true
}

fn point_light(
    source: crate::fnv_local_lights::SceneLight,
    camera_translation: [f32; 3],
    camera_forward: [f32; 3],
    radius_multiplier: f32,
    draw_distance: f32,
) -> Option<PointLight> {
    if !source.is_point() {
        return None;
    }
    let position = source.position;
    let diffuse = source.diffuse;
    let dimmer = source.dimmer;
    let native_radius = source.radius;
    // Receiver and cube coverage must match native lighting. The persisted
    // multiplier stays in this call solely to preserve the schema-one settings
    // boundary; point_light_radii deliberately gives it no rendering effect.
    let (receiver_radius, cube_radius) = point_light_radii(native_radius, radius_multiplier)?;
    let relative_position =
        std::array::from_fn(|index| position[index] - camera_translation[index]);
    if !point_light_influence_is_eligible(
        relative_position,
        receiver_radius,
        camera_forward,
        draw_distance,
    ) {
        return None;
    }
    let distance_squared = dot3(relative_position, relative_position);
    // NVR's replacement list reads `NiLight::Diff` and `Dimmer` directly.
    // `ShadowSceneLight::transition` belongs to the native prefix that OMV
    // replaces, so depending on it can turn every valid interior light black
    // before a single cube is rendered.
    let color = diffuse.map(|component| (component * dimmer).max(0.0));
    let visible_energy = color.into_iter().sum::<f32>();
    if !distance_squared.is_finite()
        || !color.into_iter().all(f32::is_finite)
        || visible_energy <= 5.0 / 255.0
    {
        return None;
    }
    Some(PointLight {
        identity: source.native_light_identity,
        position,
        relative_position,
        color,
        receiver_radius,
        cube_radius,
        distance_squared,
    })
}

fn point_light_precedes(candidate: PointLight, current: PointLight) -> bool {
    candidate.distance_squared < current.distance_squared
        || (candidate.distance_squared == current.distance_squared
            && candidate.identity < current.identity)
}

unsafe fn node_child(node: *mut u8, index: usize) -> Option<*mut u8> {
    if node.is_null() {
        return None;
    }
    let array = unsafe { node.add(NativeLayout::NI_NODE_CHILDREN) };
    let end = unsafe { read::<u16>(array, NI_TARRAY_END) } as usize;
    let data = unsafe { read::<*mut *mut u8>(array, NI_TARRAY_DATA) };
    if index >= end || data.is_null() {
        return None;
    }
    let child = unsafe { read_unaligned(data.add(index)) };
    (!child.is_null()).then_some(child)
}

unsafe fn read_global_ptr(address: usize) -> Option<*mut u8> {
    let pointer = unsafe { read_unaligned(address as *const *mut u8) };
    (!pointer.is_null()).then_some(pointer)
}

unsafe fn read<T: Copy>(base: *const u8, offset: usize) -> T {
    unsafe { read_unaligned(base.add(offset).cast::<T>()) }
}

fn dot3(left: [f32; 3], right: [f32; 3]) -> f32 {
    left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
}

const fn size_of<T>() -> usize {
    core::mem::size_of::<T>()
}

#[cfg(test)]
mod tests {
    use super::{
        DirectionalRoot, NativeBound, PointLight, PointLightSelection,
        collect_point_actor_face_masks, directional_root_set_signatures,
        point_light_dynamic_faces_from_bounds, point_scene_static_signatures,
        push_directional_root, retained_object_state_signature,
    };

    fn point(identity: usize, distance_squared: f32) -> PointLight {
        PointLight {
            identity,
            position: [0.0; 3],
            relative_position: [0.0; 3],
            color: [1.0; 3],
            receiver_radius: 512.0,
            cube_radius: 512.0,
            distance_squared,
        }
    }

    #[test]
    fn runtime_selection_keeps_the_nearest_stable_cube_subset() {
        let mut selection = PointLightSelection::with_shadow_limit(12);
        for identity in 1..=14 {
            selection.insert(point(identity, identity as f32));
        }
        selection.insert(point(101, 0.5));
        selection.insert(point(102, 13.5));
        selection.insert(point(1, 0.0));

        let shadowed: [usize; 12] = std::array::from_fn(|index| {
            selection
                .shadowed()
                .iter()
                .nth(index)
                .expect("full shadow set")
                .identity
        });
        assert_eq!(shadowed, [101, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn configured_cube_budget_reduces_faces_without_redrawing_native_energy() {
        let mut selection = PointLightSelection::with_shadow_limit(4);
        for identity in 1..=8 {
            selection.insert(point(identity, identity as f32));
        }
        assert_eq!(selection.shadowed().len(), 4);
        let shadowed: Vec<_> = selection
            .shadowed()
            .iter()
            .map(|light| light.identity)
            .collect();
        assert_eq!(shadowed, [1, 2, 3, 4]);
    }

    #[test]
    fn actor_face_masks_preserve_each_selected_light_union_without_allocation() {
        let mut selection = PointLightSelection::with_shadow_limit(2);
        let mut first = point(1, 1.0);
        first.position = [0.0, 0.0, 0.0];
        first.cube_radius = 64.0;
        selection.insert(first);
        let mut second = point(2, 2.0);
        second.position = [96.0, 0.0, 0.0];
        second.cube_radius = 48.0;
        selection.insert(second);

        let bounds = [
            [24.0, 0.0, 0.0, 4.0],
            [72.0, 12.0, 0.0, 8.0],
            [512.0, 0.0, 0.0, 4.0],
        ];
        let mut masks = Vec::with_capacity(bounds.len());
        let capacity = masks.capacity();
        let unions = collect_point_actor_face_masks(&bounds, selection.shadowed(), &mut masks)
            .expect("fixed actor-mask capacity");
        assert_eq!(masks.len(), bounds.len());
        assert_eq!(masks.capacity(), capacity);
        for (source, light) in selection.shadowed().iter().enumerate() {
            let mask_union = masks
                .iter()
                .fold(0_u8, |union, masks| union | masks[source]);
            assert_eq!(mask_union, unions[source]);
            assert_eq!(
                mask_union,
                point_light_dynamic_faces_from_bounds(&bounds, light.position, light.cube_radius,)
            );
        }
    }

    #[test]
    fn directional_root_cache_preserves_profiles_and_never_grows_in_the_hot_path() {
        let actor = DirectionalRoot {
            root: 1,
            form_type: Some(0x2A),
            is_land: false,
            is_lod: false,
            world_state: 0,
            world_bound: None,
        };
        assert!(actor.enabled_for(0));
        assert!(actor.enabled_for(2));
        assert!(!actor.enabled_for(3));

        let lod = DirectionalRoot {
            root: 2,
            form_type: None,
            is_land: true,
            is_lod: true,
            world_state: 0,
            world_bound: None,
        };
        assert!(!lod.enabled_for(1));
        assert!(lod.enabled_for(2));

        let mut roots = Vec::with_capacity(1);
        assert!(push_directional_root(
            &mut roots,
            actor.node(),
            actor.form_type,
            actor.is_land,
            actor.is_lod,
            actor.world_state,
            actor.world_bound,
        ));
        assert!(!push_directional_root(
            &mut roots,
            lod.node(),
            lod.form_type,
            lod.is_land,
            lod.is_lod,
            lod.world_state,
            lod.world_bound,
        ));
        assert_eq!(roots.len(), 1);
        assert_eq!(roots.capacity(), 1);
    }

    #[test]
    fn directional_root_signature_is_order_independent_and_profile_complete() {
        let actor = DirectionalRoot {
            root: 0x1000,
            form_type: Some(0x2A),
            is_land: false,
            is_lod: false,
            world_state: 0,
            world_bound: None,
        };
        let land_lod = DirectionalRoot {
            root: 0x2000,
            form_type: None,
            is_land: true,
            is_lod: true,
            world_state: 0,
            world_bound: None,
        };
        assert_eq!(
            directional_root_set_signatures(&[actor, land_lod]),
            directional_root_set_signatures(&[land_lod, actor]),
        );
        assert_ne!(
            directional_root_set_signatures(&[actor]),
            directional_root_set_signatures(&[actor, land_lod]),
        );
        assert_eq!(
            directional_root_set_signatures(&[land_lod]),
            directional_root_set_signatures(&[land_lod, actor]),
            "an animated actor entering the root list invalidated every static cascade"
        );
        assert_ne!(
            directional_root_set_signatures(&[actor]),
            directional_root_set_signatures(&[DirectionalRoot {
                form_type: None,
                ..actor
            }]),
        );
        let form_with_bit_five = DirectionalRoot {
            root: 0x3000,
            form_type: Some(0x20),
            is_land: false,
            is_lod: false,
            world_state: 0,
            world_bound: None,
        };
        assert_ne!(
            directional_root_set_signatures(&[form_with_bit_five]),
            directional_root_set_signatures(&[DirectionalRoot {
                form_type: None,
                ..form_with_bit_five
            }]),
            "form bits must not alias the separate no-form profile discriminator"
        );

        assert_ne!(
            directional_root_set_signatures(&[land_lod]),
            directional_root_set_signatures(&[DirectionalRoot {
                world_state: 0xDEAD_BEEF,
                ..land_lod
            }]),
            "a moved static root retained directional moments from its old transform"
        );
    }

    #[test]
    fn retained_static_signature_detects_rotation_without_bound_change() {
        let bound = NativeBound {
            center: [10.0, 20.0, 30.0],
            radius: 64.0,
        };
        let identity = [
            1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 10.0, 20.0, 30.0, 1.0,
        ];
        let rotated = [
            0.0, -1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 10.0, 20.0, 30.0, 1.0,
        ];
        assert_ne!(
            retained_object_state_signature(Some(bound), identity),
            retained_object_state_signature(Some(bound), rotated),
            "a rotating door or movable caster reused moments from its previous orientation"
        );
    }

    #[test]
    fn point_static_signature_ignores_roots_outside_the_light_volume() {
        let near = DirectionalRoot {
            root: 0x1000,
            form_type: None,
            is_land: false,
            is_lod: false,
            world_state: 11,
            world_bound: Some([10.0, 0.0, 0.0, 2.0]),
        };
        let far = DirectionalRoot {
            root: 0x2000,
            form_type: None,
            is_land: false,
            is_lod: false,
            world_state: 22,
            world_bound: Some([1_000.0, 0.0, 0.0, 2.0]),
        };
        let moved_far = DirectionalRoot {
            world_state: 33,
            ..far
        };
        let baseline = point_scene_static_signatures(&[near, far], [0.0; 3], 64.0).cube;
        assert_eq!(
            baseline,
            point_scene_static_signatures(&[near, moved_far], [0.0; 3], 64.0).cube,
        );
        assert_ne!(
            baseline,
            point_scene_static_signatures(&[near, moved_far], [950.0, 0.0, 0.0], 64.0).cube,
        );
    }

    #[test]
    fn point_static_signature_excludes_landscape_self_occluders() {
        let landscape = DirectionalRoot {
            root: 0x1000,
            form_type: None,
            is_land: true,
            is_lod: false,
            world_state: 11,
            world_bound: Some([0.0, 0.0, -4.0, 64.0]),
        };
        let fixture = DirectionalRoot {
            root: 0x2000,
            form_type: Some(0x20),
            is_land: false,
            is_lod: false,
            world_state: 22,
            world_bound: Some([8.0, 0.0, 0.0, 2.0]),
        };
        let empty = point_scene_static_signatures(&[], [0.0; 3], 64.0);
        let fixture_only = point_scene_static_signatures(&[fixture], [0.0; 3], 64.0);

        assert_eq!(
            point_scene_static_signatures(&[landscape], [0.0; 3], 64.0),
            empty,
            "a shallow landscape depression became a hard point-cube self-occluder"
        );
        assert_eq!(
            point_scene_static_signatures(&[landscape, fixture], [0.0; 3], 64.0),
            fixture_only,
            "excluding landscape self-shadowing also changed ordinary object ownership"
        );
    }

    #[test]
    fn point_static_face_signatures_localize_one_sided_caster_changes() {
        let positive_x = DirectionalRoot {
            root: 0x1000,
            form_type: None,
            is_land: false,
            is_lod: false,
            world_state: 11,
            world_bound: Some([10.0, 0.0, 0.0, 0.1]),
        };
        let baseline = point_scene_static_signatures(&[positive_x], [0.0; 3], 64.0);
        let moved = point_scene_static_signatures(
            &[DirectionalRoot {
                world_state: 22,
                ..positive_x
            }],
            [0.0; 3],
            64.0,
        );

        assert_ne!(baseline.cube, moved.cube);
        assert_ne!(baseline.faces[0], moved.faces[0]);
        assert_eq!(
            baseline.faces[1..],
            moved.faces[1..],
            "a +X-only caster invalidated unrelated cube directions"
        );
    }

    #[test]
    fn point_static_face_signatures_dirty_departed_and_arrived_directions() {
        let positive_x = DirectionalRoot {
            root: 0x1000,
            form_type: None,
            is_land: false,
            is_lod: false,
            world_state: 11,
            world_bound: Some([10.0, 0.0, 0.0, 0.1]),
        };
        let positive_y = DirectionalRoot {
            world_bound: Some([0.0, 10.0, 0.0, 0.1]),
            ..positive_x
        };
        let previous = point_scene_static_signatures(&[positive_x], [0.0; 3], 64.0);
        let current = point_scene_static_signatures(&[positive_y], [0.0; 3], 64.0);
        let changed = (0..6).fold(0_u8, |mask, face| {
            mask | (u8::from(previous.faces[face] != current.faces[face]) << face)
        });

        assert_eq!(
            changed, 0b00_0101,
            "moving one caster did not invalidate exactly its departed +X and arrived +Y faces"
        );
    }
}
