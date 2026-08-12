//! Bounded access to FNV scene objects during the common shadow transaction.
//!
//! Every borrowed pointer in this module is consumed synchronously before the
//! native tail resumes. Nothing from a cell list, node hierarchy, or
//! `ShadowSceneLight::kGeometryList` is retained across that boundary. Device
//! resources and scalar publication live in the renderer module instead.

use core::{ffi::c_void, mem::transmute, ptr::read_unaligned};

use libpsycho::os::windows::memory::validate_memory_range;

use super::{
    contract::{
        NVR_POINT_LIGHT_COUNT, SceneKind, directional_form_type_is_enabled,
        point_light_influence_is_eligible,
    },
    engine::NativeLayout,
};

const SHADOW_SCENE_MANAGER_GETTER_ADDR: usize = 0x0045_0B80;
const SHADOW_SCENE_MANAGER_LIGHTS: usize = 0xB4;
const SHADOW_SCENE_MANAGER_LIGHT_COUNT: usize = 0xBC;
const MAX_MANAGER_LIGHTS: usize = 512;
const MAX_GRID_SIDE: usize = 15;
const MAX_CELL_REFERENCES: usize = 4_096;
const MAX_POINT_GEOMETRIES: usize = 8_192;
/// Preallocated root cache used to avoid rescanning every loaded cell once per
/// due cascade. Overflow falls back to the complete per-cascade visitor.
pub(super) const DIRECTIONAL_ROOT_CACHE_CAPACITY: usize = 32_768;

const GRID_SIZE: usize = 0x0C;
const GRID_CELLS: usize = 0x10;
const CELL_STRUCT: usize = 0xC4;
const CELL_STRUCT_MASTER_NODE: usize = 0x00;
const LAND_CHILD_INDEX: usize = 2;
const LIST_ITEM: usize = 0x00;
const LIST_NEXT: usize = 0x04;
const NI_TLIST_NEXT: usize = 0x00;
const NI_TLIST_DATA: usize = 0x08;
const NI_TARRAY_DATA: usize = 0x04;
const NI_TARRAY_END: usize = 0x0A;

const CELL_INTERIOR: u8 = 1 << 0;
const CELL_BEHAVES_LIKE_EXTERIOR: u8 = 1 << 7;
const FORM_NOT_CAST_SHADOWS: u32 = 0x0000_0200;

const SHADOW_LIGHT_GEOMETRY_LIST: usize = 0xE0;
const SHADOW_LIGHT_SOURCE: usize = 0xF8;

const NATIVE_LIGHT_DISABLED_FLAGS: usize = 0x30;
const NATIVE_LIGHT_POSITION: usize = 0x8C;
const NATIVE_LIGHT_EFFECT_TYPE: usize = 0x9D;
const NATIVE_LIGHT_CAN_CARRY: usize = 0x9F;
const NATIVE_LIGHT_DIMMER: usize = 0xC4;
const NATIVE_LIGHT_DIFFUSE: usize = 0xD4;
const NATIVE_LIGHT_RADIUS: usize = 0xE0;
const NATIVE_POINT_LIGHT: u8 = 2;
const CARRIED_LIGHT_RADIUS: f32 = 256.0;

type ShadowSceneManagerGetter = unsafe extern "cdecl" fn(i32) -> *mut u8;

/// Native scene ownership recovered at the common shadow entry.
#[derive(Clone, Copy, Debug)]
pub(super) struct NativeScene {
    /// TES manager valid for this serialized call.
    pub(super) tes: *mut u8,
    /// Player reference whose third-person node is not assumed to be present
    /// in the ordinary cell reference list.
    pub(super) player: *mut u8,
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
}

/// Scalar and borrowed geometry ownership for one selected point light.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointLight {
    /// Stable native-light identity used to preserve ordering.
    pub(super) identity: usize,
    /// `ShadowSceneLight*` whose geometry list is valid in this transaction.
    shadow_scene_light: *mut u8,
    /// Absolute native light position.
    pub(super) position: [f32; 3],
    /// Camera-relative light position uploaded to generation/consumer shaders.
    pub(super) relative_position: [f32; 3],
    /// Effective RGB color after the native light dimmer.
    pub(super) color: [f32; 3],
    /// Native point-light radius.
    pub(super) radius: f32,
    distance_squared: f32,
}

/// Fixed-capacity point-light selection shared by all six-face producers.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointLightSet {
    values: [Option<PointLight>; NVR_POINT_LIGHT_COUNT],
    len: usize,
}

impl Default for PointLightSet {
    fn default() -> Self {
        Self {
            values: [None; NVR_POINT_LIGHT_COUNT],
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

    fn contains(&self, identity: usize) -> bool {
        self.iter().any(|current| current.identity == identity)
    }

    /// Insert by stable distance order and return a rejected or evicted tail.
    fn insert(&mut self, candidate: PointLight, capacity: usize) -> Option<PointLight> {
        let capacity = capacity.min(NVR_POINT_LIGHT_COUNT);
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
            shadow_limit: shadow_limit.clamp(1, NVR_POINT_LIGHT_COUNT),
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
        cell,
        renderer: renderer.cast(),
        kind,
    })
}

/// Select up to twelve cube lights and twelve tracked fallback lights.
///
/// Equal-distance candidates use native pointer identity as a deterministic
/// tiebreaker, so no light is lost through the float-key collision present in
/// NVR's `std::map<float, ...>` path. Candidates beyond the nearest twelve
/// remain present in native scene color without growing the cube-map budget;
/// OMV never redraws or globally attenuates their illumination.
///
/// # Safety
///
/// The common shadow transaction must own the scene manager and its light list.
pub(super) unsafe fn select_point_lights(
    camera_translation: [f32; 3],
    camera_forward: [f32; 3],
    shadow_limit: usize,
    radius_multiplier: f32,
    draw_distance: f32,
) -> PointLightSelection {
    let mut selected = PointLightSelection::with_shadow_limit(shadow_limit);
    if !camera_translation.into_iter().all(f32::is_finite) {
        return selected;
    }
    let getter: ShadowSceneManagerGetter = unsafe { transmute(SHADOW_SCENE_MANAGER_GETTER_ADDR) };
    let manager = unsafe { getter(0) };
    if manager.is_null() {
        return selected;
    }
    let count = (unsafe { read::<u32>(manager, SHADOW_SCENE_MANAGER_LIGHT_COUNT) } as usize)
        .min(MAX_MANAGER_LIGHTS);
    let mut node = unsafe { read::<*mut u8>(manager, SHADOW_SCENE_MANAGER_LIGHTS) };
    let mut scanned = 0usize;
    while !node.is_null() && scanned < count {
        let next = unsafe { read::<*mut u8>(node, NI_TLIST_NEXT) };
        let scene_light = unsafe { read::<*mut u8>(node, NI_TLIST_DATA) };
        if let Some(candidate) = unsafe {
            point_light(
                scene_light,
                camera_translation,
                camera_forward,
                radius_multiplier,
                draw_distance,
            )
        } {
            selected.insert(candidate);
        }
        node = next;
        scanned += 1;
    }
    selected
}

/// Visit the engine-owned geometry list for one selected point light.
///
/// # Safety
///
/// `light` must come from [`select_point_lights`] in the same common-shadow
/// invocation. `visit` must not retain the geometry pointer.
pub(super) unsafe fn visit_point_geometry(
    light: &PointLight,
    mut visit: impl FnMut(*mut u8),
) -> usize {
    let mut node = unsafe { read::<*mut u8>(light.shadow_scene_light, SHADOW_LIGHT_GEOMETRY_LIST) };
    let mut visited = 0usize;
    while !node.is_null() && visited < MAX_POINT_GEOMETRIES {
        let next = unsafe { read::<*mut u8>(node, NI_TLIST_NEXT) };
        let geometry = unsafe { read::<*mut u8>(node, NI_TLIST_DATA) };
        if !geometry.is_null() {
            visit(geometry);
        }
        node = next;
        visited += 1;
    }
    visited
}

/// Visit current-cell roots when a native point light has no geometry list.
///
/// This is NVR's documented fallback. It deliberately stays within the
/// current cell; per-object light-volume culling occurs during traversal.
///
/// # Safety
///
/// `scene` must be live for the current common-shadow invocation, and `visit`
/// must not retain a root pointer.
pub(super) unsafe fn visit_point_fallback_roots(
    scene: NativeScene,
    mut visit: impl FnMut(*mut u8, bool, bool),
) {
    unsafe { visit_cell_roots(scene.cell, None, &mut visit) };
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
        if !root.is_null() && !push_directional_root(roots, root, None, is_land, true) {
            roots.clear();
            return false;
        }
    }

    if scene.kind == SceneKind::Exterior {
        let grid = unsafe { read::<*mut u8>(scene.tes, NativeLayout::TES_GRID_CELL_ARRAY) };
        if !grid.is_null() {
            let side = unsafe { read::<u8>(grid, GRID_SIZE) } as usize;
            let cells = unsafe { read::<*mut *mut u8>(grid, GRID_CELLS) };
            if (1..=MAX_GRID_SIDE).contains(&side) && !cells.is_null() {
                for index in 0..side * side {
                    let cell = unsafe { read_unaligned(cells.add(index)) };
                    if !cell.is_null()
                        && unsafe { read::<u8>(cell, NativeLayout::CELL_FLAGS) } & CELL_INTERIOR
                            == 0
                        && !unsafe { collect_cell_directional_roots(cell, roots) }
                    {
                        roots.clear();
                        return false;
                    }
                }
                return unsafe { push_player_directional_root(scene, roots) };
            }
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
    push_directional_root(roots, node, Some(0x2A), false, false)
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
        if let Some(land) = unsafe { node_child(master, LAND_CHILD_INDEX) }
            && !push_directional_root(roots, land, None, true, false)
        {
            return false;
        }
    }

    let mut entry = unsafe { cell.add(NativeLayout::CELL_OBJECT_LIST) };
    let mut visited = 0usize;
    while !entry.is_null() && visited < MAX_CELL_REFERENCES {
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
                if !node.is_null()
                    && !push_directional_root(
                        roots,
                        node,
                        Some(unsafe { read::<u8>(base, NativeLayout::TES_FORM_TYPE) }),
                        false,
                        false,
                    )
                {
                    return false;
                }
            }
        }
        entry = unsafe { read::<*mut u8>(entry, LIST_NEXT) };
        visited += 1;
    }
    true
}

fn push_directional_root(
    roots: &mut Vec<DirectionalRoot>,
    root: *mut u8,
    form_type: Option<u8>,
    is_land: bool,
    is_lod: bool,
) -> bool {
    if roots.len() == roots.capacity() {
        return false;
    }
    roots.push(DirectionalRoot {
        root: root as usize,
        form_type,
        is_land,
        is_lod,
    });
    true
}

/// Visit exterior cell/reference roots admitted by one NVR cascade profile.
///
/// The callback receives `(root, is_land, is_lod)`. Reference nodes already
/// passed the `NotCastShadows` form bit and the map-specific form-category
/// switches. Object/land LOD roots are included only for far and LOD maps.
/// Root traversal remains bounded even if a corrupted list contains a cycle.
///
/// # Safety
///
/// `scene` must be the current result of [`current_scene`], and `visit` must
/// consume each borrowed node synchronously.
pub(super) unsafe fn visit_directional_roots(
    scene: NativeScene,
    cascade: usize,
    mut visit: impl FnMut(*mut u8, bool, bool),
) {
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
            if (1..=MAX_GRID_SIDE).contains(&side) && !cells.is_null() {
                for index in 0..side * side {
                    let cell = unsafe { read_unaligned(cells.add(index)) };
                    if !cell.is_null()
                        && unsafe { read::<u8>(cell, NativeLayout::CELL_FLAGS) } & CELL_INTERIOR
                            == 0
                    {
                        unsafe { visit_cell_roots(cell, Some(cascade), &mut visit) };
                    }
                }
                if directional_form_type_is_enabled(cascade, 0x2A)
                    && let Some(player) = unsafe { player_directional_root(scene) }
                {
                    visit(player, false, false);
                }
                return;
            }
        }
    }

    // Interior cells that behave like exteriors have no grid. Their current
    // cell still supplies ordinary statics/actors and a land child when one
    // exists, so the location toggle has meaningful NVR-compatible behavior.
    unsafe { visit_cell_roots(scene.cell, Some(cascade), &mut visit) };
    if directional_form_type_is_enabled(cascade, 0x2A)
        && let Some(player) = unsafe { player_directional_root(scene) }
    {
        visit(player, false, false);
    }
}

unsafe fn visit_cell_roots(
    cell: *mut u8,
    directional_cascade: Option<usize>,
    visit: &mut impl FnMut(*mut u8, bool, bool),
) {
    let cell_state = unsafe { read::<*mut u8>(cell, CELL_STRUCT) };
    if !cell_state.is_null() {
        let master = unsafe { read::<*mut u8>(cell_state, CELL_STRUCT_MASTER_NODE) };
        if let Some(land) = unsafe { node_child(master, LAND_CHILD_INDEX) } {
            visit(land, true, false);
        }
    }

    let mut entry = unsafe { cell.add(NativeLayout::CELL_OBJECT_LIST) };
    let mut visited = 0usize;
    while !entry.is_null() && visited < MAX_CELL_REFERENCES {
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
        visited += 1;
    }
}

unsafe fn point_light(
    scene_light: *mut u8,
    camera_translation: [f32; 3],
    camera_forward: [f32; 3],
    radius_multiplier: f32,
    draw_distance: f32,
) -> Option<PointLight> {
    if scene_light.is_null() {
        return None;
    }
    let native = unsafe { read::<*mut u8>(scene_light, SHADOW_LIGHT_SOURCE) };
    if native.is_null()
        || unsafe { read::<u8>(native, NATIVE_LIGHT_EFFECT_TYPE) } != NATIVE_POINT_LIGHT
        || unsafe { read::<u8>(native, NATIVE_LIGHT_DISABLED_FLAGS) } & 1 != 0
    {
        return None;
    }
    let position = unsafe { read_vec3(native, NATIVE_LIGHT_POSITION) };
    let diffuse = unsafe { read_vec3(native, NATIVE_LIGHT_DIFFUSE) };
    let dimmer = unsafe { read::<f32>(native, NATIVE_LIGHT_DIMMER) };
    let native_radius = unsafe { read::<f32>(native, NATIVE_LIGHT_RADIUS) };
    let can_carry = unsafe { read::<u8>(native, NATIVE_LIGHT_CAN_CARRY) } != 0;
    if !position.into_iter().all(f32::is_finite)
        || !diffuse.into_iter().all(f32::is_finite)
        || !dimmer.is_finite()
        || !native_radius.is_finite()
        || native_radius <= 0.1
    {
        return None;
    }
    // NVR fixes carried/Pip-Boy lights to a compact cube radius so the light
    // can cast useful nearby shadows instead of inheriting a huge record
    // radius. Generation and sampling must publish the same value.
    let radius = if can_carry {
        CARRIED_LIGHT_RADIUS
    } else {
        native_radius * radius_multiplier
    };
    let relative_position =
        std::array::from_fn(|index| position[index] - camera_translation[index]);
    if !point_light_influence_is_eligible(relative_position, radius, camera_forward, draw_distance)
    {
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
        identity: native as usize,
        shadow_scene_light: scene_light,
        position,
        relative_position,
        color,
        radius,
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

unsafe fn read_vec3(base: *const u8, offset: usize) -> [f32; 3] {
    unsafe {
        [
            read(base, offset),
            read(base, offset + 4),
            read(base, offset + 8),
        ]
    }
}

fn dot3(left: [f32; 3], right: [f32; 3]) -> f32 {
    left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
}

const fn size_of<T>() -> usize {
    core::mem::size_of::<T>()
}

#[cfg(test)]
mod tests {
    use super::{DirectionalRoot, PointLight, PointLightSelection, push_directional_root};

    fn point(identity: usize, distance_squared: f32) -> PointLight {
        PointLight {
            identity,
            shadow_scene_light: core::ptr::null_mut(),
            position: [0.0; 3],
            relative_position: [0.0; 3],
            color: [1.0; 3],
            radius: 512.0,
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
    fn directional_root_cache_preserves_profiles_and_never_grows_in_the_hot_path() {
        let actor = DirectionalRoot {
            root: 1,
            form_type: Some(0x2A),
            is_land: false,
            is_lod: false,
        };
        assert!(actor.enabled_for(0));
        assert!(actor.enabled_for(2));
        assert!(!actor.enabled_for(3));

        let lod = DirectionalRoot {
            root: 2,
            form_type: None,
            is_land: true,
            is_lod: true,
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
        ));
        assert!(!push_directional_root(
            &mut roots,
            lod.node(),
            lod.form_type,
            lod.is_land,
            lod.is_lod,
        ));
        assert_eq!(roots.len(), 1);
        assert_eq!(roots.capacity(), 1);
    }
}
