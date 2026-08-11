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
        NVR_POINT_DRAW_DISTANCE, NVR_POINT_LIGHT_COUNT, NVR_POINT_RADIUS_MULTIPLIER, SceneKind,
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

const SHADOW_LIGHT_TRANSITION: usize = 0xD0;
const SHADOW_LIGHT_GEOMETRY_LIST: usize = 0xE0;
const SHADOW_LIGHT_POINT: usize = 0xF4;
const SHADOW_LIGHT_AMBIENT: usize = 0xF5;
const SHADOW_LIGHT_SOURCE: usize = 0xF8;
const SHADOW_LIGHT_ACTIVE: usize = 0x110;
const SHADOW_LIGHT_INACTIVE: u16 = 0x00FF;

const NATIVE_LIGHT_DISABLED_FLAGS: usize = 0x30;
const NATIVE_LIGHT_POSITION: usize = 0x8C;
const NATIVE_LIGHT_CASTS_SHADOWS: usize = 0x9E;
const NATIVE_LIGHT_DIMMER: usize = 0xC4;
const NATIVE_LIGHT_DIFFUSE: usize = 0xD4;
const NATIVE_LIGHT_RADIUS: usize = 0xE0;

type ShadowSceneManagerGetter = unsafe extern "cdecl" fn(i32) -> *mut u8;

/// Native scene ownership recovered at the common shadow entry.
#[derive(Clone, Copy, Debug)]
pub(super) struct NativeScene {
    /// TES manager valid for this serialized call.
    pub(super) tes: *mut u8,
    /// Current player cell used for independent interior/exterior policy.
    pub(super) cell: *mut u8,
    /// Renderer receiver used by native geometry submission helpers.
    pub(super) renderer: *mut c_void,
    /// Stable location classification.
    pub(super) kind: SceneKind,
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
    /// Effective RGB color after native dimmer and transition weighting.
    pub(super) color: [f32; 3],
    /// Native point-light radius.
    pub(super) radius: f32,
    /// Whether the native light owns one of the bounded cube-shadow slots.
    casts_shadows: bool,
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
    fn insert(&mut self, candidate: PointLight) -> Option<PointLight> {
        let insertion = self
            .iter()
            .position(|current| point_light_precedes(candidate, *current))
            .unwrap_or(self.len);
        if insertion >= NVR_POINT_LIGHT_COUNT {
            return Some(candidate);
        }
        let rejected = (self.len == NVR_POINT_LIGHT_COUNT)
            .then(|| self.values[NVR_POINT_LIGHT_COUNT - 1])
            .flatten();
        let last = self.len.min(NVR_POINT_LIGHT_COUNT - 1);
        for index in (insertion..last).rev() {
            self.values[index + 1] = self.values[index];
        }
        self.values[insertion] = Some(candidate);
        self.len = (self.len + 1).min(NVR_POINT_LIGHT_COUNT);
        rejected
    }
}

/// Bounded modern-NVR point-light categories for one common-entry epoch.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PointLightSelection {
    /// Lights that receive cube maps and shadow comparisons.
    shadowed: PointLightSet,
    /// Nearby light energy retained without a cube-map comparison.
    unshadowed: PointLightSet,
}

impl PointLightSelection {
    /// Return the ordered cube-producing subset.
    pub(super) const fn shadowed(&self) -> &PointLightSet {
        &self.shadowed
    }

    /// Return the ordered tracked-light fallback subset.
    pub(super) const fn unshadowed(&self) -> &PointLightSet {
        &self.unshadowed
    }

    fn insert(&mut self, candidate: PointLight) {
        if self.shadowed.contains(candidate.identity)
            || self.unshadowed.contains(candidate.identity)
        {
            return;
        }
        if candidate.casts_shadows {
            if let Some(fallback) = self.shadowed.insert(candidate) {
                self.unshadowed.insert(fallback);
            }
        } else {
            self.unshadowed.insert(candidate);
        }
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
        cell,
        renderer: renderer.cast(),
        kind,
    })
}

/// Select up to twelve cube lights and twelve tracked fallback lights.
///
/// Equal-distance candidates use native pointer identity as a deterministic
/// tiebreaker, so no light is lost through the float-key collision present in
/// NVR's `std::map<float, ...>` path. Shadow candidates beyond the nearest
/// twelve remain eligible for the fallback set, matching modern NVR's local
/// illumination behavior without growing the cube-map budget.
///
/// # Safety
///
/// The common shadow transaction must own the scene manager and its light list.
pub(super) unsafe fn select_point_lights(
    camera_translation: [f32; 3],
    camera_forward: [f32; 3],
) -> PointLightSelection {
    let mut selected = PointLightSelection::default();
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
        if let Some(candidate) =
            unsafe { point_light(scene_light, camera_translation, camera_forward) }
        {
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
    unsafe { visit_cell_roots(scene.cell, &mut visit) };
}

/// Visit all exterior cell/ref and LOD roots admitted by native form policy.
///
/// The callback receives `(root, is_land, is_lod)`. Reference nodes already
/// passed the `NotCastShadows` form bit. Root traversal remains bounded even
/// if a corrupted list contains a cycle.
///
/// # Safety
///
/// `scene` must be the current result of [`current_scene`], and `visit` must
/// consume each borrowed node synchronously.
pub(super) unsafe fn visit_directional_roots(
    scene: NativeScene,
    mut visit: impl FnMut(*mut u8, bool, bool),
) {
    for (offset, is_land) in [
        (NativeLayout::TES_OBJECT_LOD_ROOT, false),
        (NativeLayout::TES_LAND_LOD_ROOT, true),
    ] {
        let root = unsafe { read::<*mut u8>(scene.tes, offset) };
        if !root.is_null() {
            visit(root, is_land, true);
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
                        unsafe { visit_cell_roots(cell, &mut visit) };
                    }
                }
                return;
            }
        }
    }

    // Interior cells that behave like exteriors have no grid. Their current
    // cell still supplies ordinary statics/actors and a land child when one
    // exists, so the location toggle has meaningful NVR-compatible behavior.
    unsafe { visit_cell_roots(scene.cell, &mut visit) };
}

unsafe fn visit_cell_roots(cell: *mut u8, visit: &mut impl FnMut(*mut u8, bool, bool)) {
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
) -> Option<PointLight> {
    if scene_light.is_null()
        || unsafe { read::<u8>(scene_light, SHADOW_LIGHT_POINT) } == 0
        || unsafe { read::<u8>(scene_light, SHADOW_LIGHT_AMBIENT) } != 0
        || unsafe { read::<u16>(scene_light, SHADOW_LIGHT_ACTIVE) } == SHADOW_LIGHT_INACTIVE
    {
        return None;
    }
    let native = unsafe { read::<*mut u8>(scene_light, SHADOW_LIGHT_SOURCE) };
    if native.is_null() || unsafe { read::<u8>(native, NATIVE_LIGHT_DISABLED_FLAGS) } & 1 != 0 {
        return None;
    }
    let casts_shadows = unsafe { read::<u8>(native, NATIVE_LIGHT_CASTS_SHADOWS) } != 0;
    let position = unsafe { read_vec3(native, NATIVE_LIGHT_POSITION) };
    let diffuse = unsafe { read_vec3(native, NATIVE_LIGHT_DIFFUSE) };
    let dimmer = unsafe { read::<f32>(native, NATIVE_LIGHT_DIMMER) };
    let transition = unsafe { read::<f32>(scene_light, SHADOW_LIGHT_TRANSITION) };
    let native_radius = unsafe { read::<f32>(native, NATIVE_LIGHT_RADIUS) };
    if !position.into_iter().all(f32::is_finite)
        || !diffuse.into_iter().all(f32::is_finite)
        || !dimmer.is_finite()
        || !transition.is_finite()
        || !native_radius.is_finite()
        || native_radius <= 0.1
    {
        return None;
    }
    let radius = native_radius * NVR_POINT_RADIUS_MULTIPLIER;
    let relative_position =
        std::array::from_fn(|index| position[index] - camera_translation[index]);
    if !point_light_influence_is_eligible(
        relative_position,
        radius,
        camera_forward,
        NVR_POINT_DRAW_DISTANCE,
    ) {
        return None;
    }
    let distance_squared = dot3(relative_position, relative_position);
    let color = diffuse.map(|component| (component * dimmer * transition).max(0.0));
    if !distance_squared.is_finite()
        || !color.into_iter().all(f32::is_finite)
        || color.into_iter().all(|component| component <= 1.0 / 255.0)
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
        casts_shadows,
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
    use super::{PointLight, PointLightSelection};

    fn point(identity: usize, distance_squared: f32, casts_shadows: bool) -> PointLight {
        PointLight {
            identity,
            shadow_scene_light: core::ptr::null_mut(),
            position: [0.0; 3],
            relative_position: [0.0; 3],
            color: [1.0; 3],
            radius: 512.0,
            casts_shadows,
            distance_squared,
        }
    }

    #[test]
    fn runtime_selection_demotes_cube_overflow_into_the_tracked_set() {
        let mut selection = PointLightSelection::default();
        for identity in 1..=14 {
            selection.insert(point(identity, identity as f32, true));
        }
        selection.insert(point(101, 0.5, false));
        selection.insert(point(102, 13.5, false));
        selection.insert(point(1, 0.0, false));

        let shadowed: [usize; 12] = std::array::from_fn(|index| {
            selection
                .shadowed()
                .iter()
                .nth(index)
                .expect("full shadow set")
                .identity
        });
        assert_eq!(shadowed, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let tracked: [usize; 4] = std::array::from_fn(|index| {
            selection
                .unshadowed()
                .iter()
                .nth(index)
                .expect("four tracked fallbacks")
                .identity
        });
        assert_eq!(tracked, [101, 13, 102, 14]);
    }
}
