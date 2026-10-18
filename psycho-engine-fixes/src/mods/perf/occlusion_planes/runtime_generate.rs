//! Runtime occluder collection from live cell geometry.
//!
//! The runtime walks the loaded cell's reference list and, for each opaque,
//! unskinned static geometry, derives conservative occlusion rectangles from
//! the geometry's own world-space bounding box. Planes are emitted per
//! geometry (never merged across an object), shrunk to half their extent and
//! sized conservatively, which keeps the cone narrow enough that visible
//! objects and NPCs are not falsely culled.
//!
//! The mesh bounds come from the CPU vertex array when it is present and
//! uncompressed, and fall back to the geometry's local or world bound
//! otherwise. No offline data and no authored `OBND` are required.
//!
//! This is a heuristic. An axis-aligned box around a concave mesh can still
//! over-cover empty space, so planes are shrunk, only large geometry is kept,
//! the per-cell count is capped, and the feature has a kill switch. The
//! owner's in-game visual check remains required.
//!
//! Every offset and virtual slot is verified against the supported executable:
//! the `tList` walk matches the engine's child traversal at `0x00A5DBE0`, the
//! `NiAVObject`/`NiGeometry` fields match `NiGeometry::UpdateWorldBound` at
//! `0x00A80710` and `TESObjectREFR::Set3D` at `0x005702E0`, the geometry data
//! vertex/bound fields match `0x00A87900`/`0x00A66F90`, the compression getter
//! is `0x00EE8AA0`, the `NiAlphaProperty` vtable is stored by its constructor
//! at `0x00A5D3BB`, and the `IsNode`/`IsGeometry` slots match the `NiNode`
//! (`0x0109B5AC`) and `NiTriShape` (`0x0109D454`) vtables.

use core::ffi::c_void;

use libpsycho::ffi::fnptr::FnPtr;
use wide::f32x4;

use super::contract::{
    ALPHA_BLEND, ALPHA_FLAGS, ALPHA_PROPERTY_VTABLE, ALPHA_TEST, AVOBJECT_WORLD_BOUND,
    CELL_OBJECT_LIST, COMPRESS_POSITION, FORM_TYPE_STAT, FORM_TYPE_STATIC_COLLECTION,
    GEOMETRY_ALPHA, GEOMETRY_DATA_BOUND, GEOMETRY_DATA_BOUND_RADIUS, GEOMETRY_DATA_COMPRESS,
    GEOMETRY_DATA_VERTEX_COUNT, GEOMETRY_DATA_VERTICES, GEOMETRY_MODEL_DATA, GEOMETRY_SKIN,
    IsKindFn, NIBOUND_RADIUS, NODE_CHILD_BASE, NODE_CHILD_COUNT, REFR_BASE_FORM, REFR_PARENT_CELL,
    REFR_RENDER_STATE, RENDER_STATE_NODE, TESFORM_REF_ID, TESFORM_TYPE_ID, TLIST_DATA, TLIST_NEXT,
    VTABLE_IS_GEOMETRY, VTABLE_IS_NODE, WORLD_ROTATION, WORLD_SCALE, WORLD_TRANSLATION,
};
use super::data::{PlaneRecord, PlaneRotation};
use super::raw::{read_f32_at, read_ptr, read_ptr_at, read_u8_at, read_u16_at, read_u32_at};

const MAX_REFS: usize = 2000;
const MAX_VISITED_NODES: usize = 512;
const MAX_VERTICES_PER_MESH: usize = 4096;
const VERTEX_BUDGET: usize = 200_000;
const MIN_FACE_EXTENT: f32 = 128.0;
const MIN_BOX_EXTENT: f32 = 256.0;
const MAX_BOX_EXTENT: f32 = 8192.0;
const MIN_WORLD_RADIUS: f32 = MIN_BOX_EXTENT * 0.5;
const MAX_OCCLUDER_DISTANCE: f32 = 24_576.0;
/// Rectangle shrink. Keeping the rectangle well inside the geometry's silhouette
/// narrows the camera-through-rectangle cone, which is the main guard against
/// false culling of visible objects.
pub(super) const PLANE_SHRINK: f32 = 0.6;
const OUTWARD_OFFSET: f32 = 2.0;

/// One world-space axis-aligned box.
#[derive(Clone, Copy, Debug)]
pub(super) struct Aabb {
    pub(super) min: [f32; 3],
    pub(super) max: [f32; 3],
}

impl Aabb {
    fn empty() -> Self {
        Self {
            min: [f32::INFINITY; 3],
            max: [f32::NEG_INFINITY; 3],
        }
    }

    fn merge(&mut self, other: &Aabb) {
        for axis in 0..3 {
            self.min[axis] = self.min[axis].min(other.min[axis]);
            self.max[axis] = self.max[axis].max(other.max[axis]);
        }
    }

    fn extents(&self) -> [f32; 3] {
        [
            self.max[0] - self.min[0],
            self.max[1] - self.min[1],
            self.max[2] - self.min[2],
        ]
    }

    fn is_eligible(&self) -> bool {
        let extents = self.extents();
        if extents
            .iter()
            .any(|extent| *extent <= 0.0 || !extent.is_finite())
        {
            return false;
        }
        let largest = extents[0].max(extents[1]).max(extents[2]);
        (MIN_BOX_EXTENT..=MAX_BOX_EXTENT).contains(&largest)
    }
}

/// One world-space rigid transform read from a loaded node.
#[derive(Clone, Copy, Debug)]
pub(super) struct WorldTransform {
    /// Row-major 3x3 rotation (`world = rotation * local`).
    pub(super) rotation: [f32; 9],
    pub(super) translation: [f32; 3],
    /// Signed uniform scale. A negative value mirrors the local geometry.
    pub(super) scale: f32,
}

/// Debug counters for one cell scan.
///
/// The increments are cheap and always performed; only the summary line is
/// gated on the debug level. They are the owner's only runtime evidence when a
/// cell yields too few candidates, because this repository cannot run the game.
#[derive(Default)]
pub(super) struct ScanStats {
    refs: usize,
    parent_mismatch: usize,
    base_null: usize,
    not_stat: usize,
    render_null: usize,
    node_null: usize,
    radius_reject: usize,
    nodes: usize,
    geoms: usize,
    skinned: usize,
    alpha: usize,
    no_bounds: usize,
    size_reject: usize,
    distance_reject: usize,
    budget_stop: usize,
    faces: usize,
    /// Total admitted geometry area and total emitted rectangle area, so the
    /// debug log can show how much solid surface became occluders.
    mesh_area: f32,
    rect_area: f32,
}

/// Collect up to `max_planes` occlusion rectangles for one cell.
///
/// `observer` is the player/observer world position. Candidates are filtered by
/// distance and weighted so nearby occluders win the per-cell cap over distant
/// ones of similar size. Returns the selected planes and the raw pre-cap
/// candidate count.
pub(super) fn generate(
    cell: *mut c_void,
    max_planes: usize,
    observer: Option<[f32; 3]>,
) -> (Vec<PlaneRecord>, usize) {
    let mut candidates: Vec<(f32, PlaneRecord)> = Vec::with_capacity(max_planes.max(1) * 4);
    let mut stack: Vec<*mut c_void> = Vec::with_capacity(64);
    let mut mesh_out: Vec<(f32, PlaneRecord)> = Vec::new();
    let mut vertex_buf: Vec<[f32; 3]> = Vec::with_capacity(MAX_VERTICES_PER_MESH);
    let mut vertex_budget = VERTEX_BUDGET;
    let mut stats = ScanStats::default();
    // Safety: the caller runs on the main thread after a cell change; the
    // reference list, node transforms and mesh arrays are read-only here and
    // belong to the loaded cell.
    unsafe {
        let list = (cell as *mut u8).add(CELL_OBJECT_LIST) as *mut c_void;
        let mut node = list;
        loop {
            let reference = read_ptr_at(node, TLIST_DATA);
            let next = read_ptr_at(node, TLIST_NEXT);
            if !reference.is_null() {
                stats.refs += 1;
                collect_reference(
                    reference,
                    cell,
                    observer,
                    &mut stack,
                    &mut vertex_buf,
                    &mut mesh_out,
                    &mut vertex_budget,
                    &mut candidates,
                    &mut stats,
                );
            }
            if next.is_null() || stats.refs >= MAX_REFS {
                break;
            }
            node = next;
        }
    }
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(core::cmp::Ordering::Equal));
    let raw = candidates.len();
    candidates.truncate(max_planes.max(1));
    if log::log_enabled!(log::Level::Debug) {
        log::debug!(
            "[OCCLUSION_PLANES] scan refs={} parent_mismatch={} base_null={} not_stat={} \
             render_null={} node_null={} radius={} nodes={} geoms={} skinned={} alpha={} \
             no_bounds={} size={} distance={} budget_stop={} faces={} mesh_area={:.0} \
             rect_area={:.0}",
            stats.refs,
            stats.parent_mismatch,
            stats.base_null,
            stats.not_stat,
            stats.render_null,
            stats.node_null,
            stats.radius_reject,
            stats.nodes,
            stats.geoms,
            stats.skinned,
            stats.alpha,
            stats.no_bounds,
            stats.size_reject,
            stats.distance_reject,
            stats.budget_stop,
            stats.faces,
            stats.mesh_area,
            stats.rect_area,
        );
    }
    (
        candidates.into_iter().map(|(_, plane)| plane).collect(),
        raw,
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn collect_reference(
    reference: *mut c_void,
    cell: *mut c_void,
    observer: Option<[f32; 3]>,
    stack: &mut Vec<*mut c_void>,
    vertex_buf: &mut Vec<[f32; 3]>,
    mesh_out: &mut Vec<(f32, PlaneRecord)>,
    vertex_budget: &mut usize,
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
) {
    // Stop examining further references once the shared vertex budget is spent,
    // so the cell-load pass stays bounded instead of falling back to coarse
    // sphere bounds for the remaining objects.
    if *vertex_budget == 0 {
        stats.budget_stop += 1;
        return;
    }
    // The reference comes from this cell's own `objectList`. A non-null parent
    // that differs is unexpected; a null parent is tolerated while the cell is
    // still attaching its references.
    let parent = unsafe { read_ptr_at(reference, REFR_PARENT_CELL) };
    if !parent.is_null() && parent != cell {
        stats.parent_mismatch += 1;
        return;
    }
    let base = unsafe { read_ptr_at(reference, REFR_BASE_FORM) };
    if base.is_null() {
        stats.base_null += 1;
        return;
    }
    if !admits_base_type(unsafe { read_u8_at(base, TESFORM_TYPE_ID) }) {
        stats.not_stat += 1;
        return;
    }
    // Bind every plane from this reference to its source form so a cached
    // plane can be traced back to the plugin that owns it.
    let source_form_id = unsafe { read_u32_at(base, TESFORM_REF_ID) };
    let render_state = unsafe { read_ptr_at(reference, REFR_RENDER_STATE) };
    if render_state.is_null() {
        stats.render_null += 1;
        return;
    }
    let node = unsafe { read_ptr_at(render_state, RENDER_STATE_NODE) };
    if node.is_null() {
        stats.node_null += 1;
        return;
    }
    // Cheap rejection before the node walk: the engine's world-bound radius is
    // at least half the object's largest extent. A null bound is allowed; the
    // geometry pass then decides.
    if let Some(radius) = unsafe { world_bound_radius(node) }
        && radius < MIN_WORLD_RADIUS
    {
        stats.radius_reject += 1;
        return;
    }
    mesh_out.clear();
    unsafe {
        collect_object_planes(node, stack, vertex_buf, vertex_budget, mesh_out, stats);
    }
    for (area, mut plane) in mesh_out.drain(..) {
        plane.source_form_id = source_form_id;
        let mut weight = 1.0f32;
        if let Some(observer) = observer {
            let offset = [
                plane.position[0] - observer[0],
                plane.position[1] - observer[1],
                plane.position[2] - observer[2],
            ];
            let distance =
                (offset[0] * offset[0] + offset[1] * offset[1] + offset[2] * offset[2]).sqrt();
            if !distance.is_finite() || distance > MAX_OCCLUDER_DISTANCE {
                stats.distance_reject += 1;
                continue;
            }
            // Score by roughly the plane's solid angle from the observer, so
            // the per-cell cap keeps the occluders that can hide the most: a
            // large near window beats a large distant one.
            weight = 1.0 + (distance * distance) / (2048.0 * 2048.0);
        }
        stats.faces += 1;
        out.push((area / weight, plane));
    }
}

unsafe fn world_bound_radius(object: *mut c_void) -> Option<f32> {
    let bound = unsafe { read_ptr_at(object, AVOBJECT_WORLD_BOUND) };
    if bound.is_null() {
        return None;
    }
    let radius = unsafe { read_f32_at(bound, NIBOUND_RADIUS) };
    (radius.is_finite() && radius > 0.0).then_some(radius)
}

/// True when no alpha blend/test flag is set. `None` means no alpha property.
pub(super) fn alpha_is_opaque(flags: Option<u16>) -> bool {
    flags.is_none_or(|flags| flags & (ALPHA_BLEND | ALPHA_TEST) == 0)
}

/// True for the static-like base forms whose loaded 3D may be an occluder.
pub(super) fn admits_base_type(type_id: u8) -> bool {
    matches!(type_id, FORM_TYPE_STAT | FORM_TYPE_STATIC_COLLECTION)
}

/// True when the geometry has no skinned instance and no transparent alpha
/// property. The `+0x9C` pointer is treated as an alpha property only when its
/// vtable matches `NiAlphaProperty`; otherwise the geometry is admitted, so a
/// wrong or shifted property offset cannot reject the whole cell.
unsafe fn admits_geometry(object: *mut c_void) -> bool {
    let alpha = unsafe { read_ptr_at(object, GEOMETRY_ALPHA) };
    if alpha.is_null() {
        return true;
    }
    if unsafe { read_ptr(alpha as usize) } as usize != ALPHA_PROPERTY_VTABLE {
        return true;
    }
    let flags = unsafe { read_u16_at(alpha, ALPHA_FLAGS) };
    alpha_is_opaque(Some(flags))
}

/// Walk the node tree and emit occlusion rectangles for every opaque,
/// unskinned geometry below `root`, one box per geometry.
unsafe fn collect_object_planes(
    root: *mut c_void,
    stack: &mut Vec<*mut c_void>,
    vertex_buf: &mut Vec<[f32; 3]>,
    vertex_budget: &mut usize,
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
) {
    stack.clear();
    stack.push(root);
    let mut visited = 0usize;
    while let Some(object) = stack.pop() {
        visited += 1;
        if visited > MAX_VISITED_NODES {
            return;
        }
        stats.nodes += 1;
        let is_node = unsafe { call_kind(object, VTABLE_IS_NODE) };
        let is_geometry = unsafe { call_kind(object, VTABLE_IS_GEOMETRY) };
        if !is_geometry.is_null() {
            stats.geoms += 1;
            if !unsafe { read_ptr_at(object, GEOMETRY_SKIN) }.is_null() {
                stats.skinned += 1;
            } else if !unsafe { admits_geometry(object) } {
                stats.alpha += 1;
            } else if let Some(bounds) =
                unsafe { geometry_world_aabb(object, vertex_buf, vertex_budget) }
            {
                if bounds.is_eligible() {
                    // Bounding-box surface area is the available occluder
                    // surface; the emitted rectangle area is what we use.
                    let extents = bounds.extents();
                    stats.mesh_area += 2.0
                        * (extents[0] * extents[1]
                            + extents[1] * extents[2]
                            + extents[2] * extents[0]);
                    let before = out.len();
                    faces_from_box(&bounds.min, &bounds.max, out);
                    for entry in &out[before..] {
                        stats.rect_area += entry.0;
                    }
                } else {
                    stats.size_reject += 1;
                }
            } else {
                stats.no_bounds += 1;
            }
        }
        if !is_node.is_null() {
            let base = unsafe { read_ptr_at(object, NODE_CHILD_BASE) };
            let count = unsafe { read_u16_at(object, NODE_CHILD_COUNT) } as usize;
            if base.is_null() {
                continue;
            }
            for index in 0..count.min(MAX_VISITED_NODES) {
                let child = unsafe { read_ptr_at(base, index * 4) };
                if !child.is_null() {
                    stack.push(child);
                }
            }
        }
    }
}

unsafe fn geometry_world_aabb(
    object: *mut c_void,
    vertex_buf: &mut Vec<[f32; 3]>,
    vertex_budget: &mut usize,
) -> Option<Aabb> {
    let world = unsafe { read_world_transform(object) }?;
    let model = unsafe { read_ptr_at(object, GEOMETRY_MODEL_DATA) };
    if model.is_null() {
        return unsafe { world_bound_aabb(object) };
    }
    if let Some(local) = unsafe { vertices_local_aabb(model, vertex_buf, vertex_budget) } {
        return Some(transform_aabb(&local, &world));
    }
    if let Some(local) = unsafe { local_bound_aabb(model) } {
        return Some(transform_aabb(&local, &world));
    }
    unsafe { world_bound_aabb(object) }
}

unsafe fn vertices_local_aabb(
    model: *mut c_void,
    vertex_buf: &mut Vec<[f32; 3]>,
    vertex_budget: &mut usize,
) -> Option<Aabb> {
    let compress = unsafe { read_u8_at(model, GEOMETRY_DATA_COMPRESS) };
    if compress & COMPRESS_POSITION != 0 {
        return None;
    }
    let count = unsafe { read_u16_at(model, GEOMETRY_DATA_VERTEX_COUNT) } as usize;
    if count == 0 || count > MAX_VERTICES_PER_MESH || count > *vertex_budget {
        return None;
    }
    let vertices = unsafe { read_ptr_at(model, GEOMETRY_DATA_VERTICES) };
    if vertices.is_null() {
        return None;
    }
    vertex_buf.clear();
    for index in 0..count {
        let offset = index * 12;
        let point = [
            unsafe { read_f32_at(vertices, offset) },
            unsafe { read_f32_at(vertices, offset + 4) },
            unsafe { read_f32_at(vertices, offset + 8) },
        ];
        if !point.iter().all(|value| value.is_finite()) {
            return None;
        }
        vertex_buf.push(point);
    }
    *vertex_budget -= count;
    Some(aabb_of(vertex_buf))
}

/// Axis-aligned bounds of a point cloud, four points at a time with a portable
/// SIMD vector (`wide` wraps SSE/AVX/NEON with a scalar fallback) and a scalar
/// tail.
pub(super) fn aabb_of(points: &[[f32; 3]]) -> Aabb {
    let mut min_x = f32x4::splat(f32::INFINITY);
    let mut min_y = f32x4::splat(f32::INFINITY);
    let mut min_z = f32x4::splat(f32::INFINITY);
    let mut max_x = f32x4::splat(f32::NEG_INFINITY);
    let mut max_y = f32x4::splat(f32::NEG_INFINITY);
    let mut max_z = f32x4::splat(f32::NEG_INFINITY);
    let mut chunks = points.chunks_exact(4);
    for chunk in &mut chunks {
        let x = f32x4::new([chunk[0][0], chunk[1][0], chunk[2][0], chunk[3][0]]);
        let y = f32x4::new([chunk[0][1], chunk[1][1], chunk[2][1], chunk[3][1]]);
        let z = f32x4::new([chunk[0][2], chunk[1][2], chunk[2][2], chunk[3][2]]);
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        min_z = min_z.min(z);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
        max_z = max_z.max(z);
    }
    let reduce_min = |value: f32x4| value.to_array().into_iter().fold(f32::INFINITY, f32::min);
    let reduce_max = |value: f32x4| {
        value
            .to_array()
            .into_iter()
            .fold(f32::NEG_INFINITY, f32::max)
    };
    let mut min = [reduce_min(min_x), reduce_min(min_y), reduce_min(min_z)];
    let mut max = [reduce_max(max_x), reduce_max(max_y), reduce_max(max_z)];
    for point in chunks.remainder() {
        min[0] = min[0].min(point[0]);
        min[1] = min[1].min(point[1]);
        min[2] = min[2].min(point[2]);
        max[0] = max[0].max(point[0]);
        max[1] = max[1].max(point[1]);
        max[2] = max[2].max(point[2]);
    }
    Aabb { min, max }
}

unsafe fn local_bound_aabb(model: *mut c_void) -> Option<Aabb> {
    let center = [
        unsafe { read_f32_at(model, GEOMETRY_DATA_BOUND) },
        unsafe { read_f32_at(model, GEOMETRY_DATA_BOUND + 4) },
        unsafe { read_f32_at(model, GEOMETRY_DATA_BOUND + 8) },
    ];
    let radius = unsafe { read_f32_at(model, GEOMETRY_DATA_BOUND_RADIUS) };
    if !center.iter().all(|value| value.is_finite()) || !radius.is_finite() || radius <= 0.0 {
        return None;
    }
    Some(Aabb {
        min: [center[0] - radius, center[1] - radius, center[2] - radius],
        max: [center[0] + radius, center[1] + radius, center[2] + radius],
    })
}

unsafe fn world_bound_aabb(object: *mut c_void) -> Option<Aabb> {
    let bound = unsafe { read_ptr_at(object, AVOBJECT_WORLD_BOUND) };
    if bound.is_null() {
        return None;
    }
    let center = [
        unsafe { read_f32_at(bound, 0) },
        unsafe { read_f32_at(bound, 4) },
        unsafe { read_f32_at(bound, 8) },
    ];
    let radius = unsafe { read_f32_at(bound, NIBOUND_RADIUS) };
    if !center.iter().all(|value| value.is_finite()) || !radius.is_finite() || radius <= 0.0 {
        return None;
    }
    Some(Aabb {
        min: [center[0] - radius, center[1] - radius, center[2] - radius],
        max: [center[0] + radius, center[1] + radius, center[2] + radius],
    })
}

/// Transform a local AABB by a rigid transform. The signed scale is preserved
/// so mirrored objects map to the correct world-space side.
pub(super) fn transform_aabb(local: &Aabb, world: &WorldTransform) -> Aabb {
    let mut result = Aabb::empty();
    for corner in 0..8 {
        let local_point = [
            if corner & 1 == 0 {
                local.min[0]
            } else {
                local.max[0]
            },
            if corner & 2 == 0 {
                local.min[1]
            } else {
                local.max[1]
            },
            if corner & 4 == 0 {
                local.min[2]
            } else {
                local.max[2]
            },
        ];
        let scaled = [
            local_point[0] * world.scale,
            local_point[1] * world.scale,
            local_point[2] * world.scale,
        ];
        let rotated = transform_direction(&world.rotation, &scaled);
        let point = Aabb {
            min: [
                rotated[0] + world.translation[0],
                rotated[1] + world.translation[1],
                rotated[2] + world.translation[2],
            ],
            max: [
                rotated[0] + world.translation[0],
                rotated[1] + world.translation[1],
                rotated[2] + world.translation[2],
            ],
        };
        result.merge(&point);
    }
    result
}

unsafe fn call_kind(object: *mut c_void, slot: usize) -> *mut c_void {
    let vtable = unsafe { read_ptr(object as usize) };
    if vtable.is_null() {
        return core::ptr::null_mut();
    }
    let entry = unsafe { read_ptr_at(vtable, slot) };
    if entry.is_null() {
        return core::ptr::null_mut();
    }
    // Safety: the vtable slot is `NiObject::IsNode` or `IsGeometry`, both
    // thiscall and both returning a pointer; the object is a live NiObject.
    let Ok(function) = (unsafe { FnPtr::<IsKindFn>::from_raw(entry) }) else {
        return core::ptr::null_mut();
    };
    unsafe { function.as_fn()(object) }
}

unsafe fn read_world_transform(node: *mut c_void) -> Option<WorldTransform> {
    let mut rotation = [0.0f32; 9];
    for (index, slot) in rotation.iter_mut().enumerate() {
        *slot = unsafe { read_f32_at(node, WORLD_ROTATION + index * 4) };
    }
    let translation = [
        unsafe { read_f32_at(node, WORLD_TRANSLATION) },
        unsafe { read_f32_at(node, WORLD_TRANSLATION + 4) },
        unsafe { read_f32_at(node, WORLD_TRANSLATION + 8) },
    ];
    let scale = unsafe { read_f32_at(node, WORLD_SCALE) };
    if !rotation.iter().all(|value| value.is_finite())
        || !translation.iter().all(|value| value.is_finite())
        || !scale.is_finite()
        || scale == 0.0
    {
        return None;
    }
    Some(WorldTransform {
        rotation,
        translation,
        // Keep the sign: a negative uniform scale mirrors the local geometry,
        // and `transform_aabb` must use it to place the world-space box on the
        // correct side of the translation. Face sizes use the magnitude.
        scale,
    })
}

/// Derive the six face rectangles of one world-space box.
///
/// The engine's plane rectangle lies in local X/Z with local Y as the normal:
/// `0x00C35C10` builds corners as `position +/- sizeX * M*(1,0,0) +/- sizeY *
/// M*(0,0,1)`. The returned matrix therefore stores columns `(tangent,
/// normal, bitangent)`. The stored size is the full face extent; `create_plane`
/// halves it at the native setter.
///
/// This function reads no engine memory and is unit-tested.
pub(super) fn faces_from_box(min: &[f32; 3], max: &[f32; 3], out: &mut Vec<(f32, PlaneRecord)>) {
    let center = [
        (min[0] + max[0]) * 0.5,
        (min[1] + max[1]) * 0.5,
        (min[2] + max[2]) * 0.5,
    ];
    let extents = [max[0] - min[0], max[1] - min[1], max[2] - min[2]];
    for axis in 0..3usize {
        let tangent_a = (axis + 1) % 3;
        let tangent_b = (axis + 2) % 3;
        let extent_a = extents[tangent_a];
        let extent_b = extents[tangent_b];
        if extent_a < MIN_FACE_EXTENT || extent_b < MIN_FACE_EXTENT {
            continue;
        }
        let area = extent_a * extent_b;
        for sign in [1.0f32, -1.0f32] {
            let normal_local = unit_axis(axis, sign);
            let tangent_a_local = unit_axis(tangent_a, 1.0);
            // Choose the second tangent so (tangent, normal, bitangent) is a
            // right-handed basis: tangent x normal = bitangent.
            let tangent_b_local = unit_axis(tangent_b, -sign);
            let face_center = [
                center[0] + normal_local[0] * extents[0] * 0.5,
                center[1] + normal_local[1] * extents[1] * 0.5,
                center[2] + normal_local[2] * extents[2] * 0.5,
            ];
            let position = [
                face_center[0] + normal_local[0] * OUTWARD_OFFSET,
                face_center[1] + normal_local[1] * OUTWARD_OFFSET,
                face_center[2] + normal_local[2] * OUTWARD_OFFSET,
            ];
            let size = [extent_a * PLANE_SHRINK, extent_b * PLANE_SHRINK];
            let rotation = [
                tangent_a_local[0],
                normal_local[0],
                tangent_b_local[0],
                tangent_a_local[1],
                normal_local[1],
                tangent_b_local[1],
                tangent_a_local[2],
                normal_local[2],
                tangent_b_local[2],
            ];
            out.push((
                area,
                PlaneRecord {
                    position,
                    size,
                    rotation: PlaneRotation::Matrix(rotation),
                    priority: 255,
                    // Filled in by the caller from the reference's base form.
                    source_form_id: 0,
                },
            ));
        }
    }
}

fn unit_axis(axis: usize, sign: f32) -> [f32; 3] {
    let mut value = [0.0f32; 3];
    value[axis] = sign;
    value
}

fn transform_direction(rotation: &[f32; 9], vector: &[f32; 3]) -> [f32; 3] {
    [
        rotation[0] * vector[0] + rotation[1] * vector[1] + rotation[2] * vector[2],
        rotation[3] * vector[0] + rotation[4] * vector[1] + rotation[5] * vector[2],
        rotation[6] * vector[0] + rotation[7] * vector[1] + rotation[8] * vector[2],
    ]
}
