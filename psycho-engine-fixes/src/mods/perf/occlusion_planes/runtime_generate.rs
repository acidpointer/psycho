//! Runtime occluder collection from live cell geometry.
//!
//! The runtime walks the loaded cell's reference list and, for each opaque,
//! unskinned static geometry, derives conservative occlusion rectangles from
//! the geometry's own local vertex box and live world transform. Planes are
//! emitted per geometry (never merged across an object), oriented by the node's
//! world rotation, fitted to the largest axis-aligned rectangle supported by
//! the vertices near each face, and shrunk once more for safety.
//!
//! Only uncompressed vertex data is accepted. The engine's local/world bound is
//! a sphere; turning it into a box produces a rectangle that can float far
//! outside the mesh, so geometry without readable vertices is skipped. No
//! offline data and no authored `OBND` are required.
//!
//! Injected planes are one-sided: `+0xEA` is cleared after construction so the
//! engine's own camera-side test rejects a plane whenever the camera is behind
//! its face. Horizontal faces (ground and roofs) are skipped, and a face whose
//! support hull cannot contain a useful rectangle is rejected. Coplanar
//! rectangles that share a full edge are merged into their rectangular union,
//! which culls more per plane without covering empty space.
//!
//! This is still a heuristic. A convex hull around a concave mesh can over-cover
//! empty space, so planes are shrunk, only large geometry is kept, the per-cell
//! count is capped, and the feature has a kill switch. The owner's in-game
//! visual check remains required.
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
    GEOMETRY_ALPHA, GEOMETRY_DATA_COMPRESS, GEOMETRY_DATA_VERTEX_COUNT, GEOMETRY_DATA_VERTICES,
    GEOMETRY_MODEL_DATA, GEOMETRY_SKIN, IsKindFn, NIBOUND_RADIUS, NODE_CHILD_BASE,
    NODE_CHILD_COUNT, REFR_BASE_FORM, REFR_PARENT_CELL, REFR_RENDER_STATE, RENDER_STATE_NODE,
    TESFORM_REF_ID, TESFORM_TYPE_ID, TLIST_DATA, TLIST_NEXT, VTABLE_IS_GEOMETRY, VTABLE_IS_NODE,
    WORLD_ROTATION, WORLD_SCALE, WORLD_TRANSLATION,
};
use super::data::PlaneRecord;
use super::raw::{read_f32_at, read_ptr, read_ptr_at, read_u8_at, read_u16_at, read_u32_at};

const MAX_REFS: usize = 2000;
const MAX_VISITED_NODES: usize = 512;
const MAX_VERTICES_PER_MESH: usize = 4096;
const VERTEX_BUDGET: usize = 200_000;
const MIN_FACE_EXTENT: f32 = 128.0;
const MIN_BOX_EXTENT: f32 = 256.0;
const MAX_BOX_EXTENT: f32 = 8192.0;
const MIN_WORLD_RADIUS: f32 = MIN_BOX_EXTENT * 0.5;
const MAX_OCCLUDER_DISTANCE: f32 = 262_144.0;
/// Additional shrink applied after the rectangle is fitted inside the vertex
/// support hull. The support fit is the primary guard against floating faces;
/// this margin absorbs tessellation and transform error.
pub(super) const PLANE_SHRINK: f32 = 0.8;
/// Vertices within this fraction of the box extent are treated as part of the
/// face support. Absolute minimum keeps sub-unit meshes from rejecting a face
/// because of transform noise.
const SUPPORT_TOLERANCE_RATIO: f32 = 0.05;
const SUPPORT_TOLERANCE_MIN: f32 = 4.0;
/// Fraction of the box face that must be supported before a rectangle is
/// emitted. A rectangle smaller than this is treated as an unsafe bound-derived
/// face rather than a wall.
const MIN_SUPPORT_SCALE: f32 = 0.05;
/// World-space normal magnitude above which a face is treated as horizontal
/// ground/roof and skipped. Vertical walls have a normal Z near zero.
const MAX_HORIZONTAL_NORMAL: f32 = 0.8;
const OUTWARD_OFFSET: f32 = 2.0;

/// One axis-aligned box in a geometry's local space.
#[derive(Clone, Copy, Debug)]
pub(super) struct Aabb {
    pub(super) min: [f32; 3],
    pub(super) max: [f32; 3],
}

impl Aabb {
    fn center(&self) -> [f32; 3] {
        [
            (self.min[0] + self.max[0]) * 0.5,
            (self.min[1] + self.max[1]) * 0.5,
            (self.min[2] + self.max[2]) * 0.5,
        ]
    }

    fn extents(&self) -> [f32; 3] {
        [
            self.max[0] - self.min[0],
            self.max[1] - self.min[1],
            self.max[2] - self.min[2],
        ]
    }

    /// True when the world-space largest extent is in the admission range.
    /// `world_scale` is the node's uniform scale; the box itself stays in local
    /// space so its faces keep the node's orientation.
    fn is_eligible(&self, world_scale: f32) -> bool {
        let extents = self.extents();
        if extents
            .iter()
            .any(|extent| *extent <= 0.0 || !extent.is_finite())
            || !world_scale.is_finite()
            || world_scale == 0.0
        {
            return false;
        }
        let largest = extents[0].max(extents[1]).max(extents[2]) * world_scale.abs();
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
    no_vertices: usize,
    size_reject: usize,
    horizontal_reject: usize,
    support_reject: usize,
    small_reject: usize,
    distance_reject: usize,
    distance_max: f32,
    budget_stop: usize,
    faces: usize,
    /// Total admitted geometry area and total emitted rectangle area, so the
    /// debug log can show how much solid surface became occluders.
    mesh_area: f32,
    rect_area: f32,
    /// Merged rectangle area that the per-cell cap dropped, so the log shows
    /// whether the cap is the coverage limiter.
    cap_drop_area: f32,
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
) -> (Vec<PlaneRecord>, usize, bool) {
    let mut candidates: Vec<(f32, PlaneRecord)> = Vec::with_capacity(max_planes.max(1) * 4);
    let mut stack: Vec<*mut c_void> = Vec::with_capacity(64);
    let mut mesh_out: Vec<(f32, PlaneRecord)> = Vec::new();
    let mut vertex_buf: Vec<[f32; 3]> = Vec::with_capacity(MAX_VERTICES_PER_MESH);
    let mut support_points: Vec<[f32; 2]> = Vec::with_capacity(64);
    let mut support_hull: Vec<[f32; 2]> = Vec::with_capacity(64);
    let mut support_upper: Vec<[f32; 2]> = Vec::with_capacity(64);
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
                    &mut stack,
                    &mut vertex_buf,
                    &mut mesh_out,
                    &mut vertex_budget,
                    &mut candidates,
                    &mut stats,
                    &mut support_points,
                    &mut support_hull,
                    &mut support_upper,
                );
            }
            if next.is_null() || stats.refs >= MAX_REFS {
                break;
            }
            node = next;
        }
    }
    // Merge coplanar adjacent rectangles before scoring and capping. Two
    // support-validated rectangles that share a full edge have a rectangular
    // union, so the merged rectangle cannot cover empty space, and it culls
    // more bounds per plane while reducing the pair cost.
    merge_coplanar(&mut candidates);

    // Distance filter and score against the observer after merging, so the
    // merged center is the one that is scored.
    let mut scored: Vec<(f32, PlaneRecord)> = Vec::with_capacity(candidates.len());
    for (area, plane) in candidates.drain(..) {
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
                if distance.is_finite() {
                    stats.distance_max = stats.distance_max.max(distance);
                }
                continue;
            }
            // Score by roughly the plane's solid angle from the observer, so
            // the per-cell cap keeps the occluders that can hide the most: a
            // large near window beats a large distant one.
            weight = 1.0 + (distance * distance) / (2048.0 * 2048.0);
        }
        scored.push((area / weight, plane));
    }
    let raw = scored.len();
    let raw_area: f32 = scored
        .iter()
        .map(|(_, plane)| plane.size[0] * plane.size[1])
        .sum();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(core::cmp::Ordering::Equal));
    scored.truncate(max_planes.max(1));
    let kept_area: f32 = scored
        .iter()
        .map(|(_, plane)| plane.size[0] * plane.size[1])
        .sum();
    stats.rect_area = raw_area;
    stats.cap_drop_area = (raw_area - kept_area).max(0.0);
    let planes: Vec<PlaneRecord> = scored.into_iter().map(|(_, plane)| plane).collect();
    if log::log_enabled!(log::Level::Debug) {
        log::debug!(
            "[OCCLUSION_PLANES] scan refs={} parent_mismatch={} base_null={} not_stat={} \
             render_null={} node_null={} radius={} nodes={} geoms={} skinned={} alpha={} \
             no_vertices={} size={} horizontal={} support={} small={} distance={} \
             dist_max={:.0} budget_stop={} faces={} mesh_area={:.0} rect_area={:.0} \
             cap_drop={:.0}",
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
            stats.no_vertices,
            stats.size_reject,
            stats.horizontal_reject,
            stats.support_reject,
            stats.small_reject,
            stats.distance_reject,
            stats.distance_max,
            stats.budget_stop,
            stats.faces,
            stats.mesh_area,
            stats.rect_area,
            stats.cap_drop_area,
        );
    }
    (
        planes,
        raw,
        // All references have an attached render node, so no more 3D can
        // appear: the settle window can stop after the first identical pass.
        stats.render_null == 0 && stats.node_null == 0,
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn collect_reference(
    reference: *mut c_void,
    cell: *mut c_void,
    stack: &mut Vec<*mut c_void>,
    vertex_buf: &mut Vec<[f32; 3]>,
    mesh_out: &mut Vec<(f32, PlaneRecord)>,
    vertex_budget: &mut usize,
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
    support_points: &mut Vec<[f32; 2]>,
    support_hull: &mut Vec<[f32; 2]>,
    support_upper: &mut Vec<[f32; 2]>,
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
        collect_object_planes(
            node,
            stack,
            vertex_buf,
            vertex_budget,
            mesh_out,
            stats,
            support_points,
            support_hull,
            support_upper,
        );
    }
    for (area, mut plane) in mesh_out.drain(..) {
        plane.source_form_id = source_form_id;
        stats.faces += 1;
        out.push((area, plane));
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
#[inline]
pub(super) fn alpha_is_opaque(flags: Option<u16>) -> bool {
    flags.is_none_or(|flags| flags & (ALPHA_BLEND | ALPHA_TEST) == 0)
}

/// True for the static-like base forms whose loaded 3D may be an occluder.
#[inline]
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
    support_points: &mut Vec<[f32; 2]>,
    support_hull: &mut Vec<[f32; 2]>,
    support_upper: &mut Vec<[f32; 2]>,
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
            } else if let Some((local, world)) =
                unsafe { geometry_local_box(object, vertex_buf, vertex_budget) }
            {
                if local.is_eligible(world.scale) {
                    // World-space box surface area is the available occluder
                    // surface; the emitted rectangle area is what we use.
                    let extents = local.extents();
                    let world_scale = world.scale.abs();
                    stats.mesh_area += 2.0
                        * ((extents[0] * world_scale) * (extents[1] * world_scale)
                            + (extents[1] * world_scale) * (extents[2] * world_scale)
                            + (extents[2] * world_scale) * (extents[0] * world_scale));
                    let rejects = faces_from_oriented_box(
                        &local,
                        &world,
                        vertex_buf,
                        out,
                        support_points,
                        support_hull,
                        support_upper,
                    );
                    stats.horizontal_reject += rejects.horizontal;
                    stats.support_reject += rejects.unsupported;
                    stats.small_reject += rejects.small;
                } else {
                    stats.size_reject += 1;
                }
            } else {
                stats.no_vertices += 1;
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

/// Read the geometry's local vertex bounds and its world transform.
///
/// Only real vertex data is accepted. The engine's local/world bound is a
/// sphere, and turning it into a box produces a rectangle far outside the
/// actual mesh; that is not a safe occluder. Geometry with compressed or
/// unavailable vertices is skipped until the compressed layout is verified.
unsafe fn geometry_local_box(
    object: *mut c_void,
    vertex_buf: &mut Vec<[f32; 3]>,
    vertex_budget: &mut usize,
) -> Option<(Aabb, WorldTransform)> {
    let world = unsafe { read_world_transform(object) }?;
    let model = unsafe { read_ptr_at(object, GEOMETRY_MODEL_DATA) };
    if model.is_null() {
        return None;
    }
    let local = unsafe { vertices_local_aabb(model, vertex_buf, vertex_budget) }?;
    Some((local, world))
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
    // Safety: the model data owns a contiguous array of `count` NiPoint3
    // vertices (12-byte, 4-byte aligned). The pointer was checked non-null and
    // the count was bounded above; the scan runs on the main thread while the
    // cell is stable, and this is a read-only borrow for the duration of the
    // call. Reading through a slice lets the compiler vectorize the copy
    // instead of emitting one volatile load per float.
    let slice = unsafe { core::slice::from_raw_parts(vertices as *const [f32; 3], count) };
    if !slice
        .iter()
        .all(|point| point.iter().all(|value| value.is_finite()))
    {
        return None;
    }
    vertex_buf.clear();
    vertex_buf.extend_from_slice(slice);
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

/// Transform a local point by the node's rigid transform.
#[inline]
pub(super) fn transform_point(world: &WorldTransform, local: &[f32; 3]) -> [f32; 3] {
    let scaled = [
        local[0] * world.scale,
        local[1] * world.scale,
        local[2] * world.scale,
    ];
    let rotated = transform_direction(&world.rotation, &scaled);
    [
        rotated[0] + world.translation[0],
        rotated[1] + world.translation[1],
        rotated[2] + world.translation[2],
    ]
}

/// Transform and normalize a local direction. Returns `None` when the result
/// cannot be normalized, so a degenerate transform never reaches the engine.
#[inline]
pub(super) fn transform_unit_direction(
    world: &WorldTransform,
    local: &[f32; 3],
) -> Option<[f32; 3]> {
    let scaled = [
        local[0] * world.scale,
        local[1] * world.scale,
        local[2] * world.scale,
    ];
    let rotated = transform_direction(&world.rotation, &scaled);
    let length =
        (rotated[0] * rotated[0] + rotated[1] * rotated[1] + rotated[2] * rotated[2]).sqrt();
    if !length.is_finite() || length <= 0.0 {
        return None;
    }
    Some([
        rotated[0] / length,
        rotated[1] / length,
        rotated[2] / length,
    ])
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
        // and the face builder must use it to place the face on the correct
        // side of the translation. Face sizes use the magnitude.
        scale,
    })
}

/// Faces rejected by the oriented-face builder.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FaceRejects {
    /// Face normal is close to vertical (ground, roof or steep slope).
    pub(super) horizontal: usize,
    /// The vertex support hull cannot contain a useful centered rectangle.
    pub(super) unsupported: usize,
    /// The supported rectangle is below the minimum face extent.
    pub(super) small: usize,
}

/// Derive face rectangles from one local box and its world transform.
///
/// The engine's rectangle lies in local X/Z with local Y as the normal:
/// `0x00C35C10` builds corners as `position +/- sizeX * M*(1,0,0) +/- sizeY *
/// M*(0,0,1)`. The returned matrix therefore stores columns `(tangent,
/// normal, bitangent)`, and `bitangent = tangent x normal`. The stored size is
/// the full world-space face extent; `create_plane` halves it at the native
/// setter.
///
/// The local box preserves the node's orientation instead of re-axis-aligning
/// to world space. Each face is fitted to the convex hull of the vertices near
/// that face, so a sphere bound, a sparse corner or an empty AABB face cannot
/// become a large floating rectangle. Horizontal faces are skipped: ground and
/// roofs rarely occlude a standing player and are the most common source of
/// over-cover.
///
/// This function reads no engine memory and is unit-tested.
pub(super) fn faces_from_oriented_box(
    local: &Aabb,
    world: &WorldTransform,
    vertices: &[[f32; 3]],
    out: &mut Vec<(f32, PlaneRecord)>,
    support_points: &mut Vec<[f32; 2]>,
    support_hull: &mut Vec<[f32; 2]>,
    support_upper: &mut Vec<[f32; 2]>,
) -> FaceRejects {
    let mut rejects = FaceRejects::default();
    let center = local.center();
    let extents = local.extents();
    let world_scale = world.scale.abs();
    for axis in 0..3usize {
        let tangent_a = (axis + 1) % 3;
        let tangent_b = (axis + 2) % 3;
        let extent_a = extents[tangent_a] * world_scale;
        let extent_b = extents[tangent_b] * world_scale;
        if extent_a < MIN_FACE_EXTENT || extent_b < MIN_FACE_EXTENT {
            continue;
        }
        for sign in [1.0f32, -1.0f32] {
            let face_coord = if sign > 0.0 {
                local.max[axis]
            } else {
                local.min[axis]
            };
            let mut normal_local = [0.0f32; 3];
            normal_local[axis] = sign;
            let Some(outward) = transform_unit_direction(world, &normal_local) else {
                rejects.unsupported += 1;
                continue;
            };
            // Horizontal faces are ground, roofs or steep slopes. The player
            // views the world from above the ground, so these over-cover far
            // more than they occlude.
            if outward[2].abs() >= MAX_HORIZONTAL_NORMAL {
                rejects.horizontal += 1;
                continue;
            }
            let Some(rect) = support_rect(
                vertices,
                axis,
                face_coord,
                extents[axis],
                center[tangent_a],
                center[tangent_b],
                extents[tangent_a] * 0.5,
                extents[tangent_b] * 0.5,
                support_points,
                support_hull,
                support_upper,
            ) else {
                rejects.unsupported += 1;
                continue;
            };
            let Some(tangent) = transform_unit_direction(world, &unit_axis(tangent_a, 1.0)) else {
                rejects.unsupported += 1;
                continue;
            };
            // `0x00C358A0` builds the engine plane from corners `p0 = +A+B`,
            // `p1 = +A-B`, `p2 = -A-B` and computes `(p1-p0) x (p2-p1)`, which
            // equals the stored local +Y column. It activates the plane on that
            // plane's negative side. Store the inverse of the geometric outward
            // normal so the engine activates the rectangle only when the camera
            // is outside the solid face. The rectangle is symmetric, so the
            // flipped normal and bitangent cover the same area.
            let normal = [-outward[0], -outward[1], -outward[2]];
            let bitangent = cross(tangent, normal);
            let size = [
                rect.half_u * 2.0 * world_scale * PLANE_SHRINK,
                rect.half_v * 2.0 * world_scale * PLANE_SHRINK,
            ];
            if size[0] < MIN_FACE_EXTENT || size[1] < MIN_FACE_EXTENT {
                rejects.small += 1;
                continue;
            }
            let mut local_face_center = center;
            local_face_center[axis] = face_coord;
            local_face_center[tangent_a] = rect.center_u;
            local_face_center[tangent_b] = rect.center_v;
            let face_center = transform_point(world, &local_face_center);
            let position = [
                face_center[0] + outward[0] * OUTWARD_OFFSET,
                face_center[1] + outward[1] * OUTWARD_OFFSET,
                face_center[2] + outward[2] * OUTWARD_OFFSET,
            ];
            let rotation = [
                tangent[0],
                normal[0],
                bitangent[0],
                tangent[1],
                normal[1],
                bitangent[1],
                tangent[2],
                normal[2],
                bitangent[2],
            ];
            out.push((
                size[0] * size[1],
                PlaneRecord {
                    position,
                    size,
                    rotation,
                    priority: 255,
                    // Filled in by the caller from the reference's base form.
                    source_form_id: 0,
                },
            ));
        }
    }
    rejects
}

/// Coplanar rectangles are merged only when their union is exactly a rectangle.
/// Two support-validated rectangles that share a full edge have a rectangular
/// union, so the merged rectangle stays inside the union of two solid-backed
/// rectangles and cannot cover empty space.
const MERGE_PLANE_TOLERANCE: f32 = 1.0;
/// Grouping tolerance: puts near-parallel faces in the same candidate bucket.
const MERGE_GROUP_TOLERANCE: f32 = 0.999;
/// Actual merge tolerance: only nearly identical normals and axes merge, so a
/// merged rectangle cannot drift far off the second face's plane.
const MERGE_AXIS_TOLERANCE: f32 = 0.9999;

/// In-plane axis-aligned bounds of one rectangle.
#[derive(Clone, Copy, Debug)]
struct Rect2 {
    u_min: f32,
    u_max: f32,
    v_min: f32,
    v_max: f32,
}

/// Merge coplanar adjacent rectangles in place, replacing each group with its
/// rectangular union. Bounded to a few passes; a chain of segments is handled
/// by the repeated pass.
pub(super) fn merge_coplanar(candidates: &mut Vec<(f32, PlaneRecord)>) {
    if candidates.len() < 2 {
        return;
    }
    let planes: Vec<PlaneRecord> = candidates.drain(..).map(|(_, plane)| plane).collect();
    // Group by orientation first so the quadratic merge only compares faces
    // that could share a plane. A dense cell has few distinct wall
    // orientations, which keeps this bounded.
    let mut groups: Vec<([f32; 3], Vec<PlaneRecord>)> = Vec::new();
    for plane in planes {
        let normal = basis(plane.rotation).1;
        let mut target = None;
        for (index, (group_normal, _)) in groups.iter().enumerate() {
            if dot3(normal, *group_normal) > MERGE_GROUP_TOLERANCE {
                target = Some(index);
                break;
            }
        }
        match target {
            Some(index) => groups[index].1.push(plane),
            None => groups.push((normal, vec![plane])),
        }
    }
    for (_, mut group) in groups {
        for _ in 0..3 {
            let mut changed = false;
            let mut i = 0;
            while i < group.len() {
                let mut j = i + 1;
                while j < group.len() {
                    if let Some(merged) = merge_rect(&group[i], &group[j]) {
                        group[i] = merged;
                        group.swap_remove(j);
                        changed = true;
                    } else {
                        j += 1;
                    }
                }
                i += 1;
            }
            if !changed {
                break;
            }
        }
        candidates.extend(
            group
                .into_iter()
                .map(|plane| (plane.size[0] * plane.size[1], plane)),
        );
    }
}

fn basis(rotation: [f32; 9]) -> ([f32; 3], [f32; 3], [f32; 3]) {
    (
        [rotation[0], rotation[3], rotation[6]],
        [rotation[1], rotation[4], rotation[7]],
        [rotation[2], rotation[5], rotation[8]],
    )
}

fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn rect2(plane: &PlaneRecord, tangent: [f32; 3], bitangent: [f32; 3]) -> Rect2 {
    let (plane_tangent, _, plane_bitangent) = basis(plane.rotation);
    let half_u = plane.size[0] * 0.5;
    let half_v = plane.size[1] * 0.5;
    let mut u_min = f32::INFINITY;
    let mut u_max = f32::NEG_INFINITY;
    let mut v_min = f32::INFINITY;
    let mut v_max = f32::NEG_INFINITY;
    for (su, sv) in [(1.0f32, 1.0f32), (1.0, -1.0), (-1.0, -1.0), (-1.0, 1.0)] {
        let point = [
            plane.position[0] + su * half_u * plane_tangent[0] + sv * half_v * plane_bitangent[0],
            plane.position[1] + su * half_u * plane_tangent[1] + sv * half_v * plane_bitangent[1],
            plane.position[2] + su * half_u * plane_tangent[2] + sv * half_v * plane_bitangent[2],
        ];
        let u = dot3(point, tangent);
        let v = dot3(point, bitangent);
        u_min = u_min.min(u);
        u_max = u_max.max(u);
        v_min = v_min.min(v);
        v_max = v_max.max(v);
    }
    Rect2 {
        u_min,
        u_max,
        v_min,
        v_max,
    }
}

/// Rectangular union of two in-plane rectangles, or `None` when the union would
/// not be a rectangle.
fn union_rect(a: Rect2, b: Rect2) -> Option<Rect2> {
    let tol = MERGE_PLANE_TOLERANCE;
    let contains = |outer: Rect2, inner: Rect2| {
        outer.u_min <= inner.u_min + tol
            && outer.u_max >= inner.u_max - tol
            && outer.v_min <= inner.v_min + tol
            && outer.v_max >= inner.v_max - tol
    };
    if contains(a, b) {
        return Some(a);
    }
    if contains(b, a) {
        return Some(b);
    }
    // Same v interval and adjacent/overlapping u interval.
    if (a.v_min - b.v_min).abs() <= tol
        && (a.v_max - b.v_max).abs() <= tol
        && a.u_min <= b.u_max + tol
        && b.u_min <= a.u_max + tol
    {
        return Some(Rect2 {
            u_min: a.u_min.min(b.u_min),
            u_max: a.u_max.max(b.u_max),
            v_min: a.v_min.min(b.v_min),
            v_max: a.v_max.max(b.v_max),
        });
    }
    // Same u interval and adjacent/overlapping v interval.
    if (a.u_min - b.u_min).abs() <= tol
        && (a.u_max - b.u_max).abs() <= tol
        && a.v_min <= b.v_max + tol
        && b.v_min <= a.v_max + tol
    {
        return Some(Rect2 {
            u_min: a.u_min.min(b.u_min),
            u_max: a.u_max.max(b.u_max),
            v_min: a.v_min.min(b.v_min),
            v_max: a.v_max.max(b.v_max),
        });
    }
    None
}

fn merge_rect(a: &PlaneRecord, b: &PlaneRecord) -> Option<PlaneRecord> {
    let (tangent_a, normal_a, bitangent_a) = basis(a.rotation);
    let (tangent_b, normal_b, bitangent_b) = basis(b.rotation);
    if dot3(normal_a, normal_b) < MERGE_AXIS_TOLERANCE {
        return None;
    }
    let offset_a = dot3(normal_a, a.position);
    let offset_b = dot3(normal_a, b.position);
    if (offset_a - offset_b).abs() > MERGE_PLANE_TOLERANCE {
        return None;
    }
    let direct = dot3(tangent_a, tangent_b).abs() > MERGE_AXIS_TOLERANCE
        && dot3(bitangent_a, bitangent_b).abs() > MERGE_AXIS_TOLERANCE;
    let swapped = dot3(tangent_a, bitangent_b).abs() > MERGE_AXIS_TOLERANCE
        && dot3(bitangent_a, tangent_b).abs() > MERGE_AXIS_TOLERANCE;
    if !direct && !swapped {
        return None;
    }
    let union = union_rect(
        rect2(a, tangent_a, bitangent_a),
        rect2(b, tangent_a, bitangent_a),
    )?;
    let size = [union.u_max - union.u_min, union.v_max - union.v_min];
    if size[0] <= 0.0 || size[1] <= 0.0 {
        return None;
    }
    let center_u = (union.u_min + union.u_max) * 0.5;
    let center_v = (union.v_min + union.v_max) * 0.5;
    let position = [
        center_u * tangent_a[0] + center_v * bitangent_a[0] + offset_a * normal_a[0],
        center_u * tangent_a[1] + center_v * bitangent_a[1] + offset_a * normal_a[1],
        center_u * tangent_a[2] + center_v * bitangent_a[2] + offset_a * normal_a[2],
    ];
    Some(PlaneRecord {
        position,
        size,
        rotation: a.rotation,
        priority: a.priority.max(b.priority),
        source_form_id: a.source_form_id,
    })
}

/// Largest axis-aligned rectangle supported by the face's vertices.
#[derive(Clone, Copy, Debug)]
pub(super) struct SupportRect {
    pub(super) center_u: f32,
    pub(super) center_v: f32,
    pub(super) half_u: f32,
    pub(super) half_v: f32,
}

/// Find the largest axis-aligned rectangle backed by vertices near the face.
///
/// The fast path keeps the previous centered rectangle: binary-search the
/// largest centered scale whose four corners lie inside the 2D convex hull of
/// the face's support vertices. When no useful centered rectangle exists, a
/// bounded occupancy grid finds the largest rectangle anywhere in the hull.
/// Every result is inside the convex hull, which is the same support bound the
/// centered path used, so this only adds coverage, not a new over-cover class.
///
/// A face with fewer than three support points (a sphere bound, a single corner
/// or a line) is rejected instead of being treated as a solid wall.
pub(super) fn support_rect(
    vertices: &[[f32; 3]],
    axis: usize,
    face_coord: f32,
    extent_axis: f32,
    center_u: f32,
    center_v: f32,
    half_u_param: f32,
    half_v_param: f32,
    points: &mut Vec<[f32; 2]>,
    hull: &mut Vec<[f32; 2]>,
    upper: &mut Vec<[f32; 2]>,
) -> Option<SupportRect> {
    let tangent_a = (axis + 1) % 3;
    let tangent_b = (axis + 2) % 3;
    let tolerance = SUPPORT_TOLERANCE_MIN.max(extent_axis * SUPPORT_TOLERANCE_RATIO);
    points.clear();
    for vertex in vertices {
        if (vertex[axis] - face_coord).abs() <= tolerance {
            points.push([vertex[tangent_a], vertex[tangent_b]]);
        }
    }
    if points.len() < 3 {
        return None;
    }
    convex_hull(points, hull, upper);
    if hull.len() < 3 {
        return None;
    }

    // Centered candidate. It is the cheapest and keeps the previous behavior
    // for well-shaped faces.
    let centered = if rectangle_inside(
        hull,
        center_u,
        center_v,
        half_u_param * MIN_SUPPORT_SCALE,
        half_v_param * MIN_SUPPORT_SCALE,
    ) {
        let mut low = MIN_SUPPORT_SCALE;
        let mut high = 1.0f32;
        for _ in 0..20 {
            let mid = (low + high) * 0.5;
            if rectangle_inside(
                hull,
                center_u,
                center_v,
                half_u_param * mid,
                half_v_param * mid,
            ) {
                low = mid;
            } else {
                high = mid;
            }
        }
        Some(SupportRect {
            center_u,
            center_v,
            half_u: half_u_param * low,
            half_v: half_v_param * low,
        })
    } else {
        None
    };

    // Only search the grid when the centered rectangle is missing or clearly
    // smaller than the face, so the common case stays cheap.
    let grid = if centered
        .is_none_or(|rect| rect.half_u < half_u_param * 0.6 || rect.half_v < half_v_param * 0.6)
    {
        grid_support_rect(hull)
    } else {
        None
    };

    let best = match (centered, grid) {
        (Some(centered), Some(grid)) => {
            if grid.half_u * grid.half_v > centered.half_u * centered.half_v {
                Some(grid)
            } else {
                Some(centered)
            }
        }
        (Some(centered), None) => Some(centered),
        (None, Some(grid)) => Some(grid),
        (None, None) => None,
    }?;
    if best.half_u < half_u_param * MIN_SUPPORT_SCALE
        || best.half_v < half_v_param * MIN_SUPPORT_SCALE
    {
        return None;
    }
    Some(best)
}

/// Convert the largest grid rectangle inside the hull into face-local bounds.
fn grid_support_rect(hull: &[[f32; 2]]) -> Option<SupportRect> {
    let (u0, v0, u1, v1, columns, rows) = largest_supported_rect(hull)?;
    let columns = columns as f32;
    let rows = rows as f32;
    if columns <= 0.0 || rows <= 0.0 {
        return None;
    }
    // Inset by half a cell so the emitted rectangle keeps a margin from the
    // hull boundary even before the global `PLANE_SHRINK`.
    let half_u = (u1 - u0) * 0.5 - (u1 - u0) / columns * 0.5;
    let half_v = (v1 - v0) * 0.5 - (v1 - v0) / rows * 0.5;
    if half_u <= 0.0 || half_v <= 0.0 {
        return None;
    }
    Some(SupportRect {
        center_u: (u0 + u1) * 0.5,
        center_v: (v0 + v1) * 0.5,
        half_u,
        half_v,
    })
}

/// Grid occupancy search for the largest axis-aligned rectangle inside a convex
/// hull. Returns `(u0, v0, u1, v1, columns, rows)` in local face coordinates.
/// Fixed-size stack storage keeps the per-face cost allocation-free.
const SUPPORT_GRID: usize = 16;
const MAX_SUPPORT_HULL_EDGES: usize = 96;

fn largest_supported_rect(hull: &[[f32; 2]]) -> Option<(f32, f32, f32, f32, usize, usize)> {
    if hull.len() > MAX_SUPPORT_HULL_EDGES {
        return None;
    }
    let mut min_u = f32::INFINITY;
    let mut max_u = f32::NEG_INFINITY;
    let mut min_v = f32::INFINITY;
    let mut max_v = f32::NEG_INFINITY;
    for point in hull {
        min_u = min_u.min(point[0]);
        max_u = max_u.max(point[0]);
        min_v = min_v.min(point[1]);
        max_v = max_v.max(point[1]);
    }
    let du = max_u - min_u;
    let dv = max_v - min_v;
    if !(du > 0.0) || !(dv > 0.0) {
        return None;
    }
    let cw = du / SUPPORT_GRID as f32;
    let ch = dv / SUPPORT_GRID as f32;
    let mut inside = [false; SUPPORT_GRID * SUPPORT_GRID];
    for gy in 0..SUPPORT_GRID {
        for gx in 0..SUPPORT_GRID {
            let u0 = min_u + gx as f32 * cw;
            let u1 = u0 + cw;
            let v0 = min_v + gy as f32 * ch;
            let v1 = v0 + ch;
            inside[gy * SUPPORT_GRID + gx] = point_inside_convex(hull, [u0, v0])
                && point_inside_convex(hull, [u1, v0])
                && point_inside_convex(hull, [u1, v1])
                && point_inside_convex(hull, [u0, v1]);
        }
    }
    // Largest rectangle of `true` cells (histogram method).
    let mut heights = [0usize; SUPPORT_GRID];
    let mut stack = [(0usize, 0usize); SUPPORT_GRID + 1];
    let mut stack_len;
    let mut best = (0usize, 0usize, 0usize, 0usize, 0usize); // area, left, right, bottom, height
    for gy in 0..SUPPORT_GRID {
        for gx in 0..SUPPORT_GRID {
            heights[gx] = if inside[gy * SUPPORT_GRID + gx] {
                heights[gx] + 1
            } else {
                0
            };
        }
        stack_len = 0;
        for gx in 0..=SUPPORT_GRID {
            let current = if gx == SUPPORT_GRID { 0 } else { heights[gx] };
            let mut start = gx;
            while stack_len > 0 {
                let (height, index) = stack[stack_len - 1];
                if height <= current {
                    break;
                }
                stack_len -= 1;
                let area = height * (gx - index);
                if area > best.0 {
                    best = (area, index, gx, gy + 1 - height, height);
                }
                start = index;
            }
            stack[stack_len] = (current, start);
            stack_len += 1;
        }
    }
    if best.0 == 0 {
        return None;
    }
    let (_, left, right, bottom, height) = best;
    let u0 = min_u + left as f32 * cw;
    let u1 = min_u + right as f32 * cw;
    let v0 = min_v + bottom as f32 * ch;
    let v1 = v0 + height as f32 * ch;
    Some((u0, v0, u1, v1, right - left, height))
}

/// Convex hull of 2D points in counter-clockwise order (monotone chain). The
/// caller-owned buffers keep this allocation-free per face.
fn convex_hull(points: &mut Vec<[f32; 2]>, hull: &mut Vec<[f32; 2]>, upper: &mut Vec<[f32; 2]>) {
    points.sort_by(|a, b| a[0].total_cmp(&b[0]).then(a[1].total_cmp(&b[1])));
    points.dedup_by(|a, b| a[0] == b[0] && a[1] == b[1]);
    hull.clear();
    upper.clear();
    if points.len() < 3 {
        hull.extend_from_slice(points);
        return;
    }
    let cross = |o: [f32; 2], a: [f32; 2], b: [f32; 2]| {
        (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])
    };
    for point in points.iter() {
        while hull.len() >= 2 && cross(hull[hull.len() - 2], hull[hull.len() - 1], *point) <= 0.0 {
            hull.pop();
        }
        hull.push(*point);
    }
    for point in points.iter().rev() {
        while upper.len() >= 2
            && cross(upper[upper.len() - 2], upper[upper.len() - 1], *point) <= 0.0
        {
            upper.pop();
        }
        upper.push(*point);
    }
    hull.pop();
    upper.pop();
    hull.extend_from_slice(upper);
}

#[inline]
fn rectangle_inside(
    hull: &[[f32; 2]],
    center_u: f32,
    center_v: f32,
    half_u: f32,
    half_v: f32,
) -> bool {
    let corners = [
        [center_u - half_u, center_v - half_v],
        [center_u + half_u, center_v - half_v],
        [center_u + half_u, center_v + half_v],
        [center_u - half_u, center_v + half_v],
    ];
    corners
        .iter()
        .all(|corner| point_inside_convex(hull, *corner))
}

#[inline]
fn point_inside_convex(hull: &[[f32; 2]], point: [f32; 2]) -> bool {
    // The hull is counter-clockwise, so a point is inside when it is on the
    // left side of every edge. A small negative epsilon absorbs f32 noise on
    // a corner that lies exactly on an edge.
    const EPSILON: f32 = -0.01;
    for index in 0..hull.len() {
        let a = hull[index];
        let b = hull[(index + 1) % hull.len()];
        let edge = (b[0] - a[0]) * (point[1] - a[1]) - (b[1] - a[1]) * (point[0] - a[0]);
        if edge < EPSILON {
            return false;
        }
    }
    true
}

#[inline]
fn unit_axis(axis: usize, sign: f32) -> [f32; 3] {
    let mut value = [0.0f32; 3];
    value[axis] = sign;
    value
}

#[inline]
fn cross(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

#[inline]
fn transform_direction(rotation: &[f32; 9], vector: &[f32; 3]) -> [f32; 3] {
    [
        rotation[0] * vector[0] + rotation[1] * vector[1] + rotation[2] * vector[2],
        rotation[3] * vector[0] + rotation[4] * vector[1] + rotation[5] * vector[2],
        rotation[6] * vector[0] + rotation[7] * vector[1] + rotation[8] * vector[2],
    ]
}
