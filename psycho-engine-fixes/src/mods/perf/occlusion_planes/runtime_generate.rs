//! Runtime occluder collection from live cell geometry.
//!
//! The runtime walks the loaded cell's reference list and, for each opaque,
//! unskinned triangle mesh, extracts large coplanar surface patches (walls,
//! floors, building facades). Each patch is emitted as an occlusion rectangle
//! only when its projected triangles cover nearly the whole rectangle, so the
//! plane sits on real solid geometry instead of on the empty region of an
//! axis-aligned bounding box. That is what keeps the injected planes from
//! false-culling visible objects and NPCs.
//!
//! The mesh is read from `NiGeometryData`: transformed vertices and the
//! `NiTriShapeData` triangle index list. `NiTriStrips`, compressed positions
//! and meshes without a triangle list are skipped, because their silhouette
//! cannot be verified. No offline data and no authored `OBND` are required.
//!
//! This is still a heuristic, but a conservative one: planes are shrunk, only
//! large patches are kept, the per-cell count is capped, and the feature has a
//! kill switch. The owner's in-game visual check remains required.
//!
//! Every offset and virtual slot is verified against the supported executable:
//! the geometry data fields match `0x00A87900`/`0x00A66F90`, the compression
//! getter is `0x00EE8AA0`, the triangle list members are read by the field
//! writer at `0x00A7BDAB`/`0x00A7BDE8`, the `NiAlphaProperty` vtable is stored
//! by its constructor at `0x00A5D3BB`, and the `IsNode`/`IsGeometry`/`IsTriShape`
//! slots match the `NiNode` (`0x0109B5AC`) and `NiTriShape` (`0x0109D454`)
//! vtables.

use core::ffi::c_void;

use libpsycho::ffi::fnptr::FnPtr;

use super::contract::{
    ALPHA_BLEND, ALPHA_FLAGS, ALPHA_PROPERTY_VTABLE, ALPHA_TEST, AVOBJECT_WORLD_BOUND,
    CELL_OBJECT_LIST, COMPRESS_POSITION, FORM_TYPE_STAT, FORM_TYPE_STATIC_COLLECTION,
    GEOMETRY_ALPHA, GEOMETRY_DATA_COMPRESS, GEOMETRY_DATA_VERTEX_COUNT, GEOMETRY_DATA_VERTICES,
    GEOMETRY_MODEL_DATA, GEOMETRY_SKIN, GEOMETRY_TRI_LIST, GEOMETRY_TRI_LIST_LENGTH, IsKindFn,
    NIBOUND_RADIUS, NODE_CHILD_BASE, NODE_CHILD_COUNT, REFR_BASE_FORM, REFR_PARENT_CELL,
    REFR_RENDER_STATE, RENDER_STATE_NODE, TESFORM_TYPE_ID, TLIST_DATA, TLIST_NEXT,
    VTABLE_IS_GEOMETRY, VTABLE_IS_NODE, VTABLE_IS_TRI_SHAPE, WORLD_ROTATION, WORLD_SCALE,
    WORLD_TRANSLATION,
};
use super::data::{PlaneRecord, PlaneRotation};
use super::raw::{read_f32_at, read_ptr, read_ptr_at, read_u8_at, read_u16_at, read_u32_at};

const MAX_REFS: usize = 5000;
const MAX_VISITED_NODES: usize = 1024;
const MAX_VERTICES_PER_MESH: usize = 8192;
const MAX_TRI_INDICES: usize = 12_288;
const VERTEX_BUDGET: usize = 400_000;
const TRIANGLE_BUDGET: usize = 200_000;
const MIN_FACE_EXTENT: f32 = 128.0;
const MIN_WORLD_RADIUS: f32 = 128.0;
const MAX_OCCLUDER_DISTANCE: f32 = 24_576.0;
const PLANE_SHRINK: f32 = 0.8;
const OUTWARD_OFFSET: f32 = 1.0;
/// Coplanar patch clustering: triangles whose world normals differ by less
/// than this dot product and whose plane distances differ by less than the
/// tolerance join one patch.
const CLUSTER_NORMAL_DOT: f32 = 0.999;
const CLUSTER_DISTANCE_TOLERANCE: f32 = 1.0;
const MAX_CLUSTERS_PER_MESH: usize = 32;
/// Patch coverage grid. A patch contributes the largest all-covered
/// sub-rectangle of this grid, so a window or courtyard becomes a smaller solid
/// plane instead of a plane over empty space.
const COVERAGE_GRID: usize = 6;

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
    no_mesh: usize,
    triangles: usize,
    clusters: usize,
    cluster_area_reject: usize,
    coverage_reject: usize,
    size_reject: usize,
    distance_reject: usize,
    budget_stop: usize,
    faces: usize,
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
    let mut vertex_buf: Vec<[f32; 3]> = Vec::with_capacity(MAX_VERTICES_PER_MESH);
    let mut index_buf: Vec<u16> = Vec::with_capacity(MAX_TRI_INDICES);
    let mut mesh_out: Vec<(f32, PlaneRecord)> = Vec::new();
    let mut vertex_budget = VERTEX_BUDGET;
    let mut triangle_budget = TRIANGLE_BUDGET;
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
                    &mut index_buf,
                    &mut mesh_out,
                    &mut vertex_budget,
                    &mut triangle_budget,
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
             no_mesh={} triangles={} clusters={} cluster_area={} coverage={} size={} \
             distance={} budget_stop={} faces={}",
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
            stats.no_mesh,
            stats.triangles,
            stats.clusters,
            stats.cluster_area_reject,
            stats.coverage_reject,
            stats.size_reject,
            stats.distance_reject,
            stats.budget_stop,
            stats.faces,
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
    index_buf: &mut Vec<u16>,
    mesh_out: &mut Vec<(f32, PlaneRecord)>,
    vertex_budget: &mut usize,
    triangle_budget: &mut usize,
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
) {
    // Stop examining further references once the shared vertex budget is spent,
    // so the cell-load pass stays bounded.
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
            index_buf,
            vertex_budget,
            triangle_budget,
            mesh_out,
            stats,
        );
    }
    for (area, plane) in mesh_out.drain(..) {
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
            // Prefer nearby occluders when the per-cell cap selects by score.
            weight = 1.0 + distance / 2048.0;
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

/// Walk the node tree and emit occluder planes for every opaque, unskinned
/// triangle mesh below `root`.
#[allow(clippy::too_many_arguments)]
unsafe fn collect_object_planes(
    root: *mut c_void,
    stack: &mut Vec<*mut c_void>,
    vertex_buf: &mut Vec<[f32; 3]>,
    index_buf: &mut Vec<u16>,
    vertex_budget: &mut usize,
    triangle_budget: &mut usize,
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
            } else {
                unsafe {
                    geometry_planes(
                        object,
                        vertex_buf,
                        index_buf,
                        vertex_budget,
                        triangle_budget,
                        out,
                        stats,
                    );
                }
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

/// Read one `NiTriShape` mesh, transform its vertices to world space and emit
/// planes for its large, well-covered coplanar patches.
unsafe fn geometry_planes(
    object: *mut c_void,
    vertex_buf: &mut Vec<[f32; 3]>,
    index_buf: &mut Vec<u16>,
    vertex_budget: &mut usize,
    triangle_budget: &mut usize,
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
) {
    // Only a triangle mesh has an index list whose silhouette we can verify.
    if unsafe { call_kind(object, VTABLE_IS_TRI_SHAPE) }.is_null() {
        stats.no_mesh += 1;
        return;
    }
    let world = match unsafe { read_world_transform(object) } {
        Some(world) => world,
        None => {
            stats.no_mesh += 1;
            return;
        }
    };
    let model = unsafe { read_ptr_at(object, GEOMETRY_MODEL_DATA) };
    if model.is_null() {
        stats.no_mesh += 1;
        return;
    }
    if unsafe { read_u8_at(model, GEOMETRY_DATA_COMPRESS) } & COMPRESS_POSITION != 0 {
        stats.no_mesh += 1;
        return;
    }
    let vertex_count = unsafe { read_u16_at(model, GEOMETRY_DATA_VERTEX_COUNT) } as usize;
    if vertex_count == 0 || vertex_count > MAX_VERTICES_PER_MESH || vertex_count > *vertex_budget {
        stats.no_mesh += 1;
        return;
    }
    let vertices = unsafe { read_ptr_at(model, GEOMETRY_DATA_VERTICES) };
    if vertices.is_null() {
        stats.no_mesh += 1;
        return;
    }
    vertex_buf.clear();
    for index in 0..vertex_count {
        let offset = index * 12;
        let local = [
            unsafe { read_f32_at(vertices, offset) },
            unsafe { read_f32_at(vertices, offset + 4) },
            unsafe { read_f32_at(vertices, offset + 8) },
        ];
        if !local.iter().all(|value| value.is_finite()) {
            stats.no_mesh += 1;
            return;
        }
        vertex_buf.push(transform_point(local, &world));
    }
    let index_count = unsafe { read_u32_at(model, GEOMETRY_TRI_LIST_LENGTH) } as usize;
    let indices = unsafe { read_ptr_at(model, GEOMETRY_TRI_LIST) };
    if indices.is_null() {
        stats.no_mesh += 1;
        return;
    }
    let usable = index_count
        .min(MAX_TRI_INDICES)
        .min((*triangle_budget).saturating_mul(3));
    if usable < 3 {
        stats.no_mesh += 1;
        return;
    }
    index_buf.clear();
    for index in 0..usable {
        index_buf.push(unsafe { read_u16_at(indices, index * 2) });
    }
    *vertex_budget -= vertex_count;
    *triangle_budget = (*triangle_budget).saturating_sub(usable / 3);
    stats.triangles += usable / 3;
    mesh_planes(vertex_buf, index_buf, out, stats);
}

/// One coplanar triangle patch found in a mesh.
struct Cluster {
    normal: [f32; 3],
    distance: f32,
    area: f32,
    triangles: Vec<[u16; 3]>,
}

/// Extract large, well-covered coplanar patches from a world-space mesh.
///
/// A patch is emitted as an occlusion rectangle only when its triangles cover
/// `MIN_FACE_COVERAGE` of the rectangle grid. That rejects bounding-box planes
/// over empty space and keeps planes on real solid surfaces, which is what
/// prevents false culling.
pub(super) fn mesh_planes(
    vertices: &[[f32; 3]],
    indices: &[u16],
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
) {
    let mut clusters: Vec<Cluster> = Vec::new();
    for triangle in indices.chunks_exact(3) {
        let a = usize::from(triangle[0]);
        let b = usize::from(triangle[1]);
        let c = usize::from(triangle[2]);
        if a >= vertices.len() || b >= vertices.len() || c >= vertices.len() {
            continue;
        }
        let (normal, area) = match triangle_plane(vertices[a], vertices[b], vertices[c]) {
            Some(value) => value,
            None => continue,
        };
        let distance = dot(normal, vertices[a]);
        if let Some(cluster) = clusters.iter_mut().find(|cluster| {
            dot(normal, cluster.normal) >= CLUSTER_NORMAL_DOT
                && (distance - cluster.distance).abs() <= CLUSTER_DISTANCE_TOLERANCE
        }) {
            cluster
                .triangles
                .push([triangle[0], triangle[1], triangle[2]]);
            cluster.area += area;
        } else if clusters.len() < MAX_CLUSTERS_PER_MESH {
            clusters.push(Cluster {
                normal,
                distance,
                area,
                triangles: vec![[triangle[0], triangle[1], triangle[2]]],
            });
        }
    }
    for cluster in &clusters {
        stats.clusters += 1;
        if cluster.area < MIN_FACE_EXTENT * MIN_FACE_EXTENT {
            stats.cluster_area_reject += 1;
            continue;
        }
        let (tangent, bitangent) = plane_basis(cluster.normal);
        let Some((min_u, min_v, width, height)) =
            cluster_bounds(vertices, cluster, tangent, bitangent)
        else {
            stats.cluster_area_reject += 1;
            continue;
        };
        if width < MIN_FACE_EXTENT || height < MIN_FACE_EXTENT {
            stats.cluster_area_reject += 1;
            continue;
        }
        let mask = cluster_mask(
            vertices, cluster, tangent, bitangent, min_u, min_v, width, height,
        );
        let Some((x0, y0, x1, y1)) = largest_solid_rectangle(mask) else {
            stats.coverage_reject += 1;
            continue;
        };
        // Convert the all-covered grid rectangle back to plane coordinates.
        let cell_w = width / COVERAGE_GRID as f32;
        let cell_h = height / COVERAGE_GRID as f32;
        let u0 = min_u + x0 as f32 * cell_w;
        let u1 = min_u + (x1 as f32 + 1.0) * cell_w;
        let v0 = min_v + y0 as f32 * cell_h;
        let v1 = min_v + (y1 as f32 + 1.0) * cell_h;
        let sub_width = u1 - u0;
        let sub_height = v1 - v0;
        if sub_width < MIN_FACE_EXTENT || sub_height < MIN_FACE_EXTENT {
            stats.size_reject += 1;
            continue;
        }
        let mid_u = (u0 + u1) * 0.5;
        let mid_v = (v0 + v1) * 0.5;
        let center = [
            tangent[0] * mid_u + bitangent[0] * mid_v + cluster.normal[0] * cluster.distance,
            tangent[1] * mid_u + bitangent[1] * mid_v + cluster.normal[1] * cluster.distance,
            tangent[2] * mid_u + bitangent[2] * mid_v + cluster.normal[2] * cluster.distance,
        ];
        // Score by the emitted rectangle's area, not the triangle area sum, so
        // the largest visible windows win the per-cell cap.
        push_plane(
            center,
            cluster.normal,
            tangent,
            bitangent,
            sub_width,
            sub_height,
            sub_width * sub_height,
            out,
        );
    }
}

/// Project the patch bounds into its plane. Returns `(min_u, min_v, width,
/// height)`.
fn cluster_bounds(
    vertices: &[[f32; 3]],
    cluster: &Cluster,
    tangent: [f32; 3],
    bitangent: [f32; 3],
) -> Option<(f32, f32, f32, f32)> {
    let mut min_u = f32::INFINITY;
    let mut max_u = f32::NEG_INFINITY;
    let mut min_v = f32::INFINITY;
    let mut max_v = f32::NEG_INFINITY;
    for triangle in &cluster.triangles {
        for &index in triangle {
            let point = vertices[usize::from(index)];
            let u = dot(point, tangent);
            let v = dot(point, bitangent);
            min_u = min_u.min(u);
            max_u = max_u.max(u);
            min_v = min_v.min(v);
            max_v = max_v.max(v);
        }
    }
    if !(min_u.is_finite() && max_u.is_finite() && min_v.is_finite() && max_v.is_finite()) {
        return None;
    }
    let width = max_u - min_u;
    let height = max_v - min_v;
    if width <= 0.0 || height <= 0.0 {
        return None;
    }
    Some((min_u, min_v, width, height))
}

/// Rasterize the patch triangles into its coverage grid.
#[allow(clippy::too_many_arguments)]
fn cluster_mask(
    vertices: &[[f32; 3]],
    cluster: &Cluster,
    tangent: [f32; 3],
    bitangent: [f32; 3],
    min_u: f32,
    min_v: f32,
    width: f32,
    height: f32,
) -> u64 {
    let mut mask = 0u64;
    for triangle in &cluster.triangles {
        let mut points = [[0.0f32; 2]; 3];
        for (slot, &index) in triangle.iter().enumerate() {
            let point = vertices[usize::from(index)];
            points[slot] = [dot(point, tangent), dot(point, bitangent)];
        }
        rasterize_triangle(points, [min_u, min_v], [width, height], &mut mask);
    }
    mask
}

/// Largest all-covered axis-aligned sub-rectangle of the grid, inclusive.
fn largest_solid_rectangle(mask: u64) -> Option<(usize, usize, usize, usize)> {
    let mut best: Option<(usize, usize, usize, usize)> = None;
    let mut best_cells = 0usize;
    for y0 in 0..COVERAGE_GRID {
        for x0 in 0..COVERAGE_GRID {
            for y1 in y0..COVERAGE_GRID {
                for x1 in x0..COVERAGE_GRID {
                    let mut solid = true;
                    'scan: for y in y0..=y1 {
                        for x in x0..=x1 {
                            if mask & (1u64 << (y * COVERAGE_GRID + x)) == 0 {
                                solid = false;
                                break 'scan;
                            }
                        }
                    }
                    if solid {
                        let cells = (x1 - x0 + 1) * (y1 - y0 + 1);
                        if cells > best_cells {
                            best_cells = cells;
                            best = Some((x0, y0, x1, y1));
                        }
                    }
                }
            }
        }
    }
    best
}

/// Rasterize one 2D triangle into the patch grid.
fn rasterize_triangle(points: [[f32; 2]; 3], origin: [f32; 2], size: [f32; 2], mask: &mut u64) {
    let cell = |value: f32, min: f32, extent: f32| -> i32 {
        (((value - min) / extent) * COVERAGE_GRID as f32).floor() as i32
    };
    let min_x = points.iter().map(|p| p[0]).fold(f32::INFINITY, f32::min);
    let max_x = points
        .iter()
        .map(|p| p[0])
        .fold(f32::NEG_INFINITY, f32::max);
    let min_y = points.iter().map(|p| p[1]).fold(f32::INFINITY, f32::min);
    let max_y = points
        .iter()
        .map(|p| p[1])
        .fold(f32::NEG_INFINITY, f32::max);
    let x0 = cell(min_x, origin[0], size[0]).clamp(0, COVERAGE_GRID as i32 - 1);
    let x1 = cell(max_x, origin[0], size[0]).clamp(0, COVERAGE_GRID as i32 - 1);
    let y0 = cell(min_y, origin[1], size[1]).clamp(0, COVERAGE_GRID as i32 - 1);
    let y1 = cell(max_y, origin[1], size[1]).clamp(0, COVERAGE_GRID as i32 - 1);
    for y in y0..=y1 {
        for x in x0..=x1 {
            let point = [
                origin[0] + (x as f32 + 0.5) / COVERAGE_GRID as f32 * size[0],
                origin[1] + (y as f32 + 0.5) / COVERAGE_GRID as f32 * size[1],
            ];
            if point_in_triangle(point, points) {
                let cell_index = (y as usize) * COVERAGE_GRID + x as usize;
                *mask |= 1u64 << cell_index;
            }
        }
    }
}

fn point_in_triangle(point: [f32; 2], triangle: [[f32; 2]; 3]) -> bool {
    let edge = |a: [f32; 2], b: [f32; 2]| -> f32 {
        (point[0] - b[0]) * (a[1] - b[1]) - (a[0] - b[0]) * (point[1] - b[1])
    };
    let d1 = edge(triangle[0], triangle[1]);
    let d2 = edge(triangle[1], triangle[2]);
    let d3 = edge(triangle[2], triangle[0]);
    let has_negative = d1 < 0.0 || d2 < 0.0 || d3 < 0.0;
    let has_positive = d1 > 0.0 || d2 > 0.0 || d3 > 0.0;
    !(has_negative && has_positive)
}

/// Emit one occlusion rectangle for a verified patch.
#[allow(clippy::too_many_arguments)]
fn push_plane(
    center: [f32; 3],
    normal: [f32; 3],
    tangent: [f32; 3],
    bitangent: [f32; 3],
    width: f32,
    height: f32,
    area: f32,
    out: &mut Vec<(f32, PlaneRecord)>,
) {
    let position = [
        center[0] + normal[0] * OUTWARD_OFFSET,
        center[1] + normal[1] * OUTWARD_OFFSET,
        center[2] + normal[2] * OUTWARD_OFFSET,
    ];
    let size = [width * PLANE_SHRINK, height * PLANE_SHRINK];
    // Row-major columns: tangent, normal, bitangent (the engine spans local X/Z
    // and takes local Y as the rectangle normal).
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
        area,
        PlaneRecord {
            position,
            size,
            rotation: PlaneRotation::Matrix(rotation),
            priority: 255,
        },
    ));
}

fn triangle_plane(a: [f32; 3], b: [f32; 3], c: [f32; 3]) -> Option<([f32; 3], f32)> {
    let ab = [b[0] - a[0], b[1] - a[1], b[2] - a[2]];
    let ac = [c[0] - a[0], c[1] - a[1], c[2] - a[2]];
    let cross = [
        ab[1] * ac[2] - ab[2] * ac[1],
        ab[2] * ac[0] - ab[0] * ac[2],
        ab[0] * ac[1] - ab[1] * ac[0],
    ];
    let length = (cross[0] * cross[0] + cross[1] * cross[1] + cross[2] * cross[2]).sqrt();
    if !length.is_finite() || length < 1e-6 {
        return None;
    }
    let area = length * 0.5;
    Some((
        [cross[0] / length, cross[1] / length, cross[2] / length],
        area,
    ))
}

/// A unit in-plane basis for `normal`: tangent and bitangent with
/// `tangent x normal = bitangent`.
fn plane_basis(normal: [f32; 3]) -> ([f32; 3], [f32; 3]) {
    let axis = if normal[0].abs() <= normal[1].abs() && normal[0].abs() <= normal[2].abs() {
        [1.0, 0.0, 0.0]
    } else if normal[1].abs() <= normal[2].abs() {
        [0.0, 1.0, 0.0]
    } else {
        [0.0, 0.0, 1.0]
    };
    let tangent = normalize(cross(normal, axis));
    let bitangent = cross(tangent, normal);
    (tangent, bitangent)
}

fn dot(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn cross(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

fn normalize(value: [f32; 3]) -> [f32; 3] {
    let length = (value[0] * value[0] + value[1] * value[1] + value[2] * value[2]).sqrt();
    if !length.is_finite() || length <= 0.0 {
        [0.0, 0.0, 0.0]
    } else {
        [value[0] / length, value[1] / length, value[2] / length]
    }
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
    // Safety: the vtable slot is `IsNode`, `IsGeometry` or `IsTriShape`, all
    // thiscall and all returning a pointer; the object is a live NiObject.
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
        scale,
    })
}

/// Apply a rigid transform to a local point.
pub(super) fn transform_point(local: [f32; 3], world: &WorldTransform) -> [f32; 3] {
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

fn transform_direction(rotation: &[f32; 9], vector: &[f32; 3]) -> [f32; 3] {
    [
        rotation[0] * vector[0] + rotation[1] * vector[1] + rotation[2] * vector[2],
        rotation[3] * vector[0] + rotation[4] * vector[1] + rotation[5] * vector[2],
        rotation[6] * vector[0] + rotation[7] * vector[1] + rotation[8] * vector[2],
    ]
}
