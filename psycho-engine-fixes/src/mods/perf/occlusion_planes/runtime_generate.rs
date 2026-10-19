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
//! A face whose support rectangle nearly fills its vertex hull is trusted as
//! solid and keeps the engine's two-sided window (`+0xEA = 1`); a lower
//! coverage face stays one-sided, so the engine's own camera-side test rejects
//! it whenever the camera is behind its face. Horizontal faces (ground and
//! roofs) are skipped, and a face whose support hull cannot contain a useful
//! rectangle is rejected. Coplanar rectangles that share a full edge are merged
//! into their rectangular union, which culls more per plane without covering
//! empty space.
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
    SHAPE_DATA_VTABLES, SHAPE_TRI_LIST, SHAPE_TRI_LIST_LENGTH, STRIPS_DATA_VTABLES,
    STRIPS_STRIP_LENGTHS, STRIPS_STRIP_LISTS, STRIPS_US_STRIPS, TESFORM_REF_ID, TESFORM_TYPE_ID,
    TLIST_DATA, TLIST_NEXT, TRI_BASED_TRIANGLES, VTABLE_IS_GEOMETRY, VTABLE_IS_NODE,
    WORLD_ROTATION, WORLD_SCALE, WORLD_TRANSLATION,
};
use super::data::PlaneRecord;
use super::raw::{read_f32_at, read_ptr, read_ptr_at, read_u8_at, read_u16_at, read_u32_at};

const MAX_REFS: usize = 2000;
const MAX_VISITED_NODES: usize = 512;
const MAX_VERTICES_PER_MESH: usize = 4096;
const VERTEX_BUDGET: usize = 200_000;
/// Upper bound on the triangles read from one mesh. A face-coverage test needs
/// the triangle list, and a malformed or huge mesh must not make a cell change
/// unbounded.
const MAX_TRIANGLES_PER_MESH: usize = 8192;
/// Shared bound on the triangles pulled from the meshes of one cell scan.
const TRIANGLE_BUDGET: usize = 400_000;
const MIN_FACE_EXTENT: f32 = 128.0;
const MIN_BOX_EXTENT: f32 = 256.0;
const MAX_BOX_EXTENT: f32 = 8192.0;
const MIN_WORLD_RADIUS: f32 = MIN_BOX_EXTENT * 0.5;
const MAX_OCCLUDER_DISTANCE: f32 = 262_144.0;
/// Additional shrink applied after the rectangle is fitted inside the vertex
/// support hull. The support fit is the primary guard against floating faces;
/// this margin absorbs tessellation and transform error. A larger plane makes a
/// wider camera-through-rectangle pyramid, which is what lets the engine cull
/// the scene-node bounds behind it, so the margin is kept small.
pub(super) const PLANE_SHRINK: f32 = 0.9;
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
/// Support coverage floor below which a face is treated as too irregular for
/// the engine's two-sided window (`+0xEA = 1`). The rectangle is always inside
/// the vertex hull, so the floor only rejects a strongly non-rectangular hull
/// (a star or a sliver); a plain triangle at about 0.5 still passes.
pub(super) const TWO_SIDED_COVERAGE: f32 = 0.35;
/// World-space thickness of a face's mesh along its own normal below which the
/// mesh is treated as a thin panel (a decal, a facade quad or a one-sided
/// billboard) instead of a solid volume. Such a mesh may be rendered one-sided,
/// so its back side can be invisible; the face keeps the conservative one-sided
/// activation even when its support coverage is high.
const MIN_FACE_THICKNESS: f32 = 16.0;
const OUTWARD_OFFSET: f32 = 2.0;

/// Fingerprint of the generation constants. Mixed into the cache signature so
/// any change to extraction or merge semantics invalidates cached planes
/// automatically, even when the manual format version is not bumped.
pub(super) fn generation_signature() -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let values = [
        PLANE_SHRINK,
        MIN_FACE_EXTENT,
        MIN_BOX_EXTENT,
        MAX_BOX_EXTENT,
        MIN_SUPPORT_SCALE,
        SUPPORT_TOLERANCE_RATIO,
        SUPPORT_TOLERANCE_MIN,
        MAX_HORIZONTAL_NORMAL,
        TWO_SIDED_COVERAGE,
        MIN_FACE_THICKNESS,
        MERGE_OFFSET_TOLERANCE,
        MERGE_GAP_TOLERANCE,
        MERGE_GROUP_TOLERANCE,
        MERGE_AXIS_TOLERANCE,
        // The merge pair budget can change the merged set for dense cells, so
        // a cached set generated under a different budget is not reused.
        MERGE_PAIR_BUDGET as f32,
        // Hole-aware coverage semantics: a geometry whose triangles cannot be
        // read produces no plane, so the extracted set changed.
        MAX_TRIANGLES_PER_MESH as f32,
        TRIANGLE_BUDGET as f32,
    ];
    for value in values {
        for byte in value.to_bits().to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
    }
    hash ^= SUPPORT_GRID as u64;
    hash.wrapping_mul(0x100_0000_01b3)
}

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
    /// A geometry whose model data could not be decoded as a triangle mesh, so
    /// its faces can never be proven solid.
    no_triangles: usize,
    size_reject: usize,
    horizontal_reject: usize,
    support_reject: usize,
    small_reject: usize,
    /// Faces rejected because a window, open door or other missing surface lies
    /// inside the support rectangle (the triangle coverage test).
    opening_reject: usize,
    /// Emitted faces kept one-sided by the thin-panel guard or the coverage
    /// floor, so the scan line shows which gate limits the two-sided planes.
    thin_faces: usize,
    low_coverage_faces: usize,
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

/// Work budget for one frame's slice of a cell generation.
///
/// Generating a dense cell is the single largest main-thread cost of the
/// feature: a release build measured 20-32 ms for the Fairfax exterior cells
/// (the triangle coverage test alone is linear in the mesh triangles), which
/// drops a frame on cell entry while the settle window repeats it. The walk is
/// resumable and pays at most this many triangles and references per call, so
/// no single frame stalls on generation while the final set stays complete. A
/// single geometry is capped at `MAX_TRIANGLES_PER_MESH`, so a frame's slice
/// cannot exceed one mesh's coverage work.
const GENERATION_TRIANGLES_PER_FRAME: usize = 8_000;
/// Upper bound on references examined in one frame's generation slice.
const GENERATION_REFS_PER_FRAME: usize = 96;
/// Wall-clock ceiling for one frame's generation slice. A single reference can
/// carry a mesh of `MAX_TRIANGLES_PER_MESH` triangles on up to six faces, so the
/// triangle budget alone cannot bound a pathological mesh; this stops the slice
/// after the current reference once the ceiling is passed. It is kept under the
/// module's 2 ms frame-cost warning so a normal slice never trips it.
const GENERATION_SLICE_BUDGET_MS: u128 = 1;

/// Resumable per-cell occluder generation.
///
/// A cell's reference list can be hundreds of meshes; walking all of them once
/// is the frame stall. `advance` examines at most `GENERATION_REFS_PER_FRAME`
/// references (and `GENERATION_TRIANGLES_PER_FRAME` triangles) and returns
/// `true` only when the whole list has been walked, so the caller can spread a
/// cell over several frames. References are located by re-walking the list from
/// its head to `cursor` each call, so no engine list node is held across frames
/// (the engine can re-link the list while geometry streams in); a re-link can
/// therefore skip or repeat a reference, which only wastes a duplicate that the
/// shared dedup already handles.
pub(super) struct Generation {
    cell: usize,
    max_planes: usize,
    observer: Option<[f32; 3]>,
    cursor: usize,
    done: bool,
    candidates: Vec<(f32, PlaneRecord)>,
    stack: Vec<usize>,
    mesh_out: Vec<(f32, PlaneRecord)>,
    vertex_buf: Vec<[f32; 3]>,
    triangles: Vec<[u16; 3]>,
    support_points: Vec<[f32; 2]>,
    support_hull: Vec<[f32; 2]>,
    support_upper: Vec<[f32; 2]>,
    coverage: CoverageScratch,
    vertex_budget: usize,
    triangle_budget: usize,
    stats: ScanStats,
    spent_ms: f32,
}

impl Generation {
    pub(super) fn new(cell: *mut c_void, max_planes: usize, observer: Option<[f32; 3]>) -> Self {
        Self {
            cell: cell as usize,
            max_planes,
            observer,
            cursor: 0,
            done: false,
            candidates: Vec::with_capacity(max_planes.max(1) * 4),
            stack: Vec::with_capacity(64),
            mesh_out: Vec::new(),
            vertex_buf: Vec::with_capacity(MAX_VERTICES_PER_MESH),
            triangles: Vec::with_capacity(MAX_TRIANGLES_PER_MESH),
            support_points: Vec::with_capacity(64),
            support_hull: Vec::with_capacity(64),
            support_upper: Vec::with_capacity(64),
            coverage: CoverageScratch::default(),
            vertex_budget: VERTEX_BUDGET,
            triangle_budget: TRIANGLE_BUDGET,
            stats: ScanStats::default(),
            spent_ms: 0.0,
        }
    }

    /// The cell this generation was started for.
    pub(super) fn cell(&self) -> *mut c_void {
        self.cell as *mut c_void
    }

    /// Advance the walk by at most one frame's work budget.
    ///
    /// Returns `true` when the walk is finished. The per-reference budget is
    /// derived from the triangles the reference's geometry actually consumed,
    /// so a cell of many tiny meshes and a cell of a few huge ones both stop
    /// after roughly the same triangle work.
    ///
    /// # Safety
    ///
    /// The caller runs on the xNVSE event thread while the cell is loaded; the
    /// reference list, node transforms and mesh arrays are read-only here.
    pub(super) unsafe fn advance(&mut self) -> bool {
        if self.done {
            return true;
        }
        let started = std::time::Instant::now();
        let done = unsafe { self.advance_slice() };
        self.spent_ms += started.elapsed().as_secs_f32() * 1000.0;
        done
    }

    /// One bounded slice of the walk.
    ///
    /// # Safety
    ///
    /// Same contract as [`Generation::advance`].
    unsafe fn advance_slice(&mut self) -> bool {
        let mut triangle_slice = GENERATION_TRIANGLES_PER_FRAME;
        let mut refs_left = GENERATION_REFS_PER_FRAME;
        let slice_started = std::time::Instant::now();
        // Safety: see the function contract. Every pointer is read from the
        // cell's own list and null-checked before it is dereferenced.
        unsafe {
            let cell = self.cell as *mut c_void;
            let list = (cell as *mut u8).add(CELL_OBJECT_LIST) as *mut c_void;
            let mut node = list;
            let mut index = 0usize;
            while index < self.cursor {
                node = read_ptr_at(node, TLIST_NEXT);
                if node.is_null() {
                    self.done = true;
                    return true;
                }
                index += 1;
            }
            loop {
                // The shared cell budgets are spent: finalize with what was
                // collected, exactly as the previous single-pass loop did.
                if self.stats.refs >= MAX_REFS
                    || self.vertex_budget == 0
                    || self.triangle_budget == 0
                {
                    self.done = true;
                    return true;
                }
                if refs_left == 0 {
                    return false;
                }
                let reference = read_ptr_at(node, TLIST_DATA);
                let next = read_ptr_at(node, TLIST_NEXT);
                self.cursor += 1;
                if !reference.is_null() {
                    self.stats.refs += 1;
                    let triangles_before = self.triangle_budget;
                    let vertices_before = self.vertex_budget;
                    collect_reference(
                        reference,
                        cell,
                        &mut self.stack,
                        &mut self.vertex_buf,
                        &mut self.triangles,
                        &mut self.mesh_out,
                        &mut self.vertex_budget,
                        &mut self.triangle_budget,
                        &mut self.candidates,
                        &mut self.stats,
                        &mut self.support_points,
                        &mut self.support_hull,
                        &mut self.support_upper,
                        &mut self.coverage,
                    );
                    let spent = (triangles_before - self.triangle_budget)
                        .max(vertices_before - self.vertex_budget);
                    triangle_slice = triangle_slice.saturating_sub(spent);
                    refs_left = refs_left.saturating_sub(1);
                }
                if next.is_null() || self.stats.refs >= MAX_REFS {
                    self.done = true;
                    return true;
                }
                node = next;
                if refs_left == 0
                    || triangle_slice == 0
                    || self.vertex_budget == 0
                    || self.triangle_budget == 0
                    || slice_started.elapsed().as_millis() >= GENERATION_SLICE_BUDGET_MS
                {
                    return false;
                }
            }
        }
    }

    /// Score, cap and log the finished set. Consumes the generator. Returns the
    /// selected planes, the raw pre-cap candidate count, whether every reference
    /// had attached 3D, and the total generator time in milliseconds.
    pub(super) fn finish(mut self) -> (Vec<PlaneRecord>, usize, bool, f32) {
        // Merge coplanar adjacent rectangles before scoring and capping. Two
        // support-validated rectangles that share a full edge have a rectangular
        // union, so the merged rectangle cannot cover empty space, and it culls
        // more bounds per plane while reducing the pair cost. The merge is the
        // quadratic step, so its time is reported to target any future cost
        // work.
        let merge_started = std::time::Instant::now();
        merge_coplanar(&mut self.candidates);
        let merge_ms = merge_started.elapsed().as_secs_f32() * 1000.0;

        // Distance filter and score against the observer after merging, so the
        // merged center is the one that is scored. The union selection reuses
        // the same rule across loaded cells so a nearby plane always beats a
        // distant one regardless of which cell produced it.
        let candidate_count = self.candidates.len();
        let selection = select_planes(self.candidates, self.observer, self.max_planes);
        let stats = &mut self.stats;
        stats.rect_area = selection.raw_area;
        stats.cap_drop_area = selection.cap_drop_area;
        stats.distance_reject = selection.distance_reject;
        stats.distance_max = selection.distance_max;
        let planes = selection.planes;
        let raw = candidate_count.saturating_sub(stats.distance_reject);
        if super::runtime::debug_log_enabled() {
            log::debug!(
                "[OCCLUSION_PLANES] scan refs={} parent_mismatch={} base_null={} not_stat={} \
                 render_null={} node_null={} radius={} nodes={} geoms={} skinned={} alpha={} \
                 no_vertices={} no_triangles={} size={} horizontal={} support={} small={} opening={} distance={} \
                 dist_max={:.0} budget_stop={} faces={} mesh_area={:.0} rect_area={:.0} \
                 cap_drop={:.0} thin={} low_cov={} merge_ms={:.1}",
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
                stats.no_triangles,
                stats.size_reject,
                stats.horizontal_reject,
                stats.support_reject,
                stats.small_reject,
                stats.opening_reject,
                stats.distance_reject,
                stats.distance_max,
                stats.budget_stop,
                stats.faces,
                stats.mesh_area,
                stats.rect_area,
                stats.cap_drop_area,
                stats.thin_faces,
                stats.low_coverage_faces,
                merge_ms,
            );
        }
        (
            planes,
            raw,
            // All references have an attached render node, so no more 3D can
            // appear: the settle window can stop after the first identical pass.
            // Require at least one walked reference: an empty list can mean the
            // cell is still attaching, so it is not a finished generation and a
            // neighbor must not be cached as complete on it.
            stats.refs > 0 && stats.render_null == 0 && stats.node_null == 0,
            self.spent_ms,
        )
    }
}

/// Result of the shared score-and-cap step.
///
/// The per-cell generator and the cross-cell union use this exact rule so the
/// injected set does not depend on which cell happened to produce a plane.
pub(super) struct Selection {
    pub(super) planes: Vec<PlaneRecord>,
    /// Emitted rectangle area before the cap.
    pub(super) raw_area: f32,
    /// Emitted rectangle area the cap dropped.
    pub(super) cap_drop_area: f32,
    pub(super) distance_reject: usize,
    pub(super) distance_max: f32,
}

/// Filter by observer distance, weight by approximate solid angle, sort and cap.
///
/// A plane's usefulness is its angular size from the camera, so the weight is
/// `1 + (distance / 2048)^2`: a large near rectangle beats a large distant one,
/// and the per-budget cap keeps the occluders that can hide the most bounds.
pub(super) fn select_planes(
    candidates: Vec<(f32, PlaneRecord)>,
    observer: Option<[f32; 3]>,
    max_planes: usize,
) -> Selection {
    let mut scored: Vec<(f32, PlaneRecord)> = Vec::with_capacity(candidates.len());
    let mut distance_reject = 0usize;
    let mut distance_max = 0.0f32;
    for (area, plane) in candidates {
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
                distance_reject += 1;
                if distance.is_finite() {
                    distance_max = distance_max.max(distance);
                }
                continue;
            }
            weight = 1.0 + (distance * distance) / (2048.0 * 2048.0);
        }
        scored.push((area / weight, plane));
    }
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
    Selection {
        planes: scored.into_iter().map(|(_, plane)| plane).collect(),
        raw_area,
        cap_drop_area: (raw_area - kept_area).max(0.0),
        distance_reject,
        distance_max,
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn collect_reference(
    reference: *mut c_void,
    cell: *mut c_void,
    stack: &mut Vec<usize>,
    vertex_buf: &mut Vec<[f32; 3]>,
    triangles: &mut Vec<[u16; 3]>,
    mesh_out: &mut Vec<(f32, PlaneRecord)>,
    vertex_budget: &mut usize,
    triangle_budget: &mut usize,
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
    support_points: &mut Vec<[f32; 2]>,
    support_hull: &mut Vec<[f32; 2]>,
    support_upper: &mut Vec<[f32; 2]>,
    coverage: &mut CoverageScratch,
) {
    // Stop examining further references once a shared budget is spent, so the
    // cell-load pass stays bounded instead of falling back to coarse sphere
    // bounds for the remaining objects. The triangle budget matters because the
    // coverage test needs the mesh triangles for every emitted face.
    if *vertex_budget == 0 || *triangle_budget == 0 {
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
            triangles,
            vertex_budget,
            triangle_budget,
            mesh_out,
            stats,
            support_points,
            support_hull,
            support_upper,
            coverage,
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
    stack: &mut Vec<usize>,
    vertex_buf: &mut Vec<[f32; 3]>,
    triangles: &mut Vec<[u16; 3]>,
    vertex_budget: &mut usize,
    triangle_budget: &mut usize,
    out: &mut Vec<(f32, PlaneRecord)>,
    stats: &mut ScanStats,
    support_points: &mut Vec<[f32; 2]>,
    support_hull: &mut Vec<[f32; 2]>,
    support_upper: &mut Vec<[f32; 2]>,
    coverage: &mut CoverageScratch,
) {
    stack.clear();
    stack.push(root as usize);
    let mut visited = 0usize;
    while let Some(object) = stack.pop() {
        let object = object as *mut c_void;
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
            } else if let Some((local, world, model)) =
                unsafe { geometry_local_box(object, vertex_buf, vertex_budget) }
            {
                if local.is_eligible(world.scale) {
                    // The triangles are the engine's own definition of the
                    // surface; without them a face cannot be proven hole-free,
                    // so the geometry contributes no occluder.
                    if !unsafe {
                        read_mesh_triangles(model, triangles, vertex_buf.len(), triangle_budget)
                    } {
                        stats.no_triangles += 1;
                    } else {
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
                            triangles,
                            out,
                            support_points,
                            support_hull,
                            support_upper,
                            coverage,
                        );
                        stats.horizontal_reject += rejects.horizontal;
                        stats.support_reject += rejects.unsupported;
                        stats.small_reject += rejects.small;
                        stats.opening_reject += rejects.opening;
                        stats.thin_faces += rejects.thin;
                        stats.low_coverage_faces += rejects.low_coverage;
                    }
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
                    stack.push(child as usize);
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
) -> Option<(Aabb, WorldTransform, *mut c_void)> {
    let world = unsafe { read_world_transform(object) }?;
    let model = unsafe { read_ptr_at(object, GEOMETRY_MODEL_DATA) };
    if model.is_null() {
        return None;
    }
    let local = unsafe { vertices_local_aabb(model, vertex_buf, vertex_budget) }?;
    Some((local, world, model))
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

/// Read a mesh's triangles.
///
/// A window frame, an empty door frame and any wall with an opening are meshes
/// with absent triangles: the opening is visible because there is no surface
/// there, not because of a material or property flag. The triangle list is the
/// engine's own definition of what surface exists, so it is the authority for a
/// hole. `NiTriShapeData` and `NiTriStripsData` (and their dynamic variants) are
/// decoded. Returns `false` for an unknown class, a malformed list or a mesh over
/// the budget; the caller then emits nothing for that geometry, because a plane
/// that cannot be proven hole-free must not be injected.
unsafe fn read_mesh_triangles(
    model: *mut c_void,
    triangles: &mut Vec<[u16; 3]>,
    vertex_count: usize,
    triangle_budget: &mut usize,
) -> bool {
    triangles.clear();
    if vertex_count == 0 || *triangle_budget == 0 {
        return false;
    }
    let vtable = unsafe { read_ptr(model as usize) } as usize;
    let declared = unsafe { read_u16_at(model, TRI_BASED_TRIANGLES) } as usize;
    if SHAPE_DATA_VTABLES.contains(&vtable) {
        let count = unsafe { read_u32_at(model, SHAPE_TRI_LIST_LENGTH) } as usize;
        if count == 0 || !count.is_multiple_of(3) || count / 3 > MAX_TRIANGLES_PER_MESH {
            return false;
        }
        if count / 3 > *triangle_budget {
            return false;
        }
        let list = unsafe { read_ptr_at(model, SHAPE_TRI_LIST) };
        if list.is_null() {
            return false;
        }
        // Safety: `NiTriShapeData::m_pusTriList` owns `m_uiTriListLength`
        // consecutive `u16` indices. The count is bounded above and the pointer
        // was checked non-null; this is a read-only main-thread borrow.
        let slice = unsafe { core::slice::from_raw_parts(list as *const u16, count) };
        triangles.reserve(count / 3);
        for indices in slice.chunks_exact(3) {
            if indices.iter().any(|index| *index as usize >= vertex_count) {
                triangles.clear();
                return false;
            }
            triangles.push([indices[0], indices[1], indices[2]]);
        }
        // The declared triangle count is the engine's own cross-check that the
        // vtable and field layout are the expected class.
        if declared != 0 && declared != triangles.len() {
            triangles.clear();
            return false;
        }
        *triangle_budget -= count / 3;
        !triangles.is_empty()
    } else if STRIPS_DATA_VTABLES.contains(&vtable) {
        let strips = unsafe { read_u16_at(model, STRIPS_US_STRIPS) } as usize;
        if strips == 0 || strips > MAX_TRIANGLES_PER_MESH {
            return false;
        }
        let lengths = unsafe { read_ptr_at(model, STRIPS_STRIP_LENGTHS) };
        let lists = unsafe { read_ptr_at(model, STRIPS_STRIP_LISTS) };
        if lengths.is_null() || lists.is_null() {
            return false;
        }
        // Safety: `m_pusStripLengths` owns `m_usStrips` `u16` lengths. Read it as
        // one borrow, then the concatenated index list as one borrow, so the
        // per-index engine reads collapse into a slice instead of volatile loads.
        let strip_lengths = unsafe { core::slice::from_raw_parts(lengths as *const u16, strips) };
        let max_indices = MAX_TRIANGLES_PER_MESH.saturating_mul(4);
        let mut total = 0usize;
        for length in strip_lengths {
            total = total.saturating_add(*length as usize);
        }
        if total == 0 || total > max_indices {
            return false;
        }
        let list = unsafe { core::slice::from_raw_parts(lists as *const u16, total) };
        let mut offset = 0usize;
        for &length in strip_lengths {
            let length = length as usize;
            if length >= 3 {
                for index in 0..length - 2 {
                    if triangles.len() >= MAX_TRIANGLES_PER_MESH || *triangle_budget == 0 {
                        break;
                    }
                    let i0 = list[offset + index] as usize;
                    let i1 = list[offset + index + 1] as usize;
                    let i2 = list[offset + index + 2] as usize;
                    if i0 >= vertex_count || i1 >= vertex_count || i2 >= vertex_count {
                        triangles.clear();
                        return false;
                    }
                    triangles.push([i0 as u16, i1 as u16, i2 as u16]);
                    *triangle_budget -= 1;
                }
            }
            offset += length;
            if triangles.len() >= MAX_TRIANGLES_PER_MESH {
                break;
            }
        }
        if declared != 0 && declared != triangles.len() {
            triangles.clear();
            return false;
        }
        !triangles.is_empty()
    } else {
        false
    }
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
    /// A window, open door or other missing surface lies inside the support
    /// rectangle (the triangle coverage test).
    pub(super) opening: usize,
    /// Emitted face kept one-sided because its mesh is a thin panel.
    pub(super) thin: usize,
    /// Emitted face kept one-sided because its support coverage is below the
    /// two-sided floor.
    pub(super) low_coverage: usize,
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
/// become a large floating rectangle. A face whose rectangle is not fully
/// backed by the mesh's triangles is rejected: the hull is convex and spans a
/// window or an open doorway, and an occluder that covers an opening would cull
/// whatever is visible through it. Horizontal faces are skipped: ground and
/// roofs rarely occlude a standing player and are the most common source of
/// over-cover.
///
/// This function reads no engine memory and is unit-tested.
pub(super) fn faces_from_oriented_box(
    local: &Aabb,
    world: &WorldTransform,
    vertices: &[[f32; 3]],
    triangles: &[[u16; 3]],
    out: &mut Vec<(f32, PlaneRecord)>,
    support_points: &mut Vec<[f32; 2]>,
    support_hull: &mut Vec<[f32; 2]>,
    support_upper: &mut Vec<[f32; 2]>,
    coverage: &mut CoverageScratch,
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
            // The support hull is convex, so it spans a window opening, an empty
            // door frame or any other missing surface. Only emit a rectangle the
            // mesh's own triangles actually back.
            let tolerance = SUPPORT_TOLERANCE_MIN.max(extents[axis] * SUPPORT_TOLERANCE_RATIO);
            // The support hull is convex, so it spans a window opening, an empty
            // door frame or any other missing surface. Reduce the rectangle to
            // the largest part the mesh's own triangles actually back; if there
            // is no solid part, drop the face.
            let Some((rect_center_u, rect_center_v, rect_half_u, rect_half_v)) =
                covered_face_rect_scratch(
                    vertices,
                    triangles,
                    axis,
                    face_coord,
                    tolerance,
                    rect.center_u,
                    rect.center_v,
                    rect.half_u,
                    rect.half_v,
                    coverage,
                )
            else {
                rejects.opening += 1;
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
                rect_half_u * 2.0 * world_scale * PLANE_SHRINK,
                rect_half_v * 2.0 * world_scale * PLANE_SHRINK,
            ];
            if size[0] < MIN_FACE_EXTENT || size[1] < MIN_FACE_EXTENT {
                rejects.small += 1;
                continue;
            }
            // A face on a thin mesh is not a solid-volume face: the mesh may be
            // a one-sided panel whose back is invisible, so the engine's
            // two-sided window could false-cull from behind it. A face whose
            // support hull is strongly non-rectangular is likewise kept
            // one-sided. Both reasons are counted so a playtest can tell which
            // gate is limiting the two-sided planes.
            let thickness = extents[axis] * world_scale;
            let side_confidence = if thickness < MIN_FACE_THICKNESS {
                rejects.thin += 1;
                0.0
            } else {
                if rect.coverage < TWO_SIDED_COVERAGE {
                    rejects.low_coverage += 1;
                }
                rect.coverage
            };
            let mut local_face_center = center;
            local_face_center[axis] = face_coord;
            local_face_center[tangent_a] = rect_center_u;
            local_face_center[tangent_b] = rect_center_v;
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
                    coverage: side_confidence,
                },
            ));
        }
    }
    rejects
}

/// Grid resolution of the covered-sub-rectangle search. A face that covers an
/// opening is reduced to the largest solid rectangle; eight cells per axis is
/// enough to recover the solid band around a window or door while staying cheap.
const FACE_GRID: usize = 16;

/// Reusable buffers for the triangle coverage test.
///
/// A cell can own hundreds of static meshes and each mesh is tested on up to
/// six faces. Allocating a `Vec` and a `HashMap` per face was the dominant
/// generation cost: a release build measured 0.09-1.7 ms for one solid face and
/// up to 3.0 ms for a face with an opening as the mesh grew to 8192 triangles,
/// so a dense cell stalled the frame thread for 20-30 ms per pass. The buffers
/// are reused across every face of every geometry in one generation pass.
#[derive(Default)]
pub(super) struct CoverageScratch {
    subset: Vec<[u16; 3]>,
    edge_keys: Vec<u64>,
    boundary: Vec<(u16, u16)>,
    mask: [[bool; FACE_GRID]; FACE_GRID],
}

/// Collect the triangles that lie in the face plane. A triangle counts only when
/// all three vertices are within the support tolerance, so the projection
/// describes the actual face surface. Returns `false` (leaving `out` empty) when
/// an index is out of range or no triangle is near the face.
fn near_face_triangles_into(
    vertices: &[[f32; 3]],
    triangles: &[[u16; 3]],
    axis: usize,
    face_coord: f32,
    tolerance: f32,
    out: &mut Vec<[u16; 3]>,
) -> bool {
    out.clear();
    let near = |index: u16| -> bool {
        let vertex = vertices[index as usize];
        (vertex[axis] - face_coord).abs() <= tolerance
    };
    for triangle in triangles {
        let [a, b, c] = *triangle;
        if a as usize >= vertices.len()
            || b as usize >= vertices.len()
            || c as usize >= vertices.len()
        {
            out.clear();
            return false;
        }
        if near(a) && near(b) && near(c) {
            out.push(*triangle);
        }
    }
    !out.is_empty()
}

/// Edges used by exactly one near-face triangle. Those are the perimeter of the
/// face and of every opening in it.
///
/// Only edges whose 2D bounding box overlaps the candidate rectangle are kept:
/// an edge outside it cannot cross the rectangle or any cell of the recovery
/// grid, and the face's own perimeter lies outside the inset candidate, so a
/// solid face sorts an empty list. The packed keys are then sorted and the
/// singleton runs selected, which is exact for any edge multiplicity (a
/// non-manifold edge with three or more triangles is not a boundary, matching
/// the previous count). This replaces a per-face `HashMap` over every edge,
/// which was the dominant generation cost on dense meshes.
#[allow(clippy::too_many_arguments)]
fn boundary_edges_sorted(
    vertices: &[[f32; 3]],
    subset: &[[u16; 3]],
    tangent_a: usize,
    tangent_b: usize,
    rect: [f32; 4],
    edge_keys: &mut Vec<u64>,
    boundary: &mut Vec<(u16, u16)>,
) {
    let [u0, v0, u1, v1] = rect;
    edge_keys.clear();
    edge_keys.reserve(subset.len() * 3);
    for triangle in subset {
        for (a, b) in [
            (triangle[0], triangle[1]),
            (triangle[1], triangle[2]),
            (triangle[2], triangle[0]),
        ] {
            if a == b {
                continue;
            }
            let pa = vertices[a as usize];
            let pb = vertices[b as usize];
            let min_u = pa[tangent_a].min(pb[tangent_a]);
            let max_u = pa[tangent_a].max(pb[tangent_a]);
            let min_v = pa[tangent_b].min(pb[tangent_b]);
            let max_v = pa[tangent_b].max(pb[tangent_b]);
            if max_u < u0 || min_u > u1 || max_v < v0 || min_v > v1 {
                continue;
            }
            let (low, high) = if a < b { (a, b) } else { (b, a) };
            edge_keys.push(((low as u64) << 16) | high as u64);
        }
    }
    edge_keys.sort_unstable();
    boundary.clear();
    let mut start = 0usize;
    while start < edge_keys.len() {
        let key = edge_keys[start];
        let mut end = start + 1;
        while end < edge_keys.len() && edge_keys[end] == key {
            end += 1;
        }
        if end - start == 1 {
            boundary.push(((key >> 16) as u16, (key & 0xFFFF) as u16));
        }
        start = end;
    }
}

/// True when the axis-aligned `[u0, u1] x [v0, v1]` region is fully backed by the
/// near-face triangles: no opening boundary crosses it and its corners and center
/// are inside a triangle.
fn rect_covered(
    vertices: &[[f32; 3]],
    subset: &[[u16; 3]],
    boundary: &[(u16, u16)],
    tangent_a: usize,
    tangent_b: usize,
    u0: f32,
    u1: f32,
    v0: f32,
    v1: f32,
) -> bool {
    if u1 <= u0 || v1 <= v0 {
        return false;
    }
    for &(a, b) in boundary {
        let pa = vertices[a as usize];
        let pb = vertices[b as usize];
        if segment_intersects_rect(
            [pa[tangent_a], pa[tangent_b]],
            [pb[tangent_a], pb[tangent_b]],
            [u0, v0, u1, v1],
        ) {
            return false;
        }
    }
    for (u, v) in [
        ((u0 + u1) * 0.5, (v0 + v1) * 0.5),
        (u0, v0),
        (u1, v0),
        (u0, v1),
        (u1, v1),
    ] {
        if !point_in_triangle_subset(vertices, subset, tangent_a, tangent_b, u, v) {
            return false;
        }
    }
    true
}

/// Largest fully backed rectangle inside the candidate face rectangle, or `None`
/// when no solid part remains.
///
/// A window opening, an empty door frame or any other missing surface is visible
/// because the mesh has no triangles there. The support hull is convex and spans
/// that hole, so the candidate rectangle is checked against the mesh triangles
/// and reduced to the largest solid rectangle. This keeps the wall around a
/// window or doorway as an occluder without ever covering the opening.
/// Convenience wrapper that owns a scratch buffer, for tests and one-off
/// callers. The generation path reuses a scratch across faces.
#[cfg(test)]
pub(super) fn covered_face_rect(
    vertices: &[[f32; 3]],
    triangles: &[[u16; 3]],
    axis: usize,
    face_coord: f32,
    tolerance: f32,
    center_u: f32,
    center_v: f32,
    half_u: f32,
    half_v: f32,
) -> Option<(f32, f32, f32, f32)> {
    let mut scratch = CoverageScratch::default();
    covered_face_rect_scratch(
        vertices,
        triangles,
        axis,
        face_coord,
        tolerance,
        center_u,
        center_v,
        half_u,
        half_v,
        &mut scratch,
    )
}

/// `covered_face_rect` with caller-owned scratch buffers, so one generation pass
/// does not allocate per face.
#[allow(clippy::too_many_arguments)]
pub(super) fn covered_face_rect_scratch(
    vertices: &[[f32; 3]],
    triangles: &[[u16; 3]],
    axis: usize,
    face_coord: f32,
    tolerance: f32,
    center_u: f32,
    center_v: f32,
    half_u: f32,
    half_v: f32,
    scratch: &mut CoverageScratch,
) -> Option<(f32, f32, f32, f32)> {
    if vertices.is_empty() || triangles.is_empty() {
        return None;
    }
    let tangent_a = (axis + 1) % 3;
    let tangent_b = (axis + 2) % 3;
    if !near_face_triangles_into(
        vertices,
        triangles,
        axis,
        face_coord,
        tolerance,
        &mut scratch.subset,
    ) {
        return None;
    }
    // Inset the candidate so the face's own perimeter does not read as an
    // opening boundary.
    let inset = (half_u.min(half_v) * 0.02).clamp(0.0, 4.0);
    let u0 = center_u - half_u + inset;
    let u1 = center_u + half_u - inset;
    let v0 = center_v - half_v + inset;
    let v1 = center_v + half_v - inset;
    if u1 <= u0 || v1 <= v0 {
        return None;
    }
    // The boundary list is filtered to the candidate rectangle, so a solid face
    // skips the sort entirely and a face with an opening keeps only the opening
    // edges that can cross the candidate.
    boundary_edges_sorted(
        vertices,
        &scratch.subset,
        tangent_a,
        tangent_b,
        [u0, v0, u1, v1],
        &mut scratch.edge_keys,
        &mut scratch.boundary,
    );
    let (subset, boundary) = (&scratch.subset, &scratch.boundary);
    // Fast path: the whole face is solid, so keep the original size.
    if rect_covered(
        vertices, subset, boundary, tangent_a, tangent_b, u0, u1, v0, v1,
    ) {
        return Some((center_u, center_v, half_u, half_v));
    }
    // Recover the largest solid sub-rectangle around the opening. Rasterize the
    // projected triangles into the grid, then clear every cell an opening
    // boundary crosses, so a cell is covered only when it is fully backed.
    let cell_w = (u1 - u0) / FACE_GRID as f32;
    let cell_h = (v1 - v0) / FACE_GRID as f32;
    let mask = &mut scratch.mask;
    for row in mask.iter_mut() {
        for cell in row.iter_mut() {
            *cell = false;
        }
    }
    let cell_index =
        |value: f32, origin: f32, cell: f32| -> i64 { ((value - origin) / cell).floor() as i64 };
    for triangle in subset {
        let a = vertices[triangle[0] as usize];
        let b = vertices[triangle[1] as usize];
        let c = vertices[triangle[2] as usize];
        let pa = [a[tangent_a], a[tangent_b]];
        let pb = [b[tangent_a], b[tangent_b]];
        let pc = [c[tangent_a], c[tangent_b]];
        let min_u = pa[0].min(pb[0]).min(pc[0]);
        let max_u = pa[0].max(pb[0]).max(pc[0]);
        let min_v = pa[1].min(pb[1]).min(pc[1]);
        let max_v = pa[1].max(pb[1]).max(pc[1]);
        let column0 = cell_index(min_u, u0, cell_w).clamp(0, FACE_GRID as i64 - 1);
        let column1 = cell_index(max_u, u0, cell_w).clamp(0, FACE_GRID as i64 - 1);
        let row0 = cell_index(min_v, v0, cell_h).clamp(0, FACE_GRID as i64 - 1);
        let row1 = cell_index(max_v, v0, cell_h).clamp(0, FACE_GRID as i64 - 1);
        for row in row0..=row1 {
            for column in column0..=column1 {
                let center = [
                    u0 + (column as f32 + 0.5) * cell_w,
                    v0 + (row as f32 + 0.5) * cell_h,
                ];
                if point_in_triangle_2d(center, pa, pb, pc) {
                    mask[row as usize][column as usize] = true;
                }
            }
        }
    }
    for &(a, b) in boundary {
        let pa = vertices[a as usize];
        let pb = vertices[b as usize];
        let a2 = [pa[tangent_a], pa[tangent_b]];
        let b2 = [pb[tangent_a], pb[tangent_b]];
        let min_u = a2[0].min(b2[0]) - cell_w;
        let max_u = a2[0].max(b2[0]) + cell_w;
        let min_v = a2[1].min(b2[1]) - cell_h;
        let max_v = a2[1].max(b2[1]) + cell_h;
        let column0 = cell_index(min_u, u0, cell_w).clamp(0, FACE_GRID as i64 - 1);
        let column1 = cell_index(max_u, u0, cell_w).clamp(0, FACE_GRID as i64 - 1);
        let row0 = cell_index(min_v, v0, cell_h).clamp(0, FACE_GRID as i64 - 1);
        let row1 = cell_index(max_v, v0, cell_h).clamp(0, FACE_GRID as i64 - 1);
        for row in row0..=row1 {
            for column in column0..=column1 {
                let cu0 = u0 + column as f32 * cell_w;
                let cu1 = cu0 + cell_w;
                let cv0 = v0 + row as f32 * cell_h;
                let cv1 = cv0 + cell_h;
                if segment_intersects_rect(a2, b2, [cu0, cv0, cu1, cv1]) {
                    mask[row as usize][column as usize] = false;
                }
            }
        }
    }
    let (column0, row0, column1, row1) = largest_covered_rect(mask)?;
    let su0 = u0 + column0 as f32 * cell_w;
    let su1 = u0 + (column1 + 1) as f32 * cell_w;
    let sv0 = v0 + row0 as f32 * cell_h;
    let sv1 = v0 + (row1 + 1) as f32 * cell_h;
    Some((
        (su0 + su1) * 0.5,
        (sv0 + sv1) * 0.5,
        (su1 - su0) * 0.5,
        (sv1 - sv0) * 0.5,
    ))
}

/// Largest all-`true` rectangle in a small boolean grid, as inclusive cell
/// `(column0, row0, column1, row1)` bounds.
fn largest_covered_rect(
    mask: &[[bool; FACE_GRID]; FACE_GRID],
) -> Option<(usize, usize, usize, usize)> {
    let mut best: Option<(usize, usize, usize, usize, usize)> = None;
    for top in 0..FACE_GRID {
        let mut heights = [0usize; FACE_GRID];
        for row in top..FACE_GRID {
            for column in 0..FACE_GRID {
                heights[column] = if mask[row][column] {
                    heights[column] + 1
                } else {
                    0
                };
            }
            let mut stack: Vec<(usize, usize)> = Vec::with_capacity(FACE_GRID + 1);
            for column in 0..=FACE_GRID {
                let height = if column < FACE_GRID {
                    heights[column]
                } else {
                    0
                };
                let mut start = column;
                while let Some(&(stack_start, stack_height)) = stack.last() {
                    if stack_height <= height {
                        break;
                    }
                    stack.pop();
                    let width = column - stack_start;
                    let area = stack_height * width;
                    if best.is_none_or(|current| area > current.0) {
                        best = Some((area, stack_start, row + 1 - stack_height, column - 1, row));
                    }
                    start = stack_start;
                }
                if height > 0 {
                    stack.push((start, height));
                }
            }
        }
    }
    best.map(|(_, column0, row0, column1, row1)| (column0, row0, column1, row1))
}

/// True when `(u, v)` lies inside at least one of the projected triangles.
fn point_in_triangle_subset(
    vertices: &[[f32; 3]],
    subset: &[[u16; 3]],
    tangent_a: usize,
    tangent_b: usize,
    u: f32,
    v: f32,
) -> bool {
    for triangle in subset {
        let a = vertices[triangle[0] as usize];
        let b = vertices[triangle[1] as usize];
        let c = vertices[triangle[2] as usize];
        if point_in_triangle_2d(
            [u, v],
            [a[tangent_a], a[tangent_b]],
            [b[tangent_a], b[tangent_b]],
            [c[tangent_a], c[tangent_b]],
        ) {
            return true;
        }
    }
    false
}

/// 2D point-in-triangle test. A point on an edge counts as inside, so a sample
/// on a shared internal triangle edge does not read as an opening.
fn point_in_triangle_2d(p: [f32; 2], a: [f32; 2], b: [f32; 2], c: [f32; 2]) -> bool {
    let cross = |p: [f32; 2], a: [f32; 2], b: [f32; 2]| {
        (b[0] - a[0]) * (p[1] - a[1]) - (b[1] - a[1]) * (p[0] - a[0])
    };
    let d1 = cross(p, a, b);
    let d2 = cross(p, b, c);
    let d3 = cross(p, c, a);
    // Relative tolerance: a point on an internal edge stays inside even after
    // the float rounding of a large projected triangle.
    let epsilon = (d1.abs() + d2.abs() + d3.abs()).max(1.0) * 1.0e-4;
    let has_negative = d1 < -epsilon || d2 < -epsilon || d3 < -epsilon;
    let has_positive = d1 > epsilon || d2 > epsilon || d3 > epsilon;
    !(has_negative && has_positive)
}

/// True when the 2D segment `a`-`b` enters the axis-aligned rectangle
/// `[x0, y0, x1, y1]`. A segment that only touches the rectangle boundary is
/// not an opening inside the rectangle.
fn segment_intersects_rect(a: [f32; 2], b: [f32; 2], rect: [f32; 4]) -> bool {
    let [x0, y0, x1, y1] = rect;
    let inside = |p: [f32; 2]| p[0] > x0 && p[0] < x1 && p[1] > y0 && p[1] < y1;
    if inside(a) || inside(b) {
        return true;
    }
    segments_intersect(a, b, [x0, y0], [x1, y0])
        || segments_intersect(a, b, [x1, y0], [x1, y1])
        || segments_intersect(a, b, [x1, y1], [x0, y1])
        || segments_intersect(a, b, [x0, y1], [x0, y0])
}

fn segments_intersect(p1: [f32; 2], p2: [f32; 2], q1: [f32; 2], q2: [f32; 2]) -> bool {
    let orient = |a: [f32; 2], b: [f32; 2], c: [f32; 2]| {
        (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
    };
    let d1 = orient(q1, q2, p1);
    let d2 = orient(q1, q2, p2);
    let d3 = orient(p1, p2, q1);
    let d4 = orient(p1, p2, q2);
    ((d1 > 0.0) != (d2 > 0.0)) && ((d3 > 0.0) != (d4 > 0.0))
}

/// Coplanar rectangles are merged only when their union is exactly a rectangle.
/// Two support-validated rectangles that share a full edge have a rectangular
/// union, so the merged rectangle stays inside the union of two solid-backed
/// rectangles and cannot cover empty space.
const MERGE_OFFSET_TOLERANCE: f32 = 1.0;
/// In-plane gap allowed when the union is still a rectangle. Sized to bridge a
/// tile seam between wall pieces, which makes one larger occluder, but far
/// below a doorway (about 64 units), so it cannot bridge a real opening.
const MERGE_GAP_TOLERANCE: f32 = 4.0;
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

/// Upper bound on pairwise merge comparisons for one cell.
///
/// The merge is quadratic within a coplanar group, and `merge_coplanar` runs in
/// one frame when a generation completes. A release benchmark measured ~38 ns
/// per non-merging comparison (two `rect2` projections), so the documented
/// cells that emit up to 892 raw candidates would spend about 15 ms in one
/// frame when nothing merges. The budget bounds that to roughly a millisecond;
/// once it is spent the remaining candidates are kept unmerged and the
/// score-and-cap step still selects the largest.
const MERGE_PAIR_BUDGET: usize = 30_000;

/// Merge coplanar adjacent rectangles in place, replacing each group with its
/// rectangular union. Bounded to a few passes; a chain of segments is handled
/// by the repeated pass. Pairwise work is bounded by `MERGE_PAIR_BUDGET` so a
/// dense cell cannot stall the completion frame.
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
    let mut budget = MERGE_PAIR_BUDGET;
    for (_, mut group) in groups {
        if budget > 0 {
            'passes: for _ in 0..3 {
                let mut changed = false;
                let mut i = 0;
                while i < group.len() {
                    let mut j = i + 1;
                    while j < group.len() {
                        if budget == 0 {
                            break 'passes;
                        }
                        budget -= 1;
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
    let tol = MERGE_GAP_TOLERANCE;
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
    if (offset_a - offset_b).abs() > MERGE_OFFSET_TOLERANCE {
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
        // Inherit the lower confidence so a merged plane never becomes
        // two-sided because one of its sources was well shaped.
        coverage: a.coverage.min(b.coverage),
    })
}

/// Largest axis-aligned rectangle supported by the face's vertices.
#[derive(Clone, Copy, Debug)]
pub(super) struct SupportRect {
    pub(super) center_u: f32,
    pub(super) center_v: f32,
    pub(super) half_u: f32,
    pub(super) half_v: f32,
    /// Rectangle area divided by the support hull area, before `PLANE_SHRINK`.
    /// High values mean the rectangle fills a solid, well-shaped face; low
    /// values mean the hull is much larger than the safe rectangle.
    pub(super) coverage: f32,
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
            coverage: 0.0,
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
    let hull_area = polygon_area(hull);
    let rectangle_area = 4.0 * best.half_u * best.half_v;
    let mut best = best;
    best.coverage = if hull_area > 0.0 {
        (rectangle_area / hull_area).clamp(0.0, 1.0)
    } else {
        0.0
    };
    Some(best)
}

/// Absolute area of a convex polygon in counter-clockwise order.
fn polygon_area(polygon: &[[f32; 2]]) -> f32 {
    if polygon.len() < 3 {
        return 0.0;
    }
    let mut sum = 0.0f32;
    for index in 0..polygon.len() {
        let a = polygon[index];
        let b = polygon[(index + 1) % polygon.len()];
        sum += a[0] * b[1] - b[0] * a[1];
    }
    (sum * 0.5).abs()
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
        coverage: 0.0,
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
