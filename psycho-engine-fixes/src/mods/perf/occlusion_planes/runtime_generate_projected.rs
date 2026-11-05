//! Camera-scoped connected-triangle fallback for meshes with no legacy rectangle.
//! Fitting is a proposal only. Exact signs certify the final native axis-aligned
//! corners, source depth, source-facing side and a convex box of cameras. Thus
//! holes, open meshes and unknown solid interiors need no special assumption.
//! The native admission bridge must enforce the box for every visibility pass.
use super::super::{data::CameraBounds, exact::orient};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sides {
    Unknown,
    Front,
    Back,
    Both,
}

impl Sides {
    /// NiStencilProperty flags: enabled stencil is not admitted. Modes 0/1
    /// keep the positive world-winding side, 2 the negative, 3 both. The native
    /// renderer flips its projection and cull mapping together for handedness.
    pub(super) fn from_flags(flags: u16) -> Self {
        if flags & 1 != 0 {
            return Self::Unknown;
        }
        match (flags >> 10) & 3 {
            0 | 1 => Self::Front,
            2 => Self::Back,
            _ => Self::Both,
        }
    }

    fn admits(self, sign: i8) -> bool {
        sign != 0
            && match self {
                Self::Unknown => false,
                Self::Front => sign > 0,
                Self::Back => sign < 0,
                Self::Both => true,
            }
    }
}

fn side(triangle: [[f32; 3]; 3], p: [f32; 3]) -> Option<i8> {
    orient(triangle[1], triangle[2], p, triangle[0])
}

fn cross64(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
fn sub64(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    std::array::from_fn(|i| a[i] - b[i])
}
fn dot64(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

/// Proposal geometry is projected only along the dominant view axis. Grazing
/// proxy axes can magnify tiny triangles into large quads with useless domains.
struct Projection {
    axis: usize,
    coordinate: f32,
    sign: f32,
    camera: [f32; 3],
    points: [[f64; 2]; PATCH_VERTICES],
    len: usize,
    min: [f64; 2],
    max: [f64; 2],
}
impl Projection {
    fn new(points: &[[f32; 3]], camera: [f32; 3]) -> Option<Self> {
        let axis = (0..3).max_by(|&i, &j| {
            let d = |i| {
                (f64::from(camera[i])
                    - points.iter().map(|p| f64::from(p[i])).sum::<f64>() / points.len() as f64)
                    .abs()
            };
            d(i).total_cmp(&d(j))
        })?;
        let lo = points.iter().map(|p| p[axis]).fold(f32::INFINITY, f32::min);
        let hi = points
            .iter()
            .map(|p| p[axis])
            .fold(f32::NEG_INFINITY, f32::max);
        let (coordinate, sign) = if camera[axis] < lo {
            ((hi + OUTWARD_OFFSET).next_up(), -1.0)
        } else if camera[axis] > hi {
            ((lo - OUTWARD_OFFSET).next_down(), 1.0)
        } else {
            return None;
        };
        if !coordinate.is_finite() {
            return None;
        }
        let mut out = Self {
            axis,
            coordinate,
            sign,
            camera,
            points: [[0.0; 2]; PATCH_VERTICES],
            len: points.len(),
            min: [f64::INFINITY; 2],
            max: [f64::NEG_INFINITY; 2],
        };
        for (i, &p) in points.iter().enumerate() {
            let projected = out.project(p);
            if projected.iter().any(|v| !v.is_finite()) {
                return None;
            }
            out.points[i] = projected;
            for j in 0..2 {
                out.min[j] = out.min[j].min(projected[j]);
                out.max[j] = out.max[j].max(projected[j]);
            }
        }
        (0..2).all(|i| out.max[i] > out.min[i]).then_some(out)
    }
    fn project(&self, p: [f32; 3]) -> [f64; 2] {
        let t = (f64::from(self.coordinate) - f64::from(self.camera[self.axis]))
            / (f64::from(p[self.axis]) - f64::from(self.camera[self.axis]));
        [(self.axis + 1) % 3, (self.axis + 2) % 3]
            .map(|i| f64::from(self.camera[i]) + t * (f64::from(p[i]) - f64::from(self.camera[i])))
    }
    fn record(&self, center: [f64; 2], half: [f64; 2]) -> Option<PlaneRecord> {
        let size = half.map(|v| (2.0 * v * f64::from(PLANE_SHRINK)) as f32);
        if size
            .iter()
            .any(|&v| !v.is_finite() || !(MIN_FACE_EXTENT..=MAX_BOX_EXTENT).contains(&v))
        {
            return None;
        }
        let mut position = [0.0; 3];
        position[self.axis] = self.coordinate;
        position[(self.axis + 1) % 3] = center[0] as f32;
        position[(self.axis + 2) % 3] = center[1] as f32;
        let tangent = unit_axis((self.axis + 1) % 3, 1.0);
        let normal = unit_axis(self.axis, self.sign);
        let bitangent = cross(tangent, normal);
        let plane = PlaneRecord {
            camera: None,
            position,
            size,
            rotation: [
                tangent[0],
                normal[0],
                bitangent[0],
                tangent[1],
                normal[1],
                bitangent[1],
                tangent[2],
                normal[2],
                bitangent[2],
            ],
            priority: 0,
            source_form_id: 0,
            coverage: 1.0,
        };
        let distance = position
            .into_iter()
            .zip(self.camera)
            .map(|(p, c)| (f64::from(p) - f64::from(c)).powi(2))
            .sum::<f64>();
        (plane.valid_native()
            && distance.is_finite()
            && distance <= f64::from(MAX_OCCLUDER_DISTANCE).powi(2))
        .then_some(plane)
    }
    fn analytic(&self) -> Option<PlaneRecord> {
        let center: [f64; 2] = std::array::from_fn(|i| {
            self.points[..self.len].iter().map(|p| p[i]).sum::<f64>() / self.len as f64
        });
        let half: [f64; 2] = std::array::from_fn(|i| (self.max[i] - self.min[i]) * 0.5);
        let mut scale = 1.0f64;
        for a in 0..self.len {
            let b = (a + 1) % self.len;
            let dx = self.points[b][0] - self.points[a][0];
            let dy = self.points[b][1] - self.points[a][1];
            let support =
                (dx * (center[1] - self.points[a][1]) - dy * (center[0] - self.points[a][0])).abs();
            let loss = dx.abs() * half[1] + dy.abs() * half[0];
            if loss > 0.0 {
                scale = scale.min(support / loss);
            }
        }
        self.record(center, half.map(|v| v * scale))
    }
    fn raster(
        &self,
        patch: &Patch,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        world: &WorldTransform,
        mask: &mut [[bool; FACE_GRID]; FACE_GRID],
    ) -> Option<PlaneRecord> {
        *mask = [[false; FACE_GRID]; FACE_GRID];
        let grid = |p: [f64; 2]| {
            std::array::from_fn::<_, 2, _>(|i| {
                ((p[i] - self.min[i]) * FACE_GRID as f64 / (self.max[i] - self.min[i])) as f32
            })
        };
        for &index in &patch.triangles[..patch.count] {
            let [a, b, c] = triangles[index]
                .map(|i| grid(self.project(transform_point(world, &vertices[i as usize]))));
            let low = a[1]
                .min(b[1])
                .min(c[1])
                .floor()
                .clamp(0.0, (FACE_GRID - 1) as f32) as usize;
            let high = a[1]
                .max(b[1])
                .max(c[1])
                .floor()
                .clamp(0.0, (FACE_GRID - 1) as f32) as usize;
            for (row, cells) in mask.iter_mut().enumerate().take(high + 1).skip(low) {
                for column in (0..FACE_GRID).step_by(4) {
                    if cells[column..column + 4].iter().all(|&v| v) {
                        continue;
                    }
                    let x = f32x4::new(std::array::from_fn(|lane| (column + lane) as f32 + 0.5));
                    let bits =
                        coverage_work::triangle_mask(x, f32x4::splat(row as f32 + 0.5), a, b, c);
                    for lane in 0..4 {
                        cells[column + lane] |= bits & (1 << lane) != 0;
                    }
                }
            }
        }
        // This raster only proposes a rectangle. Clearing boundary cells makes
        // the proposal useful; exact camera-domain separation proves support.
        for i in 0..self.len {
            let a = grid(self.points[i]);
            let b = grid(self.points[(i + 1) % self.len]);
            let low = std::array::from_fn::<_, 2, _>(|j| {
                (a[j].min(b[j]).floor() - 1.0).clamp(0.0, (FACE_GRID - 1) as f32) as usize
            });
            let high = std::array::from_fn::<_, 2, _>(|j| {
                (a[j].max(b[j]).floor() + 1.0).clamp(0.0, (FACE_GRID - 1) as f32) as usize
            });
            for (row, cells) in mask.iter_mut().enumerate().take(high[1] + 1).skip(low[1]) {
                for (column, cell) in cells.iter_mut().enumerate().take(high[0] + 1).skip(low[0]) {
                    if *cell
                        && segment_intersects_rect(
                            a,
                            b,
                            [
                                column as f32,
                                row as f32,
                                (column + 1) as f32,
                                (row + 1) as f32,
                            ],
                        )
                    {
                        *cell = false;
                    }
                }
            }
        }
        let (x0, y0, x1, y1) = largest_covered_rect(mask)?;
        let lo = [x0, y0];
        let hi = [x1 + 1, y1 + 1];
        let min: [f64; 2] = std::array::from_fn(|i| {
            self.min[i] + lo[i] as f64 * (self.max[i] - self.min[i]) / FACE_GRID as f64
        });
        let max: [f64; 2] = std::array::from_fn(|i| {
            self.min[i] + hi[i] as f64 * (self.max[i] - self.min[i]) / FACE_GRID as f64
        });
        self.record(
            std::array::from_fn(|i| (min[i] + max[i]) * 0.5),
            std::array::from_fn(|i| (max[i] - min[i]) * 0.5),
        )
    }
}

fn patch_proposals(
    patch: &Patch,
    vertices: &[[f32; 3]],
    triangles: &[[u16; 3]],
    world: &WorldTransform,
    camera: [f32; 3],
    mask: &mut [[bool; FACE_GRID]; FACE_GRID],
) -> (Option<PlaneRecord>, Option<PlaneRecord>) {
    let points = patch_points(patch, vertices, world);
    let Some(projection) = Projection::new(&points[..patch.len], camera) else {
        return (None, None);
    };
    let analytic = if patch.count == 1 || convex_proposal(patch, vertices, world, camera) {
        projection.analytic()
    } else {
        None
    };
    let raster = if patch.count > 1 {
        projection.raster(patch, vertices, triangles, world, mask)
    } else {
        None
    };
    (analytic, raster)
}

/// One triangle patch is retained only while its owned mesh is at the front.
/// Additional connected triangles share exact welded edges; no gap is filled.
const PATCH_TRIANGLES: usize = 32;
const PATCH_VERTICES: usize = PATCH_TRIANGLES + 2;

#[derive(Clone, Copy)]
pub(super) struct Patch {
    triangles: [usize; PATCH_TRIANGLES],
    count: usize,
    boundary: [u16; PATCH_VERTICES],
    len: usize,
}

#[derive(Default)]
pub(super) struct ProjectedScratch {
    points: Vec<([u32; 3], u16)>,
    weld: Vec<u16>,
    used: Vec<bool>,
    mask: [[bool; FACE_GRID]; FACE_GRID],
}

#[derive(Clone, Copy)]
enum Phase {
    Weld,
    SortVertices,
    MapVertices,
    Edges,
    SortEdges,
    Seed,
    Grow,
    Checkpoint,
    Fit,
    Single,
    Done,
}

/// Bounded setup and connected projection charts, at most 32 actual
/// triangles each. Edge keys reuse the legacy face scratch. Only one best plane
/// survives per mesh. No full transformed vertex array or permanent mesh copy.
pub(super) struct ProjectedWork {
    phase: Phase,
    index: usize,
    seed: usize,
    edge: usize,
    single: usize,
    winding: i8,
    patch: Patch,
    pub(super) best: Option<PlaneRecord>,
    certificate: Option<Certificate>,
    alternative: Option<(PlaneRecord, Patch)>,
    #[cfg(test)]
    pub(super) source: Option<Patch>,
}
impl ProjectedWork {
    pub(super) fn new(
        scratch: &mut ProjectedScratch,
        edges: &mut Vec<u64>,
        vertices: usize,
        triangles: usize,
    ) -> Self {
        scratch.points.clear();
        scratch.weld.clear();
        scratch.weld.resize(vertices, 0);
        scratch.used.clear();
        scratch.used.resize(triangles, false);
        edges.clear();
        edges.reserve_exact(triangles * 3);
        Self {
            phase: Phase::Weld,
            index: 0,
            seed: 0,
            edge: 0,
            single: 0,
            winding: 0,
            patch: Patch {
                triangles: [0; PATCH_TRIANGLES],
                count: 0,
                boundary: [0; PATCH_VERTICES],
                len: 0,
            },
            best: None,
            certificate: None,
            alternative: None,
            #[cfg(test)]
            source: None,
        }
    }

    fn prepare(
        &mut self,
        plane: PlaneRecord,
        patch: Patch,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        world: &WorldTransform,
        camera: [f32; 3],
        sides: Sides,
    ) -> bool {
        let area = plane.size[0] * plane.size[1];
        if self
            .best
            .as_ref()
            .is_some_and(|old| area <= old.size[0] * old.size[1])
        {
            return false;
        }
        self.certificate =
            Certificate::new(plane, patch, vertices, triangles, world, camera, sides);
        self.certificate.is_some()
    }
    fn consider(
        &mut self,
        patch: Patch,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        world: &WorldTransform,
        camera: [f32; 3],
        sides: Sides,
        scratch: &mut ProjectedScratch,
    ) -> bool {
        let (analytic, raster) = patch_proposals(
            &patch,
            vertices,
            triangles,
            world,
            camera,
            &mut scratch.mask,
        );
        let (first, second) = match (analytic, raster) {
            (Some(a), Some(b)) => {
                if a.size[0] * a.size[1] >= b.size[0] * b.size[1] {
                    (Some(a), Some(b))
                } else {
                    (Some(b), Some(a))
                }
            }
            (a, b) => (a.or(b), None),
        };
        self.alternative = second.map(|plane| (plane, patch));
        if let Some(plane) = first
            && self.prepare(plane, patch, vertices, triangles, world, camera, sides)
        {
            return true;
        }
        if let Some((plane, patch)) = self.alternative.take() {
            return self.prepare(plane, patch, vertices, triangles, world, camera, sides);
        }
        false
    }

    pub(super) fn advance(
        &mut self,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        world: &WorldTransform,
        camera: [f32; 3],
        sides: Sides,
        scratch: &mut ProjectedScratch,
        edges: &mut Vec<u64>,
        operations: usize,
    ) -> bool {
        if let Some(certificate) = self.certificate.as_mut() {
            if certificate.advance(16) {
                if let Some(bounds) = certificate.result {
                    let mut plane = certificate.plane;
                    plane.camera = Some(bounds);
                    self.best = Some(plane);
                    #[cfg(test)]
                    {
                        self.source = Some(certificate.patch);
                    }
                }
                self.certificate = None;
            }
            return false;
        }
        if let Some((plane, patch)) = self.alternative.take() {
            self.prepare(plane, patch, vertices, triangles, world, camera, sides);
            return false;
        }
        for _ in 0..operations {
            match self.phase {
                Phase::Weld => {
                    if let Some(p) = vertices.get(self.index) {
                        let key = p.map(|v| {
                            if v.to_bits() & 0x7fffffff == 0 {
                                0
                            } else {
                                v.to_bits()
                            }
                        });
                        scratch.points.push((key, self.index as u16));
                        self.index += 1;
                    } else {
                        self.phase = Phase::SortVertices;
                    }
                }
                Phase::SortVertices => {
                    scratch.points.sort_unstable();
                    self.index = 0;
                    self.phase = Phase::MapVertices;
                }
                Phase::MapVertices => {
                    if self.index == scratch.points.len() {
                        self.index = 0;
                        self.phase = Phase::Edges;
                        continue;
                    }
                    let (key, vertex) = scratch.points[self.index];
                    if self.index != 0 && scratch.points[self.index - 1].0 == key {
                        scratch.weld[vertex as usize] =
                            scratch.weld[scratch.points[self.index - 1].1 as usize];
                    } else {
                        scratch.weld[vertex as usize] = vertex;
                    }
                    self.index += 1;
                }
                Phase::Edges => {
                    if let Some(t) = triangles.get(self.index) {
                        if t.iter().any(|&i| i as usize >= vertices.len()) {
                            self.phase = Phase::Done;
                            continue;
                        }
                        let t = t.map(|i| scratch.weld[i as usize]);
                        for (a, b) in [(t[0], t[1]), (t[1], t[2]), (t[2], t[0])] {
                            if a != b {
                                let (lo, hi) = if a < b { (a, b) } else { (b, a) };
                                edges.push(
                                    (u64::from(lo) << 48)
                                        | (u64::from(hi) << 32)
                                        | ((self.index as u64) << 1)
                                        | u64::from(a < b),
                                );
                            }
                        }
                        self.index += 1;
                    } else {
                        self.phase = Phase::SortEdges;
                    }
                }
                Phase::SortEdges => {
                    edges.sort_unstable();
                    self.phase = Phase::Seed;
                }
                Phase::Seed => {
                    if self.seed == triangles.len() {
                        self.phase = Phase::Done;
                        continue;
                    }
                    let i = self.seed;
                    self.seed += 1;
                    if scratch.used[i] {
                        continue;
                    }
                    scratch.used[i] = true;
                    let t = triangles[i].map(|i| scratch.weld[i as usize]);
                    if t[0] == t[1] || t[1] == t[2] || t[0] == t[2] {
                        continue;
                    }
                    let points = t.map(|i| transform_point(world, &vertices[i as usize]));
                    let normal = cross64(
                        sub64(points[1].map(f64::from), points[0].map(f64::from)),
                        sub64(points[2].map(f64::from), points[0].map(f64::from)),
                    );
                    let facing = dot64(
                        normal,
                        sub64(camera.map(f64::from), points[0].map(f64::from)),
                    );
                    if !facing.is_finite()
                        || facing == 0.0
                        || !sides.admits(if facing > 0.0 { 1 } else { -1 })
                    {
                        continue;
                    }
                    self.winding = if facing > 0.0 { 1 } else { -1 };
                    self.patch.triangles[0] = i;
                    self.patch.count = 1;
                    self.patch.boundary[..3].copy_from_slice(&t);
                    self.patch.len = 3;
                    self.edge = 0;
                    self.phase = Phase::Grow;
                }
                Phase::Grow => {
                    if self.patch.count == PATCH_TRIANGLES || self.edge == self.patch.len {
                        self.phase = Phase::Fit;
                        continue;
                    }
                    let a = self.patch.boundary[self.edge];
                    let b = self.patch.boundary[(self.edge + 1) % self.patch.len];
                    self.edge += 1;
                    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
                    let key = (u64::from(lo) << 16) | u64::from(hi);
                    let start = edges.partition_point(|v| *v >> 32 < key);
                    let end = edges.partition_point(|v| *v >> 32 <= key);
                    if end - start != 2 || (edges[start] ^ edges[start + 1]) & 1 == 0 {
                        continue;
                    }
                    let neighbor = [edges[start], edges[start + 1]]
                        .into_iter()
                        .map(|v| ((v & 0xffffffff) >> 1) as usize)
                        .find(|&i| !scratch.used[i]);
                    let Some(neighbor) = neighbor else {
                        continue;
                    };
                    let t = triangles[neighbor].map(|i| scratch.weld[i as usize]);
                    let Some(vertex) = t.into_iter().find(|&i| i != a && i != b) else {
                        continue;
                    };
                    // Adding a new vertex across one boundary edge preserves a
                    // topological disk. Reject rejoining any existing vertex,
                    // including a vertex already made interior by growth.
                    if self.patch.triangles[..self.patch.count].iter().any(|&i| {
                        triangles[i]
                            .iter()
                            .any(|&v| scratch.weld[v as usize] == vertex)
                    }) {
                        continue;
                    }
                    let mut patch = self.patch;
                    let insert = self.edge;
                    patch.boundary.copy_within(insert..patch.len, insert + 1);
                    patch.boundary[insert] = vertex;
                    patch.len += 1;
                    patch.triangles[patch.count] = neighbor;
                    patch.count += 1;
                    let p = triangles[neighbor]
                        .map(|i| transform_point(world, &vertices[i as usize]).map(f64::from));
                    let facing = dot64(
                        cross64(sub64(p[1], p[0]), sub64(p[2], p[0])),
                        sub64(camera.map(f64::from), p[0]),
                    );
                    if !facing.is_finite() || facing * f64::from(self.winding) <= 0.0 {
                        continue;
                    }
                    self.patch = patch;
                    scratch.used[neighbor] = true;
                    self.edge = 0;
                    if matches!(self.patch.count, 8 | 16) {
                        self.phase = Phase::Checkpoint;
                    }
                }
                Phase::Checkpoint => {
                    let exact_work = self.consider(
                        self.patch, vertices, triangles, world, camera, sides, scratch,
                    );
                    self.phase = Phase::Grow;
                    let _ = exact_work;
                    return false;
                }
                Phase::Fit => {
                    let exact_work = self.consider(
                        self.patch, vertices, triangles, world, camera, sides, scratch,
                    );
                    self.single = 0;
                    self.phase = if self.patch.count > 1 {
                        Phase::Single
                    } else {
                        Phase::Seed
                    };
                    let _ = exact_work;
                    return false;
                }
                Phase::Single => {
                    if self.single == self.patch.count {
                        self.phase = Phase::Seed;
                        continue;
                    }
                    let index = self.patch.triangles[self.single];
                    self.single += 1;
                    let mut patch = Patch {
                        triangles: [0; PATCH_TRIANGLES],
                        count: 1,
                        boundary: [0; PATCH_VERTICES],
                        len: 3,
                    };
                    patch.triangles[0] = index;
                    patch.boundary[..3]
                        .copy_from_slice(&triangles[index].map(|i| scratch.weld[i as usize]));
                    // An unsuccessful aggregate may not erase the useful
                    // individual triangles it consumed during chart growth.
                    if self.consider(patch, vertices, triangles, world, camera, sides, scratch) {
                        return false;
                    }
                }
                Phase::Done => return true,
            }
        }
        matches!(self.phase, Phase::Done)
    }
}

fn patch_points(
    patch: &Patch,
    vertices: &[[f32; 3]],
    world: &WorldTransform,
) -> [[f32; 3]; PATCH_VERTICES] {
    std::array::from_fn(|i| {
        if i < patch.len {
            transform_point(world, &vertices[patch.boundary[i] as usize])
        } else {
            [0.0; 3]
        }
    })
}

fn convex_proposal(
    patch: &Patch,
    vertices: &[[f32; 3]],
    world: &WorldTransform,
    camera: [f32; 3],
) -> bool {
    let p = patch_points(patch, vertices, world).map(|v| v.map(f64::from));
    let camera = camera.map(f64::from);
    let sign = dot64(
        cross64(sub64(p[0], camera), sub64(p[1], camera)),
        sub64(p[2], camera),
    )
    .signum();
    if !sign.is_finite() || sign == 0.0 {
        return false;
    }
    (0..patch.len).all(|a| {
        (0..patch.len).all(|b| {
            if b == a || b == (a + 1) % patch.len {
                return true;
            }
            let d = dot64(
                cross64(sub64(p[a], camera), sub64(p[(a + 1) % patch.len], camera)),
                sub64(p[b], camera),
            );
            d.is_finite() && d * sign >= 0.0
        })
    })
}

#[derive(Clone, Copy)]
enum Point {
    Boundary(u8),
    Quad(u8),
}
#[derive(Clone, Copy)]
struct Constraint {
    points: [Point; 3],
    sign: i8,
}
impl Constraint {
    const EMPTY: Self = Self {
        points: [Point::Quad(0); 3],
        sign: 0,
    };
}
#[derive(Clone, Copy)]
enum Separator {
    Quad(usize),
    Edge(i8),
}
const QUAD_EDGES: [(usize, usize); 4] = [(0, 1), (1, 3), (3, 2), (2, 0)];

/// Transient world input and selected boundary halfspaces. No transformed
/// full-mesh array is duplicated. Raster samples never enter the certificate.
struct Geometry {
    triangles: [[[f32; 3]; 3]; PATCH_TRIANGLES],
    points: [[f32; 3]; PATCH_VERTICES],
    quad: [[f32; 3]; 4],
    raw_quad: [[f32; 3]; 8],
    count: usize,
    len: usize,
    axis: usize,
    lo: u32,
    hi: u32,
    positive: bool,
    sign: i8,
    cones: [Constraint; PATCH_VERTICES * 4],
    cone_count: usize,
    separated: bool,
}
impl Geometry {
    fn new(
        plane: &PlaneRecord,
        patch: &Patch,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        world: &WorldTransform,
        camera: [f32; 3],
        sides: Sides,
    ) -> Option<Self> {
        use super::super::data::coordinate_key;
        let points = patch_points(patch, vertices, world);
        let triangles: [[[f32; 3]; 3]; PATCH_TRIANGLES] = std::array::from_fn(|i| {
            if i < patch.count {
                triangles[patch.triangles[i]].map(|j| transform_point(world, &vertices[j as usize]))
            } else {
                [[0.0; 3]; 3]
            }
        });
        let sign = side(triangles[0], camera)?;
        if !sides.admits(sign) {
            return None;
        }
        let axis = (0..3).find(|&i| plane.rotation[i * 3 + 1] != 0.0)?;
        let raw_quad = envelope::corners(plane)?;
        let mut lo = u32::MAX;
        let mut hi = 0;
        for t in &triangles[..patch.count] {
            for p in t {
                let k = coordinate_key(p[axis])?;
                lo = lo.min(k);
                hi = hi.max(k);
            }
        }
        let c = coordinate_key(camera[axis])?;
        let positive = c < lo;
        if !positive && c <= hi {
            return None;
        }
        let mut geometry = Self {
            triangles,
            points,
            quad: [raw_quad[0]; 4],
            raw_quad,
            count: patch.count,
            len: patch.len,
            axis,
            lo,
            hi,
            positive,
            sign,
            cones: [Constraint::EMPTY; PATCH_VERTICES * 4],
            cone_count: 0,
            separated: false,
        };
        geometry.enclose(camera, camera).then_some(geometry)
    }
    fn enclose(&mut self, min: [f32; 3], max: [f32; 3]) -> bool {
        let Some(quad) = envelope::enclose(self.raw_quad, self.axis, min, max, self.positive)
        else {
            return false;
        };
        if !quad.iter().all(|p| {
            super::super::data::coordinate_key(p[self.axis]).is_some_and(|q| {
                if self.positive {
                    q > self.hi
                } else {
                    q < self.lo
                }
            })
        }) {
            return false;
        }
        self.quad = quad;
        self.cone_count = 0;
        self.separated = false;
        true
    }
    fn center(&self) -> [f32; 3] {
        std::array::from_fn(|i| envelope::midpoint(self.quad[0][i], self.quad[3][i]))
    }
    fn seed(&self, index: usize, camera: [f32; 3]) -> bool {
        let t = self.triangles[index];
        let q = self.center();
        [(0, 1), (1, 2), (2, 0)]
            .into_iter()
            .all(|(a, b)| orient(t[a], t[b], q, camera).is_some_and(|s| s == 0 || s == -self.sign))
    }
    fn separator(&self, edge: usize, camera: [f32; 3]) -> Option<Separator> {
        let a = self.points[edge];
        let b = self.points[(edge + 1) % self.len];
        let outside = if self.positive { -1 } else { 1 };
        for (index, (x, y)) in QUAD_EDGES.into_iter().enumerate() {
            if orient(self.quad[x], self.quad[y], a, camera) == Some(outside)
                && orient(self.quad[x], self.quad[y], b, camera) == Some(outside)
            {
                return Some(Separator::Quad(index));
            }
        }
        let sign = orient(a, b, self.quad[0], camera)?;
        (sign != 0
            && self.quad[1..]
                .iter()
                .all(|&q| orient(a, b, q, camera) == Some(sign)))
        .then_some(Separator::Edge(sign))
    }
    fn append_separator(&mut self, edge: usize, camera: [f32; 3]) -> bool {
        let Some(separator) = self.separator(edge, camera) else {
            return false;
        };
        let mut append = |points, sign| {
            self.cones[self.cone_count] = Constraint { points, sign };
            self.cone_count += 1;
        };
        let a = Point::Boundary(edge as u8);
        let b = Point::Boundary(((edge + 1) % self.len) as u8);
        match separator {
            Separator::Quad(index) => {
                let (x, y) = QUAD_EDGES[index];
                let sign = if self.positive { -1 } else { 1 };
                append([Point::Quad(x as u8), Point::Quad(y as u8), a], sign);
                append([Point::Quad(x as u8), Point::Quad(y as u8), b], sign);
            }
            Separator::Edge(sign) => {
                for i in 0..4 {
                    append([a, b, Point::Quad(i)], sign);
                }
            }
        }
        true
    }
    fn constraints(&self) -> usize {
        1 + self.count + self.cone_count
    }
    fn constraint(&self, mut index: usize, camera: [f32; 3]) -> bool {
        if !self.separated {
            return false;
        }
        if index == 0 {
            return super::super::data::coordinate_key(camera[self.axis]).is_some_and(|c| {
                if self.positive {
                    c < self.lo
                } else {
                    c > self.hi
                }
            });
        }
        index -= 1;
        if index < self.count {
            return side(self.triangles[index], camera) == Some(self.sign);
        }
        let c = self.cones[index - self.count];
        let p = c.points.map(|p| match p {
            Point::Boundary(i) => self.points[i as usize],
            Point::Quad(i) => self.quad[i as usize],
        });
        orient(p[0], p[1], p[2], camera) == Some(c.sign)
    }
    /// F64 proposes a region only. Exact boundary separation and source-side
    /// tests at all eight rounded corners remain the authority.
    fn radius(&self, camera: [f32; 3]) -> f64 {
        let c = camera.map(f64::from);
        let mut radius = f64::INFINITY;
        for t in &self.triangles[..self.count] {
            for p in t {
                radius = radius.min((c[self.axis] - f64::from(p[self.axis])).abs());
            }
        }
        let mut limit = |point: [f64; 3], normal: [f64; 3]| {
            let d = normal.iter().map(|v| v.abs()).sum::<f64>();
            if d > 0.0 {
                radius = radius.min(dot64(sub64(c, point), normal).abs() / d);
            }
        };
        for t in &self.triangles[..self.count] {
            let t = t.map(|p| p.map(f64::from));
            limit(t[0], cross64(sub64(t[1], t[0]), sub64(t[2], t[0])));
        }
        let q = self.quad.map(|p| p.map(f64::from));
        let determinant = |a, b, p| dot64(cross64(sub64(a, c), sub64(b, c)), sub64(p, c));
        for edge in 0..self.len {
            let a = self.points[edge].map(f64::from);
            let b = self.points[(edge + 1) % self.len].map(f64::from);
            let outside = if self.positive { -1.0 } else { 1.0 };
            let mut found = false;
            for (x, y) in QUAD_EDGES {
                if determinant(q[x], q[y], a) * outside > 0.0
                    && determinant(q[x], q[y], b) * outside > 0.0
                {
                    for p in [a, b] {
                        limit(q[x], cross64(sub64(q[y], q[x]), sub64(p, q[x])));
                    }
                    found = true;
                    break;
                }
            }
            if found {
                continue;
            }
            let sign = determinant(a, b, q[0]).signum();
            if sign == 0.0
                || !sign.is_finite()
                || !q.iter().all(|&p| determinant(a, b, p) * sign > 0.0)
            {
                return 0.0;
            }
            for p in q {
                limit(a, cross64(sub64(b, a), sub64(p, a)));
            }
        }
        radius * 0.5
    }
}

#[derive(Clone, Copy)]
enum CertPhase {
    Faces,
    Seed,
    Boundary,
    Corners,
}
/// A connected oriented patch is a disk. At C0 its rectangle center is covered.
/// Preserve face winding and keep every boundary segment disjoint from the
/// rectangle throughout a convex camera box: coverage winding then stays
/// nonzero over the whole rectangle. Concave boundaries and open meshes need
/// no hull filling, watertightness assumption or corner-sampling surrogate.
struct Certificate {
    geometry: Geometry,
    plane: PlaneRecord,
    #[cfg(test)]
    patch: Patch,
    camera: [f32; 3],
    radius: f64,
    min: [f32; 3],
    max: [f32; 3],
    bounds: CameraBounds,
    phase: CertPhase,
    index: usize,
    corner: usize,
    attempt: usize,
    result: Option<CameraBounds>,
}
impl Certificate {
    fn new(
        plane: PlaneRecord,
        patch: Patch,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        world: &WorldTransform,
        camera: [f32; 3],
        sides: Sides,
    ) -> Option<Self> {
        let geometry = Geometry::new(&plane, &patch, vertices, triangles, world, camera, sides)?;
        let radius = geometry.radius(camera);
        let mut job = Self {
            geometry,
            plane,
            #[cfg(test)]
            patch,
            camera,
            radius,
            min: [0.0; 3],
            max: [0.0; 3],
            bounds: CameraBounds::new(camera, camera)?,
            phase: CertPhase::Faces,
            index: 0,
            corner: 0,
            attempt: 0,
            result: None,
        };
        job.set_box().then_some(job)
    }
    fn set_box(&mut self) -> bool {
        if !self.radius.is_finite() || self.radius <= 0.0 {
            return false;
        }
        self.min = std::array::from_fn(|i| (f64::from(self.camera[i]) - self.radius) as f32);
        self.max = std::array::from_fn(|i| (f64::from(self.camera[i]) + self.radius) as f32);
        let Some(bounds) = CameraBounds::new(self.min, self.max) else {
            return false;
        };
        if !(0..3).all(|i| self.min[i] < self.camera[i] && self.max[i] > self.camera[i]) {
            return false;
        }
        self.bounds = bounds;
        self.geometry.enclose(self.min, self.max)
    }
    fn shrink(&mut self) -> bool {
        if self.attempt == 7 {
            return false;
        }
        self.attempt += 1;
        self.radius *= 0.5;
        self.phase = CertPhase::Seed;
        self.index = 0;
        self.corner = 0;
        self.set_box()
    }
    fn advance(&mut self, operations: usize) -> bool {
        let mut spent = 0;
        loop {
            let cost = match self.phase {
                CertPhase::Faces | CertPhase::Corners => 1,
                CertPhase::Seed => 3,
                CertPhase::Boundary => 12,
            };
            if spent != 0 && spent + cost > operations {
                return false;
            }
            spent += cost;
            match self.phase {
                CertPhase::Faces => {
                    if side(self.geometry.triangles[self.index], self.camera)
                        != Some(self.geometry.sign)
                    {
                        return true;
                    }
                    self.index += 1;
                    if self.index == self.geometry.count {
                        self.index = 0;
                        self.phase = CertPhase::Seed;
                    }
                }
                CertPhase::Seed => {
                    if self.geometry.seed(self.index, self.camera) {
                        self.index = 0;
                        self.phase = CertPhase::Boundary;
                    } else {
                        self.index += 1;
                        if self.index == self.geometry.count {
                            return true;
                        }
                    }
                }
                CertPhase::Boundary => {
                    if !self.geometry.append_separator(self.index, self.camera) {
                        if !self.shrink() {
                            return true;
                        }
                        continue;
                    }
                    self.index += 1;
                    if self.index == self.geometry.len {
                        self.geometry.separated = true;
                        self.index = 0;
                        self.phase = CertPhase::Corners;
                    }
                }
                CertPhase::Corners => {
                    let camera = std::array::from_fn(|i| {
                        if self.corner & (1 << i) == 0 {
                            self.min[i]
                        } else {
                            self.max[i]
                        }
                    });
                    if !self.geometry.constraint(self.index, camera) {
                        if !self.shrink() {
                            return true;
                        }
                        continue;
                    }
                    self.index += 1;
                    if self.index == self.geometry.constraints() {
                        self.index = 0;
                        self.corner += 1;
                        if self.corner == 8 {
                            self.result = Some(self.bounds);
                            return true;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) fn patch_supported(
    plane: &PlaneRecord,
    patch: &Patch,
    vertices: &[[f32; 3]],
    triangles: &[[u16; 3]],
    world: &WorldTransform,
    camera: [f32; 3],
    sides: Sides,
) -> bool {
    Geometry::new(plane, patch, vertices, triangles, world, camera, sides).is_some_and(|mut g| {
        let (min, max) = plane.camera.map(|b| b.limits()).unwrap_or((camera, camera));
        if !g.enclose(min, max) || !(0..g.count).any(|i| g.seed(i, camera)) {
            return false;
        }
        if !(0..g.len).all(|i| g.append_separator(i, camera)) {
            return false;
        }
        g.separated = true;
        (0..g.constraints()).all(|i| g.constraint(i, camera))
    })
}
