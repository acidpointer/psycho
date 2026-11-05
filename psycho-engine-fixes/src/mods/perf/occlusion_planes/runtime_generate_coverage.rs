//! Resumable coverage of an owned mesh face. No engine pointer is retained.
//! Source filtering, boundary proof and recovery rasterization share the
//! original scalar predicates and ordering. Scratch belongs to one generation;
//! only a completed result may enter the reusable local surface cache.
use super::*;

/// Four independent coverage samples. Arithmetic and epsilon evaluation keep
/// the scalar predicate's order; no fused multiply-add or reciprocal is used.
pub(super) fn triangle_mask(x: f32x4, y: f32x4, a: [f32; 2], b: [f32; 2], c: [f32; 2]) -> u32 {
    let area = triangle_area_2d(a, b, c);
    if !area.is_finite() || area == 0.0 {
        return 0;
    }
    let cross = |a: [f32; 2], b: [f32; 2]| {
        f32x4::splat(b[0] - a[0]) * (y - f32x4::splat(a[1]))
            - f32x4::splat(b[1] - a[1]) * (x - f32x4::splat(a[0]))
    };
    let d1 = cross(a, b);
    let d2 = cross(b, c);
    let d3 = cross(c, a);
    // SSE max chooses the finite RHS for a NaN LHS, matching scalar max(1).
    let epsilon =
        (d1.abs() + d2.abs() + d3.abs()).fast_max(f32x4::splat(1.0)) * f32x4::splat(1.0e-4);
    let negative = d1.simd_lt(-epsilon) | d2.simd_lt(-epsilon) | d3.simd_lt(-epsilon);
    let positive = d1.simd_gt(epsilon) | d2.simd_gt(epsilon) | d3.simd_gt(epsilon);
    (!(negative & positive)).to_bitmask() & 15
}

/// Support setup followed by resumable coverage. The supporting hull sort is
/// bounded by the admitted mesh vertex count; expensive triangle/grid work
/// yields independently. This job owns no native or borrowed input.
pub(super) struct LocalFaceWork {
    coverage: Option<CoverageWork>,
    confidence: f32,
    pub(super) result: LocalFace,
}

impl LocalFaceWork {
    pub(super) fn new(
        local: &Aabb,
        vertices: &[[f32; 3]],
        face: usize,
        points: &mut Vec<[f32; 2]>,
        hull: &mut Vec<[f32; 2]>,
        upper: &mut Vec<[f32; 2]>,
        scratch: &mut CoverageScratch,
    ) -> Self {
        let axis = face / 2;
        let a = (axis + 1) % 3;
        let b = (axis + 2) % 3;
        let extent = local.extents();
        let center = local.center();
        let coordinate = if face % 2 == 0 {
            local.max[axis]
        } else {
            local.min[axis]
        };
        let Some(rect) = support_rect(
            vertices,
            axis,
            coordinate,
            extent[axis],
            center[a],
            center[b],
            extent[a] * 0.5,
            extent[b] * 0.5,
            points,
            hull,
            upper,
        ) else {
            return Self {
                coverage: None,
                confidence: 0.0,
                result: LocalFace::Unsupported,
            };
        };
        Self {
            coverage: Some(CoverageWork::new(
                axis,
                coordinate,
                SUPPORT_TOLERANCE_MIN.max(extent[axis] * SUPPORT_TOLERANCE_RATIO),
                [rect.center_u, rect.center_v, rect.half_u, rect.half_v],
                scratch,
            )),
            confidence: rect.coverage,
            result: LocalFace::Opening,
        }
    }

    pub(super) fn advance(
        &mut self,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        scratch: &mut CoverageScratch,
        operations: usize,
    ) -> bool {
        let Some(work) = self.coverage.as_mut() else {
            return true;
        };
        if !work.advance(vertices, triangles, scratch, operations) {
            return false;
        }
        if let Some([center_u, center_v, half_u, half_v]) = work.result {
            self.result = LocalFace::Rectangle {
                center_u,
                center_v,
                half_u,
                half_v,
                coverage: self.confidence,
            };
        }
        self.coverage = None;
        true
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Filter,
    Edges,
    Sort,
    Runs,
    Boundary,
    Points,
    Fill,
    Clear,
    Finish,
    Done,
}

struct Raster {
    points: [[f32; 2]; 3],
    row: usize,
    last: usize,
    left: usize,
    right: usize,
}

/// One face coverage job. Each operation examines one triangle, boundary key,
/// point/triangle pair, or raster row. Sorting is a separately bounded stage.
pub(super) struct CoverageWork {
    phase: Phase,
    axis: usize,
    coordinate: f32,
    tolerance: f32,
    original: [f32; 4],
    rect: [f32; 4],
    cell: [f32; 2],
    index: usize,
    run_start: usize,
    point: usize,
    raster: Option<Raster>,
    pub(super) result: Option<[f32; 4]>,
}

impl CoverageWork {
    pub(super) fn new(
        axis: usize,
        coordinate: f32,
        tolerance: f32,
        original: [f32; 4],
        scratch: &mut CoverageScratch,
    ) -> Self {
        let [u, v, hu, hv] = original;
        let inset = (hu.min(hv) * 0.02).clamp(0.0, 4.0);
        let rect = [
            u - hu + inset,
            v - hv + inset,
            u + hu - inset,
            v + hv - inset,
        ];
        scratch.subset.clear();
        scratch.edge_keys.clear();
        scratch.boundary.clear();
        scratch.mask = [[false; FACE_GRID]; FACE_GRID];
        Self {
            phase: if rect[2] > rect[0] && rect[3] > rect[1] {
                Phase::Filter
            } else {
                Phase::Done
            },
            axis,
            coordinate,
            tolerance,
            original,
            rect,
            cell: [
                (rect[2] - rect[0]) / FACE_GRID as f32,
                (rect[3] - rect[1]) / FACE_GRID as f32,
            ],
            index: 0,
            run_start: 0,
            point: 0,
            raster: None,
            result: None,
        }
    }

    fn transition(&mut self, phase: Phase) {
        self.phase = phase;
        self.index = 0;
    }

    fn project(&self, vertices: &[[f32; 3]], index: u16) -> [f32; 2] {
        let p = vertices[index as usize];
        [p[(self.axis + 1) % 3], p[(self.axis + 2) % 3]]
    }

    fn raster(&self, points: [[f32; 2]; 3], padding: bool) -> Raster {
        let pad = if padding { self.cell } else { [0.0; 2] };
        let minimum = |a: usize| points[0][a].min(points[1][a]).min(points[2][a]) - pad[a];
        let maximum = |a: usize| points[0][a].max(points[1][a]).max(points[2][a]) + pad[a];
        let cell = |value: f32, a: usize| {
            (((value - self.rect[a]) / self.cell[a]).floor() as i64).clamp(0, FACE_GRID as i64 - 1)
                as usize
        };
        Raster {
            points,
            left: cell(minimum(0), 0),
            right: cell(maximum(0), 0),
            row: cell(minimum(1), 1),
            last: cell(maximum(1), 1),
        }
    }

    pub(super) fn advance(
        &mut self,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
        scratch: &mut CoverageScratch,
        operations: usize,
    ) -> bool {
        for _ in 0..operations {
            match self.phase {
                Phase::Filter => {
                    let Some(t) = triangles.get(self.index) else {
                        scratch.edge_keys.reserve_exact(scratch.subset.len() * 3);
                        self.transition(if scratch.subset.is_empty() {
                            Phase::Done
                        } else {
                            Phase::Edges
                        });
                        continue;
                    };
                    self.index += 1;
                    if !append_near_face_triangle(
                        vertices,
                        t,
                        self.axis,
                        self.coordinate,
                        self.tolerance,
                        &mut scratch.subset,
                    ) {
                        self.phase = Phase::Done;
                    }
                }
                Phase::Edges => {
                    let Some(&t) = scratch.subset.get(self.index) else {
                        self.transition(Phase::Sort);
                        continue;
                    };
                    self.index += 1;
                    for (a, b) in [(t[0], t[1]), (t[1], t[2]), (t[2], t[0])] {
                        if a == b {
                            continue;
                        }
                        let pa = self.project(vertices, a);
                        let pb = self.project(vertices, b);
                        if pa[0].max(pb[0]) < self.rect[0]
                            || pa[0].min(pb[0]) > self.rect[2]
                            || pa[1].max(pb[1]) < self.rect[1]
                            || pa[1].min(pb[1]) > self.rect[3]
                        {
                            continue;
                        }
                        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
                        scratch.edge_keys.push(((lo as u64) << 16) | hi as u64);
                    }
                }
                Phase::Sort => {
                    scratch.edge_keys.sort_unstable();
                    self.run_start = 0;
                    self.transition(Phase::Runs);
                }
                Phase::Runs => {
                    if self.index == scratch.edge_keys.len() {
                        self.transition(Phase::Boundary);
                        continue;
                    }
                    let key = scratch.edge_keys[self.run_start];
                    self.index += 1;
                    if self.index == scratch.edge_keys.len() || scratch.edge_keys[self.index] != key
                    {
                        if self.index - self.run_start == 1 {
                            scratch
                                .boundary
                                .push(((key >> 16) as u16, (key & 0xffff) as u16));
                        }
                        self.run_start = self.index;
                    }
                }
                Phase::Boundary => {
                    let Some(&(a, b)) = scratch.boundary.get(self.index) else {
                        self.point = 0;
                        self.transition(Phase::Points);
                        continue;
                    };
                    self.index += 1;
                    if segment_intersects_rect(
                        self.project(vertices, a),
                        self.project(vertices, b),
                        self.rect,
                    ) {
                        self.transition(Phase::Fill);
                    }
                }
                Phase::Points => {
                    let [u0, v0, u1, v1] = self.rect;
                    let p = [
                        [(u0 + u1) * 0.5, (v0 + v1) * 0.5],
                        [u0, v0],
                        [u1, v0],
                        [u0, v1],
                        [u1, v1],
                    ][self.point];
                    let Some(t) = scratch.subset.get(self.index) else {
                        self.transition(Phase::Fill);
                        continue;
                    };
                    self.index += 1;
                    if point_in_triangle_2d(
                        p,
                        self.project(vertices, t[0]),
                        self.project(vertices, t[1]),
                        self.project(vertices, t[2]),
                    ) {
                        self.point += 1;
                        self.index = 0;
                        if self.point == 5 {
                            self.result = Some(self.original);
                            self.phase = Phase::Done;
                        }
                    }
                }
                Phase::Fill => {
                    if self.raster.is_none() {
                        let Some(t) = scratch.subset.get(self.index) else {
                            self.transition(Phase::Clear);
                            continue;
                        };
                        self.raster = Some(self.raster(
                            [
                                self.project(vertices, t[0]),
                                self.project(vertices, t[1]),
                                self.project(vertices, t[2]),
                            ],
                            false,
                        ));
                    }
                    let raster = self.raster.as_mut().expect("inserted owned raster");
                    let [a, b, c] = raster.points;
                    let mut column = raster.left;
                    while column + 3 <= raster.right {
                        if scratch.mask[raster.row][column..column + 4]
                            .iter()
                            .any(|&covered| !covered)
                        {
                            let positions = f32x4::new([
                                column as f32,
                                (column + 1) as f32,
                                (column + 2) as f32,
                                (column + 3) as f32,
                            ]);
                            let x = f32x4::splat(self.rect[0])
                                + (positions + f32x4::splat(0.5)) * f32x4::splat(self.cell[0]);
                            let y = self.rect[1] + (raster.row as f32 + 0.5) * self.cell[1];
                            let bits = triangle_mask(x, f32x4::splat(y), a, b, c);
                            for lane in 0..4 {
                                if bits & (1 << lane) != 0 {
                                    scratch.mask[raster.row][column + lane] = true;
                                }
                            }
                        }
                        column += 4;
                    }
                    for column in column..=raster.right {
                        let p = [
                            self.rect[0] + (column as f32 + 0.5) * self.cell[0],
                            self.rect[1] + (raster.row as f32 + 0.5) * self.cell[1],
                        ];
                        let covered = &mut scratch.mask[raster.row][column];
                        if !*covered && point_in_triangle_2d(p, a, b, c) {
                            *covered = true;
                        }
                    }
                    raster.row += 1;
                    if raster.row > raster.last {
                        self.raster = None;
                        self.index += 1;
                    }
                }
                Phase::Clear => {
                    if self.raster.is_none() {
                        let Some(&(a, b)) = scratch.boundary.get(self.index) else {
                            self.transition(Phase::Finish);
                            continue;
                        };
                        let pa = self.project(vertices, a);
                        let pb = self.project(vertices, b);
                        self.raster = Some(self.raster([pa, pb, pb], true));
                    }
                    let raster = self.raster.as_mut().expect("inserted owned raster");
                    for column in raster.left..=raster.right {
                        let u0 = self.rect[0] + column as f32 * self.cell[0];
                        let v0 = self.rect[1] + raster.row as f32 * self.cell[1];
                        if segment_intersects_rect(
                            raster.points[0],
                            raster.points[1],
                            [u0, v0, u0 + self.cell[0], v0 + self.cell[1]],
                        ) {
                            scratch.mask[raster.row][column] = false;
                        }
                    }
                    raster.row += 1;
                    if raster.row > raster.last {
                        self.raster = None;
                        self.index += 1;
                    }
                }
                Phase::Finish => {
                    if let Some((left, top, right, bottom)) = largest_covered_rect(&scratch.mask) {
                        let u0 = self.rect[0] + left as f32 * self.cell[0];
                        let u1 = self.rect[0] + (right + 1) as f32 * self.cell[0];
                        let v0 = self.rect[1] + top as f32 * self.cell[1];
                        let v1 = self.rect[1] + (bottom + 1) as f32 * self.cell[1];
                        self.result = Some([
                            (u0 + u1) * 0.5,
                            (v0 + v1) * 0.5,
                            (u1 - u0) * 0.5,
                            (v1 - v0) * 0.5,
                        ]);
                    }
                    self.phase = Phase::Done;
                }
                Phase::Done => return true,
            }
        }
        matches!(self.phase, Phase::Done)
    }
}
