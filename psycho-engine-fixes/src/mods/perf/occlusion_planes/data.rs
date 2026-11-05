//! Occlusion-plane records and cell identity.
//!
//! The runtime collector builds records from live cell geometry. A record is a
//! rectangle, a world position, a size, and a row-major rotation matrix that
//! maps the plane's local X/Z rectangle axes and local Y normal to world space
//! (`world = rotation * local`, matching the engine's `NiMatrix3` convention
//! and `0x00C35C10` corner builder). The side policy is part of native identity.
//! Hashes locate descriptors; complete descriptor equality decides reuse.

/// Identifies the cell whose planes apply.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CellKey {
    /// Interior cell FormID.
    Interior { form_id: u32 },
    /// Exterior worldspace FormID and grid coordinates.
    Exterior { worldspace: u32, x: i32, y: i32 },
}

/// One occlusion-plane rectangle.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlaneRecord {
    /// Additional planes are admitted only inside this certified camera box.
    /// Legacy rectangles have no camera-scoped certificate.
    pub(super) camera: Option<CameraBounds>,
    /// World-space rectangle center.
    pub position: [f32; 3],
    /// Full rectangle width and height. The native `+0x14/+0x18` fields are
    /// half-extents, so `create_plane` halves this value at the native
    /// boundary.
    pub size: [f32; 2],
    /// Row-major 3x3 matrix mapping local axes to world.
    pub rotation: [f32; 9],
    /// Higher priority survives the per-cell cap.
    pub priority: u8,
    /// `TESForm::refID` of the first source base form, for diagnostics and
    /// identity. Merged provenance is validated from the full captured cell.
    pub source_form_id: u32,
    /// Side confidence of the source face (`0.0..=1.0`). High values mean the
    /// rectangle fills a solid, well-shaped, thick face and can use two-sided
    /// activation; a low value (an irregular or thin-panel face) keeps the
    /// conservative one-sided behavior.
    pub coverage: f32,
}

/// Exact native behavior plus source identity. Geometry uses finite float bits,
/// canonicalizing signed zero. No hash or rounding tolerance establishes
/// equality, and confidence values with the same native policy may reuse one
/// object. This descriptor also provides deterministic selection tie ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct PlaneIdentity {
    geometry: [u32; 14],
    two_sided: bool,
    priority: u8,
    source: u32,
    camera: Option<CameraBounds>,
}

/// Ordered binary32 keys make admission independent of rounding and DAZ/FTZ.
/// Signed zero is canonicalized; nonfinite camera coordinates are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct CameraBounds {
    pub(super) min: [u32; 3],
    pub(super) max: [u32; 3],
    pub(super) epoch: u64,
}

pub(super) fn coordinate_key(value: f32) -> Option<u32> {
    let mut bits = value.to_bits();
    if bits & 0x7f800000 == 0x7f800000 {
        return None;
    }
    if bits & 0x7fffffff == 0 {
        bits = 0;
    }
    Some(if bits >> 31 != 0 {
        !bits
    } else {
        bits ^ 0x80000000
    })
}

/// Exact finite descriptor bits; only the two signed zeros compare equal.
/// Integer lanes preserve subnormals even when the caller enables DAZ.
pub(super) fn canonical_bits<const N: usize>(values: [f32; N]) -> [u32; N] {
    use wide::u32x4;
    let mut bits = values.map(f32::to_bits);
    let mut chunks = bits.chunks_exact_mut(4);
    for chunk in &mut chunks {
        let lanes = u32x4::new([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let zero = (lanes & u32x4::splat(0x7fffffff)).simd_eq(u32x4::ZERO);
        chunk.copy_from_slice(&zero.select(u32x4::ZERO, lanes).to_array());
    }
    for value in chunks.into_remainder() {
        if *value & 0x7fffffff == 0 {
            *value = 0;
        }
    }
    bits
}

impl CameraBounds {
    #[cfg(test)]
    pub(super) fn limits(&self) -> ([f32; 3], [f32; 3]) {
        let decode = |key: u32| {
            f32::from_bits(if key >> 31 != 0 {
                key ^ 0x80000000
            } else {
                !key
            })
        };
        (self.min.map(decode), self.max.map(decode))
    }
    pub(super) fn new(min: [f32; 3], max: [f32; 3]) -> Option<Self> {
        let min = [
            coordinate_key(min[0])?,
            coordinate_key(min[1])?,
            coordinate_key(min[2])?,
        ];
        let max = [
            coordinate_key(max[0])?,
            coordinate_key(max[1])?,
            coordinate_key(max[2])?,
        ];
        (0..3)
            .all(|i| min[i] <= max[i])
            .then_some(Self { min, max, epoch: 0 })
    }

    #[inline]
    pub(super) fn contains(&self, camera: [f32; 3]) -> bool {
        use wide::u32x4;
        let bits = u32x4::new([
            camera[0].to_bits(),
            camera[1].to_bits(),
            camera[2].to_bits(),
            0,
        ]);
        let magnitude = bits & u32x4::splat(0x7fffffff);
        if magnitude.simd_ge(u32x4::splat(0x7f800000)).any() {
            return false;
        }
        let sign = bits >> 31;
        let flipped = bits ^ (u32x4::splat(0x80000000) | (u32x4::ZERO - sign));
        let mut key = magnitude
            .simd_eq(u32x4::ZERO)
            .select(u32x4::splat(0x80000000), flipped)
            .to_array();
        key[3] = 0;
        let point = u32x4::new(key);
        let min = wide::u32x4::new([self.min[0], self.min[1], self.min[2], 0]);
        let max = wide::u32x4::new([self.max[0], self.max[1], self.max[2], 0]);
        (point.simd_lt(min) | point.simd_gt(max)).none()
    }
}

impl PlaneRecord {
    /// Numeric native boundary: finite fields, nonzero half extents and finite
    /// corners in the verified native multiply/add order. No guessed world-size
    /// cutoff or rotation tolerance is used. Rotation comes from the live rigid
    /// transform and the generator's normalized plane basis.
    pub(super) fn valid_native(&self) -> bool {
        if !self
            .position
            .iter()
            .chain(&self.rotation)
            .all(|v| v.is_finite())
            || !self.size.iter().all(|v| v.is_finite() && *v * 0.5 > 0.0)
            || !(0.0..=1.0).contains(&self.coverage)
        {
            return false;
        }
        for x in [-0.5, 0.5] {
            for z in [-0.5, 0.5] {
                for axis in 0..3 {
                    let corner = self.position[axis]
                        + x * self.size[0] * self.rotation[axis * 3]
                        + z * self.size[1] * self.rotation[axis * 3 + 2];
                    if !corner.is_finite() {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Native `+0xEA` policy; keep this decision shared by reuse and creation.
    pub(super) fn two_sided(&self) -> bool {
        self.coverage >= super::runtime_generate::TWO_SIDED_COVERAGE
    }

    /// Canonical descriptor of the fields consumed by the native factory.
    pub(super) fn identity(&self) -> PlaneIdentity {
        let mut geometry = [0.0; 14];
        for (out, value) in geometry.iter_mut().zip(
            self.position
                .into_iter()
                .chain(self.size)
                .chain(self.rotation),
        ) {
            *out = value;
        }
        PlaneIdentity {
            geometry: canonical_bits(geometry),
            two_sided: self.two_sided(),
            priority: self.priority,
            source: self.source_form_id,
            camera: self.camera,
        }
    }
}
