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
        let mut geometry = [0; 14];
        for (out, value) in geometry.iter_mut().zip(
            self.position
                .into_iter()
                .chain(self.size)
                .chain(self.rotation),
        ) {
            *out = if value == 0.0 { 0 } else { value.to_bits() };
        }
        PlaneIdentity {
            geometry,
            two_sided: self.two_sided(),
            priority: self.priority,
            source: self.source_form_id,
        }
    }
}
