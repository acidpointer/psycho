//! Occlusion-plane records and cell identity.
//!
//! The runtime collector builds records from live cell geometry. A record is a
//! rectangle, a world position, a size, and a row-major rotation matrix that
//! maps the plane's local X/Z rectangle axes and local Y normal to world space
//! (`world = rotation * local`, matching the engine's `NiMatrix3` convention
//! and `0x00C35C10` corner builder). Injected planes are one-sided: the local
//! +Y normal must point toward the side the player views, because the engine
//! activates the plane only from that side.

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
    /// `TESForm::refID` of the base form this plane was generated from, used to
    /// bind a cached plane to its source plugin.
    pub source_form_id: u32,
    /// Side confidence of the source face (`0.0..=1.0`). High values mean the
    /// rectangle fills a solid, well-shaped, thick face and can use two-sided
    /// activation; a low value (an irregular or thin-panel face) keeps the
    /// conservative one-sided behavior.
    pub coverage: f32,
}
