//! Occlusion-plane records and optional TOML overrides.
//!
//! The runtime collector builds records from live cell geometry. An optional
//! TOML file can override a cell with hand-authored records. Both paths use the
//! same native injection: a rectangle, a world position, a size, and a
//! row-major rotation matrix that maps the plane's local X/Z rectangle axes and
//! local Y normal to world space (`world = rotation * local`, matching the
//! engine's `NiMatrix3` convention and `0x00C35C10` corner builder). Injected
//! planes are one-sided: the local +Y normal must point toward the side the
//! player views, because the engine activates the plane only from that side.
//!
//! Hand-authored records use the engine's `XOCP` axis-angle form, which is
//! converted by the native rotation builder so the authored math is unchanged.

use std::collections::HashMap;

use serde::Deserialize;

/// Identifies the cell whose planes apply.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CellKey {
    /// Interior cell FormID.
    Interior { form_id: u32 },
    /// Exterior worldspace FormID and grid coordinates.
    Exterior { worldspace: u32, x: i32, y: i32 },
}

/// Plane rotation source. The TOML path keeps the engine's axis-angle builder;
/// the runtime collector supplies a ready matrix.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PlaneRotation {
    /// Axis-angle, converted by the engine's verified rotation builder.
    AxisAngle { axis: [f32; 3], angle: f32 },
    /// Row-major 3x3 matrix mapping local axes to world.
    Matrix([f32; 9]),
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
    /// Rotation source.
    pub rotation: PlaneRotation,
    /// Higher priority survives the per-cell cap.
    pub priority: u8,
    /// `TESForm::refID` of the base form this plane was generated from, used to
    /// bind a cached plane to its source plugin. Zero for hand-authored
    /// overrides.
    pub source_form_id: u32,
}

/// Parsed, capped plane records keyed by cell.
pub struct PlaneSet {
    cells: HashMap<CellKey, Vec<PlaneRecord>>,
}

impl PlaneSet {
    /// Empty set used when no override file is present or valid.
    pub(super) fn empty() -> Self {
        Self {
            cells: HashMap::new(),
        }
    }

    /// Parse a TOML override file and cap each cell's list.
    pub(super) fn parse(text: &str, max_per_cell: usize) -> Result<Self, String> {
        let raw: RawFile = toml::from_str(text).map_err(|error| error.to_string())?;
        let cap = max_per_cell.max(1);
        let mut cells: HashMap<CellKey, Vec<PlaneRecord>> = HashMap::new();
        for (cell_index, raw_cell) in raw.cells.iter().enumerate() {
            let key = raw_cell.key(cell_index)?;
            let mut planes = Vec::with_capacity(raw_cell.planes.len().min(cap));
            for (plane_index, raw_plane) in raw_cell.planes.iter().enumerate() {
                planes.push(raw_plane.validate(cell_index, plane_index)?);
            }
            planes.sort_by_key(|plane| std::cmp::Reverse(plane.priority));
            planes.truncate(cap);
            if planes.is_empty() {
                continue;
            }
            if cells.contains_key(&key) {
                return Err(format!("cells[{cell_index}]: duplicate cell key"));
            }
            cells.insert(key, planes);
        }
        Ok(Self { cells })
    }

    /// Plane records for one cell, if any.
    pub(super) fn planes(&self, key: &CellKey) -> Option<&[PlaneRecord]> {
        self.cells.get(key).map(Vec::as_slice)
    }

    /// Number of cells with at least one plane.
    pub(super) fn cell_count(&self) -> usize {
        self.cells.len()
    }
}

#[derive(Deserialize)]
struct RawFile {
    #[serde(default)]
    cells: Vec<RawCell>,
}

#[derive(Deserialize)]
struct RawCell {
    kind: String,
    #[serde(default)]
    cell: Option<i64>,
    #[serde(default)]
    worldspace: Option<i64>,
    #[serde(default)]
    grid: Option<[i32; 2]>,
    #[serde(default)]
    planes: Vec<RawPlane>,
}

impl RawCell {
    fn key(&self, index: usize) -> Result<CellKey, String> {
        match self.kind.as_str() {
            "interior" => {
                let cell = self
                    .cell
                    .ok_or_else(|| format!("cells[{index}]: interior cell requires `cell`"))?;
                let form_id = u32::try_from(cell)
                    .map_err(|_| format!("cells[{index}]: `cell` out of range"))?;
                if form_id == 0 {
                    return Err(format!("cells[{index}]: `cell` must be nonzero"));
                }
                Ok(CellKey::Interior { form_id })
            }
            "exterior" => {
                let worldspace = self.worldspace.ok_or_else(|| {
                    format!("cells[{index}]: exterior cell requires `worldspace`")
                })?;
                let worldspace = u32::try_from(worldspace)
                    .map_err(|_| format!("cells[{index}]: `worldspace` out of range"))?;
                if worldspace == 0 {
                    return Err(format!("cells[{index}]: `worldspace` must be nonzero"));
                }
                let grid = self
                    .grid
                    .ok_or_else(|| format!("cells[{index}]: exterior cell requires `grid`"))?;
                Ok(CellKey::Exterior {
                    worldspace,
                    x: grid[0],
                    y: grid[1],
                })
            }
            other => Err(format!("cells[{index}]: unknown kind `{other}`")),
        }
    }
}

#[derive(Deserialize)]
struct RawPlane {
    position: [f32; 3],
    /// Full rectangle width and height.
    size: [f32; 2],
    #[serde(default = "default_axis")]
    axis: [f32; 3],
    #[serde(default)]
    angle: f32,
    #[serde(default = "default_priority")]
    priority: u8,
}

fn default_axis() -> [f32; 3] {
    [0.0, 0.0, 1.0]
}

fn default_priority() -> u8 {
    255
}

impl RawPlane {
    fn validate(&self, cell: usize, plane: usize) -> Result<PlaneRecord, String> {
        let location = format!("cells[{cell}].planes[{plane}]");
        if !self.position.iter().all(|value| value.is_finite()) {
            return Err(format!("{location}: position is not finite"));
        }
        if !self.size.iter().all(|value| value.is_finite())
            || self.size[0] <= 0.0
            || self.size[1] <= 0.0
        {
            return Err(format!("{location}: size must be finite and positive"));
        }
        if !self.axis.iter().all(|value| value.is_finite()) {
            return Err(format!("{location}: axis is not finite"));
        }
        if !self.angle.is_finite() {
            return Err(format!("{location}: angle is not finite"));
        }
        let length_squared: f32 = self.axis.iter().map(|value| value * value).sum();
        if length_squared == 0.0 {
            if self.angle != 0.0 {
                return Err(format!("{location}: zero axis requires zero angle"));
            }
        } else if (length_squared - 1.0).abs() > 0.05 {
            return Err(format!("{location}: axis must be unit length or all zero"));
        }
        Ok(PlaneRecord {
            position: self.position,
            size: self.size,
            rotation: PlaneRotation::AxisAngle {
                axis: self.axis,
                angle: self.angle,
            },
            priority: self.priority,
            source_form_id: 0,
        })
    }
}
