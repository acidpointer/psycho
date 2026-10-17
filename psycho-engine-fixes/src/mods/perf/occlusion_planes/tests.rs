//! Pure-logic tests for the override parser and runtime occluder geometry.
//!
//! The engine-calling lifecycle and the live scene walk need the game runtime.
//! These tests cover the override validation, cell-key resolution, per-cell
//! capping, and the world-space face rectangles so a malformed override or a
//! broken box transform cannot reach the engine unnoticed.

use core::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::data::{CellKey, PlaneRecord, PlaneRotation, PlaneSet};
use super::runtime::{native_size, plane_signature, release_plane, retain_plane};
use super::runtime_generate::{
    ScanStats, WorldTransform, admits_base_type, alpha_is_opaque, mesh_planes, transform_point,
};

static DELETE_THIS_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "thiscall" fn fake_delete_this(_: *mut c_void) {
    DELETE_THIS_CALLS.fetch_add(1, Ordering::SeqCst);
}

#[repr(C)]
struct FakeObject {
    vtable: *const usize,
    refcount: i32,
}

#[test]
fn refcount_path_increments_and_destroys_at_zero() {
    DELETE_THIS_CALLS.store(0, Ordering::SeqCst);
    let vtable: [usize; 2] = [0, fake_delete_this as *const () as usize];
    let mut object = FakeObject {
        vtable: vtable.as_ptr(),
        refcount: 0,
    };
    let pointer = &mut object as *mut FakeObject as *mut c_void;
    unsafe { retain_plane(pointer) };
    assert_eq!(object.refcount, 1);
    unsafe { release_plane(pointer) };
    assert_eq!(object.refcount, 0);
    assert_eq!(DELETE_THIS_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn release_above_zero_does_not_destroy() {
    DELETE_THIS_CALLS.store(0, Ordering::SeqCst);
    let vtable: [usize; 2] = [0, fake_delete_this as *const () as usize];
    let mut object = FakeObject {
        vtable: vtable.as_ptr(),
        refcount: 2,
    };
    let pointer = &mut object as *mut FakeObject as *mut c_void;
    unsafe { release_plane(pointer) };
    assert_eq!(object.refcount, 1);
    assert_eq!(DELETE_THIS_CALLS.load(Ordering::SeqCst), 0);
}

const VALID: &str = r#"
[[cells]]
kind = "exterior"
worldspace = 0x0000003C
grid = [-3, -12]

[[cells.planes]]
position = [1.0, 2.0, 3.0]
size = [100.0, 200.0]
axis = [0.0, 1.0, 0.0]
angle = 1.5707964
priority = 10

[[cells.planes]]
position = [4.0, 5.0, 6.0]
size = [50.0, 60.0]
priority = 200

[[cells]]
kind = "interior"
cell = 0x0003C944

[[cells.planes]]
position = [0.0, 0.0, 0.0]
size = [10.0, 10.0]
"#;

#[test]
fn parses_exterior_and_interior_cells() {
    let set = PlaneSet::parse(VALID, 16).expect("valid data");
    assert_eq!(set.cell_count(), 2);

    let exterior = CellKey::Exterior {
        worldspace: 0x3C,
        x: -3,
        y: -12,
    };
    let planes = set.planes(&exterior).expect("exterior planes");
    assert_eq!(planes.len(), 2);
    assert_eq!(planes[0].priority, 200);
    assert_eq!(planes[1].priority, 10);
    assert_eq!(planes[0].position, [4.0, 5.0, 6.0]);
    assert_eq!(
        planes[0].rotation,
        PlaneRotation::AxisAngle {
            axis: [0.0, 0.0, 1.0],
            angle: 0.0,
        }
    );

    let interior = CellKey::Interior { form_id: 0x3C944 };
    let planes = set.planes(&interior).expect("interior planes");
    assert_eq!(planes.len(), 1);
    assert_eq!(planes[0].priority, 255);
}

#[test]
fn caps_each_cell_by_priority() {
    let set = PlaneSet::parse(VALID, 1).expect("valid data");
    let exterior = CellKey::Exterior {
        worldspace: 0x3C,
        x: -3,
        y: -12,
    };
    let planes = set.planes(&exterior).expect("exterior planes");
    assert_eq!(planes.len(), 1);
    assert_eq!(planes[0].priority, 200);
}

#[test]
fn rejects_missing_cell_identity() {
    let missing = r#"
[[cells]]
kind = "exterior"
grid = [0, 0]
[[cells.planes]]
position = [0.0, 0.0, 0.0]
size = [1.0, 1.0]
"#;
    assert!(PlaneSet::parse(missing, 16).is_err());

    let unknown = r#"
[[cells]]
kind = "void"
cell = 1
"#;
    assert!(PlaneSet::parse(unknown, 16).is_err());

    let duplicate = r#"
[[cells]]
kind = "interior"
cell = 1
[[cells.planes]]
position = [0.0, 0.0, 0.0]
size = [1.0, 1.0]
[[cells]]
kind = "interior"
cell = 1
[[cells.planes]]
position = [0.0, 0.0, 0.0]
size = [1.0, 1.0]
"#;
    assert!(PlaneSet::parse(duplicate, 16).is_err());
}

#[test]
fn rejects_invalid_geometry() {
    let zero_size = r#"
[[cells]]
kind = "interior"
cell = 1
[[cells.planes]]
position = [0.0, 0.0, 0.0]
size = [0.0, 1.0]
"#;
    assert!(PlaneSet::parse(zero_size, 16).is_err());

    let bad_axis = r#"
[[cells]]
kind = "interior"
cell = 1
[[cells.planes]]
position = [0.0, 0.0, 0.0]
size = [1.0, 1.0]
axis = [0.0, 0.0, 0.5]
angle = 1.0
"#;
    assert!(PlaneSet::parse(bad_axis, 16).is_err());
}

/// A flat quad becomes one occluder plane on the quad's plane, and the emitted
/// matrix follows the engine's (tangent, normal, bitangent) convention.
#[test]
fn flat_wall_patch_produces_one_plane() {
    let vertices = [
        [-500.0f32, -250.0, 0.0],
        [500.0, -250.0, 0.0],
        [500.0, 250.0, 0.0],
        [-500.0, 250.0, 0.0],
    ];
    let indices = [0u16, 1, 2, 0, 2, 3];
    let mut out = Vec::new();
    mesh_planes(&vertices, &indices, &mut out, &mut ScanStats::default());
    assert_eq!(out.len(), 1, "one solid wall patch");
    let (area, plane) = &out[0];
    assert!((area - 500_000.0).abs() < 1.0);
    let min = plane.size[0].min(plane.size[1]);
    let max = plane.size[0].max(plane.size[1]);
    assert!((min - 400.0).abs() < 0.5, "500 * 0.8");
    assert!((max - 800.0).abs() < 0.5, "1000 * 0.8");

    let PlaneRotation::Matrix(matrix) = plane.rotation else {
        panic!("runtime planes use a matrix");
    };
    let tangent = [matrix[0], matrix[3], matrix[6]];
    let normal = [matrix[1], matrix[4], matrix[7]];
    let bitangent = [matrix[2], matrix[5], matrix[8]];
    let dot = |a: [f32; 3], b: [f32; 3]| a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
    for axis in [tangent, normal, bitangent] {
        let length = (axis[0] * axis[0] + axis[1] * axis[1] + axis[2] * axis[2]).sqrt();
        assert!((length - 1.0).abs() < 1e-4);
    }
    assert!(dot(tangent, normal).abs() < 1e-4);
    assert!(dot(tangent, bitangent).abs() < 1e-4);
    assert!(dot(normal, bitangent).abs() < 1e-4);
    let cross = [
        tangent[1] * normal[2] - tangent[2] * normal[1],
        tangent[2] * normal[0] - tangent[0] * normal[2],
        tangent[0] * normal[1] - tangent[1] * normal[0],
    ];
    for index in 0..3 {
        assert!((cross[index] - bitangent[index]).abs() < 1e-4);
    }
    assert!(
        (normal[2].abs() - 1.0).abs() < 1e-3,
        "wall is in the z=0 plane"
    );
    // Engine corner formula: corners are position +/- halfX*col0 +/- halfY*col2,
    // so every corner stays in the rectangle's plane.
    let half = native_size(plane.size);
    for sign_a in [-1.0f32, 1.0] {
        for sign_b in [-1.0f32, 1.0] {
            let offset = [
                sign_a * half[0] * tangent[0] + sign_b * half[1] * bitangent[0],
                sign_a * half[0] * tangent[1] + sign_b * half[1] * bitangent[1],
                sign_a * half[0] * tangent[2] + sign_b * half[1] * bitangent[2],
            ];
            assert!(dot(offset, normal).abs() < 0.01);
        }
    }
}

/// A wall in the XZ plane is extracted with its rotated normal; the old
/// axis-aligned bounding-box approach could not represent this correctly.
#[test]
fn rotated_wall_patch_is_extracted() {
    let vertices = [
        [-500.0f32, 0.0, -250.0],
        [500.0, 0.0, -250.0],
        [500.0, 0.0, 250.0],
        [-500.0, 0.0, 250.0],
    ];
    let indices = [0u16, 1, 2, 0, 2, 3];
    let mut out = Vec::new();
    mesh_planes(&vertices, &indices, &mut out, &mut ScanStats::default());
    assert_eq!(out.len(), 1);
    let PlaneRotation::Matrix(matrix) = out[0].1.rotation else {
        panic!("runtime planes use a matrix");
    };
    let normal = [matrix[1], matrix[4], matrix[7]];
    assert!((normal[1].abs() - 1.0).abs() < 1e-3, "wall normal is +/-Y");
}

/// A large opening splits the patch; the emitted plane covers a solid
/// sub-rectangle instead of the empty slot.
#[test]
fn opening_reduces_the_emitted_rectangle() {
    let vertices = [
        [-500.0f32, 100.0, 0.0],
        [500.0, 100.0, 0.0],
        [500.0, 500.0, 0.0],
        [-500.0, 500.0, 0.0],
        [-500.0, -500.0, 0.0],
        [500.0, -500.0, 0.0],
        [500.0, -100.0, 0.0],
        [-500.0, -100.0, 0.0],
    ];
    let indices = [0u16, 1, 2, 0, 2, 3, 4, 5, 6, 4, 6, 7];
    let mut out = Vec::new();
    mesh_planes(&vertices, &indices, &mut out, &mut ScanStats::default());
    assert_eq!(out.len(), 1);
    let min = out[0].1.size[0].min(out[0].1.size[1]);
    assert!(min < 400.0, "the slot shrinks the solid rectangle: {min}");
}

#[test]
fn small_patch_produces_no_plane() {
    let vertices = [
        [-32.0f32, -32.0, 0.0],
        [32.0, -32.0, 0.0],
        [32.0, 32.0, 0.0],
        [-32.0, 32.0, 0.0],
    ];
    let indices = [0u16, 1, 2, 0, 2, 3];
    let mut out = Vec::new();
    mesh_planes(&vertices, &indices, &mut out, &mut ScanStats::default());
    assert!(out.is_empty());
}

#[test]
fn negative_scale_mirrors_transform_point() {
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [100.0, 0.0, 0.0],
        scale: -1.0,
    };
    let point = transform_point([2.0, 0.0, 0.0], &world);
    assert!((point[0] - 98.0).abs() < 1e-4);
    assert!(point[1].abs() < 1e-4);
}

#[test]
fn alpha_flags_gate_transparent_geometry() {
    assert!(alpha_is_opaque(None));
    assert!(alpha_is_opaque(Some(0)));
    // ALPHA_BLEND = 0x0001, ALPHA_TEST = 0x0200.
    assert!(!alpha_is_opaque(Some(0x0001)));
    assert!(!alpha_is_opaque(Some(0x0200)));
    assert!(!alpha_is_opaque(Some(0x0201)));
    assert!(alpha_is_opaque(Some(0x0002)));
}

#[test]
fn base_type_admission_covers_static_content() {
    assert!(admits_base_type(0x20)); // TESObjectSTAT
    assert!(admits_base_type(0x21)); // BGSStaticCollection
    assert!(!admits_base_type(0x22)); // BGSMovableStatic (can move)
    assert!(!admits_base_type(0x2A)); // TESNPC
    assert!(!admits_base_type(0x00));
}

#[test]
fn plane_signature_changes_with_the_set() {
    let record = |x: f32| PlaneRecord {
        position: [x, 0.0, 0.0],
        size: [100.0, 200.0],
        rotation: PlaneRotation::Matrix([1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]),
        priority: 255,
    };
    let first = [record(1.0)];
    let same = [record(1.0)];
    let moved = [record(2.0)];
    assert_eq!(plane_signature(&first), plane_signature(&same));
    assert_ne!(plane_signature(&first), plane_signature(&moved));
    assert_eq!(plane_signature(&first), plane_signature(&first));
    assert_ne!(plane_signature(&first), plane_signature(&[]));
}
