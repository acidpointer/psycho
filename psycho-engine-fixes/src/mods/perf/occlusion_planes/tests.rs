//! Pure-logic tests for the override parser and runtime occluder geometry.
//!
//! The engine-calling lifecycle and the live scene walk need the game runtime.
//! These tests cover the override validation, cell-key resolution, per-cell
//! capping, and the world-space AABB face rectangles so a malformed override or
//! a broken box transform cannot reach the engine unnoticed.

use core::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::data::{CellKey, PlaneRecord, PlaneRotation, PlaneSet};
use super::runtime::{native_size, plane_signature, release_plane, retain_plane};
use super::runtime_generate::{
    Aabb, PLANE_SHRINK, WorldTransform, aabb_of, admits_base_type, alpha_is_opaque, faces_from_box,
    transform_aabb,
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

#[test]
fn box_faces_cover_all_six_sides_of_an_eligible_box() {
    let mut faces = Vec::new();
    faces_from_box(&[0.0, 0.0, 0.0], &[1000.0, 500.0, 3000.0], &mut faces);
    assert_eq!(faces.len(), 6);
    // Largest area first cannot be asserted here (the collector sorts), but the
    // +Y faces are the largest at 1000 x 3000.
    let largest = faces.iter().map(|(area, _)| *area).fold(f32::MIN, f32::max);
    assert_eq!(largest, 1000.0 * 3000.0);
}

#[test]
fn box_face_normal_and_size_follow_the_box() {
    let mut faces = Vec::new();
    faces_from_box(
        &[-500.0, -500.0, -500.0],
        &[500.0, 500.0, 500.0],
        &mut faces,
    );
    assert_eq!(faces.len(), 6);
    // Every face is the same size for a cube, and the engine's matrix columns
    // are (tangent, normal, bitangent): local X/Z is the rectangle and local Y
    // is the normal.
    for (_, plane) in &faces {
        assert!((plane.size[0] - 1000.0 * PLANE_SHRINK).abs() < 0.01);
        assert!((plane.size[1] - 1000.0 * PLANE_SHRINK).abs() < 0.01);
        let PlaneRotation::Matrix(matrix) = plane.rotation else {
            panic!("runtime faces use a matrix");
        };
        let tangent = [matrix[0], matrix[3], matrix[6]];
        let normal = [matrix[1], matrix[4], matrix[7]];
        let bitangent = [matrix[2], matrix[5], matrix[8]];
        for axis in [tangent, normal, bitangent] {
            let length = (axis[0] * axis[0] + axis[1] * axis[1] + axis[2] * axis[2]).sqrt();
            assert!((length - 1.0).abs() < 1e-4);
        }
        let dot = |a: [f32; 3], b: [f32; 3]| a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
        assert!(dot(tangent, normal).abs() < 1e-4);
        assert!(dot(tangent, bitangent).abs() < 1e-4);
        assert!(dot(normal, bitangent).abs() < 1e-4);
        // Right-handed: tangent x normal = bitangent.
        let cross = [
            tangent[1] * normal[2] - tangent[2] * normal[1],
            tangent[2] * normal[0] - tangent[0] * normal[2],
            tangent[0] * normal[1] - tangent[1] * normal[0],
        ];
        for index in 0..3 {
            assert!((cross[index] - bitangent[index]).abs() < 1e-4);
        }
    }
}

#[test]
fn native_corners_cover_the_box_face() {
    let min = [0.0f32, 0.0, 0.0];
    let max = [1000.0f32, 500.0, 3000.0];
    let mut faces = Vec::new();
    faces_from_box(&min, &max, &mut faces);
    assert_eq!(faces.len(), 6);
    let extents = [max[0] - min[0], max[1] - min[1], max[2] - min[2]];
    for (_, plane) in &faces {
        let PlaneRotation::Matrix(matrix) = plane.rotation else {
            panic!("runtime faces use a matrix");
        };
        let tangent = [matrix[0], matrix[3], matrix[6]];
        let bitangent = [matrix[2], matrix[5], matrix[8]];
        // The plane center is the box face center pushed two units outward
        // along the geometric face normal.
        let mut axis = 0usize;
        let mut sign = 0.0f32;
        for candidate in 0..3 {
            if plane.position[candidate] > max[candidate] + 1.0 {
                axis = candidate;
                sign = 1.0;
            } else if plane.position[candidate] < min[candidate] - 1.0 {
                axis = candidate;
                sign = -1.0;
            }
        }
        assert!(sign != 0.0, "face center is outside the box");
        let mut normal = [0.0f32; 3];
        normal[axis] = sign;
        let half = native_size(plane.size);
        let in_plane = [(axis + 1) % 3, (axis + 2) % 3];
        let expected = [
            extents[in_plane[0]] * PLANE_SHRINK,
            extents[in_plane[1]] * PLANE_SHRINK,
        ];
        let mut actual = [plane.size[0], plane.size[1]];
        actual
            .as_mut_slice()
            .sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mut expected_sorted = expected;
        expected_sorted
            .as_mut_slice()
            .sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert!((actual[0] - expected_sorted[0]).abs() < 0.01);
        assert!((actual[1] - expected_sorted[1]).abs() < 0.01);
        for sign_a in [-1.0f32, 1.0] {
            for sign_b in [-1.0f32, 1.0] {
                let offset = [
                    sign_a * half[0] * tangent[0] + sign_b * half[1] * bitangent[0],
                    sign_a * half[0] * tangent[1] + sign_b * half[1] * bitangent[1],
                    sign_a * half[0] * tangent[2] + sign_b * half[1] * bitangent[2],
                ];
                let along_normal =
                    offset[0] * normal[0] + offset[1] * normal[1] + offset[2] * normal[2];
                assert!(
                    along_normal.abs() < 0.01,
                    "corner leaves the face plane: {along_normal}"
                );
            }
        }
    }
}

#[test]
fn simd_aabb_matches_scalar_for_every_tail_length() {
    let points: Vec<[f32; 3]> = (0..11)
        .map(|index| {
            let value = index as f32;
            [value * -1.5, value * 0.25 + 3.0, 10.0 - value]
        })
        .collect();
    for count in 0..=points.len() {
        let slice = &points[..count];
        let bounds = aabb_of(slice);
        if count == 0 {
            continue;
        }
        for axis in 0..3 {
            let expected_min = slice.iter().map(|p| p[axis]).fold(f32::INFINITY, f32::min);
            let expected_max = slice
                .iter()
                .map(|p| p[axis])
                .fold(f32::NEG_INFINITY, f32::max);
            assert!((bounds.min[axis] - expected_min).abs() < 1e-5);
            assert!((bounds.max[axis] - expected_max).abs() < 1e-5);
        }
    }
}

#[test]
fn negative_scale_mirrors_the_world_box() {
    let local = Aabb {
        min: [0.0, 0.0, 0.0],
        max: [2.0, 2.0, 2.0],
    };
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [100.0, 0.0, 0.0],
        scale: -1.0,
    };
    let world_box = transform_aabb(&local, &world);
    assert!((world_box.min[0] - 98.0).abs() < 1e-4);
    assert!((world_box.max[0] - 100.0).abs() < 1e-4);
    assert!((world_box.min[1] + 2.0).abs() < 1e-4);
    assert!((world_box.max[1] - 0.0).abs() < 1e-4);
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
        source_form_id: 0,
    };
    let first = [record(1.0)];
    let same = [record(1.0)];
    let moved = [record(2.0)];
    assert_eq!(plane_signature(&first), plane_signature(&same));
    assert_ne!(plane_signature(&first), plane_signature(&moved));
    assert_eq!(plane_signature(&first), plane_signature(&first));
    assert_ne!(plane_signature(&first), plane_signature(&[]));
}

#[test]
fn plane_signature_is_order_independent() {
    let record = |x: f32, id: u32| PlaneRecord {
        position: [x, id as f32, 0.0],
        size: [100.0, 200.0],
        rotation: PlaneRotation::Matrix([1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]),
        priority: 255,
        source_form_id: id,
    };
    let forward = [record(1.0, 1), record(2.0, 2), record(3.0, 3)];
    let mut reversed = forward;
    reversed.reverse();
    // The engine may emit the same planes in a different order after it
    // re-links a cell's reference list; the settle comparison must not treat
    // that as a change or the window runs to exhaustion.
    assert_eq!(plane_signature(&forward), plane_signature(&reversed));

    let moved = [record(1.0, 1), record(2.0, 2), record(9.0, 3)];
    assert_ne!(plane_signature(&forward), plane_signature(&moved));
    let removed = [record(1.0, 1), record(2.0, 2)];
    assert_ne!(plane_signature(&forward), plane_signature(&removed));
}

#[test]
fn small_boxes_produce_no_faces() {
    let mut faces = Vec::new();
    faces_from_box(&[0.0, 0.0, 0.0], &[64.0, 64.0, 64.0], &mut faces);
    assert!(faces.is_empty());
}
