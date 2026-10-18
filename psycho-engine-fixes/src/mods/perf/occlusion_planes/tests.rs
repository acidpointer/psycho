//! Pure-logic tests for the override parser and runtime occluder geometry.
//!
//! The engine-calling lifecycle and the live scene walk need the game runtime.
//! These tests cover the override validation, cell-key resolution, per-cell
//! capping, oriented face generation, vertex-support fitting and the one-sided
//! camera contract so a malformed override or a broken box transform cannot
//! reach the engine unnoticed.

use core::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::data::{CellKey, PlaneRecord, PlaneRotation, PlaneSet};
use super::runtime::{native_size, plane_signature, release_plane, retain_plane};
use super::runtime_generate::{
    Aabb, PLANE_SHRINK, WorldTransform, aabb_of, admits_base_type, alpha_is_opaque,
    faces_from_oriented_box, transform_point,
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

fn identity_world(translation: [f32; 3], scale: f32) -> WorldTransform {
    WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation,
        scale,
    }
}

fn box_vertices(local: &Aabb) -> Vec<[f32; 3]> {
    let mut vertices = Vec::with_capacity(8);
    for corner in 0..8 {
        vertices.push([
            if corner & 1 == 0 {
                local.min[0]
            } else {
                local.max[0]
            },
            if corner & 2 == 0 {
                local.min[1]
            } else {
                local.max[1]
            },
            if corner & 4 == 0 {
                local.min[2]
            } else {
                local.max[2]
            },
        ]);
    }
    vertices
}

fn plane_basis(plane: &PlaneRecord) -> ([f32; 3], [f32; 3], [f32; 3]) {
    let PlaneRotation::Matrix(matrix) = plane.rotation else {
        panic!("runtime faces use a matrix");
    };
    (
        [matrix[0], matrix[3], matrix[6]],
        [matrix[1], matrix[4], matrix[7]],
        [matrix[2], matrix[5], matrix[8]],
    )
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

#[test]
fn vertical_box_faces_are_oriented_and_supported() {
    let local = Aabb {
        min: [-500.0, -500.0, -500.0],
        max: [500.0, 500.0, 500.0],
    };
    let vertices = box_vertices(&local);
    let mut faces = Vec::new();
    let rejects = faces_from_oriented_box(
        &local,
        &identity_world([0.0; 3], 1.0),
        &vertices,
        &mut faces,
    );
    assert_eq!(faces.len(), 4, "only the four vertical faces are emitted");
    assert_eq!(rejects.horizontal, 2, "the floor and ceiling are skipped");
    for (area, plane) in &faces {
        assert!(
            (*area - (1000.0 * PLANE_SHRINK).powi(2)).abs() < 2.0,
            "area={area} size={:?}",
            plane.size
        );
        assert!((plane.size[0] - 1000.0 * PLANE_SHRINK).abs() < 0.01);
        assert!((plane.size[1] - 1000.0 * PLANE_SHRINK).abs() < 0.01);
        let (tangent, normal, bitangent) = plane_basis(plane);
        for axis in [tangent, normal, bitangent] {
            let length = dot(axis, axis).sqrt();
            assert!((length - 1.0).abs() < 1e-4);
        }
        assert!(dot(tangent, normal).abs() < 1e-4);
        assert!(dot(tangent, bitangent).abs() < 1e-4);
        assert!(dot(normal, bitangent).abs() < 1e-4);
        let handed = cross(tangent, normal);
        for index in 0..3 {
            assert!((handed[index] - bitangent[index]).abs() < 1e-4);
        }
        // The emitted center is the box face center pushed outward.
        let face_center = [
            plane.position[0] - normal[0] * 2.0,
            plane.position[1] - normal[1] * 2.0,
            plane.position[2] - normal[2] * 2.0,
        ];
        let on_face = face_center
            .iter()
            .any(|value| (*value - 500.0).abs() < 0.01 || (*value + 500.0).abs() < 0.01);
        assert!(on_face);
    }
}

#[test]
fn rotated_box_faces_follow_the_box_not_the_world_aabb() {
    let local = Aabb {
        min: [-500.0, -250.0, -150.0],
        max: [500.0, 250.0, 150.0],
    };
    let vertices = box_vertices(&local);
    let angle = core::f32::consts::FRAC_PI_4;
    let (sin, cos) = angle.sin_cos();
    let world = WorldTransform {
        // Row-major yaw about +Z.
        rotation: [cos, -sin, 0.0, sin, cos, 0.0, 0.0, 0.0, 1.0],
        translation: [100.0, 200.0, 300.0],
        scale: 1.0,
    };
    let mut faces = Vec::new();
    faces_from_oriented_box(&local, &world, &vertices, &mut faces);
    assert_eq!(faces.len(), 4);

    let centers = [
        [local.min[0], 0.0, 0.0],
        [local.max[0], 0.0, 0.0],
        [0.0, local.min[1], 0.0],
        [0.0, local.max[1], 0.0],
        [0.0, 0.0, local.min[2]],
        [0.0, 0.0, local.max[2]],
    ];
    let world_centers: Vec<[f32; 3]> = centers
        .iter()
        .map(|center| transform_point(&world, center))
        .collect();
    for (_, plane) in &faces {
        let (_, normal, _) = plane_basis(plane);
        assert!(
            normal[2].abs() < 0.01,
            "vertical walls have a horizontal normal"
        );
        assert!(
            normal[0].abs() > 0.5 || normal[1].abs() > 0.5,
            "the face followed the world rotation"
        );
        let face_center = [
            plane.position[0] - normal[0] * 2.0,
            plane.position[1] - normal[1] * 2.0,
            plane.position[2] - normal[2] * 2.0,
        ];
        let matched = world_centers.iter().any(|center| {
            (center[0] - face_center[0]).abs() < 0.01
                && (center[1] - face_center[1]).abs() < 0.01
                && (center[2] - face_center[2]).abs() < 0.01
        });
        assert!(matched, "face center is not on a transformed box face");
    }
}

#[test]
fn faces_without_vertex_support_are_rejected() {
    let local = Aabb {
        min: [-500.0, -500.0, -500.0],
        max: [500.0, 500.0, 500.0],
    };
    let mut faces = Vec::new();
    let rejects = faces_from_oriented_box(&local, &identity_world([0.0; 3], 1.0), &[], &mut faces);
    assert!(faces.is_empty());
    assert!(rejects.unsupported >= 4);

    // A single corner or a line cannot support a solid face either.
    for vertices in [
        vec![[0.0f32, 0.0, 0.0]],
        vec![[-500.0f32, -500.0, -500.0], [500.0, 500.0, 500.0]],
    ] {
        let mut faces = Vec::new();
        faces_from_oriented_box(
            &local,
            &identity_world([0.0; 3], 1.0),
            &vertices,
            &mut faces,
        );
        assert!(faces.is_empty());
    }
}

#[test]
fn horizontal_ground_faces_are_rejected() {
    // A flat floor plate: the two large faces point up and down.
    let floor = Aabb {
        min: [-500.0, -500.0, -10.0],
        max: [500.0, 500.0, 10.0],
    };
    let mut faces = Vec::new();
    let rejects = faces_from_oriented_box(
        &floor,
        &identity_world([0.0; 3], 1.0),
        &box_vertices(&floor),
        &mut faces,
    );
    assert!(faces.is_empty());
    assert_eq!(rejects.horizontal, 2);

    // A vertical wall: the large faces have horizontal normals and survive.
    let wall = Aabb {
        min: [-10.0, -500.0, -500.0],
        max: [10.0, 500.0, 500.0],
    };
    let mut faces = Vec::new();
    faces_from_oriented_box(
        &wall,
        &identity_world([0.0; 3], 1.0),
        &box_vertices(&wall),
        &mut faces,
    );
    assert_eq!(faces.len(), 2);
    for (_, plane) in &faces {
        let (_, normal, _) = plane_basis(plane);
        assert!(normal[2].abs() < 0.01);
    }
}

#[test]
fn negative_scale_mirrors_oriented_faces() {
    let local = Aabb {
        min: [0.0, 0.0, 0.0],
        max: [500.0, 500.0, 500.0],
    };
    let world = identity_world([1000.0, 0.0, 0.0], -1.0);
    let mut faces = Vec::new();
    faces_from_oriented_box(&local, &world, &box_vertices(&local), &mut faces);
    assert_eq!(faces.len(), 4);
    for (_, plane) in &faces {
        let (_, normal, _) = plane_basis(plane);
        let face_center = [
            plane.position[0] - normal[0] * 2.0,
            plane.position[1] - normal[1] * 2.0,
            plane.position[2] - normal[2] * 2.0,
        ];
        // Local x=500 maps to world x=500 with outward -X; local x=0 maps to
        // world x=1000 with outward +X.
        if normal[0] < -0.9 {
            assert!((face_center[0] - 500.0).abs() < 0.01);
        } else if normal[0] > 0.9 {
            assert!((face_center[0] - 1000.0).abs() < 0.01);
        }
        assert!((plane.size[0] - 500.0 * PLANE_SHRINK).abs() < 0.01);
        assert!((plane.size[1] - 500.0 * PLANE_SHRINK).abs() < 0.01);
    }
}

#[test]
fn engine_camera_side_contract_matches_the_outward_normal() {
    // `0x00C35C10` builds p0..p3 in this order:
    //   p0 = position + A + B, p1 = position + A - B,
    //   p2 = position - A - B, p3 = position - A + B
    // where A = sizeX * tangent and B = sizeY * bitangent are the native
    // half-extents. `0x00A699D0` then computes
    //   n = (p0 - p1) x (p2 - p0) = -normal
    // and `0x00C358A0` activates the plane only when the camera is on the
    // negative side of n, which is the rectangle's outward (+normal) side.
    let plane = PlaneRecord {
        position: [0.0, 0.0, 0.0],
        size: [200.0, 200.0],
        rotation: PlaneRotation::Matrix([1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]),
        priority: 255,
        source_form_id: 0,
    };
    let (tangent, normal, bitangent) = plane_basis(&plane);
    let half = native_size(plane.size);
    let a = [
        tangent[0] * half[0],
        tangent[1] * half[0],
        tangent[2] * half[0],
    ];
    let b = [
        bitangent[0] * half[1],
        bitangent[1] * half[1],
        bitangent[2] * half[1],
    ];
    let add = |x: [f32; 3], y: [f32; 3]| [x[0] + y[0], x[1] + y[1], x[2] + y[2]];
    let sub = |x: [f32; 3], y: [f32; 3]| [x[0] - y[0], x[1] - y[1], x[2] - y[2]];
    let p0 = add(add(plane.position, a), b);
    let p1 = sub(add(plane.position, a), b);
    let p2 = sub(sub(plane.position, a), b);
    let engine_normal = cross(sub(p0, p1), sub(p2, p0));
    let length = dot(engine_normal, engine_normal).sqrt();
    let engine_normal = [
        engine_normal[0] / length,
        engine_normal[1] / length,
        engine_normal[2] / length,
    ];
    assert!(dot(engine_normal, normal) < -0.99);

    let outward_camera = [0.0, 100.0, 0.0];
    let inward_camera = [0.0, -100.0, 0.0];
    assert!(dot(engine_normal, sub(outward_camera, p0)) < 0.0);
    assert!(dot(engine_normal, sub(inward_camera, p0)) > 0.0);
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
fn small_boxes_produce_no_faces() {
    let local = Aabb {
        min: [0.0, 0.0, 0.0],
        max: [64.0, 64.0, 64.0],
    };
    let mut faces = Vec::new();
    faces_from_oriented_box(
        &local,
        &identity_world([0.0; 3], 1.0),
        &box_vertices(&local),
        &mut faces,
    );
    assert!(faces.is_empty());
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
