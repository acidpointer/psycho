//! Actual WoodShack01 BlackVoid surface regressions. The complete archived
//! vertex/index input includes zero-area strip connectors; those connectors
//! must neither prove coverage nor change the extracted solid rectangles.

use super::*;

pub(super) fn mesh() -> (Vec<[f32; 3]>, Vec<[u16; 3]>) {
    let bytes = include_bytes!("fixtures/woodshack_blackvoid.bin");
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut offset = 4;
    let vertices = (0..count)
        .map(|_| {
            std::array::from_fn(|_| {
                let value = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                offset += 4;
                value
            })
        })
        .collect();
    let count = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let triangles = (0..count)
        .map(|_| {
            std::array::from_fn(|_| {
                let value = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
                offset += 2;
                value
            })
        })
        .collect();
    assert_eq!(offset, bytes.len());
    (vertices, triangles)
}

#[test]
fn actual_plane_side_policy_changes_reuse_identity() {
    let (vertices, triangles) = mesh();
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [0.0; 3],
        scale: 1.0,
    };
    let mut planes = Vec::new();
    faces_from_oriented_box(
        &aabb_of(&vertices),
        &world,
        &vertices,
        &triangles,
        &mut planes,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut CoverageScratch::default(),
    );
    let mut before = planes[0].1;
    before.coverage = 0.349;
    let mut after = before;
    after.coverage = 0.351;
    assert_ne!(
        super::super::runtime::plane_key(&before),
        super::super::runtime::plane_key(&after),
        "opposite native side policies must not reuse one native plane",
    );
}

#[test]
fn actual_strip_connector_covers_no_point() {
    let (vertices, triangles) = mesh();
    assert_eq!(triangles[6], [23, 23, 23]);
    let vertex = vertices[23];
    for axis in 0..3 {
        let projected = [vertex[(axis + 1) % 3], vertex[(axis + 2) % 3]];
        assert!(!point_in_triangle_2d(
            [0.0; 2], projected, projected, projected
        ));
    }
}

#[test]
fn actual_face_subset_excludes_strip_connectors() {
    let (vertices, triangles) = mesh();
    let mut subset = Vec::new();
    let vertex = vertices[23];
    for axis in 0..3 {
        near_face_triangles_into(&vertices, &triangles, axis, vertex[axis], 4.0, &mut subset);
        assert!(!subset.contains(&triangles[6]));
    }
}

#[test]
fn complete_actual_surface_preserves_rectangles_without_connectors() {
    let (vertices, triangles) = mesh();
    let surface: Vec<_> = triangles
        .iter()
        .copied()
        .filter(|t| t[0] != t[1] && t[1] != t[2] && t[2] != t[0])
        .collect();
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [0.0; 3],
        scale: 1.0,
    };
    let extract = |triangles: &[[u16; 3]]| {
        let mut planes = Vec::new();
        faces_from_oriented_box(
            &aabb_of(&vertices),
            &world,
            &vertices,
            triangles,
            &mut planes,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut Vec::new(),
            &mut CoverageScratch::default(),
        );
        planes
            .into_iter()
            .map(|(_, p)| (p.position, p.size, p.rotation))
            .collect::<Vec<_>>()
    };
    let complete = extract(&triangles);
    assert_eq!(complete.len(), 4);
    assert_eq!(complete, extract(&surface));
}

#[test]
fn actual_owned_snapshot_completes_without_native_memory() {
    let (vertices, triangles) = mesh();
    let local = aabb_of(&vertices);
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [0.0; 3],
        scale: 1.0,
    };
    let mut expected = Vec::new();
    faces_from_oriented_box(
        &local,
        &world,
        &vertices,
        &triangles,
        &mut expected,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut CoverageScratch::default(),
    );
    merge_coplanar(&mut expected);
    let expected = select_planes(expected, None, 128).planes;

    // This is the production Rust-owned capture boundary with the actual
    // archived mesh. No engine allocation, callback or object is substituted.
    let mut generation = Generation::new(128, None);
    generation.done = true;
    generation.stats.refs = 1;
    generation.snapshots.push_back(MeshSnapshot {
        surface: surface_cache::capture(local, &vertices, &triangles)
            .expect("actual mesh fits the existing shared budget"),
        world,
        source_form_id: 0,
        reference: ReferenceIdentity {
            form_id: 0,
            address: 0,
        },
        geometry: 0,
        recorded: false,
        face: 0,
    });
    while !generation.advance(std::time::Instant::now()) {}
    let (planes, _, ready, _) = generation.finish();
    assert!(ready);
    assert_eq!(planes.len(), 4);
    assert_eq!(
        super::super::runtime::plane_signature(&planes),
        super::super::runtime::plane_signature(&expected)
    );
}
