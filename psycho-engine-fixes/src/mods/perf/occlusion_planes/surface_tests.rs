//! Actual WoodShack01 BlackVoid surface regressions. The complete archived
//! vertex/index input includes zero-area strip connectors; those connectors
//! must neither prove coverage nor change the extracted solid rectangles.

use super::*;

pub(super) fn mesh() -> (Vec<[f32; 3]>, Vec<[u16; 3]>) {
    mesh_input(include_bytes!("fixtures/woodshack_blackvoid.bin"))
}

fn mesh_input(bytes: &[u8]) -> (Vec<[f32; 3]>, Vec<[u16; 3]>) {
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
fn actual_finite_bounds_preserve_bits_for_all_tails() {
    let (mut vertices, _) = mesh();
    for special in [0.0, -0.0, f32::from_bits(1), -f32::MAX, f32::MAX] {
        vertices[0] = [special; 3];
        for count in 0..=vertices.len() {
            let before = aabb_of(&vertices[..count]);
            let after = finite_aabb_of(&vertices[..count]);
            assert_eq!(before.min.map(f32::to_bits), after.min.map(f32::to_bits));
            assert_eq!(before.max.map(f32::to_bits), after.max.map(f32::to_bits));
        }
    }
}

#[test]
fn actual_orientation_matches_independent_rational_asset_oracle() {
    let bytes = include_bytes!("fixtures/orientation_cases.bin");
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 4 + count * 49);
    for record in bytes[4..].chunks_exact(49) {
        let p: [[f32; 3]; 4] = std::array::from_fn(|i| {
            std::array::from_fn(|j| {
                let offset = (i * 3 + j) * 4;
                f32::from_le_bytes(record[offset..offset + 4].try_into().unwrap())
            })
        });
        assert_eq!(
            super::super::exact::orient(p[0], p[1], p[2], p[3]),
            Some(record[48] as i8)
        );
    }
    let (vertices, _) = mesh();
    let mut invalid = vertices[0];
    invalid[0] = f32::NAN;
    assert_eq!(
        super::super::exact::orient(invalid, vertices[1], vertices[2], vertices[3]),
        None
    );
}

fn rock_plane() -> (
    PlaneRecord,
    projected::Patch,
    Vec<[f32; 3]>,
    Vec<[u16; 3]>,
    WorldTransform,
    [f32; 3],
) {
    let (vertices, triangles) = mesh_input(include_bytes!("fixtures/rockwasteland07.bin"));
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [0.0; 3],
        scale: 1.0,
    };
    let local = finite_aabb_of(&vertices);
    let mut camera = local.center();
    camera[0] += local.extents().into_iter().fold(0.0f32, f32::max) * 2.0;
    let mut legacy = Vec::new();
    faces_from_oriented_box(
        &local,
        &world,
        &vertices,
        &triangles,
        &mut legacy,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut CoverageScratch::default(),
    );
    assert!(
        legacy.is_empty(),
        "actual rock demonstrates the six-face coverage gap"
    );
    let mut scratch = ProjectedScratch::default();
    let mut edges = Vec::new();
    let mut work = ProjectedWork::new(&mut scratch, &mut edges, vertices.len(), triangles.len());
    while !work.advance(
        &vertices,
        &triangles,
        &world,
        camera,
        Sides::Both,
        &mut scratch,
        &mut edges,
        64,
    ) {}
    (
        work.best
            .expect("actual rock has certified additional coverage"),
        work.source.unwrap(),
        vertices,
        triangles,
        world,
        camera,
    )
}

#[test]
fn actual_rock_generates_scoped_planes_and_rejects_expired_cameras() {
    let (mut plane, patch, vertices, triangles, world, camera) = rock_plane();
    assert!(projected::patch_supported(
        &plane,
        &patch,
        &vertices,
        &triangles,
        &world,
        camera,
        Sides::Both
    ));
    let front = projected::patch_supported(
        &plane,
        &patch,
        &vertices,
        &triangles,
        &world,
        camera,
        Sides::from_flags(0x4180),
    );
    let back = projected::patch_supported(
        &plane,
        &patch,
        &vertices,
        &triangles,
        &world,
        camera,
        Sides::from_flags(0x4980),
    );
    assert_ne!(
        front, back,
        "opposite source cull modes cannot admit the same patch side"
    );
    assert!(!projected::patch_supported(
        &plane,
        &patch,
        &vertices,
        &triangles,
        &world,
        camera,
        Sides::from_flags(0x4181)
    ));
    let bounds = plane.camera.as_mut().unwrap();
    bounds.epoch = 7;
    use super::super::camera_guard::filter;
    assert_eq!(filter(0x80, bounds, 7, camera), 0x80);
    assert_eq!(filter(0, bounds, 7, camera), 0);
    assert_eq!(filter(1, bounds, 8, camera), 0);
    let behind = plane.position;
    assert_eq!(filter(1, bounds, 7, behind), 0);
    assert_eq!(filter(1, bounds, 7, [f32::NAN; 3]), 0);

    // The actual production owned scheduler, starting at its captured-data
    // boundary. Native engine objects and calls are never substituted.
    let mut generation = Generation::new(128, Some(camera));
    generation.camera = Some((camera, 7));
    generation.done = true;
    generation.stats.refs = 1;
    generation.snapshots.push_back(MeshSnapshot {
        surface: surface_cache::capture(finite_aabb_of(&vertices), &vertices, &triangles).unwrap(),
        world,
        source_form_id: 0,
        reference: ReferenceIdentity {
            form_id: 0,
            address: 0,
        },
        geometry: 0,
        recorded: true,
        face: 0,
        produced: false,
        sides: Sides::Both,
    });
    let expired = std::time::Instant::now() - std::time::Duration::from_millis(10);
    assert!(!generation.advance(expired));
    while !generation.advance(std::time::Instant::now()) {}
    let (output, _, ready, _) = generation.finish();
    assert!(ready);
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].identity(), plane.identity());
}

#[test]
fn actual_scoped_output_cannot_merge_or_displace_legacy_under_the_cap() {
    let (plane, _, _, _, _, _) = rock_plane();
    let (vertices, triangles) = mesh();
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [0.0; 3],
        scale: 1.0,
    };
    let mut legacy = Vec::new();
    faces_from_oriented_box(
        &finite_aabb_of(&vertices),
        &world,
        &vertices,
        &triangles,
        &mut legacy,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut CoverageScratch::default(),
    );
    merge_coplanar(&mut legacy);
    let expected = select_planes(legacy.clone(), None, 2).planes;
    let mut candidates = vec![(plane.size[0] * plane.size[1], plane)];
    candidates.extend(legacy);
    merge_coplanar(&mut candidates);
    assert_eq!(
        candidates
            .iter()
            .filter(|(_, p)| p.camera.is_some())
            .count(),
        1
    );
    let output = select_planes(candidates, None, 2).planes;
    assert_eq!(
        super::super::runtime::plane_signature(&output),
        super::super::runtime::plane_signature(&expected)
    );
}

#[test]
#[cfg(target_arch = "x86")]
fn actual_numeric_kernels_preserve_caller_modes_and_exact_admission() {
    struct Restore(u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restore the valid MXCSR value saved on this same thread.
            unsafe {
                core::arch::asm!("ldmxcsr [{}]",in(reg)&self.0,options(nostack,preserves_flags));
            }
        }
    }
    let (plane, patch, vertices, triangles, world, camera) = rock_plane();
    let oracle = include_bytes!("fixtures/orientation_cases.bin");
    let conversions: Vec<_> = oracle[4..]
        .chunks_exact(49)
        .flat_map(|record| {
            record[..48].chunks_exact(4).map(|b| {
                let bits = u32::from_le_bytes(b.try_into().unwrap());
                let value = f32::from_bits(bits);
                (bits, f64::from(value).to_bits())
            })
        })
        .collect();
    let mut saved = 0u32;
    // SAFETY: SSE2 is a supported-target baseline; these stack words are valid
    // four-byte operands. Only this test thread's control state is affected.
    unsafe {
        core::arch::asm!("stmxcsr [{}]",in(reg)&mut saved,options(nostack,preserves_flags));
    }
    let restore = Restore(saved);
    let mut identities_preserved = true;
    for rounding in 0..4 {
        for denormals in 0..4 {
            let control = (saved & !0xE07F)
                | 0x1F80
                | (rounding << 13)
                | ((denormals & 1) << 6)
                | ((denormals >> 1) << 15);
            unsafe {
                core::arch::asm!("ldmxcsr [{}]",in(reg)&control,options(nostack,preserves_flags));
            }
            actual_finite_bounds_preserve_bits_for_all_tails();
            actual_triangle_simd_matches_scalar_edges_and_offsets();
            actual_orientation_matches_independent_rational_asset_oracle();
            for &(bits, double) in &conversions {
                assert_eq!(
                    envelope::conversion_probe(f32::from_bits(bits)),
                    (double, bits, bits)
                );
            }
            assert!(projected::patch_supported(
                &plane,
                &patch,
                &vertices,
                &triangles,
                &world,
                camera,
                Sides::Both
            ));
            let subnormal = super::super::data::CameraBounds::new(
                [f32::from_bits(1); 3],
                [f32::from_bits(3); 3],
            )
            .unwrap();
            assert!(subnormal.contains([f32::from_bits(2); 3]));
            assert!(!subnormal.contains([0.0; 3]));
            let mut changed_plane = plane;
            let index = plane
                .rotation
                .iter()
                .position(|v| v.to_bits() & 0x7fffffff == 0)
                .unwrap();
            changed_plane.rotation[index] = std::hint::black_box(f32::from_bits(1));
            let mut changed_world = world;
            let index = world
                .rotation
                .iter()
                .position(|v| v.to_bits() & 0x7fffffff == 0)
                .unwrap();
            changed_world.rotation[index] = std::hint::black_box(f32::from_bits(1));
            identities_preserved &= changed_plane.identity() != plane.identity();
            identities_preserved &= changed_world.identity() != world.identity();
        }
    }
    drop(restore);
    assert!(
        identities_preserved,
        "DAZ must not erase subnormal descriptor bits"
    );
    let mut after = 0u32;
    unsafe {
        core::arch::asm!("stmxcsr [{}]",in(reg)&mut after,options(nostack,preserves_flags));
    }
    assert_eq!(after, saved);
}

#[test]
fn actual_triangle_simd_matches_scalar_edges_and_offsets() {
    let (vertices, triangles) = mesh();
    for axis in 0..3 {
        for t in &triangles {
            let points = t.map(|i| {
                [
                    vertices[i as usize][(axis + 1) % 3],
                    vertices[i as usize][(axis + 2) % 3],
                ]
            });
            for offset in [0.0, 1.0, -1.0, f32::MIN_POSITIVE] {
                let [a, b, c] = points;
                let samples = [a, b, c, [(a[0] + b[0]) * 0.5, (a[1] + b[1]) * 0.5]];
                let x = f32x4::new(samples.map(|p| p[0] + offset));
                let y = f32x4::new(samples.map(|p| p[1] - offset));
                let expected = samples.iter().enumerate().fold(0, |bits, (i, p)| {
                    bits | (u32::from(point_in_triangle_2d(
                        [p[0] + offset, p[1] - offset],
                        a,
                        b,
                        c,
                    )) << i)
                });
                assert_eq!(coverage_work::triangle_mask(x, y, a, b, c), expected);
            }
        }
    }
}

#[test]
fn actual_local_faces_complete_across_single_operation_advances() {
    let (vertices, triangles) = mesh();
    let local = finite_aabb_of(&vertices);
    for face in 0..6 {
        let mut scratch = CoverageScratch::default();
        let mut work = LocalFaceWork::new(
            &local,
            &vertices,
            face,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut Vec::new(),
            &mut scratch,
        );
        let mut advances = 1;
        while !work.advance(&vertices, &triangles, &mut scratch, 1) {
            advances += 1;
        }
        let expected = local_face(
            &local,
            &vertices,
            &triangles,
            face,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut Vec::new(),
            &mut CoverageScratch::default(),
        );
        match (work.result, expected) {
            (
                LocalFace::Rectangle {
                    center_u,
                    center_v,
                    half_u,
                    half_v,
                    coverage,
                },
                LocalFace::Rectangle {
                    center_u: u,
                    center_v: v,
                    half_u: hu,
                    half_v: hv,
                    coverage: c,
                },
            ) => {
                assert_eq!(
                    [center_u, center_v, half_u, half_v, coverage].map(f32::to_bits),
                    [u, v, hu, hv, c].map(f32::to_bits)
                );
                assert!(advances > 1);
            }
            (LocalFace::Opening, LocalFace::Opening)
            | (LocalFace::Unsupported, LocalFace::Unsupported) => {}
            _ => panic!("slicing changed an actual face result"),
        }
    }
}

/// Physical complete NIF geometry inputs. These are independent local meshes,
/// not an invented cell population or a reconstruction of runtime materials.
#[test]
#[ignore = "inspect supplied complete rock/cliff geometry with production extraction"]
fn natural_asset_extraction() {
    use std::io::{Cursor, Read};
    let bytes = std::fs::read(
        std::env::var("PSYCHO_OCCLUSION_NATURAL").expect("supplied natural mesh corpus"),
    )
    .unwrap();
    let mut input = Cursor::new(bytes.as_slice());
    fn u32_input(input: &mut Cursor<&[u8]>) -> u32 {
        let mut b = [0; 4];
        input.read_exact(&mut b).unwrap();
        u32::from_le_bytes(b)
    }
    let count = u32_input(&mut input);
    let world = WorldTransform {
        rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        translation: [0.0; 3],
        scale: 1.0,
    };
    let mut total = 0;
    let mut recovered = 0;
    let mut scoped = 0;
    let sides = if std::env::var("PSYCHO_OCCLUSION_NATURAL_SIDES").as_deref() == Ok("front") {
        Sides::Front
    } else {
        Sides::Both
    };
    let mut slices = Vec::new();
    let started = std::time::Instant::now();
    for index in 0..count {
        let vc = u32_input(&mut input) as usize;
        let tc = u32_input(&mut input) as usize;
        let vertices: Vec<[f32; 3]> = (0..vc)
            .map(|_| std::array::from_fn(|_| f32::from_bits(u32_input(&mut input))))
            .collect();
        let triangles: Vec<[u16; 3]> = (0..tc)
            .map(|_| {
                std::array::from_fn(|_| {
                    let mut b = [0; 2];
                    input.read_exact(&mut b).unwrap();
                    u16::from_le_bytes(b)
                })
            })
            .collect();
        let local = finite_aabb_of(&vertices);
        let mut planes = Vec::new();
        if local.is_eligible(1.0) {
            faces_from_oriented_box(
                &local,
                &world,
                &vertices,
                &triangles,
                &mut planes,
                &mut Vec::new(),
                &mut Vec::new(),
                &mut Vec::new(),
                &mut CoverageScratch::default(),
            );
        }
        println!(
            "natural index={index} vertices={vc} triangles={tc} eligible={} legacy_planes={} extents={:?}",
            local.is_eligible(1.0),
            planes.len(),
            local.extents()
        );
        total += planes.len();
        if planes.is_empty() && local.is_eligible(1.0) {
            let mut found = false;
            let extent = local.extents().into_iter().fold(0.0f32, f32::max);
            for axis in 0..3 {
                for direction in [-1.0, 1.0] {
                    let mut camera = local.center();
                    camera[axis] += direction * extent * 2.0;
                    let mut scratch = ProjectedScratch::default();
                    let mut edges = Vec::new();
                    let mut work = ProjectedWork::new(
                        &mut scratch,
                        &mut edges,
                        vertices.len(),
                        triangles.len(),
                    );
                    loop {
                        let slice = std::time::Instant::now();
                        let done = work.advance(
                            &vertices,
                            &triangles,
                            &world,
                            camera,
                            sides,
                            &mut scratch,
                            &mut edges,
                            64,
                        );
                        slices.push(slice.elapsed().as_secs_f64() * 1e6);
                        if done {
                            break;
                        }
                    }
                    if let Some(plane) = work.best {
                        assert!(plane.camera.unwrap().contains(camera));
                        assert!(projected::patch_supported(
                            &plane,
                            &work.source.unwrap(),
                            &vertices,
                            &triangles,
                            &world,
                            camera,
                            sides
                        ));
                        scoped += 1;
                        found = true;
                        println!(
                            "projected index={index} axis={axis} direction={direction} size={:?} domain={:?}",
                            plane.size, plane.camera
                        );
                    }
                }
            }
            recovered += usize::from(found);
        }
    }
    assert_eq!(input.position() as usize, bytes.len());
    slices.sort_by(f64::total_cmp);
    println!(
        "projected slices={} p99_us={:.3} max_us={:.3} sides={sides:?}",
        slices.len(),
        slices[(slices.len() - 1) * 99 / 100],
        slices[slices.len() - 1]
    );
    println!("natural meshes={count} legacy_planes={total}");
    println!(
        "natural recovered_meshes={recovered} scoped_viewpoints={scoped} elapsed_ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.0
    );
    assert!(
        recovered > 0,
        "fallback must recover actual zero-output natural meshes"
    );
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

        produced: false,
        sides: Sides::Unknown,
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

#[test]
fn actual_owned_snapshot_respects_expired_frame_budget() {
    let (vertices, triangles) = mesh();
    let local = aabb_of(&vertices);
    let mut generation = Generation::new(128, None);
    generation.done = true;
    generation.stats.refs = 1;
    generation.snapshots.push_back(MeshSnapshot {
        surface: surface_cache::capture(local, &vertices, &triangles).unwrap(),
        world: WorldTransform {
            rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            translation: [0.0; 3],
            scale: 1.0,
        },
        source_form_id: 0,
        reference: ReferenceIdentity {
            form_id: 0,
            address: 0,
        },
        geometry: 0,
        recorded: false,
        face: 0,

        produced: false,
        sides: Sides::Unknown,
    });
    // The real monotonic frame clock says native acquisition already spent the
    // budget. Owned coverage must wait for a fresh frame, without discarding it.
    let expired = std::time::Instant::now() - std::time::Duration::from_millis(10);
    assert!(!generation.advance(expired));
    assert_eq!(
        generation.snapshots.front().unwrap().face,
        0,
        "an expired frame must not start another face"
    );
    assert!(generation.candidates.is_empty());
    while !generation.advance(std::time::Instant::now()) {}
    let (planes, _, ready, _) = generation.finish();
    assert!(ready);
    assert_eq!(planes.len(), 4);
}

#[test]
fn actual_limited_snapshot_retains_coverage_without_full_completeness() {
    let (vertices, triangles) = mesh();
    let local = aabb_of(&vertices);
    let mut generation = Generation::new(128, None);
    generation.done = true;
    generation.stats.refs = 1;
    // Native capture records this when a hard shared input limit stops a scan.
    // This admitted actual surface remains usable; the result is not complete.
    generation.stats.budget_stop = 1;
    generation.snapshots.push_back(MeshSnapshot {
        surface: surface_cache::capture(local, &vertices, &triangles).unwrap(),
        world: WorldTransform {
            rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            translation: [0.0; 3],
            scale: 1.0,
        },
        source_form_id: 0,
        reference: ReferenceIdentity {
            form_id: 0,
            address: 0,
        },
        geometry: 0,
        recorded: false,
        face: 0,

        produced: false,
        sides: Sides::Unknown,
    });
    assert!(!generation.source_pending());
    while !generation.advance(std::time::Instant::now()) {}
    let (planes, _, ready, _) = generation.finish();
    assert!(!ready);
    assert_eq!(planes.len(), 4);
}
