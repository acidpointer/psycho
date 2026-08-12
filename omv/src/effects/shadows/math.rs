//! Allocation-free shadow-camera math with D3D9 row-vector conventions.
//!
//! The engine submits camera-relative object transforms. Every matrix produced
//! here therefore consumes camera-relative world positions as well. Absolute
//! camera translation is used only for texel-grid stabilization, matching the
//! NVR contract without exposing large world coordinates to shader math.

use super::contract::{CascadeSplit, NVR_CASCADE_RESOLUTION};

const MIN_VECTOR_LENGTH_SQUARED: f32 = 1.0e-8;
const POINT_NEAR_PLANE: f32 = 0.1;
const SUN_YAW_QUANTUM_RADIANS: f32 = core::f32::consts::PI / 180.0;
const SUN_PITCH_QUANTUM_RADIANS: f32 = core::f32::consts::PI / 720.0;
const SUN_SMOOTHING_FACTOR: f32 = 0.1;
const SUN_SMOOTHING_MAX_ANGLE_RADIANS: f32 = 5.0 * core::f32::consts::PI / 180.0;

/// Stabilize the native sky direction before any cascade consumes it.
///
/// NVR quantizes yaw to one degree and pitch to one quarter degree, then
/// blends small changes by one tenth. Applying the result to the entire map
/// family is important: independently moving the always-current near cascade
/// while distant cascades retain an older direction produces a visible seam.
/// Large discontinuities bypass smoothing so weather or time jumps cannot
/// spend many frames casting shadows from a stale direction.
pub(super) fn stabilize_sun_direction(
    previous: Option<[f32; 3]>,
    current: [f32; 3],
) -> Option<[f32; 3]> {
    let current = normalized(current)?;
    let yaw = current[1].atan2(current[0]);
    let horizontal = (current[0] * current[0] + current[1] * current[1]).sqrt();
    let pitch = current[2].atan2(horizontal);
    let yaw = (yaw / SUN_YAW_QUANTUM_RADIANS).round() * SUN_YAW_QUANTUM_RADIANS;
    let pitch = (pitch / SUN_PITCH_QUANTUM_RADIANS).round() * SUN_PITCH_QUANTUM_RADIANS;
    let quantized = [
        pitch.cos() * yaw.cos(),
        pitch.cos() * yaw.sin(),
        pitch.sin(),
    ];

    let Some(previous) = previous.and_then(normalized) else {
        return Some(quantized);
    };
    let angle = dot3(previous, quantized).clamp(-1.0, 1.0).acos();
    if angle > SUN_SMOOTHING_MAX_ANGLE_RADIANS {
        return Some(quantized);
    }
    normalized(add3(
        scale3(previous, 1.0 - SUN_SMOOTHING_FACTOR),
        scale3(quantized, SUN_SMOOTHING_FACTOR),
    ))
}

/// Pure camera data required to construct directional shadow cascades.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct ShadowCamera {
    /// Native perspective near plane.
    pub(super) near: f32,
    /// Native perspective far plane.
    pub(super) far: f32,
    /// Left frustum slope in camera space.
    pub(super) frustum_left: f32,
    /// Right frustum slope in camera space.
    pub(super) frustum_right: f32,
    /// Bottom frustum slope in camera space.
    pub(super) frustum_bottom: f32,
    /// Top frustum slope in camera space.
    pub(super) frustum_top: f32,
    /// World-space camera-forward unit vector.
    pub(super) forward: [f32; 3],
    /// World-space camera-up unit vector.
    pub(super) up: [f32; 3],
    /// World-space camera-right unit vector.
    pub(super) right: [f32; 3],
    /// Absolute world translation used only by stable texel rounding.
    pub(super) translation: [f32; 3],
    /// NVR tangent-ratio expansion for a narrower-than-default world FOV.
    pub(super) fov_compensation: f32,
}

impl ShadowCamera {
    fn valid(self) -> bool {
        let scalars = [
            self.near,
            self.far,
            self.frustum_left,
            self.frustum_right,
            self.frustum_bottom,
            self.frustum_top,
        ];
        scalars.into_iter().all(f32::is_finite)
            && self.forward.into_iter().all(f32::is_finite)
            && self.up.into_iter().all(f32::is_finite)
            && self.right.into_iter().all(f32::is_finite)
            && self.translation.into_iter().all(f32::is_finite)
            && self.fov_compensation.is_finite()
            && self.fov_compensation >= 1.0
            && self.near >= 0.0
            && self.far > self.near
            && self.frustum_right > self.frustum_left
            && self.frustum_top > self.frustum_bottom
            && normalized(self.forward).is_some()
            && normalized(self.up).is_some()
            && normalized(self.right).is_some()
    }
}

/// Camera-relative bounding sphere used by cascade and cube culling.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Sphere {
    /// Camera-relative center.
    pub(super) center: [f32; 3],
    /// Nonnegative world-space radius.
    pub(super) radius: f32,
}

/// Stable light projection and culling planes for one directional cascade.
#[derive(Clone, Copy, Debug)]
pub(super) struct CascadeProjection {
    /// Camera-relative world-to-light clip transform, in D3D row-major form.
    pub(super) world_to_shadow: [[f32; 4]; 4],
    /// Camera-relative center of the stabilized receiver-coverage sphere.
    pub(super) center: [f32; 3],
    /// Quantized bounding-sphere radius used by the orthographic projection.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) radius: f32,
    /// Unpadded receiver sphere used to decide whether a retained map still
    /// covers the current camera slice.
    pub(super) receiver_radius: f32,
    planes: [[f32; 4]; 6],
}

impl CascadeProjection {
    /// Current camera-slice sphere used only for receiver cascade selection.
    ///
    /// This must not be replaced by the larger cached-map coverage sphere:
    /// doing so pins blend boundaries to an older camera and makes them sweep
    /// across large walls until the map cache refreshes.
    pub(super) const fn receiver_sphere(self) -> [f32; 4] {
        [
            self.center[0],
            self.center[1],
            self.center[2],
            self.receiver_radius,
        ]
    }

    /// Return whether a camera-relative sphere intersects the light frustum.
    pub(super) fn contains(self, sphere: Sphere) -> bool {
        sphere.radius.is_finite()
            && sphere.radius >= 0.0
            && sphere.center.into_iter().all(f32::is_finite)
            && self.planes.iter().all(|plane| {
                dot3([plane[0], plane[1], plane[2]], sphere.center) + plane[3] >= -sphere.radius
            })
    }
}

/// Return the receiver-owned gameplay maps for one animated caster bound.
///
/// Cascade coverage spheres are nested, so treating every geometric
/// intersection as ownership makes a player inside the near map invalidate the
/// middle and far static maps every frame. The consumer always chooses the
/// smallest containing receiver sphere. Match that rule here and add only the
/// adjacent map when the actor overlaps the outer ten-percent blend shell.
/// LOD is deliberately excluded because NVR's LOD profile excludes actors.
pub(super) fn dynamic_caster_cascade_mask(
    projections: [CascadeProjection; 4],
    bound: Sphere,
) -> u8 {
    if !bound.center.into_iter().all(f32::is_finite)
        || !bound.radius.is_finite()
        || bound.radius < 0.0
    {
        return 0b0111;
    }
    for (index, projection) in projections[..3].iter().enumerate() {
        let distance = length3(sub3(bound.center, projection.center));
        if distance - bound.radius <= projection.receiver_radius {
            let mut mask = 1 << index;
            if index < 2 && distance + bound.radius > projection.receiver_radius * 0.9 {
                mask |= 1 << (index + 1);
            }
            return mask;
        }
    }
    0
}

/// View-projection data for one D3D cube-map face.
#[derive(Clone, Copy, Debug)]
pub(super) struct PointCubeView {
    /// Canonical face direction in NVR/D3D face order.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) direction: [f32; 3],
    /// Stable up vector paired with the face direction.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) up: [f32; 3],
    /// Camera-relative world-to-light clip transform.
    pub(super) world_to_shadow: [[f32; 4]; 4],
}

/// Build NVR's four-cascade stable orthographic projection for one slice.
///
/// The slice is bounded by a sphere rounded up to one sixteenth of a world
/// unit. Projection translation is then rounded in shadow-texel space with
/// ties-to-even behavior. The latter matters on long sessions: ordinary
/// half-away rounding alternates differently at exact half texels and causes
/// a visible one-pixel cascade twitch.
pub(super) fn cascade_projection(
    camera: ShadowCamera,
    split: CascadeSplit,
    sun_direction: [f32; 3],
    resolution: u32,
) -> Option<CascadeProjection> {
    if !camera.valid()
        || resolution == 0
        || !split.near.is_finite()
        || !split.far.is_finite()
        || split.near < camera.near
        || split.far <= split.near
        || split.far > camera.far
    {
        return None;
    }
    let sun = normalized(sun_direction)?;
    let forward = normalized(camera.forward)?;
    let up = normalized(camera.up)?;
    let right = normalized(camera.right)?;

    let mut corners = [[0.0; 3]; 8];
    for (plane, distance) in [split.near, split.far].into_iter().enumerate() {
        let horizontal = [camera.frustum_left, camera.frustum_right];
        let vertical = [camera.frustum_top, camera.frustum_bottom];
        for (corner, (x, y)) in [
            (horizontal[0], vertical[0]),
            (horizontal[1], vertical[0]),
            (horizontal[1], vertical[1]),
            (horizontal[0], vertical[1]),
        ]
        .into_iter()
        .enumerate()
        {
            corners[plane * 4 + corner] = add3(
                scale3(forward, distance),
                add3(scale3(right, x * distance), scale3(up, y * distance)),
            );
        }
    }

    let center = scale3(
        corners.into_iter().fold([0.0; 3], add3),
        1.0 / corners.len() as f32,
    );
    let radius = corners
        .into_iter()
        .map(|corner| length3(sub3(corner, center)))
        .fold(0.0_f32, f32::max);
    let receiver_radius = (radius * 16.0).ceil() / 16.0;
    if !receiver_radius.is_finite() || receiver_radius <= 0.0 {
        return None;
    }
    // A small producer guard band lets a cached map remain valid through
    // ordinary camera translation/rotation. Without it, equal-radius receiver
    // and map spheres can never contain one another after any movement, which
    // forces either a full redraw or stale, angle-dependent coverage. NVR's
    // independent tangent-ratio expansion is then applied for aiming/zoom;
    // conflating these two margins made zoom change distant map coverage.
    let radius = receiver_radius * camera.fov_compensation * 1.06;

    // FNV's sky vector points from the scene toward the sun. The light camera
    // therefore sits one cascade radius along that vector and looks back at
    // the slice center. Reversing this sign flips the light-space depth axis
    // and makes the receiver compare against the wrong caster ordering.
    let light_eye = add3(center, scale3(sun, radius));
    let stable_up = if length_squared3(cross3([0.0, 0.0, 1.0], sun)) <= MIN_VECTOR_LENGTH_SQUARED {
        [0.0, 1.0, 0.0]
    } else {
        [0.0, 0.0, 1.0]
    };
    let view = look_at_rh(light_eye, center, stable_up)?;
    let mut projection =
        orthographic_off_center_rh(-radius, radius, -radius, radius, 0.0, radius * 2.0)?;

    // Geometry translations are camera-relative. Projecting the camera-
    // relative location of absolute world origin makes the map grid stable in
    // absolute world space, exactly as NVR's rounding matrix intended.
    let provisional = multiply4(view, projection);
    let origin = transform4(
        [
            -camera.translation[0],
            -camera.translation[1],
            -camera.translation[2],
            1.0,
        ],
        provisional,
    );
    let half_resolution = resolution as f32 * 0.5;
    let shadow_x = origin[0] * half_resolution;
    let shadow_y = origin[1] * half_resolution;
    let offset_x = (bankers_round(shadow_x) - shadow_x) / half_resolution;
    let offset_y = (bankers_round(shadow_y) - shadow_y) / half_resolution;
    projection[3][0] += offset_x;
    projection[3][1] += offset_y;

    let world_to_shadow = multiply4(view, projection);
    let planes = extract_d3d_frustum_planes(world_to_shadow)?;
    Some(CascadeProjection {
        world_to_shadow,
        center,
        radius,
        receiver_radius,
        planes,
    })
}

/// Build all six 90-degree radial-depth cube views in D3D face order.
pub(super) fn point_cube_views(
    light_position: [f32; 3],
    radius: f32,
) -> Option<[PointCubeView; 6]> {
    if !light_position.into_iter().all(f32::is_finite)
        || !radius.is_finite()
        || radius <= POINT_NEAR_PLANE
    {
        return None;
    }
    let faces = [
        ([1.0, 0.0, 0.0], [0.0, 1.0, 0.0]),
        ([-1.0, 0.0, 0.0], [0.0, 1.0, 0.0]),
        ([0.0, 1.0, 0.0], [0.0, 0.0, 1.0]),
        ([0.0, -1.0, 0.0], [0.0, 0.0, -1.0]),
        ([0.0, 0.0, -1.0], [0.0, 1.0, 0.0]),
        ([0.0, 0.0, 1.0], [0.0, 1.0, 0.0]),
    ];
    let projection =
        perspective_fov_rh(core::f32::consts::FRAC_PI_2, 1.0, POINT_NEAR_PLANE, radius)?;
    let mut output = [PointCubeView {
        direction: [0.0; 3],
        up: [0.0; 3],
        world_to_shadow: [[0.0; 4]; 4],
    }; 6];
    for (index, (direction, up)) in faces.into_iter().enumerate() {
        let view = look_at_rh(light_position, add3(light_position, direction), up)?;
        output[index] = PointCubeView {
            direction,
            up,
            world_to_shadow: multiply4(view, projection),
        };
    }
    Some(output)
}

/// Convert an engine `NiTransform` to the row-vector D3D world matrix used by
/// NVR, subtracting the camera origin from translation for float precision.
pub(super) fn camera_relative_world_matrix(
    rotation: [[f32; 3]; 3],
    translation: [f32; 3],
    scale: f32,
    camera_translation: [f32; 3],
) -> Option<[[f32; 4]; 4]> {
    if !rotation.iter().flatten().all(|value| value.is_finite())
        || !translation.into_iter().all(f32::is_finite)
        || !camera_translation.into_iter().all(f32::is_finite)
        || !scale.is_finite()
        || scale <= 0.0
    {
        return None;
    }
    Some([
        [
            rotation[0][0] * scale,
            rotation[1][0] * scale,
            rotation[2][0] * scale,
            0.0,
        ],
        [
            rotation[0][1] * scale,
            rotation[1][1] * scale,
            rotation[2][1] * scale,
            0.0,
        ],
        [
            rotation[0][2] * scale,
            rotation[1][2] * scale,
            rotation[2][2] * scale,
            0.0,
        ],
        [
            translation[0] - camera_translation[0],
            translation[1] - camera_translation[1],
            translation[2] - camera_translation[2],
            1.0,
        ],
    ])
}

fn look_at_rh(eye: [f32; 3], at: [f32; 3], up: [f32; 3]) -> Option<[[f32; 4]; 4]> {
    let z = normalized(sub3(eye, at))?;
    let x = normalized(cross3(up, z))?;
    let y = cross3(z, x);
    Some([
        [x[0], y[0], z[0], 0.0],
        [x[1], y[1], z[1], 0.0],
        [x[2], y[2], z[2], 0.0],
        [-dot3(x, eye), -dot3(y, eye), -dot3(z, eye), 1.0],
    ])
}

fn orthographic_off_center_rh(
    left: f32,
    right: f32,
    bottom: f32,
    top: f32,
    near: f32,
    far: f32,
) -> Option<[[f32; 4]; 4]> {
    let width = right - left;
    let height = top - bottom;
    let depth = near - far;
    if ![left, right, bottom, top, near, far, width, height, depth]
        .into_iter()
        .all(f32::is_finite)
        || width <= 0.0
        || height <= 0.0
        || depth >= 0.0
    {
        return None;
    }
    Some([
        [2.0 / width, 0.0, 0.0, 0.0],
        [0.0, 2.0 / height, 0.0, 0.0],
        [0.0, 0.0, 1.0 / depth, 0.0],
        [
            (left + right) / (left - right),
            (top + bottom) / (bottom - top),
            near / depth,
            1.0,
        ],
    ])
}

fn perspective_fov_rh(fov_y: f32, aspect: f32, near: f32, far: f32) -> Option<[[f32; 4]; 4]> {
    if ![fov_y, aspect, near, far].into_iter().all(f32::is_finite)
        || fov_y <= 0.0
        || fov_y >= core::f32::consts::PI
        || aspect <= 0.0
        || near <= 0.0
        || far <= near
    {
        return None;
    }
    let y = 1.0 / (fov_y * 0.5).tan();
    let x = y / aspect;
    let depth = near - far;
    Some([
        [x, 0.0, 0.0, 0.0],
        [0.0, y, 0.0, 0.0],
        [0.0, 0.0, far / depth, -1.0],
        [0.0, 0.0, near * far / depth, 0.0],
    ])
}

fn extract_d3d_frustum_planes(matrix: [[f32; 4]; 4]) -> Option<[[f32; 4]; 6]> {
    let column = |index: usize| {
        [
            matrix[0][index],
            matrix[1][index],
            matrix[2][index],
            matrix[3][index],
        ]
    };
    let x = column(0);
    let y = column(1);
    let z = column(2);
    let w = column(3);
    let raw = [
        add4(w, x),
        sub4(w, x),
        add4(w, y),
        sub4(w, y),
        z,
        sub4(w, z),
    ];
    let mut planes = [[0.0; 4]; 6];
    for (index, plane) in raw.into_iter().enumerate() {
        let length = length3([plane[0], plane[1], plane[2]]);
        if !length.is_finite() || length <= f32::EPSILON {
            return None;
        }
        planes[index] = plane.map(|value| value / length);
    }
    Some(planes)
}

fn multiply4(left: [[f32; 4]; 4], right: [[f32; 4]; 4]) -> [[f32; 4]; 4] {
    let mut output = [[0.0; 4]; 4];
    for row in 0..4 {
        for column in 0..4 {
            output[row][column] = (0..4)
                .map(|index| left[row][index] * right[index][column])
                .sum();
        }
    }
    output
}

fn transform4(vector: [f32; 4], matrix: [[f32; 4]; 4]) -> [f32; 4] {
    std::array::from_fn(|column| (0..4).map(|row| vector[row] * matrix[row][column]).sum())
}

fn bankers_round(value: f32) -> f32 {
    let floor = value.floor();
    let fraction = value - floor;
    if fraction < 0.5 {
        floor
    } else if fraction > 0.5 || floor.rem_euclid(2.0) != 0.0 {
        floor + 1.0
    } else {
        floor
    }
}

fn normalized(value: [f32; 3]) -> Option<[f32; 3]> {
    let length_squared = length_squared3(value);
    if !length_squared.is_finite() || length_squared <= MIN_VECTOR_LENGTH_SQUARED {
        return None;
    }
    Some(scale3(value, length_squared.sqrt().recip()))
}

fn length3(value: [f32; 3]) -> f32 {
    length_squared3(value).sqrt()
}

fn length_squared3(value: [f32; 3]) -> f32 {
    dot3(value, value)
}

fn dot3(left: [f32; 3], right: [f32; 3]) -> f32 {
    left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
}

fn cross3(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    [
        left[1] * right[2] - left[2] * right[1],
        left[2] * right[0] - left[0] * right[2],
        left[0] * right[1] - left[1] * right[0],
    ]
}

fn add3(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    std::array::from_fn(|index| left[index] + right[index])
}

fn sub3(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    std::array::from_fn(|index| left[index] - right[index])
}

fn scale3(value: [f32; 3], scale: f32) -> [f32; 3] {
    value.map(|component| component * scale)
}

fn add4(left: [f32; 4], right: [f32; 4]) -> [f32; 4] {
    std::array::from_fn(|index| left[index] + right[index])
}

fn sub4(left: [f32; 4], right: [f32; 4]) -> [f32; 4] {
    std::array::from_fn(|index| left[index] - right[index])
}

const _: () = assert!(NVR_CASCADE_RESOLUTION == 2_048);
