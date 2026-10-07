//! Render-thread snapshot of the authored native solar emitter.
//!
//! Sun::Create (0x00640810) owns distinct disk/glare shapes at +0x10/+0x14.
//! Only the disk is read here. Its four vertices, UVs, world transform, shade
//! texture and visibility define coverage; no screen or angular radius is
//! invented. The texture is retained for the consuming draw and released by
//! RAII. Missing, nonfinite, non-planar or singular input has no emitter.
//! Reads use the backend's epoch-cached range validation. This module has no
//! static owner, startup work, hook, Rust allocation or engine mutation.

use libpsycho::os::windows::directx9::{Device9Ref, Direct3DResult, Texture9};

use super::{
    CameraFrame, NIAVOBJECT_WORLD_ROTATION_OFFSET, NIAVOBJECT_WORLD_SCALE_OFFSET,
    NIAVOBJECT_WORLD_TRANSLATION_OFFSET, SKY_SINGLETON_PTR, SKY_SUN_OFFSET, read_prevalidated,
    read_prevalidated_ptr, read_prevalidated_vec3, read_ptr, validate_object,
};

/// Owned texture and projective UV maps for one serialized native world draw.
/// The last denominator component carries the authored disk visibility.
pub(crate) struct NativeSunDisk {
    texture: Texture9,
    pub(crate) screen_to_texture: [[f32; 4]; 3],
}

impl NativeSunDisk {
    /// Bind the retained native 2D texture to an already configured sampler.
    /// The caller owns sampler state and must unbind before resource teardown.
    pub(crate) fn bind(&self, device: &Device9Ref<'_>, sampler: u32) -> Direct3DResult<()> {
        device.set_texture(sampler, &self.texture)
    }
}

/// Resolve actual disk coverage on the serialized post-Deferred render thread.
/// Returns `None` for unavailable native data or an unsupported geometry
/// contract. Does not initialize native sky or change engine ownership.
pub(crate) fn native_sun_disk(camera: CameraFrame) -> Option<NativeSunDisk> {
    if !camera.available || !camera.world_transform.available {
        return None;
    }
    // SAFETY: Sky and its Sun retain these objects across the serialized world
    // draw. Each range is checked before unaligned reads. No pointer is retained
    // after this call except the texture, whose COM reference is acquired while
    // its native NiTexture owner is still live. Reset/teardown cannot interleave
    // with this render-thread callback. Layout proof is in the native-sky doc.
    unsafe { read_disk(camera) }
}

unsafe fn read_disk(camera: CameraFrame) -> Option<NativeSunDisk> {
    let sky = unsafe { read_ptr(SKY_SINGLETON_PTR)? };
    unsafe { validate_object(sky, SKY_SUN_OFFSET + 4)? };
    let sun = unsafe { read_prevalidated_ptr(sky, SKY_SUN_OFFSET) };
    unsafe { validate_object(sun, 0x14)? };
    let geometry = unsafe { read_prevalidated_ptr(sun, 0x10) };
    unsafe { validate_object(geometry, 0xC4)? };
    let model = unsafe { read_prevalidated_ptr(geometry, 0xB8) };
    let shade = unsafe { read_prevalidated_ptr(geometry, 0xA8) };
    unsafe { validate_object(model, 0x40)? };
    unsafe { validate_object(shade, 0x90)? };
    if unsafe { read_prevalidated::<u16>(model, 8) } != 4
        || unsafe { read_prevalidated::<u32>(shade, 0x8C) } != 0
    {
        return None;
    }
    let vertices = unsafe { read_prevalidated_ptr(model, 0x20) };
    let colors = unsafe { read_prevalidated_ptr(model, 0x28) };
    let uvs = unsafe { read_prevalidated_ptr(model, 0x2C) };
    unsafe { validate_object(vertices, 4 * 12)? };
    unsafe { validate_object(colors, 4 * 16)? };
    unsafe { validate_object(uvs, 4 * 8)? };
    // Create writes the same RGBA to all four vertices; the celestial VS
    // multiplies its alpha by the property's visibility. Preserve that alpha.
    // Varying per-vertex opacity requires a separate triangle interpolation
    // contract rather than silently replacing it with one scalar.
    let vertex_alpha = unsafe { read_prevalidated::<f32>(colors, 12) };
    if !vertex_alpha.is_finite()
        || !(0.0..=1.0).contains(&vertex_alpha)
        || (1..4).any(
            |index| unsafe { read_prevalidated::<f32>(colors, index * 16 + 12) } != vertex_alpha,
        )
    {
        return None;
    }
    // UpdateConstants uses the published sky camera only when the renderer's
    // camera-relative flag is set. Its subsequent current-camera addition
    // cancels the view translation. Otherwise ordinary view translation applies.
    // NiRenderer::GetRenderer (0x00B4F5D0) reads this exact singleton.
    let sky_renderer = unsafe { read_ptr(0x011F95F0)? };
    unsafe { validate_object(sky_renderer, 0x165)? };
    let origin = if unsafe { read_prevalidated::<u8>(sky_renderer, 0x164) } != 0 {
        let sky_camera = unsafe { read_ptr(0x011F95D8)? };
        unsafe { validate_object(sky_camera, 0x98)? };
        unsafe { read_prevalidated_vec3(sky_camera, 0x8C) }.map(f64::from)
    } else {
        camera.world_transform.translation.map(f64::from)
    };
    let translation =
        unsafe { read_prevalidated_vec3(geometry, NIAVOBJECT_WORLD_TRANSLATION_OFFSET) }
            .map(f64::from);
    let scale =
        f64::from(unsafe { read_prevalidated::<f32>(geometry, NIAVOBJECT_WORLD_SCALE_OFFSET) });
    let rotation: [[f32; 3]; 3] =
        unsafe { read_prevalidated(geometry, NIAVOBJECT_WORLD_ROTATION_OFFSET) };
    let mut points = [[0.0_f64; 3]; 4];
    let mut texture_uvs = [[0.0_f64; 2]; 4];
    for index in 0..4 {
        let local = unsafe { read_prevalidated_vec3(vertices, index * 12) }.map(f64::from);
        let world = std::array::from_fn(|row| {
            translation[row] - origin[row] + scale * dot(rotation[row].map(f64::from), local)
        });
        points[index] = std::array::from_fn(|axis| {
            // D3D view axes are native right, up, forward columns (2,1,0).
            dot(
                world,
                std::array::from_fn(|row| {
                    f64::from(camera.world_transform.rotation[row][2 - axis])
                }),
            )
        });
        texture_uvs[index] =
            unsafe { read_prevalidated::<[f32; 2]>(uvs, index * 8) }.map(f64::from);
    }
    let property_alpha = unsafe { read_prevalidated::<f32>(shade, 0x6C) };
    if !property_alpha.is_finite() || !(0.0..=1.0).contains(&property_alpha) {
        return None;
    }
    let visibility = property_alpha * vertex_alpha;
    if visibility <= 0.0 {
        return None;
    }
    let ni_texture = unsafe { read_prevalidated_ptr(shade, 0x70) };
    unsafe { validate_object(ni_texture, 0x28)? };
    let renderer = unsafe { read_prevalidated_ptr(ni_texture, 0x24) };
    unsafe { validate_object(renderer, 0x68)? };
    let raw = unsafe { read_prevalidated_ptr(renderer, 0x64) };
    unsafe { validate_object(raw, 4)? };
    let texture = unsafe { Texture9::retain_raw(raw.cast()) }.ok()?;
    NativeSunDisk::from_geometry(texture, points, texture_uvs, camera, visibility)
}

impl NativeSunDisk {
    /// Build the draw packet from the owned texture and captured view-space quad.
    /// Rejects nonfinite, singular, non-parallelogram or unsupported UV input.
    /// The caller keeps native ownership and camera capture outside this safe boundary.
    pub(crate) fn from_geometry(
        texture: Texture9,
        points: [[f64; 3]; 4],
        texture_uvs: [[f64; 2]; 4],
        camera: CameraFrame,
        visibility: f32,
    ) -> Option<Self> {
        if !camera.available || !camera.world_transform.available {
            return None;
        }
        if !visibility.is_finite()
            || !(0.0..=1.0).contains(&visibility)
            || points
                .iter()
                .flatten()
                .chain(texture_uvs.iter().flatten())
                .any(|x| !x.is_finite())
        {
            return None;
        }
        // Create supplies the complete 0..1 texture square. A different UV domain
        // needs its own geometry clipping contract, not clamp-to-edge emission.
        if texture_uvs
            .iter()
            .any(|uv| uv.iter().any(|x| *x != 0.0 && *x != 1.0))
        {
            return None;
        }
        let mapping = projective_map(points, texture_uvs, camera)?;
        let inverse = inverse(mapping)?;
        let mut screen_to_texture =
            mapping.map(|row| [row[0] as f32, row[1] as f32, row[2] as f32, 0.0]);
        let texture_to_screen =
            inverse.map(|row| [row[0] as f32, row[1] as f32, row[2] as f32, 0.0]);
        if screen_to_texture
            .iter()
            .flatten()
            .chain(texture_to_screen.iter().flatten())
            .any(|x| !x.is_finite())
        {
            return None;
        }
        screen_to_texture[2][3] = visibility;
        Some(NativeSunDisk {
            texture,
            screen_to_texture,
        })
    }
}

fn projective_map(
    p: [[f64; 3]; 4],
    uv: [[f64; 2]; 4],
    camera: CameraFrame,
) -> Option<[[f64; 3]; 3]> {
    // Native Create builds a parallelogram with vertices 0,1,2,1+2-0.
    // Bound roundoff by the input f32 precision, not a geometric padding radius.
    for axis in 0..3 {
        let expected = p[1][axis] + p[2][axis] - p[0][axis];
        let bound = p.iter().map(|v| v[axis].abs()).fold(1.0_f64, f64::max);
        if (p[3][axis] - expected).abs() > bound * 64.0 * f64::from(f32::EPSILON) {
            return None;
        }
    }
    for axis in 0..2 {
        if (uv[3][axis] - uv[1][axis] - uv[2][axis] + uv[0][axis]).abs()
            > 64.0 * f64::from(f32::EPSILON)
        {
            return None;
        }
    }
    let a = sub(p[1], p[0]);
    let b = sub(p[2], p[0]);
    let n = cross(a, b);
    let norm2 = dot(n, n);
    let distance = dot(n, p[0]);
    if !norm2.is_finite() || norm2 == 0.0 || !distance.is_finite() || distance == 0.0 {
        return None;
    }
    let denominator = n.map(|x| x / distance);
    let dual_a = cross(b, n).map(|x| x / norm2);
    let dual_b = cross(n, a).map(|x| x / norm2);
    let numerator_a = sub(dual_a, denominator.map(|x| x * dot(dual_a, p[0])));
    let numerator_b = sub(dual_b, denominator.map(|x| x * dot(dual_b, p[0])));
    let world_map = [
        std::array::from_fn(|i| {
            denominator[i] * uv[0][0]
                + numerator_a[i] * (uv[1][0] - uv[0][0])
                + numerator_b[i] * (uv[2][0] - uv[0][0])
        }),
        std::array::from_fn(|i| {
            denominator[i] * uv[0][1]
                + numerator_a[i] * (uv[1][1] - uv[0][1])
                + numerator_b[i] * (uv[2][1] - uv[0][1])
        }),
        denominator,
    ];
    let left = f64::from(camera.frustum_left);
    let top = f64::from(camera.frustum_top);
    let width = f64::from(camera.frustum_right) - left;
    let height = top - f64::from(camera.frustum_bottom);
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return None;
    }
    Some(world_map.map(|row| {
        [
            row[0] * width,
            -row[1] * height,
            row[0] * left + row[1] * top + row[2],
        ]
    }))
}

fn inverse(m: [[f64; 3]; 3]) -> Option<[[f64; 3]; 3]> {
    let columns = [cross(m[1], m[2]), cross(m[2], m[0]), cross(m[0], m[1])];
    let determinant = dot(m[0], columns[0]);
    if !determinant.is_finite() || determinant == 0.0 {
        return None;
    }
    Some(std::array::from_fn(|row| {
        std::array::from_fn(|col| columns[col][row] / determinant)
    }))
}

fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}
fn sub(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    std::array::from_fn(|i| a[i] - b[i])
}
fn cross(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
