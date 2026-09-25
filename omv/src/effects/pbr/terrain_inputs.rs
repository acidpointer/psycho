//! Draw-local inputs for the three terrain replacement families.
//!
//! Native shader wrappers do not imply the VPT extension constant ABI. Read
//! the current engine-owned material/fog/light values after native geometry
//! setup, copy them into owned values, and publish the replacement ABI here.
//! No engine pointer survives this call. The renderer serializes this boundary
//! with material setup and keeps the geometry, pass and scene alive until the
//! submission returns. See the terrain-input audit linked by the PBR errata.
//!
//! A stack journal saves only the overwritten constant ranges (at most 56
//! pixel registers). D3D constant getters query CPU device state, not pixels.
//! Restoring the exact values keeps native constant-map caches and object PBR's
//! cached c32/c33 valid. There are no allocations, locks, caches or startup
//! state. Missing or nonfinite native inputs reject only the current draw.

use std::ffi::c_void;

use libpsycho::os::windows::directx9::Device9Ref;

use super::{engine_contracts, terrain_lights};

/// A native terrain row already classified by shader admission. Close rows
/// retain their compiled layer count and native light register capacity.
#[derive(Clone, Copy, Debug)]
pub(super) enum Family {
    Close { layers: usize, lights: usize },
    Fade,
    Lod,
}

/// Owned replacement inputs. Unused register gaps are never uploaded.
pub(super) struct Inputs {
    family: Family,
    pixel: [[f32; 4]; 60],
    fog: [[f32; 4]; 2],
}

/// Exact pre-draw device values; must be restored even if admission fails.
#[derive(Debug)]
#[must_use]
pub(super) struct ConstantScope {
    family: Family,
    pixel: [[f32; 4]; 60],
    vertex: [[f32; 4]; 2],
}

fn ranges(family: Family) -> [(usize, usize); 5] {
    match family {
        Family::Close { lights, .. } => [(32, 2), (36, 2), (39, lights), (63, lights), (88, 4)],
        Family::Fade | Family::Lod => [(38, 1), (89, 2), (0, 0), (0, 0), (0, 0)],
    }
}

impl ConstantScope {
    /// Capture before *any* terrain constant writer, including user controls.
    pub(super) fn capture(device: &Device9Ref<'_>, family: Family) -> Option<Self> {
        let mut scope = Self {
            family,
            pixel: [[0.0; 4]; 60],
            vertex: [[0.0; 4]; 2],
        };
        for (start, count) in ranges(family) {
            if count != 0 {
                device
                    .pixel_shader_constant_f(
                        start as u32,
                        &mut scope.pixel[start - 32..start - 32 + count],
                    )
                    .ok()?;
            }
        }
        if !matches!(family, Family::Close { .. }) {
            device
                .vertex_shader_constant_f(14, &mut scope.vertex)
                .ok()?;
        }
        Some(scope)
    }

    /// Restore all ranges, attempting later restores even if one call fails.
    pub(super) fn restore(self, device: &Device9Ref<'_>) -> bool {
        let mut restored = true;
        for (start, count) in ranges(self.family) {
            if count != 0 {
                restored &= device
                    .set_pixel_shader_constant_f(
                        start as u32,
                        &self.pixel[start - 32..start - 32 + count],
                    )
                    .is_ok();
            }
        }
        if !matches!(self.family, Family::Close { .. }) {
            restored &= device
                .set_vertex_shader_constant_f(14, &self.vertex)
                .is_ok();
        }
        restored
    }
}

impl Inputs {
    /// Publish extension inputs only. User controls remain owned by constants.rs.
    /// The caller holds a ConstantScope across this call and the native draw.
    pub(super) fn upload(&self, device: &Device9Ref<'_>) -> bool {
        let mut uploaded = true;
        match self.family {
            Family::Close { lights, .. } => {
                for (start, count) in [(32, 2), (36, 2), (39, lights), (63, lights), (88, 1)] {
                    if count != 0 {
                        uploaded &= device
                            .set_pixel_shader_constant_f(
                                start,
                                &self.pixel[start as usize - 32..start as usize - 32 + count],
                            )
                            .is_ok();
                    }
                }
            }
            Family::Fade | Family::Lod => {
                uploaded &= device
                    .set_pixel_shader_constant_f(38, &self.pixel[6..7])
                    .is_ok();
                uploaded &= device.set_vertex_shader_constant_f(14, &self.fog).is_ok();
            }
        }
        uploaded
    }
}

/// Copy the live native inputs at the renderer's geometry submission boundary.
///
/// Safety: geometry is the live PPLighting geometry selected by the admitted
/// native terrain row. Its property and the current pass are render-thread
/// owned and remain alive through this synchronous submission. This function
/// never accepts arbitrary external pointers or retains a native reference.
pub(super) unsafe fn capture(geometry: *mut c_void, family: Family) -> Option<Inputs> {
    let pass = engine_contracts::current_geometry_pass_fast()?;
    if unsafe { pointer(pass, 0) }? != geometry {
        return None;
    }
    let property = unsafe { pointer(geometry, 0xA8) }?;
    let count = usize::from(unsafe { value::<u16>(property, 0xA8) });
    // B68450 allocates native terrain arrays; B68660 populates their elements.
    // The supported native family has at most ten entries, including fade.
    if count == 0 || count > 10 {
        return None;
    }
    let fog = unsafe { capture_fog() }?;
    let mut inputs = Inputs {
        family,
        pixel: [[0.0; 4]; 60],
        fog,
    };
    match family {
        Family::Close { layers, lights } => {
            if !(1..=7).contains(&layers) || layers > count || ![0, 6, 12, 24].contains(&lights) {
                return None;
            }
            let exponents = unsafe { pointer(property, 0xC4) }?;
            let available = unsafe { pointer(property, 0xCC) }?;
            for i in 0..layers {
                inputs.pixel[i / 4][i % 4] = f32::from(unsafe { value::<u8>(exponents, i) })
                    * f32::from(unsafe { value::<u8>(available, i) });
            }
            inputs.pixel[4..6].copy_from_slice(&fog);
            let native = unsafe { terrain_lights::capture_native(geometry, property, pass) }?;
            if native.count > lights {
                return None;
            }
            inputs.pixel[7..7 + lights].copy_from_slice(&native.colors[..lights]);
            inputs.pixel[31..31 + lights].copy_from_slice(&native.positions[..lights]);
            inputs.pixel[56][0] = native.count as f32;
        }
        Family::Lod | Family::Fade => {
            let normals = unsafe { pointer(property, 0xB0) }?;
            let alpha = if matches!(family, Family::Fade) {
                let index = usize::from(unsafe { value::<u8>(pass, 0x0B) });
                index < count && unsafe { normal_has_alpha(normals, index) }
            } else {
                (0..count).any(|index| unsafe { normal_has_alpha(normals, index) })
            };
            // The established terrain shader ABI uses the reference producer's
            // fixed LOD exponent, independently of close-layer exponents.
            inputs.pixel[6][0] = if alpha { 30.0 } else { 0.0 };
        }
    }
    Some(inputs)
}

unsafe fn capture_fog() -> Option<[[f32; 4]; 2]> {
    // B55520 is exactly scene[index]->fog (+134). Read the same current scene
    // as native setup, rather than assuming a previous pass enabled c14/c15.
    let scene_index = unsafe { (0x011F91C4 as *const u8).read() } as usize;
    let scene = unsafe { pointer(0x011F91C8 as *mut c_void, scene_index * 4) }?;
    let fog = unsafe { pointer(scene, 0x134) }?;
    let start = unsafe { value::<f32>(fog, 0x2C) };
    let end = unsafe { value::<f32>(fog, 0x30) };
    let power = unsafe { value::<f32>(fog, 0x60) };
    let color = unsafe { value::<[f32; 3]>(fog, 0x20) };
    if ![start, end, power]
        .iter()
        .chain(color.iter())
        .all(|x| x.is_finite())
    {
        return None;
    }
    // Exact B7B450 disabled-fog representation, including its alpha component.
    let output = if start == 0.0 && end == 0.0 {
        [
            [f32::from_bits(0x48F42400), 0.0, 0.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ]
    } else {
        [
            [end, end - start, power, 0.0],
            [color[0], color[1], color[2], 0.0],
        ]
    };
    output
        .iter()
        .flatten()
        .all(|x| x.is_finite())
        .then_some(output)
}

unsafe fn normal_has_alpha(normals: *mut c_void, index: usize) -> bool {
    let Some(texture) = (unsafe { pointer(normals, index * 4) }) else {
        return false;
    };
    let Some(renderer_data) = (unsafe { pointer(texture, 0x24) }) else {
        return false;
    };
    // Native B68660 tests NiPixelFormat::RGBA/DXT3/DXT5 identically.
    matches!(unsafe { value::<u32>(renderer_data, 0x18) }, 1 | 5 | 6)
}

unsafe fn pointer(base: *mut c_void, offset: usize) -> Option<*mut c_void> {
    if base.is_null() {
        return None;
    }
    let pointer = unsafe { value::<*mut c_void>(base, offset) };
    (!pointer.is_null()).then_some(pointer)
}

unsafe fn value<T: Copy>(base: *mut c_void, offset: usize) -> T {
    unsafe { base.cast::<u8>().add(offset).cast::<T>().read_unaligned() }
}

#[cfg(test)]
#[path = "terrain_input_tests.rs"]
pub(crate) mod tests;
