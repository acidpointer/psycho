//! Read-only interoperability with Depth Resolve 1.31 world depth.
//!
//! Depth Resolve 1.31 exposes its shader-readable world depth through the
//! engine `ImageSpaceManager::GetDepthTexture` replacement, but it does not
//! expose a producer-control API. It performs two world copies itself: one
//! before alpha/water work and one after water. On NVIDIA those are direct
//! `NvAPI_D3D9_StretchRectEx` calls and cannot be observed or suppressed by a
//! D3D9 `SetRenderState` hook.
//!
//! Only the explicit `depth_resolve` provider borrows that validated shared
//! `INTZ` texture at native pre-alpha and post-world boundaries. The `omv`
//! provider independently resolves or aliases the exact requested world and
//! first-person surfaces; it never stamps current metadata onto this external
//! texture. No plugin code, driver vtable, static data, or engine callsite is
//! patched.

use core::{ffi::c_void, mem::size_of};
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        directx9::{D3DFMT_INTZ, D3DSURFACE_DESC, Texture9},
        memory::validate_memory_range,
        winapi::{get_module_handle_a, get_proc_address},
    },
};

const DEPTH_RESOLVE_MODULE: &str = "DepthResolve.dll";
const GET_DEPTH_TEXTURE_ADDRESS: usize = 0x00B5_4090;
const NI_TEXTURE_RENDERER_DATA_OFFSET: usize = 0x24;
const NI_TEXTURE_READ_SIZE: usize = NI_TEXTURE_RENDERER_DATA_OFFSET + size_of::<usize>();
const NIDX9_TEXTURE_DATA_D3D_TEXTURE_OFFSET: usize = 0x64;
const NIDX9_TEXTURE_DATA_READ_SIZE: usize =
    NIDX9_TEXTURE_DATA_D3D_TEXTURE_OFFSET + size_of::<usize>();

const PROBE_UNKNOWN: u8 = 0;
const PROBE_ABSENT: u8 = 1;
const PROBE_AVAILABLE: u8 = 2;

static PROBE_STATE: AtomicU8 = AtomicU8::new(PROBE_UNKNOWN);
const EXTERNAL_ROUTE_UNPROBED: u8 = 0;
const EXTERNAL_ROUTE_RESZ: u8 = 1;
const EXTERNAL_ROUTE_NVAPI: u8 = 2;

static EXTERNAL_COPY_ROUTE: AtomicU8 = AtomicU8::new(EXTERNAL_ROUTE_UNPROBED);
static EXTERNAL_PUBLICATIONS: AtomicU32 = AtomicU32::new(0);

type GetDepthTextureFn = unsafe extern "C" fn() -> *mut c_void;

/// Observed physical copy route used by the external producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExternalCopyRoute {
    /// The active-device capability query did not produce a result.
    Unprobed,
    /// Observable D3D9 RESZ marker route.
    Resz,
    /// Native NvAPI route without a D3D9 marker.
    Nvapi,
}

/// Fixed-size legacy-compatible counters exposed without taking a lock.
///
/// Marker fields remain zero because OMV no longer interposes the driver
/// method. `external_publications` counts borrowed pre-alpha/post-world uses.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MarkerCounters {
    /// Always zero; OMV does not observe external driver calls.
    pub(crate) external_allowed: u32,
    /// Always zero; OMV does not suppress external driver calls.
    pub(crate) external_suppressed: u32,
    /// Always zero; OMV has no marker hook.
    pub(crate) omv_allowed: u32,
    /// External world-stage snapshots successfully borrowed by OMV.
    pub(crate) external_publications: u32,
}

/// Probe the loaded Depth Resolve module and its stable public exports.
///
/// This must first run at or after xNVSE `DeferredInit`. It intentionally does
/// not call the engine depth getter because Depth Resolve creates its `INTZ`
/// resource in its own DeferredInit listener.
pub(crate) fn probe() -> bool {
    match PROBE_STATE.load(Ordering::Acquire) {
        PROBE_AVAILABLE => return true,
        PROBE_ABSENT => return false,
        _ => {}
    }

    let available = get_module_handle_a(Some(DEPTH_RESOLVE_MODULE))
        .ok()
        .is_some_and(|module| {
            get_proc_address(module, "AppendPostDepthEffect").is_ok()
                && get_proc_address(module, "PrependPostDepthEffect").is_ok()
        });
    PROBE_STATE.store(
        if available {
            PROBE_AVAILABLE
        } else {
            PROBE_ABSENT
        },
        Ordering::Release,
    );
    available
}

/// Return whether the compatible Depth Resolve module was discovered.
pub(crate) fn available() -> bool {
    match PROBE_STATE.load(Ordering::Acquire) {
        PROBE_AVAILABLE => true,
        PROBE_ABSENT => false,
        _ => probe(),
    }
}

/// Retain and validate Depth Resolve's shared world-depth texture.
///
/// The returned COM wrapper owns a retained reference; Depth Resolve still
/// owns resource creation, physical copies, and reset publication.
pub(crate) fn shared_texture(expected: Option<&D3DSURFACE_DESC>) -> Result<Texture9, &'static str> {
    if !available() {
        return Err("Depth Resolve is not loaded or its provider exports are unavailable");
    }

    let raw = unsafe { raw_shared_texture()? };
    let texture = unsafe { Texture9::retain_raw(raw) }
        .map_err(|_| "Depth Resolve returned an invalid D3D texture")?;
    let desc = texture
        .surface_level(0)
        .and_then(|surface| surface.desc())
        .map_err(|_| "Depth Resolve depth texture has no readable level 0")?;
    if desc.Format != D3DFMT_INTZ {
        return Err("Depth Resolve depth texture is not INTZ");
    }
    if desc.Width == 0 || desc.Height == 0 {
        return Err("Depth Resolve depth texture has empty dimensions");
    }
    if let Some(expected) = expected
        && (desc.Width != expected.Width || desc.Height != expected.Height)
    {
        return Err("Depth Resolve depth texture dimensions do not match the world target");
    }

    Ok(texture)
}

/// Record one successfully borrowed current external snapshot.
pub(crate) fn record_external_publication() {
    EXTERNAL_PUBLICATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Record the external producer route inferred from the active D3D9 device.
///
/// This route is diagnostic only. Freshness follows from the fixed native
/// accumulator boundaries for both RESZ and NvAPI; no driver call is hooked.
pub(crate) fn set_external_copy_route(resz_supported: Option<bool>) {
    EXTERNAL_COPY_ROUTE.store(external_copy_route_raw(resz_supported), Ordering::Release);
}

/// Return the last active-device classification of the external copy route.
pub(crate) fn external_copy_route() -> ExternalCopyRoute {
    external_copy_route_from_raw(EXTERNAL_COPY_ROUTE.load(Ordering::Acquire))
}

fn external_copy_route_raw(resz_supported: Option<bool>) -> u8 {
    match resz_supported {
        Some(true) => EXTERNAL_ROUTE_RESZ,
        Some(false) => EXTERNAL_ROUTE_NVAPI,
        None => EXTERNAL_ROUTE_UNPROBED,
    }
}

fn external_copy_route_from_raw(value: u8) -> ExternalCopyRoute {
    match value {
        EXTERNAL_ROUTE_RESZ => ExternalCopyRoute::Resz,
        EXTERNAL_ROUTE_NVAPI => ExternalCopyRoute::Nvapi,
        _ => ExternalCopyRoute::Unprobed,
    }
}

/// Return the current nonblocking shared-depth counters.
pub(crate) fn marker_counters() -> MarkerCounters {
    MarkerCounters {
        external_allowed: 0,
        external_suppressed: 0,
        omv_allowed: 0,
        external_publications: EXTERNAL_PUBLICATIONS.load(Ordering::Relaxed),
    }
}

/// Forget device-generation state while retaining module discovery.
pub(crate) fn reset_device_state() {
    EXTERNAL_COPY_ROUTE.store(EXTERNAL_ROUTE_UNPROBED, Ordering::Release);
}

unsafe fn raw_shared_texture() -> Result<*mut c_void, &'static str> {
    let function = unsafe {
        FnPtr::<GetDepthTextureFn>::from_raw(GET_DEPTH_TEXTURE_ADDRESS as *mut c_void)
            .map_err(|_| "invalid ImageSpaceManager::GetDepthTexture entry")?
    };
    let ni_texture = unsafe { function.as_fn()() };
    if ni_texture.is_null() {
        return Err("Depth Resolve has not published its INTZ texture");
    }
    validate_memory_range(ni_texture.cast_const(), NI_TEXTURE_READ_SIZE)
        .map_err(|_| "Depth Resolve returned an unreadable NiTexture")?;

    let renderer_data = unsafe {
        *(ni_texture
            .byte_add(NI_TEXTURE_RENDERER_DATA_OFFSET)
            .cast::<*mut c_void>())
    };
    if renderer_data.is_null() {
        return Err("Depth Resolve NiTexture has no renderer data");
    }
    validate_memory_range(renderer_data.cast_const(), NIDX9_TEXTURE_DATA_READ_SIZE)
        .map_err(|_| "Depth Resolve renderer data is unreadable")?;

    let texture = unsafe {
        *(renderer_data
            .byte_add(NIDX9_TEXTURE_DATA_D3D_TEXTURE_OFFSET)
            .cast::<*mut c_void>())
    };
    if texture.is_null() {
        return Err("Depth Resolve renderer data has no D3D texture");
    }
    Ok(texture)
}

#[cfg(test)]
mod tests {
    use super::{ExternalCopyRoute, external_copy_route_from_raw, external_copy_route_raw};

    #[test]
    fn failed_capability_query_remains_unprobed_instead_of_claiming_nvapi() {
        assert_eq!(
            external_copy_route_from_raw(external_copy_route_raw(None)),
            ExternalCopyRoute::Unprobed
        );
        assert_eq!(
            external_copy_route_from_raw(external_copy_route_raw(Some(false))),
            ExternalCopyRoute::Nvapi
        );
    }
}
