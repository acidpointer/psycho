//! Depth Resolve interoperability and exclusive RESZ marker ownership.
//!
//! Depth Resolve 1.31 exposes its shader-readable world depth through the
//! engine `ImageSpaceManager::GetDepthTexture` replacement, but it does not
//! expose a producer-control API. OMV therefore interoperates at the stable
//! D3D9 capability boundary:
//!
//! - the provider's `NiTexture -> NiDX9TextureData -> IDirect3DTexture9` chain
//!   is validated before OMV retains the shared `INTZ` destination;
//! - while OMV owns production, a device-vtable hook observes only the RESZ
//!   point-size marker; external production physically restores the vtable;
//! - an external marker is suppressed only when its bound destination is the
//!   exact validated shared texture and OMV is the selected producer;
//! - OMV explicitly arms its own marker, allowing it to resolve into the same
//!   shared destination without being mistaken for the inactive producer.
//!
//! Depth Resolve remains loaded and its consumers keep sampling the shared
//! texture. Only the expensive physical producer changes. No Depth Resolve
//! code, static data, or engine callsite is patched, and an unrecognized
//! texture or provider state always passes through unchanged.

use core::{ffi::c_void, mem::size_of};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        directx9::{D3DFMT_INTZ, D3DSURFACE_DESC, Texture9},
        memory::validate_memory_range,
        winapi::{get_module_handle_a, get_proc_address},
    },
};

use super::super::DepthProvider;

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
static SHARED_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static OMV_RESZ_MARKER_ACTIVE: AtomicBool = AtomicBool::new(false);
static EXTERNAL_RESZ_MARKER_REQUIRED: AtomicBool = AtomicBool::new(false);
static EXTERNAL_MARKERS_ALLOWED: AtomicU32 = AtomicU32::new(0);
static EXTERNAL_MARKERS_SUPPRESSED: AtomicU32 = AtomicU32::new(0);
static OMV_MARKERS_ALLOWED: AtomicU32 = AtomicU32::new(0);
static EXTERNAL_PUBLICATIONS: AtomicU32 = AtomicU32::new(0);
static EXTERNAL_LAST_MARKER_EPOCH: AtomicU32 = AtomicU32::new(0);

type GetDepthTextureFn = unsafe extern "C" fn() -> *mut c_void;

/// Result of classifying a RESZ marker at the shared-provider boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarkerDecision {
    /// Forward the call to the original D3D9 device method.
    Forward,
    /// Return success without emitting the inactive provider's GPU resolve.
    Suppress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarkerClassification {
    Unknown,
    Omv,
    ExternalAllowed,
    ExternalSuppressed,
}

/// Fixed-size marker counters exposed to diagnostics without taking a lock.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MarkerCounters {
    /// External markers observed and forwarded before interposition detached.
    pub(crate) external_allowed: u32,
    /// External markers acknowledged without issuing the duplicate resolve.
    pub(crate) external_suppressed: u32,
    /// OMV-owned markers forwarded through the same device hook.
    pub(crate) omv_allowed: u32,
    /// Current external snapshots borrowed at the post-world boundary.
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
/// A successful call refreshes the raw identity used by the marker hook. The
/// returned COM wrapper owns its reference; Depth Resolve still owns resource
/// creation and reset publication.
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

    SHARED_TEXTURE.store(texture.as_raw_base_texture() as usize, Ordering::Release);
    Ok(texture)
}

/// Run OMV's RESZ marker while identifying it as the active producer.
///
/// The device hook can see calls made through the original D3D9 vtable, so a
/// process-wide atomic scope is required even for OMV's own marker. FNV renders
/// D3D9 on one thread; nested scopes are rejected instead of weakening marker
/// classification.
pub(crate) fn with_omv_marker<T>(operation: impl FnOnce() -> T) -> T {
    let was_active = OMV_RESZ_MARKER_ACTIVE.swap(true, Ordering::AcqRel);
    debug_assert!(!was_active, "nested OMV RESZ marker scope");
    let result = operation();
    OMV_RESZ_MARKER_ACTIVE.store(was_active, Ordering::Release);
    result
}

/// Classify a RESZ marker after the hook has identified its bound texture.
pub(crate) fn classify_marker(
    provider: DepthProvider,
    bound_texture: usize,
    render_epoch: u32,
) -> MarkerDecision {
    let shared = SHARED_TEXTURE.load(Ordering::Acquire);
    let classification = classify_marker_state(
        provider,
        OMV_RESZ_MARKER_ACTIVE.load(Ordering::Acquire),
        shared,
        bound_texture,
    );
    match classification {
        MarkerClassification::Unknown => MarkerDecision::Forward,
        MarkerClassification::Omv => {
            OMV_MARKERS_ALLOWED.fetch_add(1, Ordering::Relaxed);
            MarkerDecision::Forward
        }
        MarkerClassification::ExternalAllowed => {
            // Publication checks this epoch after RenderWorldSceneGraph
            // returns. Merely retaining the external texture cannot prove
            // that Depth Resolve actually refreshed it this frame.
            EXTERNAL_LAST_MARKER_EPOCH.store(render_epoch, Ordering::Release);
            EXTERNAL_MARKERS_ALLOWED.fetch_add(1, Ordering::Relaxed);
            MarkerDecision::Forward
        }
        MarkerClassification::ExternalSuppressed => {
            EXTERNAL_MARKERS_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            MarkerDecision::Suppress
        }
    }
}

/// Prove external freshness through its selected physical route.
///
/// When marker interposition is attached, RESZ requires a validated
/// current-epoch marker. A physically detached external-provider path, like
/// native NvAPI, has no OMV marker observer; freshness then follows from the
/// fixed post-world call boundary established by Depth Resolve's replacement
/// function.
pub(crate) fn external_copy_is_fresh(render_epoch: u32, marker_observer_active: bool) -> bool {
    external_copy_freshness(
        EXTERNAL_RESZ_MARKER_REQUIRED.load(Ordering::Acquire),
        marker_observer_active,
        render_epoch,
        EXTERNAL_LAST_MARKER_EPOCH.load(Ordering::Acquire),
    )
}

/// Record one successfully borrowed current external snapshot.
pub(crate) fn record_external_publication() {
    EXTERNAL_PUBLICATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Record whether the external producer selected its observable RESZ route.
///
/// Native NvAPI performs the copy without a D3D9 marker. In that mode OMV is
/// only a consumer, so the fixed post-world publication boundary is the
/// available freshness contract and no producer interposition is required.
pub(crate) fn set_external_resz_marker_required(required: bool) {
    EXTERNAL_RESZ_MARKER_REQUIRED.store(required, Ordering::Release);
}

/// Return whether Depth Resolve selected its observable RESZ copy route.
pub(crate) fn external_resz_marker_required() -> bool {
    EXTERNAL_RESZ_MARKER_REQUIRED.load(Ordering::Acquire)
}

/// Return the current nonblocking RESZ ownership counters.
pub(crate) fn marker_counters() -> MarkerCounters {
    MarkerCounters {
        external_allowed: EXTERNAL_MARKERS_ALLOWED.load(Ordering::Relaxed),
        external_suppressed: EXTERNAL_MARKERS_SUPPRESSED.load(Ordering::Relaxed),
        omv_allowed: OMV_MARKERS_ALLOWED.load(Ordering::Relaxed),
        external_publications: EXTERNAL_PUBLICATIONS.load(Ordering::Relaxed),
    }
}

/// Forget device-generation state while retaining module discovery.
pub(crate) fn reset_device_state() {
    SHARED_TEXTURE.store(0, Ordering::Release);
    OMV_RESZ_MARKER_ACTIVE.store(false, Ordering::Release);
    EXTERNAL_LAST_MARKER_EPOCH.store(0, Ordering::Release);
}

fn classify_marker_state(
    provider: DepthProvider,
    omv_marker_active: bool,
    shared_texture: usize,
    bound_texture: usize,
) -> MarkerClassification {
    if omv_marker_active {
        return MarkerClassification::Omv;
    }
    if shared_texture == 0 || bound_texture != shared_texture {
        return MarkerClassification::Unknown;
    }
    if provider == DepthProvider::FalloutNewVegas {
        MarkerClassification::ExternalSuppressed
    } else {
        MarkerClassification::ExternalAllowed
    }
}

fn external_copy_freshness(
    resz_route: bool,
    marker_observer_active: bool,
    render_epoch: u32,
    last_marker_epoch: u32,
) -> bool {
    !marker_observer_active
        || !resz_route
        || (render_epoch != 0 && last_marker_epoch == render_epoch)
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
    use super::{MarkerClassification, classify_marker_state, external_copy_freshness};
    use crate::backend::DepthProvider;

    fn classify(provider: DepthProvider, omv_marker: bool, bound: usize) -> MarkerClassification {
        classify_marker_state(provider, omv_marker, 0x1234, bound)
    }

    #[test]
    fn omv_provider_suppresses_only_the_external_shared_target() {
        assert_eq!(
            classify(DepthProvider::FalloutNewVegas, false, 0x1234),
            MarkerClassification::ExternalSuppressed
        );
        assert_eq!(
            classify(DepthProvider::FalloutNewVegas, false, 0x5678),
            MarkerClassification::Unknown
        );
    }

    #[test]
    fn depth_resolve_provider_forwards_its_shared_marker() {
        assert_eq!(
            classify(DepthProvider::DepthResolve, false, 0x1234),
            MarkerClassification::ExternalAllowed
        );
    }

    #[test]
    fn omv_marker_scope_always_forwards_the_selected_target() {
        assert_eq!(
            classify(DepthProvider::FalloutNewVegas, true, 0x1234),
            MarkerClassification::Omv
        );
    }

    #[test]
    fn detached_external_route_uses_the_post_world_freshness_boundary() {
        assert!(external_copy_freshness(true, false, 7, 0));
        assert!(external_copy_freshness(false, false, 7, 0));
        assert!(external_copy_freshness(true, true, 7, 7));
        assert!(!external_copy_freshness(true, true, 7, 6));
        assert!(!external_copy_freshness(true, true, 0, 0));
    }
}
