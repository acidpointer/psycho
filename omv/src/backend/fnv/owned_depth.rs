//! Persistent sampleable backing for FNV's native depth identities.
//!
//! Installation and policy admission occur only after DeferredInit. At an idle
//! frame boundary OMV selects single-sample native target acquisition. Existing
//! pool entries, metadata and GPU backing remain native-owned and unchanged;
//! native sample-aware lookup selects compatible targets on subsequent frames.
//! Activation never resets the device or recreates UI or texture-manager owners.
//!
//! Each adopted native +0x14 field owns one transferred COM surface reference.
//! OMV retains the texture through native release/destruction. Existing backing
//! is replaced only before a complete depth/stencil clear; populated aliases
//! and zero-clear rebinds retain their contents. Real native reset notifications
//! release OMV resources and invalidate generations without rewriting resource
//! sample preferences. Allocation failure retains the native backing.
//!
//! Backing readiness is independent of provider/effect selection. Safe
//! creation/full-clear opportunities may precede a live provider change;
//! missing them cannot be repaired by replacing populated depth at capture.
//! Native MSAA policy changes require OMV selection. Snapshot and effect work
//! remain independently consumer-gated; preparation performs no frame copies.
//!
//! Locks are try-only and never cross native/COM calls. Policy changes run on
//! the renderer thread with the loading worker parked; the worker may bind an
//! already adopted identity under native renderer serialization. See
//! docs/graphics_fnv_portable_depth_transport.md for the verified engine ABI.

use anyhow::{Context, Result, bail};
use core::ffi::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        directx9::{
            D3DFMT_D24S8, D3DFMT_INTZ, D3DMULTISAMPLE_NONE, D3DSURFACE_DESC, Device9Ref, Surface9,
            Texture9,
        },
        hook::{
            callsite::Rel32CallHookContainer, pointer::PointerSlotHookContainer,
            transaction::ModificationTransaction,
        },
        memory::{read_bytes, validate_memory_range},
        winapi::get_current_thread_id,
    },
};
use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    },
};

const DEPTH_TABLES: [usize; 2] = [0x010EF114, 0x010EF184];
const RENDERER_TABLE: usize = 0x010EE4BC;
const SAMPLE_GLOBALS: [usize; 2] = [0x011C70CC, 0x011F9490];
const RESET_REQUEST: usize = 0x011C6FBB;
const LOADING_WORKER: usize = 0x011DA0C4;
const DORMANT: u8 = 0;
const ADMITTED: u8 = 1;
const ACTIVE: u8 = 2;
const FAILED: u8 = 3;

type DepthCreate = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, u32) -> bool;
type DepthDevice = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> bool;
type DepthRelease = unsafe extern "thiscall" fn(*mut c_void);
type DepthDestroy = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
type ResetNotify = unsafe extern "C" fn(bool, *mut c_void) -> bool;
type RegisterNotify = unsafe extern "thiscall" fn(*mut c_void, ResetNotify, *mut c_void) -> u32;
type FrameFinished = unsafe extern "thiscall" fn(*mut c_void);
type ClearBuffer = unsafe extern "thiscall" fn(*mut c_void, *const f32, u32);

// Only a pointer-sized deferred owner is loader-visible. All containers,
// maps and GPU ownership are allocated after the handoff.
static HOOKS: OnceLock<Box<Hooks>> = OnceLock::new();

struct Hooks {
    renderer: usize,
    thread: u32,
    ready: AtomicBool,
    capable: AtomicBool,
    adoption_logged: AtomicBool,
    policy: AtomicU8,
    adoption_failures: AtomicU32,
    resetting: AtomicBool,
    poisoned: AtomicBool,
    generation: AtomicU32,
    // Advances only when a native bind could not be journaled. A backup from
    // before that event may contain stale pixels and cannot be restored.
    untracked_bind_serial: AtomicU32,
    mrt_count: AtomicU32,
    depth_create: PointerSlotHookContainer<DepthCreate>,
    recreate: [PointerSlotHookContainer<DepthDevice>; 2],
    bind: [PointerSlotHookContainer<DepthDevice>; 2],
    release: [PointerSlotHookContainer<DepthRelease>; 2],
    destroy: [PointerSlotHookContainer<DepthDestroy>; 2],
    frame_finished: Rel32CallHookContainer<FrameFinished>,
    clear: PointerSlotHookContainer<ClearBuffer>,
    attachments: Mutex<HashMap<usize, Attachment>>,
    clear_attempts: Mutex<HashSet<usize>>,
    notification: AtomicBool,
    notification_attempted: AtomicBool,
}

struct Attachment {
    _texture: Texture9,
    surface: usize,
    backup: Option<Surface9>,
    backup_bind_serial: u32,
    native: D3DSURFACE_DESC,
    generation: u32,
    // Retention prevents address reuse from admitting a different surface.
    // Native release/reset retires these owners together with the depth.
    checked_colors: ColorValidationCache,
}

/// Two recent successful MRT sets, bounded independently of native pool size.
/// Keeping the preceding set avoids rediscovering compatibility when targets
/// alternate. Eviction only costs revalidation; it never weakens admission.
/// All owners retire with their depth attachment before native reset/release.
#[derive(Default)]
struct ColorValidationCache {
    sets: [Option<CheckedColors>; 2],
}

impl ColorValidationCache {
    fn identities(&self) -> [[usize; 4]; 2] {
        self.sets
            .each_ref()
            .map(|set| set.as_ref().map_or([0; 4], CheckedColors::identities))
    }

    /// Publish only after native success. Return the evicted COM owners so
    /// the caller releases them after dropping the attachment registry lock.
    fn publish(&mut self, colors: CheckedColors) -> Option<CheckedColors> {
        let previous = self.sets[0].replace(colors);
        std::mem::replace(&mut self.sets[1], previous)
    }
}

/// Successfully validated MRT identities. Surface descriptions cannot change
/// during a surface's lifetime; retaining each identity permits reusing the
/// validation without GetDesc or capability calls on unchanged bindings.
struct CheckedColors {
    surfaces: [Option<Surface9>; 4],
}

impl CheckedColors {
    fn identities(&self) -> [usize; 4] {
        self.surfaces.each_ref().map(|surface| {
            surface
                .as_ref()
                .map_or(0, |surface| surface.as_raw() as usize)
        })
    }
}

/// Query the actual bindings and validate only uncached identities. The native
/// target-use critical section serializes this call with attachment retirement,
/// so `checked` remains backed by its retained surfaces throughout the call.
/// A changed set is returned for publication after the native bind succeeds.
/// No allocation, shader work or registry lock occurs here.
fn validate_colors(
    device: &Device9Ref<'_>,
    native: &D3DSURFACE_DESC,
    mrt_count: u32,
    checked: [[usize; 4]; 2],
) -> Result<Option<CheckedColors>> {
    if !(1..=4).contains(&mrt_count) {
        bail!("invalid MRT count");
    }
    let mut surfaces = [None, None, None, None];
    let mut changed = false;
    for index in 0..mrt_count {
        let color = device.optional_render_target(index)?;
        let identity = color
            .as_ref()
            .map_or(0, |surface| surface.as_raw() as usize);
        if index == 0 && identity == 0 {
            bail!("missing color target");
        }
        if checked[0][index as usize] != identity {
            changed = true;
            // The retained COM identity proves an immutable description, even
            // when it moves to a different MRT slot. Do not cache by format:
            // new resources must still pass extent and sample validation.
            if let Some(color) = &color
                && !checked.iter().flatten().any(|&cached| cached == identity)
            {
                let desc = color.desc()?;
                if desc.Width > native.Width
                    || desc.Height > native.Height
                    || desc.MultiSampleType != D3DMULTISAMPLE_NONE
                {
                    bail!("incompatible depth attachment dimensions or samples");
                }
                #[cfg(test)]
                color_binding_tests::CAPABILITY_QUERIES.fetch_add(1, Ordering::Relaxed);
                device.check_depth_stencil_match(desc.Format, D3DFMT_INTZ)?;
            }
        }
        surfaces[index as usize] = color;
    }
    Ok(changed.then_some(CheckedColors { surfaces }))
}

#[cfg(test)]
mod color_binding_tests {
    use super::*;
    use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    pub(super) static CAPABILITY_QUERIES: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn alternating_live_targets_reuse_depth_compatibility() {
        let _serial = TEST_LOCK.lock();
        let owner = create_direct3d9()
            .unwrap()
            .create_windowed_device(get_desktop_window().unwrap(), 16, 16, D3DDEVTYPE_HAL)
            .unwrap();
        let device = owner.as_ref();
        let depth = device
            .create_depth_stencil_texture(16, 16, D3DFMT_INTZ)
            .unwrap();
        let desc = depth.surface_level(0).unwrap().desc().unwrap();
        let count = device.device_caps().unwrap().NumSimultaneousRTs;
        let first = device.render_target(0).unwrap();
        let second_texture = device
            .create_render_target_texture(16, 16, first.desc().unwrap().Format)
            .unwrap();
        let second = second_texture.surface_level(0).unwrap();
        let mut checked = ColorValidationCache::default();
        CAPABILITY_QUERIES.store(0, Ordering::Relaxed);
        for surface in [&first, &second].into_iter().cycle().take(128) {
            device.set_render_target(0, surface).unwrap();
            let updated = validate_colors(&device, &desc, count, checked.identities()).unwrap();
            device
                .set_depth_stencil_surface(Some(&depth.surface_level(0).unwrap()))
                .unwrap();
            if let Some(updated) = updated {
                drop(checked.publish(updated));
            }
        }
        // Both actual resources were validated once. Rebinding a still-live
        // target must not repeat adapter/device capability discovery.
        assert_eq!(CAPABILITY_QUERIES.load(Ordering::Relaxed), 2);

        // Bound retention must not turn eviction into an unchecked identity
        // hit. A third target evicts the first set; returning to it validates
        // again even though the test still holds its original COM reference.
        let third_texture = device
            .create_render_target_texture(16, 16, first.desc().unwrap().Format)
            .unwrap();
        let third = third_texture.surface_level(0).unwrap();
        for surface in [&third, &first] {
            device.set_render_target(0, surface).unwrap();
            let updated = validate_colors(&device, &desc, count, checked.identities())
                .unwrap()
                .unwrap();
            device
                .set_depth_stencil_surface(Some(&depth.surface_level(0).unwrap()))
                .unwrap();
            drop(checked.publish(updated));
        }
        assert_eq!(CAPABILITY_QUERIES.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn retained_color_validation_tracks_actual_mrt_changes() {
        let _serial = TEST_LOCK.lock();
        let owner = create_direct3d9()
            .unwrap()
            .create_windowed_device(get_desktop_window().unwrap(), 16, 16, D3DDEVTYPE_HAL)
            .unwrap();
        let device = owner.as_ref();
        let depth = device
            .create_depth_stencil_texture(16, 16, D3DFMT_INTZ)
            .unwrap();
        let desc = depth.surface_level(0).unwrap().desc().unwrap();
        let count = device.device_caps().unwrap().NumSimultaneousRTs;
        let mut cache = ColorValidationCache::default();
        let checked = validate_colors(&device, &desc, count, cache.identities())
            .unwrap()
            .unwrap();
        drop(cache.publish(checked));
        assert!(
            validate_colors(&device, &desc, count, cache.identities())
                .unwrap()
                .is_none()
        );

        // A different color resource, even with identical dimensions/format,
        // must establish its own lifetime before its validation can be reused.
        let color = device
            .create_render_target_texture(16, 16, desc_for_color(&device))
            .unwrap();
        let surface = color.surface_level(0).unwrap();
        device.set_render_target(0, &surface).unwrap();
        let changed = validate_colors(&device, &desc, count, cache.identities())
            .unwrap()
            .unwrap();
        assert_eq!(changed.identities()[0], surface.as_raw() as usize);
        drop(cache.publish(changed));
        assert!(
            validate_colors(&device, &desc, count, cache.identities())
                .unwrap()
                .is_none()
        );

        // Depth may legally be larger than color, but never smaller. Exercise
        // a real attachment change rather than a fabricated descriptor input.
        device.set_depth_stencil_surface(None).unwrap();
        let larger = device
            .create_render_target_texture(32, 16, desc_for_color(&device))
            .unwrap();
        device
            .set_render_target(0, &larger.surface_level(0).unwrap())
            .unwrap();
        assert!(validate_colors(&device, &desc, count, cache.identities()).is_err());
        device.set_render_target(0, &surface).unwrap();
        if count > 1 {
            device.set_render_target(1, &surface).unwrap();
            let mrt = validate_colors(&device, &desc, count, cache.identities())
                .unwrap()
                .unwrap();
            assert_eq!(mrt.identities()[1], surface.as_raw() as usize);
            drop(cache.publish(mrt));
            device.clear_render_target(1).unwrap();
            let cleared = validate_colors(&device, &desc, count, cache.identities())
                .unwrap()
                .unwrap();
            assert_eq!(cleared.identities()[1], 0);
        }
    }

    fn desc_for_color(device: &Device9Ref<'_>) -> D3DFORMAT {
        device.render_target(0).unwrap().desc().unwrap().Format
    }
}

impl Hooks {
    fn new(renderer: usize) -> Self {
        Self {
            renderer,
            thread: get_current_thread_id(),
            ready: AtomicBool::new(false),
            capable: AtomicBool::new(false),
            adoption_logged: AtomicBool::new(false),
            policy: AtomicU8::new(DORMANT),
            adoption_failures: AtomicU32::new(0),
            resetting: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            generation: AtomicU32::new(1),
            untracked_bind_serial: AtomicU32::new(0),
            mrt_count: AtomicU32::new(1),
            depth_create: PointerSlotHookContainer::new(),
            recreate: std::array::from_fn(|_| PointerSlotHookContainer::new()),
            bind: std::array::from_fn(|_| PointerSlotHookContainer::new()),
            release: std::array::from_fn(|_| PointerSlotHookContainer::new()),
            destroy: std::array::from_fn(|_| PointerSlotHookContainer::new()),
            frame_finished: Rel32CallHookContainer::new(),
            clear: PointerSlotHookContainer::new(),
            attachments: Mutex::new(HashMap::new()),
            clear_attempts: Mutex::new(HashSet::new()),
            notification: AtomicBool::new(false),
            notification_attempted: AtomicBool::new(false),
        }
    }

    fn on_thread(&self) -> bool {
        self.thread == get_current_thread_id()
    }
    fn mark_untracked_bind(&self) {
        // Saturation preserves the rollback prohibition instead of permitting
        // an old serial to compare equal after wraparound.
        let _ = self.untracked_bind_serial.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |serial| Some(serial.saturating_add(1)),
        );
    }
    fn admitted(&self) -> bool {
        // Resident hooks may outlive a failed later DeferredInit step. The
        // shared admission gate closes on that failure and opens only after
        // every essential owner is installed; retry does not repatch hooks.
        self.ready.load(Ordering::Acquire) && crate::startup::deferred_graphics_ready()
    }
    fn adopts(&self) -> bool {
        // Provider selection can change after the last complete clear. Keep
        // compatible backing ready at its safe lifecycle boundary even while
        // depth is disabled or externally supplied. Existing adopted backing
        // already survives provider changes; this also covers None -> OMV.
        self.admitted() && self.on_thread() && self.capable.load(Ordering::Acquire)
    }
}

/// Prepare and transactionally enable the complete engine-owned hook group.
/// Caller is the deferred main-thread handoff; no renderer callback is active.
pub(crate) fn install() -> Result<()> {
    super::depth_snapshot::prepare()?;
    let renderer = super::renderer_ptr().map_err(anyhow::Error::msg)? as usize;
    let hooks = HOOKS.get_or_init(|| Box::new(Hooks::new(renderer)));
    if hooks.ready.load(Ordering::Acquire) {
        return Ok(());
    }
    if !hooks.on_thread() || hooks.renderer != renderer {
        bail!("owned-depth renderer/thread changed");
    }
    if hooks.notification_attempted.load(Ordering::Acquire)
        && !hooks.notification.load(Ordering::Acquire)
    {
        bail!("prior reset notification registration could not be verified");
    }
    validate_memory_range(renderer as *const c_void, 0xAF0)?;
    // Fixed addresses are admitted by the native class identity and immutable
    // instruction bodies. Callable hooks chain the current live predecessor.
    if unsafe { *(renderer as *const usize) } != RENDERER_TABLE {
        bail!("unexpected native renderer class");
    }
    if read_bytes(0x0086BAE0 as *const c_void, 9)?
        != [0x55, 0x8b, 0xec, 0x83, 0xec, 0x08, 0x89, 0x4d, 0xf8]
    {
        bail!("reset notification registration contract changed");
    }
    unsafe {
        if !hooks.depth_create.is_initialized() {
            hooks.depth_create.init(
                "owned depth creation",
                (RENDERER_TABLE + 0x154) as *mut _,
                depth_create,
            )?;
        }
        let recreates: [DepthDevice; 2] = [recreate_default, recreate_additional];
        let binds: [DepthDevice; 2] = [bind_default, bind_additional];
        let releases: [DepthRelease; 2] = [release_default, release_additional];
        let destroys: [DepthDestroy; 2] = [destroy_default, destroy_additional];
        for (index, table) in DEPTH_TABLES.into_iter().enumerate() {
            validate_memory_range(table as *const c_void, 0x6C)?;
            if !hooks.recreate[index].is_initialized() {
                hooks.recreate[index].init(
                    "depth recreation",
                    (table + 0x58) as *mut _,
                    recreates[index],
                )?;
            }
            if !hooks.bind[index].is_initialized() {
                hooks.bind[index].init("depth binding", (table + 0x60) as *mut _, binds[index])?;
            }
            if !hooks.release[index].is_initialized() {
                hooks.release[index].init(
                    "depth backing release",
                    (table + 0x68) as *mut _,
                    releases[index],
                )?;
            }
            if !hooks.destroy[index].is_initialized() {
                hooks.destroy[index].init("depth destruction", table as *mut _, destroys[index])?;
            }
        }
        if !hooks.frame_finished.is_initialized() {
            hooks.frame_finished.init(
                "owned depth frame completion",
                0x0086EDF0 as *mut c_void,
                frame_finished,
            )?;
        }
        if !hooks.clear.is_initialized() {
            hooks.clear.init(
                "owned depth full clear",
                (RENDERER_TABLE + 0x188) as *mut _,
                clear_buffer,
            )?;
        }
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_pointer(&hooks.depth_create)?;
    for index in 0..2 {
        transaction.enable_pointer(&hooks.recreate[index])?;
        transaction.enable_pointer(&hooks.bind[index])?;
        transaction.enable_pointer(&hooks.release[index])?;
        transaction.enable_pointer(&hooks.destroy[index])?;
    }
    transaction.enable_callsite(&hooks.frame_finished)?;
    transaction.enable_pointer(&hooks.clear)?;
    if !hooks.notification.load(Ordering::Acquire) {
        let register = unsafe { FnPtr::<RegisterNotify>::from_raw(0x0086BAE0 as *mut c_void)? };
        let userdata = (&**hooks as *const Hooks).cast_mut().cast::<c_void>();
        hooks.notification_attempted.store(true, Ordering::Release);
        let index =
            unsafe { register.as_fn()(renderer as *mut c_void, reset_notification, userdata) };
        let count = unsafe { *((renderer + 0xADE) as *const u16) } as usize;
        let callbacks = unsafe { *((renderer + 0xAD8) as *const usize) };
        let data = unsafe { *((renderer + 0xAE8) as *const usize) };
        if index as usize >= count || callbacks == 0 || data == 0 {
            bail!("native reset notification was not registered");
        }
        validate_memory_range(callbacks as *const c_void, count * 4)?;
        validate_memory_range(data as *const c_void, count * 4)?;
        if unsafe { *((callbacks + index as usize * 4) as *const usize) }
            != reset_notification as *const () as usize
            || unsafe { *((data + index as usize * 4) as *const usize) } != userdata as usize
        {
            bail!("native reset notification identity changed");
        }
        hooks.notification.store(true, Ordering::Release);
    }
    hooks.ready.store(true, Ordering::Release);
    transaction.commit();
    log::info!("[DEPTH] Native attachment lifecycle installed; waiting for device admission");
    Ok(())
}

/// Effective native attachment policy for the existing graphics diagnostics.
/// No setting or native object is changed by this query.
pub(crate) fn status_label() -> &'static str {
    let Some(hooks) = HOOKS.get().filter(|h| h.admitted()) else {
        return "Not installed";
    };
    match hooks.policy.load(Ordering::Acquire) {
        DORMANT => "Waiting for device",
        ADMITTED => "Waiting for allocation policy",
        ACTIVE => "Single-sample acquisition; OMV AA settings apply",
        _ => "Owned depth initialization unavailable",
    }
}

/// Whether deferred admission is waiting for safe allocation-policy activation.
pub(super) fn preparing() -> bool {
    HOOKS.get().is_some_and(|h| {
        h.admitted() && matches!(h.policy.load(Ordering::Acquire), DORMANT | ADMITTED)
    })
}

/// Admit temporal preparation only while the selected world source still has
/// an owned backing in the committed generation. This runs once per epoch;
/// the small attachment registry is not searched per draw or pixel.
pub(super) fn world_source_ready(device: usize, width: u32, height: u32) -> bool {
    let Some(hooks) = HOOKS.get() else {
        return false;
    };
    if !hooks.admitted()
        || !hooks.on_thread()
        || !hooks.capable.load(Ordering::Acquire)
        || hooks.resetting.load(Ordering::Acquire)
        || hooks.poisoned.load(Ordering::Acquire)
    {
        return false;
    }
    // The admitted renderer and selected group are live on the renderer thread.
    let source = unsafe {
        if *((hooks.renderer + 0x288) as *const usize) != device {
            return false;
        }
        let Some(target) = super::current_world_rendered_texture() else {
            return false;
        };
        let Ok(group) = super::read_world_group(target) else {
            return false;
        };
        let Ok(color) = super::read_group_color_surface(group) else {
            return false;
        };
        let Ok(desc) = Surface9::raw_desc(color) else {
            return false;
        };
        if desc.Width != width || desc.Height != height {
            return false;
        }
        let Ok(source) = super::read_group_depth_surface(group) else {
            return false;
        };
        source as usize
    };
    hooks.attachments.try_lock().is_some_and(|registry| {
        registry.values().any(|a| {
            a.surface == source
                && a.native.Width >= width
                && a.native.Height >= height
                && a.generation == hooks.generation.load(Ordering::Acquire)
        })
    })
}

// Native renderer lifecycle (0x00872570) waits for this worker's
// +0x49 acknowledgement. +0x48 is the pause request; the worker publishes the
// acknowledgement before waiting on its +0x30 semaphore. Only the main-thread
// resume route releases that wait. Do not pause/resume the worker ourselves.
unsafe fn native_policy_change_ready() -> bool {
    unsafe {
        let worker = *(LOADING_WORKER as *const usize);
        if validate_memory_range(worker as *const c_void, 0x4C).is_err()
            || core::ptr::read_volatile((worker + 0x48) as *const u8) == 0
            || core::ptr::read_volatile((worker + 0x49) as *const u8) == 0
            || core::ptr::read_volatile((worker + 0x4A) as *const u8) != 0
        {
            return false;
        }
        let movie = *(0x0126FAC4 as *const usize);
        validate_memory_range(movie as *const c_void, 0x14).is_ok()
            && *((movie + 0x0C) as *const usize) == 0
            && *((movie + 0x10) as *const usize) == 0
    }
}

unsafe extern "thiscall" fn frame_finished(main: *mut c_void) {
    let Some(hooks) = HOOKS.get() else { return };
    let Ok(original) = hooks.frame_finished.original() else {
        return;
    };
    unsafe { original(main) };
    service_initialization();
}

/// Admit compatible backing after frame teardown, before provider selection
/// can miss its initializing clear. Only the selected OMV provider activates
/// single-sample allocation policy; old entries keep their keys and owners.
/// All renderer/global identities were validated at deferred installation.
fn service_initialization() {
    let Some(hooks) = HOOKS.get() else { return };
    if !hooks.admitted()
        || !hooks.on_thread()
        || !matches!(hooks.policy.load(Ordering::Acquire), DORMANT | ADMITTED)
    {
        return;
    }
    let selected = crate::backend::active_depth_provider() == super::DepthProvider::FalloutNewVegas;
    if hooks.policy.load(Ordering::Acquire) == ADMITTED && !selected {
        // Device capabilities are settled for this generation. A disabled or
        // external provider does no recurring D3D queries or worker inspection.
        return;
    }
    // Post-frame native code has returned. No drawing or target-use interval
    // may overlap admission, and an existing display request takes priority.
    unsafe {
        if *((hooks.renderer + 0x200) as *const u32) != 0
            || *((hooks.renderer + 0x208) as *const u8) != 0
            || *(RESET_REQUEST as *const u8) != 0
        {
            return;
        }
        let ptr = *((hooks.renderer + 0x288) as *const *mut c_void);
        let Some(device) = Device9Ref::from_raw_void(ptr) else {
            return;
        };
        if device.test_cooperative_level().is_err() {
            return;
        }
        if hooks.policy.load(Ordering::Acquire) == DORMANT {
            let admission = (|| -> Result<()> {
                let group = *((hooks.renderer + 0x884) as *const usize);
                validate_memory_range(group as *const c_void, 0x24)?;
                let buffer = *((group + 0x20) as *const usize);
                validate_memory_range(buffer as *const c_void, 0x14)?;
                let data = *((buffer + 0x10) as *const usize);
                validate_memory_range(data as *const c_void, 0x18)?;
                let surface = *((data + 0x14) as *const *mut c_void);
                let depth = Surface9::raw_desc(surface)?;
                if depth.Format != D3DFMT_D24S8 {
                    bail!("default depth format is outside the verified D24S8 contract");
                }
                let color = device.back_buffer(0, 0)?.desc()?;
                // Stock FNV requests single-sample presentation. An external
                // override needs a separate color/depth routing contract: the
                // manager may share this default depth by its native metadata.
                // Never change policy into a mismatched pair or attempt Reset.
                if depth.MultiSampleType != D3DMULTISAMPLE_NONE
                    || color.MultiSampleType != D3DMULTISAMPLE_NONE
                {
                    bail!("multisampled presentation requires offscreen scene routing");
                }
                device.check_depth_texture_support(D3DFMT_INTZ)?;
                device.check_depth_stencil_match(color.Format, D3DFMT_INTZ)?;
                hooks.mrt_count.store(
                    device.simultaneous_render_target_count()?.clamp(1, 4),
                    Ordering::Release,
                );
                hooks.capable.store(true, Ordering::Release);
                hooks.policy.store(ADMITTED, Ordering::Release);
                Ok(())
            })();
            if let Err(error) = admission {
                hooks.policy.store(FAILED, Ordering::Release);
                log::error!(
                    "[DEPTH] Sampleable depth admission failed; native allocation and backing retained: {error:#}"
                );
                return;
            }
        }
        if !selected || !native_policy_change_ready() {
            return;
        }
        // Only these two native globals select subsequent scene policy and
        // pool keys. Native checkout rejects old entries with different sample
        // counts/flags, without destroying their backing or retained aliases.
        // The parked worker cannot observe a partially changed policy, and no
        // native/COM call occurs between these writes and publication.
        for address in SAMPLE_GLOBALS {
            *(address as *mut u32) = 0;
        }
        hooks.policy.store(ACTIVE, Ordering::Release);
        log::info!(
            "[DEPTH] Single-sample target acquisition active; existing resources retained without renderer reset"
        );
    }
}

unsafe extern "thiscall" fn clear_buffer(renderer: *mut c_void, rectangle: *const f32, flags: u32) {
    let Some(hooks) = HOOKS.get() else { return };
    let Ok(original) = hooks.clear.original() else {
        return;
    };
    if flags & 6 == 6 && hooks.adopts() && renderer as usize == hooks.renderer {
        // Current group/buffer/data are held by the native ClearBuffer caller.
        // This boundary follows native binding and precedes any new pixels.
        let preparation = (|| -> Result<()> {
            // These scalar conditions already exclude a complete native clear.
            // Reject before walking attachments or querying the D3D device.
            if unsafe {
                *((hooks.renderer + 0x6FC) as *const u8) != 0
                    || *((hooks.renderer + 0x6CC) as *const u32) != 0
                    || *((hooks.renderer + 0x6D0) as *const u32) != 0
            } {
                return Ok(());
            }

            // The native caller owns the current group, its depth buffer and
            // renderer data throughout ClearBuffer under renderer serialization
            // (E6F0C0/E6F0E2, E6F330..E6F415). These are borrowed live native
            // objects, not asynchronous pointers. Already-owned identities need
            // no VirtualQuery, COM query or allocation on recurring clears.
            let group = unsafe { *((hooks.renderer + 0x888) as *const usize) };
            if group == 0 {
                return Ok(());
            }
            let buffer = unsafe { *((group + 0x20) as *const usize) };
            if buffer == 0 {
                return Ok(());
            }
            let data = unsafe { *((buffer + 0x10) as *const usize) };
            if data == 0 {
                return Ok(());
            }
            {
                let Some(registry) = hooks.attachments.try_lock() else {
                    return Ok(());
                };
                if registry.contains_key(&data) {
                    return Ok(());
                }
            }
            // The stock width/height getters (EE8490/EE84B0) read RT0's
            // Ni2DBuffer +8/+C. Native depth recreation fills those same fields
            // from GetDesc via A8F080. A smaller native clear cannot cover the
            // shared depth allocation. This rejection needs no COM queries or
            // memory-region scans and retains no negative cache: a subsequent
            // full-size group must remain eligible. If a provider replaces the
            // getters, defer to the existing D3D coverage validation instead.
            let group_table = unsafe { *(group as *const usize) };
            if group_table == 0x011010EC
                && unsafe { *((group_table + 0x8C) as *const usize) } == 0x00EE8490
                && unsafe { *((group_table + 0x90) as *const usize) } == 0x00EE84B0
            {
                let color = unsafe { *((group + 0x0C) as *const usize) };
                if color == 0 {
                    return Ok(());
                }
                let color_extent =
                    unsafe { core::ptr::read_unaligned((color + 8) as *const [u32; 2]) };
                let depth_extent =
                    unsafe { core::ptr::read_unaligned((buffer + 8) as *const [u32; 2]) };
                if color_extent != depth_extent {
                    return Ok(());
                }
            }
            validate_memory_range(group as *const c_void, 0x24)?;
            validate_memory_range(buffer as *const c_void, 0x14)?;
            validate_memory_range(data as *const c_void, 0x18)?;
            let table = unsafe { *(data as *const usize) };
            let Some(index) = DEPTH_TABLES.iter().position(|t| *t == table) else {
                return Ok(());
            };
            if hooks
                .clear_attempts
                .try_lock()
                .is_none_or(|attempts| attempts.contains(&data))
            {
                return Ok(());
            }
            let ptr = unsafe { *((data + 0x14) as *const *mut c_void) };
            let source = unsafe { Surface9::retain_raw(ptr)? };
            let rect = if rectangle.is_null() {
                None
            } else {
                validate_memory_range(rectangle.cast(), 16)?;
                Some(unsafe { core::ptr::read_unaligned(rectangle.cast::<[f32; 4]>()) })
            };
            let device_ptr = unsafe { *((hooks.renderer + 0x288) as *const *mut c_void) };
            let device =
                unsafe { Device9Ref::from_raw_void(device_ptr) }.context("null clear device")?;
            let clear = super::depth_adoption::NativeClear {
                flags,
                rectangle: rect,
                origin: unsafe {
                    [
                        *((hooks.renderer + 0x6CC) as *const u32),
                        *((hooks.renderer + 0x6D0) as *const u32),
                    ]
                },
                depth: unsafe { *((hooks.renderer + 0x5E4) as *const f32) },
                stencil: unsafe { *((hooks.renderer + 0x5E8) as *const u32) },
            };
            // Reserve before preparation. A driver/allocation failure is retried
            // only after this native backing's release/recreation, not per frame.
            {
                let Some(mut attempts) = hooks.clear_attempts.try_lock() else {
                    return Ok(());
                };
                attempts
                    .try_reserve(1)
                    .context("clear adoption admission allocation failed")?;
                attempts.insert(data);
            }
            let prepared = super::depth_adoption::prepare(
                &device,
                &source,
                &clear,
                hooks.mrt_count.load(Ordering::Acquire),
            )?;
            let Some(prepared) = prepared else {
                if let Some(mut attempts) = hooks.clear_attempts.try_lock() {
                    attempts.remove(&data);
                }
                return Ok(());
            };
            unsafe { adopt(hooks, data, device_ptr, Some(prepared)) };
            // Use the installed native binder to update its cached identity.
            // The normal binder wrapper retains the unused-backup rollback.
            if unsafe { bind(index, data as *mut c_void, device_ptr) }
                && hooks
                    .attachments
                    .try_lock()
                    .is_some_and(|r| r.contains_key(&data))
                && !hooks.adoption_logged.swap(true, Ordering::AcqRel)
            {
                log::info!(
                    "[DEPTH] Existing single-sample backing adopted before full depth/stencil clear; no initialization reset"
                );
            }
            Ok(())
        })();
        if let Err(error) = preparation {
            if hooks.adoption_failures.fetch_add(1, Ordering::Relaxed) < 8 {
                log::warn!(
                    "[DEPTH] Full-clear adoption unavailable; native ownership retained: {error:#}"
                );
            }
        }
    }
    unsafe { original(renderer, rectangle, flags) };
}

// All following callbacks have the exact supported x86 native ABI. The engine
// caller keeps arguments alive across the predecessor. Raw field access is
// limited to layouts proven in the native audit; no Rust reference escapes.
unsafe extern "thiscall" fn depth_create(
    renderer: *mut c_void,
    buffer: *mut c_void,
    format: *mut c_void,
    preference: u32,
) -> bool {
    let Some(hooks) = HOOKS.get() else {
        return false;
    };
    let Ok(original) = hooks.depth_create.original() else {
        return false;
    };
    // Preserve per-resource preferences, including retained old pool entries
    // rebuilt by native device-loss recovery. Allocation policy belongs to the
    // native property/key producer, not to this backing constructor.
    let result = unsafe { original(renderer, buffer, format, preference) };
    if result && hooks.adopts() && !buffer.is_null() {
        let data = unsafe { *((buffer as usize + 0x10) as *const usize) };
        let device = unsafe { *((renderer as usize + 0x288) as *const *mut c_void) };
        unsafe {
            adopt(hooks, data, device, None);
        }
    }
    result
}

unsafe fn recreate(index: usize, data: *mut c_void, device: *mut c_void) -> bool {
    let Some(hooks) = HOOKS.get() else {
        return false;
    };
    let Ok(original) = hooks.recreate[index].original() else {
        return false;
    };
    let result = unsafe { original(data, device) };
    if result && hooks.adopts() && (index == 1 || hooks.resetting.load(Ordering::Acquire)) {
        unsafe {
            adopt(hooks, data as usize, device, None);
        }
    }
    result
}

unsafe extern "thiscall" fn recreate_default(data: *mut c_void, device: *mut c_void) -> bool {
    unsafe { recreate(0, data, device) }
}
unsafe extern "thiscall" fn recreate_additional(data: *mut c_void, device: *mut c_void) -> bool {
    unsafe { recreate(1, data, device) }
}

unsafe fn adopt(
    hooks: &Hooks,
    data: usize,
    device: *mut c_void,
    prepared: Option<(Texture9, Surface9)>,
) {
    if data == 0 || hooks.poisoned.load(Ordering::Acquire) {
        return;
    }
    let result = (|| -> Result<()> {
        validate_memory_range(data as *const c_void, 0x20)?;
        if !DEPTH_TABLES.contains(&unsafe { *(data as *const usize) }) {
            bail!("unknown native depth class");
        }
        {
            let registry = hooks.attachments.try_lock().context("depth owner busy")?;
            if registry.contains_key(&data) {
                return Ok(());
            }
        }
        let field = (data + 0x14) as *mut *mut c_void;
        let native_ptr = unsafe { *field };
        let desc = unsafe { Surface9::raw_desc(native_ptr)? };
        if desc.Format != D3DFMT_D24S8 || desc.MultiSampleType != D3DMULTISAMPLE_NONE {
            return Ok(());
        }
        let device = unsafe { Device9Ref::from_raw_void(device) }.context("null depth device")?;
        let (texture, surface) = match prepared {
            Some(prepared) => prepared,
            None => {
                let texture =
                    device.create_depth_stencil_texture(desc.Width, desc.Height, D3DFMT_INTZ)?;
                let surface = texture.surface_level(0)?;
                (texture, surface)
            }
        };
        let surface_ptr = surface.as_raw() as usize;
        let mut registry = hooks.attachments.try_lock().context("depth owner busy")?;
        if registry.contains_key(&data) {
            return Ok(());
        }
        registry
            .try_reserve(1)
            .context("depth owner allocation failed")?;
        if unsafe { *field } != native_ptr {
            bail!("native depth changed during preparation");
        }
        // All fallible work precedes transfer. Native +0x14 gets the new
        // GetSurfaceLevel reference; the old owned reference moves to backup.
        let backup = unsafe { Surface9::from_owned_raw(native_ptr)? };
        unsafe {
            *field = surface.into_raw();
        }
        registry.insert(
            data,
            Attachment {
                _texture: texture,
                surface: surface_ptr,
                backup: Some(backup),
                backup_bind_serial: hooks.untracked_bind_serial.load(Ordering::Acquire),
                native: desc,
                generation: hooks.generation.load(Ordering::Acquire),
                checked_colors: ColorValidationCache::default(),
            },
        );
        Ok(())
    })();
    if let Err(error) = result {
        // Optional sampleable storage is independent of native Reset success.
        // Preparation failed before transfer: keep the valid native backing.
        if hooks.adoption_failures.fetch_add(1, Ordering::Relaxed) < 8 {
            log::warn!(
                "[DEPTH] Generation {} retains native backing; sampleable adoption failed: {error:#}",
                hooks.generation.load(Ordering::Acquire)
            );
        }
    }
}

fn retire(hooks: &Hooks, data: usize) -> Option<Attachment> {
    if let Some(mut attempts) = hooks.clear_attempts.try_lock() {
        attempts.remove(&data);
    } else {
        hooks.poisoned.store(true, Ordering::Release);
    }
    if let Some(mut registry) = hooks.attachments.try_lock() {
        registry.remove(&data)
    } else {
        // Do not dereference this identity again. Retained COM owners remain
        // safe but must be drained before a subsequent Reset may proceed.
        hooks.poisoned.store(true, Ordering::Release);
        None
    }
}

unsafe fn release(index: usize, data: *mut c_void) {
    let Some(hooks) = HOOKS.get() else {
        return;
    };
    let Ok(original) = hooks.release[index].original() else {
        return;
    };
    let retired = retire(hooks, data as usize);
    unsafe {
        original(data);
    }
    drop(retired);
}

unsafe extern "thiscall" fn release_default(data: *mut c_void) {
    unsafe {
        release(0, data);
    }
}
unsafe extern "thiscall" fn release_additional(data: *mut c_void) {
    unsafe {
        release(1, data);
    }
}

unsafe fn destroy(index: usize, data: *mut c_void, flags: u32) -> *mut c_void {
    let Some(hooks) = HOOKS.get() else {
        return data;
    };
    let Ok(original) = hooks.destroy[index].original() else {
        return data;
    };
    let retired = retire(hooks, data as usize);
    let result = unsafe { original(data, flags) };
    drop(retired);
    result
}

unsafe extern "thiscall" fn destroy_default(data: *mut c_void, flags: u32) -> *mut c_void {
    unsafe { destroy(0, data, flags) }
}
unsafe extern "thiscall" fn destroy_additional(data: *mut c_void, flags: u32) -> *mut c_void {
    unsafe { destroy(1, data, flags) }
}

unsafe fn bind(index: usize, data: *mut c_void, device_ptr: *mut c_void) -> bool {
    let Some(hooks) = HOOKS.get() else {
        return false;
    };
    let Ok(original) = hooks.bind[index].original() else {
        return false;
    };
    let expected = {
        let Some(registry) = hooks.attachments.try_lock() else {
            // The native target-use critical section owns data and its COM
            // backing. Missing our journal must not suppress its valid bind.
            // Mark before chaining so no later failure can roll back pixels
            // rendered through a successfully bound but unobserved surface.
            hooks.mark_untracked_bind();
            return unsafe { original(data, device_ptr) };
        };
        registry.get(&(data as usize)).map(|a| {
            (
                a.surface,
                a.native,
                a.generation,
                a.checked_colors.identities(),
                a.backup.is_some(),
            )
        })
    };
    let Some((surface, native, generation, checked, needs_backup_retirement)) = expected else {
        return unsafe { original(data, device_ptr) };
    };
    if hooks.poisoned.load(Ordering::Acquire)
        || generation != hooks.generation.load(Ordering::Acquire)
        || unsafe { *((data as usize + 0x14) as *const usize) } != surface
    {
        return false;
    }
    // Main and LoadingMenu renderers both bind through the native target-use
    // critical section. A previously adopted identity must remain usable by
    // either caller; only allocation/conversion admission is main-thread-only.
    let compatible = (|| -> Result<Option<CheckedColors>> {
        let device =
            unsafe { Device9Ref::from_raw_void(device_ptr) }.context("null binding device")?;
        validate_colors(
            &device,
            &native,
            hooks.mrt_count.load(Ordering::Acquire),
            checked,
        )
    })();
    let result = compatible.is_ok() && unsafe { original(data, device_ptr) };
    if result {
        let mut colors = compatible.ok().flatten();
        if colors.is_some() || needs_backup_retirement {
            let mut retired_colors = None;
            let backup = if let Some(mut registry) = hooks.attachments.try_lock() {
                registry.get_mut(&(data as usize)).and_then(|a| {
                    if let Some(colors) = colors.take() {
                        retired_colors = a.checked_colors.publish(colors);
                    }
                    a.backup.take()
                })
            } else {
                hooks.mark_untracked_bind();
                None
            };
            // Never release COM owners while holding the registry lock.
            drop(retired_colors);
            drop(backup);
        }
        return true;
    }
    // Rollback is legal only before the first successful use. The old native
    // surface has never become a stale rendering history at that point.
    let Some(mut registry) = hooks.attachments.try_lock() else {
        return false;
    };
    let Some(attachment) = registry.get_mut(&(data as usize)) else {
        return false;
    };
    let serial = hooks.untracked_bind_serial.load(Ordering::Acquire);
    if serial == u32::MAX || attachment.backup_bind_serial != serial {
        // An unobserved success may already have used this surface. Its old
        // backing is no longer a rollback candidate; retire it outside lock.
        let stale_backup = attachment.backup.take();
        drop(registry);
        drop(stale_backup);
        return false;
    }
    let Some(backup) = attachment.backup.take() else {
        return false;
    };
    unsafe {
        *((data as usize + 0x14) as *mut *mut c_void) = backup.into_raw();
    }
    let retired = registry.remove(&(data as usize));
    drop(registry);
    let failed_surface = unsafe { Surface9::from_owned_raw(surface as *mut c_void) }.ok();
    let recovered = unsafe { original(data, device_ptr) };
    drop(failed_surface);
    drop(retired);
    log::warn!("[DEPTH] Initial sampleable attachment bind failed; native backing restored");
    recovered
}

unsafe extern "thiscall" fn bind_default(data: *mut c_void, device: *mut c_void) -> bool {
    unsafe { bind(0, data, device) }
}
unsafe extern "thiscall" fn bind_additional(data: *mut c_void, device: *mut c_void) -> bool {
    unsafe { bind(1, data, device) }
}

unsafe extern "C" fn reset_notification(before: bool, userdata: *mut c_void) -> bool {
    let Some(hooks) = HOOKS.get() else {
        return true;
    };
    if userdata != (&**hooks as *const Hooks).cast_mut().cast::<c_void>() || !hooks.admitted() {
        return true;
    }
    if !hooks.on_thread() {
        return false;
    }
    if before {
        hooks.resetting.store(true, Ordering::Release);
        // A real reset can change presentation and allocation policy. Admit
        // the rebuilt device again at the idle boundary; do not adopt fresh
        // depth during reconstruction using the previous device's capabilities.
        hooks.capable.store(false, Ordering::Release);
        hooks.policy.store(DORMANT, Ordering::Release);
        let device = unsafe { *((hooks.renderer + 0x288) as *const *mut c_void) };
        if !unsafe { crate::hooks::release_for_native_reset(device) } {
            log::warn!("[DEPTH] Reset deferred before D3D Reset; an OMV resource owner is busy");
            return false;
        }
        let Some(mut attempts) = hooks.clear_attempts.try_lock() else {
            log::warn!("[DEPTH] Reset deferred before D3D Reset; depth clear tracking is busy");
            return false;
        };
        attempts.clear();
        drop(attempts);
        let Some(mut registry) = hooks.attachments.try_lock() else {
            log::warn!(
                "[DEPTH] Reset deferred before D3D Reset; depth attachment ownership is busy"
            );
            return false;
        };
        let retired = core::mem::take(&mut *registry);
        drop(registry);
        drop(retired);
        hooks.poisoned.store(false, Ordering::Release);
        hooks.generation.fetch_add(1, Ordering::AcqRel);
        true
    } else {
        hooks.resetting.store(false, Ordering::Release);
        // A later notification may still fail; this republishes only the
        // device. Capture admission separately verifies its actual attachment.
        super::publish_initial_d3d_device().is_ok()
    }
}
