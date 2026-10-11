//! Single-sample coverage for the native grass family, independent of effects.
//!
//! The native grass shader bank keeps its TMS programs when OMV's allocation
//! policy removes MSAA. Deferred preparation pairs exact native bytecode with
//! its shipped non-TMS counterpart. Grass-only SetupGeometry/PostRender slots
//! bracket both ordinary and partitioned native primitive submissions; raw
//! device changes are restored before native cached-state teardown.
//!
//! No native shader wrapper, sample global, material threshold, depth resource
//! or engine state cache is mutated. A zero-initialized pointer first publishes
//! the process owner at DeferredInit. Device resources clear before Reset;
//! preparation runs only at native bank creation and frame services. Draws
//! perform a seven-entry lookup, a sample check and a four-state journal, with
//! no compilation, allocation, file I/O, blocking lock or per-draw logging.

use core::{ffi::c_void, ptr};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use anyhow::{Context, Result, bail};
use libpsycho::os::windows::{
    directx9::*,
    hook::{pointer::PointerSlotHookContainer, transaction::ModificationTransaction},
    memory::validate_memory_range,
    winapi::get_current_thread_id,
};
use parking_lot::Mutex;

// Audited FNV 1.4.0.525 contracts are recorded in the owning depth document.
const GRASS_VTABLE: usize = 0x010B8980;
const GRASS_CACHE: usize = 0x011F9550;
const CURRENT_PASS: usize = 0x0126F74C;
const CURRENT_PASS_ID: usize = 0x011FFE30;
const HDR_FLAG: usize = 0x011F941E;
const COVERAGE_VENDOR: usize = 0x011F94B8;
const STATE_FAMILY_MAP: usize = 0x011FFA30;
const STATE_LOCKS: usize = 0x011FF9D8;
const STATE_FAMILY_COUNT: usize = 21;
const BANK_OFFSET: usize = 0x188;
const PIXEL_WRAPPER_VTABLE: usize = 0x010EF7D4;
const BANK_COUNT: usize = 7;
const NATIVE_PAIRS: &[u8] = include_bytes!("../../shaders/native_grass/native_pairs.bin");

type BuildFn = unsafe extern "thiscall" fn(*mut c_void);
type SetupFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, u32, *mut c_void) -> u32;
type FinishFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

static OWNER: AtomicPtr<Owner> = AtomicPtr::new(ptr::null_mut());

struct Owner {
    build: PointerSlotHookContainer<BuildFn>,
    setup: PointerSlotHookContainer<SetupFn>,
    finish: PointerSlotHookContainer<FinishFn>,
    state: Mutex<State>,
    admitted: AtomicBool,
    restore_failed: AtomicBool,
    thread: u32,
}

struct State {
    pairs: Vec<NativePair>,
    cache: [Option<PreparedShader>; BANK_COUNT],
    pending: Option<CoverageScope>,
    device: usize,
}

/// Pinned native program and its optional verified single-sample counterpart.
/// Both references belong to the deferred render thread until Reset.
pub(super) struct PreparedShader {
    // Pinning the source prevents pointer reuse while its cache entry exists.
    pub(super) source: PixelShader9,
    pub(super) replacement: Option<PixelShader9>,
}

impl PreparedShader {
    /// Pair an actual provider program by executable bytecode at preparation.
    /// Takes ownership of the source reference; returns an error for unverified
    /// bytecode or failed D3D resource creation. Allocates outside draw callbacks.
    pub(super) fn prepare(
        device: &Device9Ref<'_>,
        source: PixelShader9,
        pairs: &[NativePair],
    ) -> Result<Self> {
        let code = source.function()?;
        let pair = pairs
            .iter()
            .find(|pair| pair.tms == code || pair.single == code)
            .context("pixel program has no verified native single-sample counterpart")?;
        let replacement = Some(if code == pair.single {
            source.clone()
        } else {
            device.create_pixel_shader(&pair.single)?
        });
        Ok(Self {
            source,
            replacement,
        })
    }
}

/// Immutable compiled SDP pair, decoded once by the deferred owner.
pub(super) struct NativePair {
    #[cfg(test)]
    pub(super) variant: u32,
    pub(super) tms: Vec<u32>,
    pub(super) single: Vec<u32>,
}

/// Decode the immutable original SDP records outside the draw path.
/// Allocates owned DWORD programs; rejects incomplete or invalid record bounds.
pub(super) fn native_pairs() -> Result<Vec<NativePair>> {
    let mut data = NATIVE_PAIRS;
    let mut pairs = Vec::new();
    while !data.is_empty() {
        if data.len() < 12 {
            bail!("truncated grass record header");
        }
        let word = |bytes: &[u8]| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let variant = word(&data[..4]);
        let tms_len = word(&data[4..8]) as usize;
        let single_len = word(&data[8..12]) as usize;
        let end = 12usize
            .checked_add(tms_len)
            .and_then(|n| n.checked_add(single_len))
            .context("grass record size overflow")?;
        if variant > 6 || end > data.len() {
            bail!("invalid grass record");
        }
        let tms = dword_aligned_shader_bytecode(&data[12..12 + tms_len])?;
        let single = dword_aligned_shader_bytecode(&data[12 + tms_len..end])?;
        pairs.push(NativePair {
            #[cfg(test)]
            variant,
            tms,
            single,
        });
        data = &data[end..];
    }
    Ok(pairs)
}

fn owner() -> Option<&'static Owner> {
    let owner = OWNER.load(Ordering::Acquire);
    // Published boxes are process-owned and never freed while hooks exist.
    unsafe { owner.as_ref() }
}

/// Install only the grass-family dispatch slots at the deferred handoff.
///
/// Chains each current provider atomically. Any activation failure rolls back
/// all three slots before admission; repeated calls are idempotent.
pub(crate) fn install() -> Result<()> {
    if let Some(owner) = owner() {
        if owner.admitted.load(Ordering::Acquire) {
            return Ok(());
        }
        bail!("grass dispatch installation previously failed");
    }
    for (address, bytes) in [
        (GRASS_VTABLE, 0x140),
        (GRASS_CACHE, 4),
        (CURRENT_PASS, 4),
        (CURRENT_PASS_ID, 4),
        (HDR_FLAG, 1),
        (COVERAGE_VENDOR, 4),
        (STATE_FAMILY_MAP, 0x3FC),
        (STATE_LOCKS, STATE_FAMILY_COUNT * 4),
    ] {
        validate_memory_range(address as *const c_void, bytes)?;
    }
    let state = State {
        pairs: native_pairs()?,
        cache: std::array::from_fn(|_| None),
        pending: None,
        device: 0,
    };
    let owner = Box::new(Owner {
        build: PointerSlotHookContainer::new(),
        setup: PointerSlotHookContainer::new(),
        finish: PointerSlotHookContainer::new(),
        state: Mutex::new(state),
        admitted: AtomicBool::new(false),
        restore_failed: AtomicBool::new(false),
        thread: get_current_thread_id(),
    });
    unsafe {
        owner.build.init(
            "FNV grass shader bank",
            (GRASS_VTABLE + 0x13C) as *mut *mut c_void,
            build_detour,
        )?;
        owner.setup.init(
            "FNV grass SetupGeometry",
            (GRASS_VTABLE + 0x6C) as *mut *mut c_void,
            setup_detour,
        )?;
        owner.finish.init(
            "FNV grass PostRender",
            (GRASS_VTABLE + 0x8C) as *mut *mut c_void,
            finish_detour,
        )?;
    }
    let owner_ptr = Box::into_raw(owner);
    if OWNER
        .compare_exchange(
            ptr::null_mut(),
            owner_ptr,
            Ordering::Release,
            Ordering::Acquire,
        )
        .is_err()
    {
        // No hook has been activated, so this unpublished owner can be freed.
        unsafe {
            drop(Box::from_raw(owner_ptr));
        }
        bail!("grass owner already published");
    }
    let owner = unsafe { &*owner_ptr };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_pointer(&owner.build)?;
    transaction.enable_pointer(&owner.setup)?;
    transaction.enable_pointer(&owner.finish)?;
    transaction.commit();
    owner.admitted.store(true, Ordering::Release);
    service_frame();
    log::info!("[GRASS] Single-sample native coverage correction installed");
    Ok(())
}

unsafe extern "thiscall" fn build_detour(selector: *mut c_void) {
    let Some(owner) = owner() else { return };
    let Ok(original) = owner.build.original() else {
        return;
    };
    unsafe { original(selector) };
    if owner.admitted.load(Ordering::Acquire) {
        // Native bank construction already owns resource creation. This is
        // not the geometry callback, and runs before consumers see the bank.
        prepare_bank(selector);
    }
}

unsafe extern "thiscall" fn setup_detour(
    selector: *mut c_void,
    geometry: *mut c_void,
    partition: *mut c_void,
    data: u32,
    buffer: *mut c_void,
) -> u32 {
    let Some(owner) = owner() else { return 0 };
    let Ok(original) = owner.setup.original() else {
        return 0;
    };
    // Partitioned grass submits several SetupGeometry calls before PostRender.
    // Each closes its prior scope before native stream/index setup resumes.
    finish_draw();
    let result = unsafe { original(selector, geometry, partition, data, buffer) };
    if owner.admitted.load(Ordering::Acquire) {
        prepare_draw(selector);
    }
    result
}

unsafe extern "thiscall" fn finish_detour(selector: *mut c_void, geometry: *mut c_void) {
    let Some(owner) = owner() else { return };
    finish_draw();
    if let Ok(original) = owner.finish.original() {
        unsafe { original(selector, geometry) };
    }
}

/// Close any draw journal and prepare changed bank resources before presentation.
///
/// No effects toggle gates this service: allocation policy can outlive effects.
pub(crate) fn service_frame() {
    finish_draw();
    let Some(owner) = owner() else { return };
    if owner.thread != get_current_thread_id() {
        return;
    }
    if owner.restore_failed.swap(false, Ordering::AcqRel) {
        log::error!("[GRASS] Coverage state restore failed; correction waits for state recovery");
    }
    if !owner.admitted.load(Ordering::Acquire) {
        return;
    }
    // B55560 publishes the reference-owned grass selector at index 2.
    let selector = unsafe { *(GRASS_CACHE as *const *mut c_void) };
    if !selector.is_null() {
        prepare_bank(selector);
    }
}

fn prepare_bank(selector: *mut c_void) {
    let Some(owner) = owner() else { return };
    if owner.thread != get_current_thread_id() {
        return;
    }
    let Some(mut state) = owner.state.try_lock() else {
        return;
    };
    if state.pending.is_some() {
        return;
    }
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };
    // Frame services validate the reference-owned selector; the builder passes
    // its live `this`. Bank entries hold native NiD3DPixelShader references.
    if validate_memory_range(selector, 0x1E0).is_err()
        || unsafe { *(selector as *const usize) } != GRASS_VTABLE
    {
        return;
    }
    if state.device != device_ptr as usize {
        state.cache = std::array::from_fn(|_| None);
        state.device = device_ptr as usize;
    }
    for index in 0..BANK_COUNT {
        let wrapper =
            unsafe { *((selector as usize + BANK_OFFSET + index * 4) as *const *mut c_void) };
        let Some(raw) = (unsafe { pixel_handle(wrapper) }) else {
            state.cache[index] = None;
            continue;
        };
        if state.cache[index]
            .as_ref()
            .is_some_and(|entry| entry.source.as_raw() == raw)
        {
            continue;
        }
        let prepared = (|| -> Result<PreparedShader> {
            let source = unsafe { PixelShader9::retain_raw(raw) }?;
            // Compare executable bytes, never names, package IDs or mod IDs.
            PreparedShader::prepare(&device, source, &state.pairs)
        })();
        match prepared {
            Ok(entry) => state.cache[index] = Some(entry),
            Err(error) => {
                // Pin an unsupported program too, so frame service does not
                // repeatedly query or log the same unavailable capability.
                state.cache[index] =
                    unsafe { PixelShader9::retain_raw(raw) }
                        .ok()
                        .map(|source| PreparedShader {
                            source,
                            replacement: None,
                        });
                log::warn!(
                    "[GRASS] Native bank slot {index} retains its provider program: {error:#}"
                );
            }
        }
    }
}

/// Read a wrapper only in a live native selector/pass transaction.
unsafe fn pixel_handle(wrapper: *mut c_void) -> Option<*mut c_void> {
    if wrapper.is_null() {
        return None;
    }
    if validate_memory_range(wrapper, 0x30).is_err()
        || unsafe { *(wrapper as *const usize) } != PIXEL_WRAPPER_VTABLE
    {
        return None;
    }
    let raw = unsafe { *((wrapper as usize + 0x2C) as *const *mut c_void) };
    if !raw.is_null() {
        return Some(raw);
    }
    let backup = unsafe { *((wrapper as usize + 0x1C) as *const *mut c_void) };
    (!backup.is_null()).then_some(backup)
}

fn prepare_draw(selector: *mut c_void) {
    let Some(owner) = owner() else { return };
    if owner.thread != get_current_thread_id() {
        return;
    }
    let Some(mut state) = owner.state.try_lock() else {
        return;
    };
    if state.pending.is_some() {
        return;
    }
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    if state.device != device_ptr as usize {
        return;
    }
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };
    // BAA3F0 maps these two exact dispatch ranges into the 44 native passes.
    // Verify the current pointer against that row before borrowing its fields.
    let pass_id = unsafe { *(CURRENT_PASS_ID as *const u32) };
    let row = if (22..=61).contains(&pass_id) {
        pass_id - 22
    } else if (604..=647).contains(&pass_id) {
        pass_id - 604
    } else {
        return;
    };
    let pass = unsafe { *(CURRENT_PASS as *const usize) };
    if pass == 0
        || pass != unsafe { *((selector as usize + 0x6C + row as usize * 4) as *const usize) }
    {
        return;
    }
    let wrapper = unsafe { *((pass + 0x44) as *const *mut c_void) };
    // Callback lifetime proves this pass and wrapper live; range checking is
    // confined to preparation. Read only the native COM handle here.
    if wrapper.is_null() || unsafe { *(wrapper as *const usize) } != PIXEL_WRAPPER_VTABLE {
        return;
    }
    let raw = unsafe { *((wrapper as usize + 0x2C) as *const *mut c_void) };
    let raw = if raw.is_null() {
        unsafe { *((wrapper as usize + 0x1C) as *const *mut c_void) }
    } else {
        raw
    };
    let Some(replacement) = state
        .cache
        .iter()
        .flatten()
        .find(|entry| entry.source.as_raw() == raw)
        .and_then(|entry| entry.replacement.as_ref())
    else {
        return;
    };
    let hdr = unsafe { *(HDR_FLAG as *const u8) != 0 };
    let mut blend_mask = 0;
    if row < 40 && hdr {
        // B97D90 suppresses a native setter when its state family is locked.
        // Respect the same live map/counters without incrementing them: the
        // raw-device journal owns restoration, not the native cached pass.
        for (bit, render_state) in [D3DRS_ALPHABLENDENABLE, D3DRS_SRCBLEND, D3DRS_DESTBLEND]
            .into_iter()
            .enumerate()
        {
            let family =
                unsafe { *((STATE_FAMILY_MAP + render_state.0 as usize * 4) as *const u32) }
                    as usize;
            if family < STATE_FAMILY_COUNT
                && unsafe { *((STATE_LOCKS + family * 4) as *const u32) } == 0
            {
                blend_mask |= 1 << bit;
            }
        }
    }
    // B98540 uses family 20 for vendor coverage. A locked family retains its
    // provider state, just as the native non-TMS pass would.
    let vendor = if unsafe { *((STATE_LOCKS + 20 * 4) as *const u32) } == 0 {
        unsafe { *(COVERAGE_VENDOR as *const u32) }
    } else {
        0
    };
    match CoverageScope::begin(&device, raw, replacement, blend_mask, vendor) {
        Ok(scope) => state.pending = scope,
        Err(error) => {
            // Failed installation retains its complete journal for retry.
            state.pending = error;
            owner.restore_failed.store(true, Ordering::Release);
        }
    }
}

/// Journal only the shader and states changed by a single-sample grass draw.
/// The render-thread owner retains a failed restore for retry before Reset.
pub(super) struct CoverageScope {
    pixel: PixelShader9,
    states: [(D3DRENDERSTATETYPE, u32); 4],
    changed: usize,
    pixel_changed: bool,
}

impl CoverageScope {
    /// Bind the verified counterpart only for an actual single-sample RT0.
    ///
    /// A changed provider binding or any unavailable capture leaves the draw
    /// untouched. Errors return a journal only if rollback itself failed.
    /// `blend_mask` selects the unlocked enable/source/destination states;
    /// `vendor` selects native coverage state 1 (NVIDIA), 2 (AMD), or none.
    /// The caller must restore a returned scope before native state teardown.
    pub(super) fn begin(
        device: &Device9Ref<'_>,
        source: *mut c_void,
        replacement: &PixelShader9,
        blend_mask: u8,
        vendor: u32,
    ) -> std::result::Result<Option<Self>, Option<Self>> {
        let capture = (|| -> Direct3DResult<Option<Self>> {
            if device.render_target(0)?.desc()?.MultiSampleType != D3DMULTISAMPLE_NONE {
                return Ok(None);
            }
            let pixel = device.current_pixel_shader()?;
            if pixel.as_raw() != source {
                return Ok(None);
            }
            let mut scope = Self {
                pixel,
                states: [(D3DRS_ALPHABLENDENABLE, 0); 4],
                changed: 0,
                pixel_changed: source != replacement.as_raw(),
            };
            let desired = [
                (D3DRS_ALPHABLENDENABLE, 1),
                (D3DRS_SRCBLEND, D3DBLEND_SRCALPHA.0 as u32),
                (D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA.0 as u32),
                if vendor == 2 {
                    (D3DRS_POINTSIZE, u32::from_le_bytes(*b"A2M0"))
                } else {
                    (D3DRS_ADAPTIVETESS_Y, 0)
                },
            ];
            // Capture all required state before the first mutation.
            for (index, (state, value)) in desired.into_iter().enumerate() {
                if (index < 3 && blend_mask & (1 << index) == 0)
                    || (index == 3 && vendor != 1 && vendor != 2)
                {
                    continue;
                }
                let prior = device.render_state(state)?;
                if prior != value {
                    scope.states[scope.changed] = (state, prior);
                    scope.changed += 1;
                }
            }
            Ok(Some(scope))
        })();
        let mut scope = match capture {
            Ok(Some(scope)) => scope,
            Ok(None) => return Ok(None),
            Err(_) => return Err(None),
        };
        let installed = (|| -> Direct3DResult<()> {
            for &(state, _) in &scope.states[..scope.changed] {
                let value = if state == D3DRS_ALPHABLENDENABLE {
                    1
                } else if state == D3DRS_SRCBLEND {
                    D3DBLEND_SRCALPHA.0 as u32
                } else if state == D3DRS_DESTBLEND {
                    D3DBLEND_INVSRCALPHA.0 as u32
                } else if state == D3DRS_POINTSIZE {
                    u32::from_le_bytes(*b"A2M0")
                } else {
                    0
                };
                device.set_render_state(state, value)?;
            }
            if scope.pixel_changed {
                device.set_pixel_shader(replacement)
            } else {
                Ok(())
            }
        })();
        if installed.is_err() {
            return Err((!scope.restore(device)).then_some(scope));
        }
        Ok(Some(scope))
    }

    /// Attempt every restore, retaining ownership if the device rejects any.
    pub(super) fn restore(&mut self, device: &Device9Ref<'_>) -> bool {
        let mut restored = !self.pixel_changed || device.set_pixel_shader(&self.pixel).is_ok();
        for &(state, value) in self.states[..self.changed].iter().rev() {
            restored &= device.set_render_state(state, value).is_ok();
        }
        restored
    }
}

fn finish_draw() {
    let Some(owner) = owner() else { return };
    if owner.thread != get_current_thread_id() {
        return;
    }
    let Some(mut state) = owner.state.try_lock() else {
        return;
    };
    let device_ptr = state.device as *mut c_void;
    let Some(scope) = state.pending.as_mut() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };
    if scope.restore(&device) {
        state.pending = None;
    } else {
        owner.restore_failed.store(true, Ordering::Release);
    }
}

/// Release all grass COM references before native device Reset.
///
/// Returns false if a journal cannot be restored or the owner is busy, so Reset
/// cannot discard resources while a temporary binding still owns the draw.
pub(crate) fn reset_device_resources() -> bool {
    finish_draw();
    let Some(owner) = owner() else { return true };
    if owner.thread != get_current_thread_id() {
        return false;
    }
    let Some(mut state) = owner.state.try_lock() else {
        return false;
    };
    if state.pending.is_some() {
        return false;
    }
    state.cache = std::array::from_fn(|_| None);
    state.device = 0;
    true
}
