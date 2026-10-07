//! Unreleased sequential traversal for the two native scene-light consumers.
//!
//! Four shadow CALL bridges and four camera loop bridges are one pre-CRT
//! transaction. Each enumeration initializes a stack-local cursor; no node
//! survives its native pass and no extra retain, TLS, worker, or lock is added.
//! DeferredInit publishes readiness without executable writes. Native filtering,
//! arithmetic, counters, limits, and nonnull-property iterators remain in place.
//! Math admission accepts vanilla or three exact verified inlined bodies with
//! their native tails; calls keep the installed arithmetic and ABI unchanged.
//! Unsupported native/provider ownership permanently disables cursor admission.
//!
//! Native node retirement and scene stability across the pass remain unresolved
//! candidate conditions, not guarantees supplied by signature checks. Full
//! ownership checks occur at pass admission, a bounded getter check at advances;
//! no allocation, logging, Rust callback, or FPU save occurs per advance.
//! See docs/fnv_location_performance_static_audit.md for frame/liveness proof,
//! conditional work budgets, and the unvalidated runtime/startup limitations.

use core::{arch::naked_asm, ffi::c_void};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    hook::{callsite::Rel32CallHookContainer, transaction::ModificationTransaction},
    patch::OwnedCodePatch,
};

use super::lighting_contract::{NativeRange, branch, native_range, word};

#[cfg(test)]
#[path = "scene_light_scan_tests.rs"]
mod tests;

type Getter = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
static HOOKS: [Rel32CallHookContainer<Getter>; 4] = [const { Rel32CallHookContainer::new() }; 4];
static PROVIDERS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static PATCHES: OnceLock<[OwnedCodePatch; 4]> = OnceLock::new();
static PREPARED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
// Monotonic, process-lifetime rejection. Never promote an existing native-mode
// pass when readiness changes, or read a foreign frame after a rejected start.
// Integer assembly loads/stores use x86's aligned atomic DWORD representation.
static POISON: AtomicU32 = AtomicU32::new(0);
const CALLS: [usize; 4] = [0xB9D2B9, 0xB9D3E1, 0xB9D529, 0xB9D8B4];
const WINDOWS: [usize; 4] = [0xB5BE30, 0xB5BE69, 0xB5BED2, 0xB5C04A];

native_range!(SHADOW, 0xB9D150, "shadow_scan");
native_range!(CAMERA, 0xB5BCA0, "camera_scan");
native_range!(GETTER, 0xB5AC20, "scene_getter");
native_range!(PROPERTY_FIRST, 0xB70600, "property_first");
native_range!(PROPERTY_NEXT, 0xB70700, "property_next");
// These full-range alternatives are the verified leaf bytes followed by the
// untouched native tail. Their complete instructions preserve the cursor's
// dead stack slots; see the owning math compatibility contract. No arbitrary
// math hook, module identity, numerical substitution or wildcard is admitted.
static NORMALIZE: NativeRange = NativeRange::new(
    "NORMALIZE",
    0x4A0C10,
    include_bytes!("lighting_signatures/normalize.bin"),
)
.with_alternative(include_bytes!("lighting_signatures/normalize_inlined.bin"));
static VECTOR_LENGTH: NativeRange = NativeRange::new(
    "VECTOR_LENGTH",
    0x457990,
    include_bytes!("lighting_signatures/vector_length.bin"),
)
.with_alternative(include_bytes!(
    "lighting_signatures/vector_length_inlined.bin"
));
static VECTOR_SQRT: NativeRange = NativeRange::new(
    "VECTOR_SQRT",
    0x4579E0,
    include_bytes!("lighting_signatures/vector_sqrt.bin"),
)
.with_alternative(include_bytes!(
    "lighting_signatures/vector_sqrt_inlined.bin"
));
native_range!(SCALAR_SQRT, 0x4019B0, "scalar_sqrt");
const CALLEES: [&NativeRange; 7] = [
    &GETTER,
    &PROPERTY_FIRST,
    &PROPERTY_NEXT,
    &NORMALIZE,
    &VECTOR_LENGTH,
    &VECTOR_SQRT,
    &SCALAR_SQRT,
];

/// Prepare all eight inert interventions at the existing quiescent barrier.
/// Any installation error rolls back the owned transaction; no later retry or
/// gameplay mutation is supported. Original native windows are required.
pub(crate) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary(),
        "scene-light preparation requires the pre-CRT barrier"
    );
    ensure!(
        !PREPARED.load(Ordering::Acquire),
        "scene-light bridges already prepared"
    );
    let result = prepare_and_install();
    if result.is_err() {
        // Best-effort rollback can leave an owned bridge installed after an OS
        // restoration failure. A next/transfer bridge without its initial bridge
        // must never consume an uninitialized frame slot, even while inert.
        // Preparation is quiescent; latch before returning to the startup caller.
        POISON.store(1, Ordering::Release);
    }
    result
}

/// Prepare once under `install`'s barrier; errors unwind the owned transaction
/// before the outer installer permanently rejects cursor reads/transfers.
fn prepare_and_install() -> Result<()> {
    for range in CALLEES.into_iter().chain([&SHADOW, &CAMERA]) {
        range.prepare(&[])?;
    }
    let bridges: [Getter; 4] = [
        shadow_first,
        shadow_next_first,
        shadow_accumulate,
        shadow_next_accumulate,
    ];
    let mut shadow_overlays = Vec::with_capacity(4);
    for index in 0..4 {
        // Safety: complete native consumer/getter bytes prove thiscall/RET 4.
        unsafe {
            HOOKS[index].init(
                "scene-light lookup",
                CALLS[index] as *mut c_void,
                bridges[index],
            )
        }?;
        PROVIDERS[index].store(HOOKS[index].predecessor_address()?, Ordering::Release);
        shadow_overlays.push((
            CALLS[index],
            branch(0xE8, CALLS[index], bridges[index] as usize),
        ));
    }
    SHADOW.prepare(
        &shadow_overlays
            .iter()
            .map(|(a, b)| (*a, b.as_slice()))
            .collect::<Vec<_>>(),
    )?;

    let destinations = [
        camera_initial as *const () as usize,
        camera_to_brightness as *const () as usize,
        camera_to_vector as *const () as usize,
        camera_next as *const () as usize,
    ];
    let native = include_bytes!("lighting_signatures/camera_scan.bin");
    let mut camera_overlays = Vec::with_capacity(4);
    let mut patches = Vec::with_capacity(4);
    for index in 0..4 {
        let offset = WINDOWS[index] - 0xB5BCA0;
        let mut bytes = [0x90; 6];
        bytes[..5].copy_from_slice(&branch(0xE9, WINDOWS[index], destinations[index]));
        let replacement: &'static [u8] = Box::leak(Box::new(bytes));
        patches.push(OwnedCodePatch::new(
            "scene-light camera bridge",
            WINDOWS[index],
            &native[offset..offset + 6],
            replacement,
        ));
        camera_overlays.push((WINDOWS[index], replacement));
    }
    CAMERA.prepare(&camera_overlays)?;
    // Four fixed windows above are the only source of this array. Keep setup
    // failure explicit rather than panicking or retrying partially prepared state.
    let patches: [OwnedCodePatch; 4] = patches
        .try_into()
        .map_err(|_| anyhow::anyhow!("camera bridge count mismatch"))?;
    ensure!(
        PATCHES.set(patches).is_ok(),
        "camera bridges already prepared"
    );
    let stored = PATCHES
        .get()
        .ok_or_else(|| anyhow::anyhow!("camera bridges not prepared"))?;
    let mut transaction = ModificationTransaction::new();
    for hook in &HOOKS {
        transaction.enable_callsite(hook)?;
    }
    for patch in stored {
        transaction.apply_patch(patch)?;
    }
    transaction.commit();
    PREPARED.store(true, Ordering::Release);
    log::info!("[SCENE_LIGHTS] Candidate bridges prepared; native dispatch until DeferredInit");
    Ok(())
}

/// Publish readiness without touching code; rejection remains native forever.
pub(super) fn observe_event(kind: u32) {
    if kind != crate::events::DEFERRED_INIT || !PREPARED.load(Ordering::Acquire) {
        return;
    }
    // Safety: preparation validated all fixed process-lifetime executable ranges.
    let previously_rejected = POISON.load(Ordering::Acquire) != 0;
    let admitted = !previously_rejected && unsafe { qualified(&SHADOW) && qualified(&CAMERA) };
    READY.store(admitted, Ordering::Release);
    if admitted {
        log::info!("[SCENE_LIGHTS] Candidate enabled; runtime equivalence unvalidated");
    } else {
        POISON.store(1, Ordering::Release);
        log::warn!("[SCENE_LIGHTS] Native contract changed; indexed providers retained");
        report_rejection(previously_rejected);
    }
}

/// Report current capability evidence once at the existing DeferredInit boundary.
/// This does not attribute code ownership or alter admission. Earlier transient
/// rejection cannot be reconstructed from a later matching snapshot.
fn report_rejection(previously_rejected: bool) {
    log::warn!(
        "[SCENE_LIGHTS] Rejection snapshot: latched before DeferredInit={previously_rejected}"
    );
    let mut mismatches = 0;
    for range in [&SHADOW, &CAMERA].into_iter().chain(CALLEES) {
        if let Err(error) = range.diagnose() {
            mismatches += 1;
            log::warn!("[SCENE_LIGHTS] Current contract rejection: {error}");
        }
    }
    for (index, provider) in PROVIDERS.iter().enumerate() {
        let observed = provider.load(Ordering::Acquire);
        if observed != 0xB5AC20 {
            mismatches += 1;
            log::warn!(
                "[SCENE_LIGHTS] Captured getter at CALL 0x{:08X}: expected 0x00B5AC20, observed 0x{observed:08X}",
                CALLS[index]
            );
        }
    }
    if mismatches == 0 {
        log::warn!(
            "[SCENE_LIGHTS] Current contracts match; prior rejection remains unresolved and indexed traversal is retained"
        );
    }
}

// Safety: installation established mapped lifetime. This validates owned
// consumer frames before bookkeeping, not engine object lifetime or quiescence.
unsafe fn qualified(consumer: &NativeRange) -> bool {
    (unsafe { consumer.matches() && CALLEES.iter().all(|range| range.matches()) })
        && PROVIDERS
            .iter()
            .all(|p| p.load(Ordering::Acquire) == 0xB5AC20)
}

/// Initialize exactly one native pass. No new write is made to rejected frames.
/// Safety: called only by a native initial bridge with its proven aligned slot;
/// qualified consumer bytes establish that slot's dead interval. Scene/node
/// stability remains an explicitly unresolved candidate condition.
unsafe fn initialize(scene: usize, cursor: usize, consumer: &NativeRange) {
    if POISON.load(Ordering::Acquire) != 0 {
        return;
    }
    if !unsafe { qualified(consumer) } {
        POISON.store(1, Ordering::Release);
        return;
    }
    let head = if READY.load(Ordering::Acquire) && scene != 0 && unsafe { word(scene, 0xBC) } != 0 {
        unsafe { word(scene, 0xB4) }
    } else {
        0
    };
    // Zero mode is initialized even before readiness and carried through both
    // camera transfers. A later DeferredInit never promotes an existing pass.
    unsafe { (cursor as *mut u32).write(head) };
}

unsafe extern "C" fn initialize_shadow(scene: usize, cursor: usize, _: usize, _: usize) {
    // Safety: the two private initial bridges supply S+0x68 only on null-property
    // native paths. Each pass resets independently, retaining native index zero.
    unsafe { initialize(scene, cursor, &SHADOW) };
}

unsafe extern "C" fn initialize_camera(frame: usize, scene: usize, _: usize, _: usize) {
    // Safety: C+0x64 is dead between initial getter and the first vector write.
    unsafe { initialize(scene, frame + 0x64, &CAMERA) };
}

// Shadow E=entry ESP=S-8. Reserve a target at E-4 and preserve flags/all GPRs,
// making B=E-40; S+0x68 is therefore B+0x98. The initial lookup always chains
// its captured provider, with its complete incoming register/FPU state intact.
macro_rules! initial_lookup {
    ($name:ident, $provider_offset:expr) => {
        #[unsafe(naked)]
        unsafe extern "thiscall" fn $name(_: *mut c_void, _: u32) -> *mut c_void {
            naked_asm!(
                "push 0", "pushfd", "pushad", "mov ebp, esp", "and esp, -16", "sub esp, 528",
                "fxsave [esp + 16]", "lea eax, [ebp + 152]",
                "push 0", "push 0", "push eax", "push dword ptr [ebp + 24]",
                "call {initialize}", "add esp, 16", "fxrstor [esp + 16]",
                "mov eax, dword ptr [{providers} + {offset}]", "mov [ebp + 36], eax",
                "mov esp, ebp", "popad", "popfd", "ret",
                initialize = sym initialize_shadow, providers = sym PROVIDERS, offset = const $provider_offset,
            );
        }
    };
}
initial_lookup!(shadow_first, 0);
initial_lookup!(shadow_accumulate, 8);

// E=entry ESP=S-8; after pushfd/pushad B=E-36, cursor is B+0x94, index B+40.
// Only integer instructions execute. Native mode restores every incoming GPR
// and flag before tail-jumping to this exact CALL's captured provider. The
// admitted path preserves count admission and index-zero head restart (including
// narrowed-index wrap), loads one next link, and consumes the index with RET 4.
macro_rules! next_lookup {
    ($name:ident, $provider_offset:expr) => {
        #[unsafe(naked)]
        unsafe extern "thiscall" fn $name(_: *mut c_void, _: u32) -> *mut c_void {
            naked_asm!(
                "pushfd", "pushad", "cmp dword ptr [{poison}], 0", "jne 5f",
                "call {getter_owned}", "test eax, eax", "jz 5f",
                "mov eax, [esp + 148]", "test eax, eax", "jz 5f",
                "mov ecx, [esp + 24]", "mov edx, [esp + 40]",
                "cmp edx, [ecx + 188]", "jae 4f", "test edx, edx", "jz 2f",
                "mov eax, [eax]", "jmp 3f", "2:", "mov eax, [ecx + 180]",
                "3:", "mov [esp + 148], eax", "mov eax, [eax + 8]", "jmp 6f",
                "4:", "xor eax, eax",
                "6:", "mov [esp + 28], eax", "popad", "popfd", "ret 4",
                "5:", "popad", "popfd", "jmp dword ptr [{providers} + {offset}]",
                poison = sym POISON, getter_owned = sym getter_owned, providers = sym PROVIDERS, offset = const $provider_offset,
            );
        }
    };
}
next_lookup!(shadow_next_first, 4);
next_lookup!(shadow_next_accumulate, 12);

// C is native loop ESP. No target slot: B=C-36, saved EBX=B+16. Restore the
// live ST(0) and all SSE state after Rust admission, then replay the six native
// bytes. PUSH/RET resumes without sacrificing a live register or CMP flags.
#[unsafe(naked)]
unsafe extern "C" fn camera_initial() {
    naked_asm!(
        "pushfd", "pushad", "mov ebp, esp", "and esp, -16", "sub esp, 528", "fxsave [esp + 16]",
        "lea eax, [ebp + 36]", "push 0", "push 0", "push dword ptr [ebp + 16]", "push eax",
        "call {initialize}", "add esp, 16", "fxrstor [esp + 16]", "mov esp, ebp", "popad", "popfd",
        "mov [esp + 28], eax", "cmp eax, esi", "push 0xB5BE36", "ret",
        initialize = sym initialize_camera,
    );
}

// C+0x64 is about to become vector Z; carry even the zero native-mode marker to
// C+0x30 while brightness is dead, then back before brightness overwrites C+0x30.
// APP_CULLED skips both transfers and retains C+0x64. No floating register is
// used for bookkeeping. All original flags survive the two integer moves.
#[unsafe(naked)]
unsafe extern "C" fn camera_to_brightness() {
    naked_asm!(
        "pushfd", "push eax", "cmp dword ptr [{poison}], 0", "jne 2f",
        "mov eax, [esp + 108]", "mov [esp + 56], eax", "2:", "pop eax", "popfd",
        "mov eax, [esp + 108]", "fstp st(0)", "push 0xB5BE6F", "ret",
        poison = sym POISON,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn camera_to_vector() {
    naked_asm!(
        "pushfd", "push eax", "cmp dword ptr [{poison}], 0", "jne 2f",
        "mov eax, [esp + 56]", "mov [esp + 108], eax", "2:", "pop eax", "popfd",
        "fstp dword ptr [esp + 20]", "fldz", "push 0xB5BED8", "ret",
        poison = sym POISON,
    );
}

// Count admission at B5C042 remains native. On rejection reproduce the entire
// original indexed walk, not merely the first displaced load. The fast path
// supplies the same ECX payload/EAX next link and zero EDX after a positive
// index; index zero restarts the head. The same x87 values enter B5C067.
#[unsafe(naked)]
unsafe extern "C" fn camera_next() {
    naked_asm!(
        "pushfd", "pushad", "cmp dword ptr [{poison}], 0", "jne 5f",
        "call {getter_owned}", "test eax, eax", "jz 5f", "popad", "popfd",
        "mov eax, [esp + 100]", "test eax, eax", "jz 6f", "test edx, edx", "jz 2f",
        "mov eax, [eax]", "jmp 3f", "2:", "mov eax, [ebx + 180]",
        "3:", "mov [esp + 100], eax", "mov ecx, [eax + 8]", "mov eax, [eax]", "xor edx, edx",
        "push 0xB5C067", "ret",
        "5:", "popad", "popfd",
        "6:", "mov eax, [ebx + 180]", "lea ecx, [eax + 8]", "mov eax, [eax]", "mov ecx, [ecx]",
        "test edx, edx", "jbe 8f", "7:", "sub edx, 1", "lea ecx, [eax + 8]",
        "mov eax, [eax]", "mov ecx, [ecx]", "jne 7b", "8:", "push 0xB5C067", "ret",
        poison = sym POISON, getter_owned = sym getter_owned,
    );
}

// Full 54-byte getter ownership check, generated directly from the verified
// native extract. Its integer-only ABI clobbers EAX/flags and returns 0/1.
// Failure latches native mode before any bridge reads a retained cursor.
// These checks cannot synchronize code replacement during an admitted pass.
#[unsafe(naked)]
unsafe extern "C" fn getter_owned() -> u32 {
    naked_asm!(
        "cmp dword ptr [0xB5AC20], 0x24748B56", "jne 2f",
        "cmp dword ptr [0xB5AC24], 0xBCB13B08", "jne 2f",
        "cmp dword ptr [0xB5AC28], 0x72000000", "jne 2f",
        "cmp dword ptr [0xB5AC2C], 0x5EC03306", "jne 2f",
        "cmp dword ptr [0xB5AC30], 0x8B0004C2", "jne 2f",
        "cmp dword ptr [0xB5AC34], 0x0000B481", "jne 2f",
        "cmp dword ptr [0xB5AC38], 0x8D088B00", "jne 2f",
        "cmp dword ptr [0xB5AC3C], 0x028B0850", "jne 2f",
        "cmp dword ptr [0xB5AC40], 0x0E76F685", "jne 2f",
        "cmp dword ptr [0xB5AC44], 0xEA83D68B", "jne 2f",
        "cmp dword ptr [0xB5AC48], 0x08418D01", "jne 2f",
        "cmp dword ptr [0xB5AC4C], 0x008B098B", "jne 2f",
        "cmp dword ptr [0xB5AC50], 0xC25EF475", "jne 2f",
        "cmp word ptr [0xB5AC54], 0x0004", "jne 2f",
        "mov eax, 1", "ret", "2:", "mov dword ptr [{poison}], 1", "xor eax, eax", "ret",
        poison = sym POISON,
    );
}
