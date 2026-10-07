//! Unreleased invocation-local reuse of native property-light scores.
//!
//! Three caller hooks dispatch before list mutation, retaining their captured
//! provider on unsupported code, inputs, or x87 state. The private assembly
//! sorter preserves native current scoring, comparisons, relinks, and cache
//! invalidation; only predecessor scoring loads the already rounded +0x0C.
//! Preparation is transactional at the pre-CRT barrier; DeferredInit publishes
//! admission without code writes. No TLS, heap work, locks, or logs occur in a
//! sort. Input validation adds a read-only O(k) prewalk and bounded code checks.
//!
//! Native list/input exclusivity is still an unresolved candidate condition,
//! not proven by these guards. See docs/fnv_location_performance_static_audit.md.
//! This option defaults on at the owner's request; runtime/FPS acceptance is open.

use core::{arch::naked_asm, ffi::c_void};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Result, ensure};
use libpsycho::os::windows::hook::{
    callsite::Rel32CallHookContainer, transaction::ModificationTransaction,
};

use super::lighting_contract::{NativeRange, branch, native_range, word};

type Sort = unsafe extern "thiscall" fn(*mut c_void, *const c_void);
static HOOKS: [Rel32CallHookContainer<Sort>; 3] = [const { Rel32CallHookContainer::new() }; 3];
static PROVIDERS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
static PREPARED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
const SITES: [usize; 3] = [0xB6823E, 0xBB4F0E, 0xC06075];
static SCORE: usize = 0xB9DBE0;

native_range!(SORTER, 0xB70390, "property_sort");
native_range!(SCORER, 0xB9DBE0, "property_score");
native_range!(SQRT_ENTRY, 0xEC6040, "sqrt_entry");
native_range!(SQRT_BODY, 0xEC605D, "sqrt_body");
native_range!(SQRT_CLASSIFY, 0xED2808, "sqrt_classify");
native_range!(SQRT_RETURN, 0xED281E, "sqrt_return");
native_range!(CALLER_0, 0xB681CF, "sort_caller_0");
native_range!(CALLER_1, 0xBB4EDA, "sort_caller_1");
native_range!(CALLER_2, 0xC0603D, "sort_caller_2");
const COMMON: [&NativeRange; 6] = [
    &SORTER,
    &SCORER,
    &SQRT_ENTRY,
    &SQRT_BODY,
    &SQRT_CLASSIFY,
    &SQRT_RETURN,
];
const CALLERS: [&NativeRange; 3] = [&CALLER_0, &CALLER_1, &CALLER_2];

/// Install all three inert bridges once, retaining the native path on failure.
/// Requires the existing quiescent pre-CRT barrier. No gameplay patching occurs.
pub(crate) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary(),
        "light-score preparation requires the pre-CRT barrier"
    );
    ensure!(
        !PREPARED.load(Ordering::Acquire),
        "light-score bridges already prepared"
    );
    for range in COMMON.into_iter().chain(CALLERS) {
        range.prepare(&[])?;
    }
    let bridges: [Sort; 3] = [bridge_0, bridge_1, bridge_2];
    for index in 0..3 {
        // Safety: complete native caller/scorer bytes establish thiscall/RET 4.
        // Publication precedes every activation; these mapped targets outlive us.
        unsafe {
            HOOKS[index].init(
                "light-score caller",
                SITES[index] as *mut c_void,
                bridges[index],
            )
        }?;
        PROVIDERS[index].store(HOOKS[index].predecessor_address()?, Ordering::Release);
        let bytes = branch(0xE8, SITES[index], bridges[index] as usize);
        CALLERS[index].prepare(&[(SITES[index], &bytes)])?;
    }
    let mut transaction = ModificationTransaction::new();
    for hook in &HOOKS {
        transaction.enable_callsite(hook)?;
    }
    transaction.commit();
    PREPARED.store(true, Ordering::Release);
    log::info!("[LIGHT_SCORES] Candidate bridges prepared; native dispatch until DeferredInit");
    Ok(())
}

/// Publish candidate admission once through the core's existing DeferredInit.
/// No hooks are created or modified here; failed qualification retains providers.
pub(super) fn observe_event(kind: u32) {
    if kind != crate::events::DEFERRED_INIT || !PREPARED.load(Ordering::Acquire) {
        return;
    }
    // Safety: install validated process-lifetime native mappings before publishing.
    let admitted = unsafe {
        COMMON
            .into_iter()
            .chain(CALLERS)
            .all(|range| range.matches())
    } && PROVIDERS
        .iter()
        .all(|p| p.load(Ordering::Acquire) == 0xB70390);
    READY.store(admitted, Ordering::Release);
    if admitted {
        log::info!("[LIGHT_SCORES] Candidate enabled; runtime equivalence unvalidated");
    } else {
        log::warn!("[LIGHT_SCORES] Native contract changed; captured providers retained");
    }
}

#[inline]
fn finite(bits: u32) -> bool {
    bits & 0x7F80_0000 != 0x7F80_0000
}

/// Select before any mutation. `index` comes only from a constant bridge ID.
///
/// Safety: caller supplies native property/bound ownership and the aligned
/// 512-byte FXSAVE image. Reads follow the verified native fields; the prewalk
/// detects malformed chain/count/finite inputs but cannot pin concurrent owners.
unsafe fn select(property: usize, bound: usize, state: usize, index: usize) -> usize {
    let provider = PROVIDERS[index].load(Ordering::Acquire);
    if !READY.load(Ordering::Acquire) || provider != 0xB70390 {
        return provider;
    }
    // Full common code and this caller's bound/dispatch slice, including our CALL.
    if !unsafe { CALLERS[index].matches() && COMMON.iter().all(|range| range.matches()) } {
        return provider;
    }
    let control = unsafe { (state as *const u16).read() };
    let status = unsafe { ((state + 2) as *const u16).read() };
    let tag = unsafe { ((state + 4) as *const u8).read() };
    if control != 0x027F || tag != 0 || status & 0x00C0 != 0 || property == 0 || bound == 0 {
        return provider;
    }
    let scene = unsafe { word(0x11F91C8, 0) } as usize;
    if scene == 0
        || !(0..4).all(|i| finite(unsafe { word(bound, i * 4) }))
        || !(0..3).all(|i| finite(unsafe { word(scene, 0x1E4 + i * 4) }))
    {
        return provider;
    }
    let count = unsafe { word(property, 0x68) };
    let mut node = unsafe { word(property, 0x60) } as usize;
    let mut previous = 0;
    for _ in 0..count {
        if node == 0 || unsafe { word(node, 4) } as usize != previous {
            return provider;
        }
        let wrapper = unsafe { word(node, 8) } as usize;
        if wrapper == 0 {
            return provider;
        }
        let light = unsafe { word(wrapper, 0xF8) } as usize;
        if light == 0
            || !(0..3).all(|i| finite(unsafe { word(light, 0x8C + i * 4) }))
            || !finite(unsafe { word(light, 0xE0) })
        {
            return provider;
        }
        previous = node;
        node = unsafe { word(node, 0) } as usize;
    }
    if node != 0 || previous != unsafe { word(property, 0x64) } as usize {
        return provider;
    }
    optimized_sort as Sort as usize
}

// E is bridge-entry ESP. The reserved target is E-4, pushfd/pushad make B=E-40,
// and the native bound is B+44. Save all FPU/SSE state in a 16-aligned FXSAVE
// image before Rust admission. RET consumes only the private target, restoring
// the exact original thiscall entry for either sorter or captured provider.
macro_rules! sorter_bridge {
    ($bridge:ident, $select:ident, $index:expr) => {
        unsafe extern "C" fn $select(property: usize, bound: usize, state: usize, _: usize) -> usize {
            // Safety: this private assembly bridge supplies the native frame and
            // a constant in-range provider ID, retaining engine pointer ownership.
            unsafe { select(property, bound, state, $index) }
        }
        #[unsafe(naked)]
        unsafe extern "thiscall" fn $bridge(_: *mut c_void, _: *const c_void) {
            naked_asm!(
                "push 0", "pushfd", "pushad", "mov ebp, esp", "and esp, -16", "sub esp, 528",
                "fxsave [esp + 16]", "lea eax, [esp + 16]",
                "push 0", "push eax", "push dword ptr [ebp + 44]", "push dword ptr [ebp + 24]",
                "call {select}", "add esp, 16", "mov [ebp + 36], eax", "fxrstor [esp + 16]",
                "mov esp, ebp", "popad", "popfd", "ret",
                select = sym $select,
            );
        }
    };
}
sorter_bridge!(bridge_0, select_0, 0);
sorter_bridge!(bridge_1, select_1, 1);
sorter_bridge!(bridge_2, select_2, 2);

/// Native predecessor ABI: ECX wrapper, one ignored bound, one ST(0), RET 4.
#[unsafe(naked)]
unsafe extern "thiscall" fn cached_score(_: *mut c_void, _: *const c_void) -> f32 {
    naked_asm!("fld dword ptr [ecx + 12]", "ret 4");
}

// Literal control flow of B70390..B70490. Only the second helper call changes.
// Native frame rounding and FCOMP/FNSTSW preserve strict insertion behavior,
// ties/unordered handling, and conditional cache-key invalidation at +0x38.
// No callback is added to the mutable portion of the list operation.
#[unsafe(naked)]
unsafe extern "thiscall" fn optimized_sort(_: *mut c_void, _: *const c_void) {
    naked_asm!(
        "push ebp", "mov ebp, esp", "and esp, -8", "sub esp, 28",
        "push ebx", "push esi", "mov esi, [ecx + 96]", "push edi",
        "mov [esp + 20], ecx", "mov byte ptr [esp + 19], 0", "test esi, esi", "jz 15f", "jmp 3f",
        "2:", "mov esi, [esp + 24]", "mov ecx, [esp + 20]",
        "3:", "mov edi, [ecx + 96]", "mov ecx, [ebp + 8]", "mov edx, [esi]",
        "lea eax, [esi + 8]", "mov eax, [eax]", "push ecx", "mov ecx, eax", "mov [esp + 28], edx",
        "call dword ptr [{score}]", "fstp dword ptr [esp + 28]", "cmp edi, esi", "je 14f",
        "4:", "test edi, edi", "je 14f", "mov edx, [ebp + 8]", "fld dword ptr [esp + 28]",
        "lea eax, [edi + 8]", "fstp qword ptr [esp + 32]", "mov eax, [eax]", "mov ebx, edi",
        "mov edi, [edi]", "push edx", "mov ecx, eax", "call {cached}",
        "fcomp qword ptr [esp + 32]", "fnstsw ax", "test ah, 65", "jne 13f",
        "cmp esi, ebx", "je 12f", "mov eax, [esp + 20]", "cmp [eax + 96], esi", "jne 5f",
        "mov ecx, [esi]", "mov [eax + 96], ecx",
        "5:", "cmp [eax + 96], ebx", "jne 6f", "mov [eax + 96], esi",
        "6:", "cmp [eax + 100], esi", "jne 7f", "mov edx, [esi + 4]", "mov [eax + 100], edx",
        "7:", "mov eax, [esi]", "test eax, eax", "jz 8f", "mov ecx, [esi + 4]", "mov [eax + 4], ecx",
        "8:", "mov eax, [esi + 4]", "test eax, eax", "jz 9f", "mov edx, [esi]", "mov [eax], edx",
        "9:", "mov eax, [ebx + 4]", "mov [esi + 4], eax", "mov [esi], ebx", "test eax, eax", "jz 10f",
        "mov [eax], esi", "10:", "mov [ebx + 4], esi",
        "12:", "xor edi, edi", "mov byte ptr [esp + 19], 1",
        "13:", "cmp edi, esi", "jne 4b",
        "14:", "cmp dword ptr [esp + 24], 0", "jne 2b", "cmp byte ptr [esp + 19], 0", "je 15f",
        "mov ecx, [esp + 20]", "mov dword ptr [ecx + 56], 0",
        "15:", "pop edi", "pop esi", "pop ebx", "mov esp, ebp", "pop ebp", "ret 4",
        score = sym SCORE, cached = sym cached_score,
    );
}
