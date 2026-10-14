//! Preserve sparse Havok entity arrays through their native consumption flow.
//!
//! Entry compaction cannot make a caller-owned array immutable. Native add,
//! callback, pending-flush, and collection-filter stages load it independently;
//! deferred work also retains/releases every original slot. This module gives
//! each of those NULL consumers the native sparse-array skip policy without
//! moving slots, changing counts, adding references, or bypassing whole stages.
//!
//! Six exact instruction splices, three provider-preserving reference guards,
//! and the requested array-entry guards form one startup transaction. Admission
//! is published only after the entire set commits. An unadmitted rollback
//! survivor replays native code or chains its captured provider. All storage
//! and bridges live in the core for process lifetime; installation requires
//! the quiescent pre-CRT barrier.
//! Valid paths allocate, lock, and log nothing. Reference guards inspect only
//! NULL; non-NULL object validity and lifetime remain the native caller's
//! contract. No allocator/module classification or destructor hook is used.

use std::{
    arch::naked_asm,
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicPtr, Ordering},
    },
};

use anyhow::Result;
use libpsycho::os::windows::{
    hook::{inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction},
    patch::OwnedCodePatch,
};

use super::{havok, statics};

type ReferenceFn = unsafe extern "thiscall" fn(*mut c_void);
static RETAIN: LazyLock<InlineHookContainer<ReferenceFn>> = LazyLock::new(InlineHookContainer::new);
static RELEASE: LazyLock<InlineHookContainer<ReferenceFn>> =
    LazyLock::new(InlineHookContainer::new);
static RELEASE_UNLOCKED: LazyLock<InlineHookContainer<ReferenceFn>> =
    LazyLock::new(InlineHookContainer::new);
static RETAIN_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static RELEASE_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static RELEASE_UNLOCKED_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ADMITTED: AtomicBool = AtomicBool::new(false);

const SITES: [(usize, &[u8], &str); 6] = [
    (
        0xC94D90,
        &[0x8B, 0x54, 0x24, 0x5C, 0x8B, 0x34, 0x82],
        "havok_batch_entity_slot",
    ),
    (
        0xC95067,
        &[0x8B, 0x4C, 0x24, 0x5C, 0x8B, 0x2C, 0xB1],
        "havok_batch_callback_slot",
    ),
    (
        0xC67577,
        &[0x8B, 0x14, 0x9E, 0x80, 0x7A, 0x28, 0x01],
        "havok_pending_entity_slot",
    ),
    (
        0xC675B0,
        &[0x8B, 0x04, 0x9E, 0x8B, 0xB0, 0xCC, 0, 0, 0],
        "havok_pending_entity_reread",
    ),
    (
        0xCE16E0,
        &[0x8B, 0x4E, 0x08, 0x8B, 0x14, 0xB9],
        "havok_collection_filter_slot",
    ),
    (
        0xC97FE2,
        &[0x8B, 0x00, 0x33, 0xD2, 0x84, 0xC9],
        "havok_sparse_single_add_reread",
    ),
];

static REPLACEMENTS: LazyLock<[[u8; 9]; 6]> = LazyLock::new(|| {
    let targets = [
        batch_entity as *const () as usize,
        batch_callback as *const () as usize,
        pending_entity as *const () as usize,
        pending_reread as *const () as usize,
        collection_filter as *const () as usize,
        sparse_single_add as *const () as usize,
    ];
    std::array::from_fn(|i| {
        let mut bytes = [0x90; 9];
        bytes[0] = 0xE9;
        // x86 rel32 uses modular 32-bit address arithmetic, including ASLR.
        bytes[1..5]
            .copy_from_slice(&(targets[i].wrapping_sub(SITES[i].0 + 5) as u32).to_le_bytes());
        bytes
    })
});

static PATCHES: LazyLock<[OwnedCodePatch; 6]> = LazyLock::new(|| {
    std::array::from_fn(|i| {
        let (address, original, name) = SITES[i];
        OwnedCodePatch::new(name, address, original, &REPLACEMENTS[i][..original.len()])
    })
});

/// Install the complete native sparse-array consumption and reference boundary.
///
/// Called only at quiescent core startup for the supported executable. A changed
/// splice or continuation rejects installation before any target is enabled.
/// Activation failure rolls back owned writes; admission remains false even if
/// rollback itself loses ownership. Valid reference calls chain the provider
/// already installed at their shared entry, with the original ABI and pointer.
/// Either entry request installs the complete shared NULL flow. Each flag also
/// selects that entry's array-envelope guard; both false performs no setup.
pub(super) fn install(batch_entry: bool, pending_entry: bool) -> Result<()> {
    if !batch_entry && !pending_entry {
        return Ok(());
    }
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    for patch in PATCHES.iter() {
        patch.verify()?;
    }
    // These continuations own iteration, stack cleanup, and final batch state.
    // Do not skip a pushed-argument cleanup on a path which pushed nothing.
    for &(address, bytes) in &[
        (
            0xC94EE2,
            &[0x8B, 0x44, 0x24, 0x1C, 0x40, 0x3B, 0x44, 0x24, 0x60][..],
        ),
        (
            0xC9507B,
            &[0x46, 0x83, 0xC4, 0x0C, 0x3B, 0x74, 0x24, 0x60][..],
        ),
        (0xC67681, &[0x43, 0x3B, 0x5D, 0x0C][..]),
        (0xCE16F2, &[0x47, 0x3B, 0xFD, 0x7C, 0xE9][..]),
        (0xC97FF4, &[0x47, 0x3B, 0x7E, 0x0C, 0x7C, 0xD9][..]),
        (0xC97FE8, &[0x0F, 0x95, 0xC2, 0x8B, 0xCD, 0x52, 0x50][..]),
    ] {
        // SAFETY: Fixed executable ranges in the supported image; this checks
        // the proven continuation contract without dispatching engine code.
        unsafe { super::patching::verify_bytes(address, bytes)? };
    }
    unsafe {
        RETAIN.init("havok_nullable_retain", 0xC90510 as *mut c_void, retain)?;
        RELEASE.init("havok_nullable_release", 0xC905B0 as *mut c_void, release)?;
        RELEASE_UNLOCKED.init(
            "havok_nullable_release_unlocked",
            0xC903B0 as *mut c_void,
            release_unlocked,
        )?;
        // No target is exposed until every configured entry and reference
        // provider is prepared. A later entry failure cannot leave an admitted
        // sparse flow while core startup reports that installation failed.
        if batch_entry {
            statics::HAVOK_ADD_ENTITY_BATCH_HOOK.init(
                "havok_add_entity_batch_null_guard",
                statics::HAVOK_ADD_ENTITY_BATCH_ADDR as *mut c_void,
                havok::hook_havok_add_entity_batch,
            )?;
        }
        if pending_entry {
            statics::HAVOK_PENDING_ADD_FLUSH_HOOK.init(
                "havok_pending_add_null_guard",
                statics::HAVOK_PENDING_ADD_FLUSH_ADDR as *mut c_void,
                havok::hook_havok_pending_add_flush,
            )?;
        }
    }
    // Publish each captured provider before any corresponding entry can call
    // its detour. The hook containers and their trampolines live for process
    // lifetime, including failed-activation rollback survivors. Keeping these
    // addresses local avoids LazyLock/Result work on every native reference.
    RETAIN_PROVIDER.store(RETAIN.original()? as *mut c_void, Ordering::Release);
    RELEASE_PROVIDER.store(RELEASE.original()? as *mut c_void, Ordering::Release);
    RELEASE_UNLOCKED_PROVIDER.store(
        RELEASE_UNLOCKED.original()? as *mut c_void,
        Ordering::Release,
    );
    let mut tx = ModificationTransaction::new();
    tx.enable_inline(&RETAIN)?;
    tx.enable_inline(&RELEASE)?;
    tx.enable_inline(&RELEASE_UNLOCKED)?;
    if batch_entry {
        tx.enable_inline(&statics::HAVOK_ADD_ENTITY_BATCH_HOOK)?;
    }
    if pending_entry {
        tx.enable_inline(&statics::HAVOK_PENDING_ADD_FLUSH_HOOK)?;
    }
    for patch in PATCHES.iter() {
        tx.apply_patch(patch)?;
    }
    tx.commit();
    ADMITTED.store(true, Ordering::Release);
    log::info!("[HAVOK] Sparse entity consumers and deferred reference flow active");
    if batch_entry {
        log::info!("[HAVOK] Batch array admission active");
    }
    if pending_entry {
        log::info!("[HAVOK] Pending array admission active");
    }
    Ok(())
}

/// Return whether every requested sparse-flow modification has committed.
///
/// Rollback survivors must chain native providers until this publication. This
/// lifecycle value is not a live byte-ownership or object-lifetime check.
#[inline]
pub(super) fn is_admitted() -> bool {
    ADMITTED.load(Ordering::Acquire)
}

macro_rules! reference_guard {
    ($name:ident, $provider:ident) => {
        /// Preserve native reference behavior for objects; NULL owns no reference.
        ///
        /// Safety: a non-NULL pointer must satisfy the installed provider's
        /// original lifetime and ownership contract. This guard inspects no
        /// object field and neither adds nor removes a native reference itself.
        unsafe extern "thiscall" fn $name(object: *mut c_void) {
            if object.is_null() && ADMITTED.load(Ordering::Acquire) {
                return;
            }
            // SAFETY: install publishes the non-NULL, precisely typed captured
            // trampoline before enable can expose this detour. Disable and
            // rollback never clear it; the core and trampoline live for process
            // lifetime. A callable entry cannot have an unpublished provider.
            let original: ReferenceFn =
                unsafe { std::mem::transmute($provider.load(Ordering::Acquire)) };
            unsafe { original(object) };
        }
    };
}
reference_guard!(retain, RETAIN_PROVIDER);
reference_guard!(release, RELEASE_PROVIDER);
reference_guard!(release_unlocked, RELEASE_UNLOCKED_PROVIDER);

/// Replays the entity load; a NULL slot takes the native loop increment.
/// Safety: entered only at 0xC94D90 with its native registers/stack. No Rust
/// call, FPU/SSE operation, or ownership change occurs on either branch.
#[unsafe(naked)]
unsafe extern "C" fn batch_entity() {
    naked_asm!(
        "mov edx, [esp + 0x5C]", "mov esi, [edx + eax * 4]",
        "pushfd", "test esi, esi", "jnz 2f",
        "cmp byte ptr [{admitted}], 0", "je 2f",
        "popfd", "push 0xC94EE2", "ret",
        "2:", "popfd", "push 0xC94D97", "ret",
        admitted = sym ADMITTED,
    );
}

/// Replays the callback-slot load; NULL advances without creating stack args.
/// Safety: entered only at 0xC95067. The skipped native body pushes twelve
/// bytes, so this path advances ESI and resumes after that body's ADD ESP,12.
#[unsafe(naked)]
unsafe extern "C" fn batch_callback() {
    naked_asm!(
        "mov ecx, [esp + 0x5C]", "mov ebp, [ecx + esi * 4]",
        "pushfd", "test ebp, ebp", "jnz 2f",
        "cmp byte ptr [{admitted}], 0", "je 2f",
        "popfd", "inc esi", "push 0xC9507F", "ret",
        "2:", "popfd", "push 0xC9506E", "ret",
        admitted = sym ADMITTED,
    );
}

/// Checks the actual pending slot before its first object-field access.
/// Safety: entered only at 0xC67577. Valid slots replay the displaced CMP and
/// its exact flags; NULL slots retain the array register and native loop tail.
#[unsafe(naked)]
unsafe extern "C" fn pending_entity() {
    naked_asm!(
        "mov edx, [esi + ebx * 4]",
        "pushfd", "test edx, edx", "jnz 2f",
        "cmp byte ptr [{admitted}], 0", "je 2f",
        "popfd", "push 0xC67681", "ret",
        "2:", "popfd", "cmp byte ptr [edx + 0x28], 1", "push 0xC6757E", "ret",
        admitted = sym ADMITTED,
    );
}

/// Checks the pending array again after the native add helper has executed.
/// Safety: entered only at 0xC675B0. A NULL second load skips the remaining
/// slot work before any stale owner/island read; ESI still holds the array.
#[unsafe(naked)]
unsafe extern "C" fn pending_reread() {
    naked_asm!(
        "mov eax, [esi + ebx * 4]",
        "pushfd", "test eax, eax", "jnz 2f",
        "cmp byte ptr [{admitted}], 0", "je 2f",
        "popfd", "push 0xC67681", "ret",
        "2:", "popfd", "mov esi, [eax + 0xCC]", "push 0xC675B9", "ret",
        admitted = sym ADMITTED,
    );
}

/// Preserves the collection caller's post-batch filter update for each object.
/// Safety: entered only at 0xCE16E0. NULL reaches the native INC/CMP tail before
/// filter arguments are pushed; valid slots continue with the original load.
#[unsafe(naked)]
unsafe extern "C" fn collection_filter() {
    naked_asm!(
        "mov ecx, [esi + 8]", "mov edx, [ecx + edi * 4]",
        "pushfd", "test edx, edx", "jnz 2f",
        "cmp byte ptr [{admitted}], 0", "je 2f",
        "popfd", "push 0xCE16F2", "ret",
        "2:", "popfd", "push 0xCE16E6", "ret",
        admitted = sym ADMITTED,
    );
}

/// Check the sparse fallback's actual reload before its single-entity add.
/// Safety: entered only at 0xC97FE2 with EAX pointing to the selected slot and
/// CL holding the native mode flag. NULL takes the existing loop increment
/// before either stack argument is pushed. Valid entries replay XOR/TEST so
/// SETNE at 0xC97FE8 still computes the original mode. No ownership is changed.
#[unsafe(naked)]
unsafe extern "C" fn sparse_single_add() {
    naked_asm!(
        "mov eax, [eax]",
        "pushfd", "test eax, eax", "jnz 2f",
        "cmp byte ptr [{admitted}], 0", "je 2f",
        "popfd", "push 0xC97FF4", "ret",
        "2:", "popfd", "xor edx, edx", "test cl, cl", "push 0xC97FE8", "ret",
        admitted = sym ADMITTED,
    );
}
