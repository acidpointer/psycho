//! Queued reference processing hook.
//!
//! FUN_0056f700 processes a TESObjectREFR after its IO task (model loading)
//! completes. For characters with HAVOK_DEATH, the ragdoll controller's
//! bone data has been freed through the Havok allocator (which does NOT go
//! through GameHeap). The processing path reads this freed bone data for
//! skeleton update, causing a use-after-free crash at 0x00A6DF48.
//!
//! With SBM, Havok's freed memory stayed readable (zombie data in fixed
//! arenas). With mimalloc, Havok's allocator recycles memory immediately.
//!
//! Fix: skip the processing for references with HAVOK_DEATH flag. The
//! ragdoll data is already destroyed -- updating it is pointless and
//! dangerous. The game will recreate the ragdoll on the next proper
//! processing cycle if needed.

use libc::c_void;

use super::destruction_guard;
use super::statics;

/// TESForm flags field offset from object base.
const TESFORM_FLAGS_OFFSET: usize = 0x08;

/// TESForm::kFormFlag_HavokDeath -- ragdoll death in progress, bone data
/// may be freed through Havok allocator.
const FLAG_HAVOK_DEATH: u32 = 0x10000;

/// Hook for FUN_0056f700 (queued reference processing).
/// Skips processing for references with HAVOK_DEATH to prevent
/// use-after-free on freed Havok ragdoll bone data.
pub unsafe extern "fastcall" fn hook_queued_ref_process(refr: *mut c_void) {
    // Defense-in-depth: skip if destruction is actively freeing objects.
    if destruction_guard::is_destruction_active() {
        return;
    }

    if !refr.is_null() {
        let flags = unsafe { *((refr as *const u8).add(TESFORM_FLAGS_OFFSET) as *const u32) };
        if flags & FLAG_HAVOK_DEATH != 0 {
            // Ragdoll bone data freed by Havok allocator. Skip processing
            // to avoid reading recycled memory in skeleton update path.
            return;
        }
    }

    if let Ok(original) = statics::QUEUED_REF_PROCESS_HOOK.original() {
        unsafe { original(refr) };
    }
}
