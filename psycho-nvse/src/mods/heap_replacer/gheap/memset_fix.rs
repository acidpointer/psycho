//! Replacement for the game's inlined `_memset` at `0x00ec61c0`.
//!
//! Two jobs in one hook:
//!
//! 1. **NULL-dst defense.** The game heap's aligned-calloc wrapper at
//!    `FUN_00aa2240` (heap singleton vtable[4], called via NiPixelData
//!    allocation and many other code paths) does `alloc + memset`
//!    without null-checking the alloc return. When our worker OOM
//!    recovery returns NULL, memset writes to offset 0 of a NULL
//!    destination and crashes in `__VEC_memzero` at `0x00ed2c9e`. Our
//!    hook returns the NULL destination unchanged and the memset
//!    becomes a silent no-op.
//!    See analysis/ghidra/output/crash/oom_memset_crash_analysis.txt.
//!
//! 2. **Full replacement of `_memset`.** We don't call the original
//!    trampoline at all. `core::ptr::write_bytes` is LLVM-intrinsic and
//!    compiles to SSE2 `movdqa` / `movdqu` / `rep stos` depending on
//!    size and alignment. That matches what the game's inlined
//!    `__VEC_memzero` fast path was already doing, minus the trampoline
//!    + JMP + retpoline-style indirection our hook would otherwise
//!      incur. This path is called from 121+ game call sites across the
//!      render/scene graph subsystems; cutting a few cycles per call is
//!      worth the replacement.
//!
//! Safety notes on the `core::ptr::write_bytes` choice:
//!
//! - No recursion into ourselves. `write_bytes` is an LLVM intrinsic.
//!   For small sizes LLVM inlines the store sequence; for larger sizes
//!   it emits a call to `memset` from Rust's compiler-builtins, which
//!   lives inside `psycho-nvse.dll` at a different address from the
//!   game's `0x00ec61c0`. Our hook only patches the game's address, so
//!   the compiler-builtins memset runs unhooked.
//! - Matches the C memset contract: `memset(dst, val, n)` returns `dst`
//!   unchanged. Callers that check the return value see the same
//!   pointer they passed in, including NULL on the defensive path.
//! - `val` is promoted to `i32` in the cdecl ABI but only the low byte
//!   is used, matching the C standard.

use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;

/// Counts how many times we short-circuited a NULL memset. Non-zero
/// here means the game called `memset(NULL, ...)`, which means our OOM
/// path returned NULL and some caller did not check. Logged at
/// power-of-two boundaries to keep the log readable.
static NULL_SKIPS: AtomicU64 = AtomicU64::new(0);

/// Replacement for `_memset` at `0x00ec61c0`. Does not call the
/// original; performs the fill directly via `core::ptr::write_bytes`.
pub unsafe extern "C" fn hook_memset(dst: *mut c_void, val: i32, size: usize) -> *mut c_void {
    if dst.is_null() {
        let n = NULL_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 || n.is_power_of_two() {
            log::warn!(
                "[MEMSET] NULL dst skipped (total={}, val={}, size={}). \
                 Upstream allocator returned NULL and the caller did not check.",
                n,
                val,
                size,
            );
        }
        return dst;
    }

    if size != 0 {
        unsafe {
            core::ptr::write_bytes(dst as *mut u8, val as u8, size);
        }
    }
    dst
}
