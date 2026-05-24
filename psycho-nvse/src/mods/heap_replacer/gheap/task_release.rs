//! Guard for the IO task release path (`FUN_0044DD60`).
//!
//! Ghidra analysis of the QueuedTexture crash path shows task release
//! decrementing the refcount at `this + 0x08`; when it reaches zero the
//! game calls vtable[0](1). Full gheap makes stale task objects easier
//! to recycle, so an already-dead task can turn into a bad virtual call.
//!
//! This hook leaves normal positive-refcount releases alone. It only
//! blocks states the original function cannot handle safely: unreadable
//! task memory, non-positive refcount before decrement, or a final release
//! whose virtual destructor target is outside the game image.

use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};

use libpsycho::os::windows::winapi::virtual_query;

use super::statics;

const REFCOUNT_OFFSET: usize = 0x08;
const QUEUED_TEXTURE_VTABLE: usize = 0x0101_6788;
const FNV_TEXT_START: usize = 0x0040_0000;
const FNV_TEXT_END: usize = 0x00E0_0000;
const FNV_RDATA_START: usize = 0x0100_0000;
const FNV_RDATA_END: usize = 0x0110_0000;

static BAD_PTR_COUNT: AtomicU64 = AtomicU64::new(0);
static NON_POSITIVE_COUNT: AtomicU64 = AtomicU64::new(0);
static BAD_VTABLE_COUNT: AtomicU64 = AtomicU64::new(0);
static QUEUED_TEXTURE_FINAL_COUNT: AtomicU64 = AtomicU64::new(0);
static CONFIG_LOGGED: AtomicU64 = AtomicU64::new(0);

pub unsafe extern "fastcall" fn hook_task_release(task: *mut c_void) {
    if !guard_enabled() {
        call_original(task);
        return;
    }

    let task_addr = task as usize;
    if task_addr == 0 || !is_readable(task_addr, REFCOUNT_OFFSET + 4) {
        log_guard(&BAD_PTR_COUNT, "bad-ptr", task_addr, 0, 0, 0);
        return;
    }

    let vtable = unsafe { ptr::read_unaligned(task as *const usize) };
    let refcount =
        unsafe { ptr::read_unaligned((task as *const u8).add(REFCOUNT_OFFSET) as *const i32) };

    if refcount <= 0 {
        log_guard(
            &NON_POSITIVE_COUNT,
            "non-positive-refcount",
            task_addr,
            vtable,
            0,
            refcount,
        );
        return;
    }

    if vtable == QUEUED_TEXTURE_VTABLE && refcount == 1 {
        log_observe(
            &QUEUED_TEXTURE_FINAL_COUNT,
            "queuedtexture-final-release",
            task_addr,
            vtable,
            0,
            refcount,
        );
    }

    // Only the final release dispatches through the vtable. For
    // refcount > 1 the original path just decrements and returns.
    if refcount == 1 {
        match validate_final_release(vtable) {
            Some(dtor) => {
                if !is_text_ptr(dtor) {
                    log_guard(
                        &BAD_VTABLE_COUNT,
                        "bad-dtor",
                        task_addr,
                        vtable,
                        dtor,
                        refcount,
                    );
                    return;
                }
            }
            None => {
                log_guard(
                    &BAD_VTABLE_COUNT,
                    "bad-vtable",
                    task_addr,
                    vtable,
                    0,
                    refcount,
                );
                return;
            }
        }
    }

    call_original(task);
}

fn guard_enabled() -> bool {
    let enabled = crate::config::get_config()
        .map(|c| c.memory.gheap_task_release_guard)
        .unwrap_or(true);
    if !enabled && CONFIG_LOGGED.fetch_add(1, Ordering::Relaxed) == 0 {
        log::warn!("[TASK_RELEASE] guard disabled by config");
    }
    enabled
}

fn call_original(task: *mut c_void) {
    if let Ok(original) = statics::TASK_RELEASE_HOOK.original() {
        unsafe { original(task) };
    }
}

fn validate_final_release(vtable: usize) -> Option<usize> {
    if !is_rdata_ptr(vtable) || !is_readable(vtable, 4) {
        return None;
    }
    Some(unsafe { ptr::read_unaligned(vtable as *const usize) })
}

fn is_rdata_ptr(addr: usize) -> bool {
    (FNV_RDATA_START..FNV_RDATA_END).contains(&addr)
}

fn is_text_ptr(addr: usize) -> bool {
    (FNV_TEXT_START..FNV_TEXT_END).contains(&addr)
}

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(addr as *mut c_void) else {
        return false;
    };
    if info.state != MEM_COMMIT.0 || info.protect == PAGE_NOACCESS {
        return false;
    }
    if (info.protect.0 & PAGE_GUARD.0) != 0 {
        return false;
    }
    let end = addr.saturating_add(len);
    let region_end = (info.base_address as usize).saturating_add(info.region_size);
    end <= region_end
}

fn log_observe(
    counter: &AtomicU64,
    reason: &'static str,
    task: usize,
    vtable: usize,
    dtor: usize,
    refcount: i32,
) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        log::debug!(
            "[TASK_RELEASE] observe={} total={} task=0x{:08x} vt=0x{:08x} dtor=0x{:08x} rc={}",
            reason,
            n,
            task,
            vtable,
            dtor,
            refcount,
        );
    }
}

fn log_guard(
    counter: &AtomicU64,
    reason: &'static str,
    task: usize,
    vtable: usize,
    dtor: usize,
    refcount: i32,
) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        log::warn!(
            "[TASK_RELEASE] guard={} total={} task=0x{:08x} vt=0x{:08x} dtor=0x{:08x} rc={}",
            reason,
            n,
            task,
            vtable,
            dtor,
            refcount,
        );
    }
}
