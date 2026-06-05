//! Guard for the model-loader LockFreeStringMap task destructor.
//!
//! Stress testing found FUN_00446B50 dispatching task vtable slot +0x1c
//! to FUN_00449A50 after the target object was already freed. The object
//! was an 80-byte gheap pool cell whose LockFreeStringMap holder field
//! at +0x14 contained 1, so the vanilla destructor called
//! FUN_00559450(1) and faulted reading address 1.
//!
//! Normal live destructors still run through vanilla. Only cells that
//! gheap already marks free are skipped.

use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;

use super::{pool, statics};

const MODEL_TASK_VTABLE: usize = 0x0101_7138;
const MODEL_TASK_DTOR_VTABLE: usize = 0x0101_72DC;
const MODEL_TASK_POOL_SIZE: u32 = 80;

static STALE_MODEL_TASK_DTORS: AtomicU64 = AtomicU64::new(0);

pub unsafe extern "thiscall" fn hook_model_task_dtor(this: *mut c_void, flags: u32) -> *mut c_void {
    if is_stale_model_task(this) {
        log_skip(this, flags);
        return this;
    }

    match statics::MODEL_TASK_DTOR_HOOK.original() {
        Ok(original) => unsafe { original(this, flags) },
        Err(e) => {
            log::error!(
                "[MODEL_TASK] FUN_00449A50 original trampoline missing: {:?}",
                e
            );
            this
        }
    }
}

fn is_stale_model_task(this: *mut c_void) -> bool {
    let Some(info) = pool::ptr_info(this) else {
        return false;
    };
    if !info.committed || info.offset != 0 || info.item_size != MODEL_TASK_POOL_SIZE {
        return false;
    }
    if !info.is_free {
        return false;
    }

    let vtable = unsafe { core::ptr::read_unaligned(this as *const usize) };
    vtable == MODEL_TASK_VTABLE || vtable == MODEL_TASK_DTOR_VTABLE
}

fn log_skip(this: *mut c_void, flags: u32) {
    let n = STALE_MODEL_TASK_DTORS.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        let state = pool::ptr_info(this).map(|_| "free").unwrap_or("unknown");
        log::warn!(
            "[MODEL_TASK] skipped stale LockFreeStringMap<Model*> destructor total={} this=0x{:08x} flags=0x{:x} state={}",
            n,
            this as usize,
            flags,
            state,
        );
    }
}
