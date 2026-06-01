//! Guard for not-ready bhkRagdollController bone tables.
//!
//! The crash at `0x00A6DF48` is not an OOM. Ghidra shows the path:
//!
//! `FUN_00C7D810 -> FUN_00C79680 -> FUN_00C74DD0 -> FUN_00A6DF40`
//!
//! `FUN_00C79680` reads `*(ragdoll + 0xA4)[boneIndex] + 0x34`.
//! During cell attach a ragdoll can have a valid hierarchy at `+0x2A4`
//! while the bone pointer table at `+0xA4` still contains NULL entries.
//! Vanilla never checks this; with clean gheap memory the latent bug becomes
//! a reliable NULL+0x34 crash. The update wrappers are void best-effort
//! frame updates, so we skip the not-ready frame and let the next update retry.

use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};

use libpsycho::os::windows::winapi::virtual_query;

use super::statics;

const LOW_POINTER_LIMIT: usize = 0x10000;
const RAGDOLL_MIN_SIZE: usize = RAGDOLL_HIERARCHY_OFFSET + 4;
const RAGDOLL_SCENE_ROOT_OFFSET: usize = 0x48;
const RAGDOLL_TRANSFORM_ROOT_OFFSET: usize = 0x58;
const RAGDOLL_BONE_TABLE_OFFSET: usize = 0xA4;
const RAGDOLL_HIERARCHY_OFFSET: usize = 0x2A4;
const TRANSFORM_ROOT_MIN_SIZE: usize = 0x9C;
const SCENE_ROOT_MIN_SIZE: usize = 0x30;
const HIERARCHY_MIN_SIZE: usize = 0x10;
const BONE_GROUP_COUNT_OFFSET: usize = 0x1C;
const BONE_GROUP_MIN_SIZE: usize = BONE_GROUP_COUNT_OFFSET + 4;
const MAX_BONES: usize = 512;

static SKIPPED_UPDATES: AtomicU64 = AtomicU64::new(0);

pub unsafe extern "thiscall" fn hook_ragdoll_bone_transform_update(ragdoll: *mut c_void) {
    let original = match statics::RAGDOLL_BONE_TRANSFORM_UPDATE_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!(
                "[RAGDOLL] FUN_00C7D810 original trampoline missing: {:?}",
                e
            );
            return;
        }
    };

    if let Err(reason) = ragdoll_ready_for_bone_update(ragdoll) {
        log_skip("bone-transform", reason, ragdoll);
        return;
    }

    unsafe { original(ragdoll) };
}

pub unsafe extern "thiscall" fn hook_ragdoll_alternate_update(ragdoll: *mut c_void, arg: u32) {
    let original = match statics::RAGDOLL_ALTERNATE_UPDATE_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!(
                "[RAGDOLL] FUN_00C7D630 original trampoline missing: {:?}",
                e
            );
            return;
        }
    };

    if let Err(reason) = ragdoll_ready_for_bone_update(ragdoll) {
        log_skip("alternate", reason, ragdoll);
        return;
    }

    unsafe { original(ragdoll, arg) };
}

fn ragdoll_ready_for_bone_update(ragdoll: *mut c_void) -> Result<(), &'static str> {
    if ragdoll.is_null() {
        return Err("null-ragdoll");
    }

    let base = ragdoll as usize;
    if !is_readable(base, RAGDOLL_MIN_SIZE) {
        return Err("bad-ragdoll");
    }

    let scene_root = read_u32(base + RAGDOLL_SCENE_ROOT_OFFSET).ok_or("bad-scene-root-slot")?;
    if scene_root == 0 || !is_readable(scene_root as usize, SCENE_ROOT_MIN_SIZE) {
        return Err("bad-scene-root");
    }

    let transform_root =
        read_u32(base + RAGDOLL_TRANSFORM_ROOT_OFFSET).ok_or("bad-transform-root-slot")?;
    if transform_root == 0 || !is_readable(transform_root as usize, TRANSFORM_ROOT_MIN_SIZE) {
        return Err("bad-transform-root");
    }

    let hierarchy = read_u32(base + RAGDOLL_HIERARCHY_OFFSET).ok_or("bad-hierarchy-slot")?;
    if hierarchy == 0 || !is_readable(hierarchy as usize, HIERARCHY_MIN_SIZE) {
        return Err("bad-hierarchy");
    }

    let bone_group = read_u32(hierarchy as usize + 0x0C).ok_or("bad-bone-group-slot")?;
    if bone_group == 0 || !is_readable(bone_group as usize, BONE_GROUP_MIN_SIZE) {
        return Err("bad-bone-group");
    }

    let bone_count = read_u32(bone_group as usize + BONE_GROUP_COUNT_OFFSET)
        .ok_or("bad-bone-count-slot")? as usize;
    if bone_count == 0 {
        return Ok(());
    }
    if bone_count > MAX_BONES {
        return Err("bad-bone-count");
    }

    let bone_table = read_u32(base + RAGDOLL_BONE_TABLE_OFFSET).ok_or("bad-bone-table-slot")?;
    let table_len = bone_count
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or("bad-bone-count")?;
    if bone_table == 0 || !is_readable(bone_table as usize, table_len) {
        return Err("bad-bone-table");
    }

    for i in 0..bone_count {
        let Some(bone) = read_u32(bone_table as usize + i * core::mem::size_of::<u32>()) else {
            return Err("bad-bone-slot");
        };
        if bone as usize <= LOW_POINTER_LIMIT {
            return Err("null-bone");
        }
    }

    Ok(())
}

fn read_u32(addr: usize) -> Option<u32> {
    if !is_readable(addr, core::mem::size_of::<u32>()) {
        return None;
    }

    Some(unsafe { core::ptr::read_unaligned(addr as *const u32) })
}

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < LOW_POINTER_LIMIT || len == 0 {
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

    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    let region_end = (info.base_address as usize).saturating_add(info.region_size);
    end <= region_end
}

fn log_skip(site: &'static str, reason: &'static str, ragdoll: *mut c_void) {
    let n = SKIPPED_UPDATES.fetch_add(1, Ordering::Relaxed) + 1;
    if n != 1 && !n.is_power_of_two() {
        return;
    }

    log::warn!(
        "[RAGDOLL] not-ready update skipped: site={} reason={} total={} ragdoll=0x{:08X}",
        site,
        reason,
        n,
        ragdoll as usize,
    );
}
