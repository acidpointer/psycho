//! Texture cache dead set: prevents BSTaskManagerThread crashes on stale
//! NiSourceTexture pointers in the texture cache hash table.
//!
//! The texture cache (DAT_011f4468) is write-only -- entries are added but
//! never removed individually. Only full resets happen during worldspace
//! transitions. In the vanilla game with SBM, freed NiSourceTextures stay
//! readable as zombies. With mimalloc, freed memory is recycled, so stale
//! cache entries cause BSTaskManagerThread to read garbage.
//!
//! Fix: maintain a dead set of destroyed NiSourceTexture addresses.
//! - NiSourceTexture dtor hook: insert `this` into dead set
//! - Hash table find hook: check entries against dead set, skip dead ones
//! - tick(): clear dead set every frame

use libc::c_void;

use clashmap::ClashMap;
use rustc_hash::FxBuildHasher;

use libpsycho::ffi::fnptr::FnPtr;

use super::statics;

type DeadSet = ClashMap<usize, (), FxBuildHasher>;

static TEXTURE_DEAD_SET: std::sync::LazyLock<DeadSet> =
    std::sync::LazyLock::new(|| ClashMap::with_hasher(FxBuildHasher));

/// Clear the dead set. Called from on_frame_tick() every frame.
/// After one frame, new QueuedTexture tasks will load fresh textures.
pub fn clear_dead_set() {
    TEXTURE_DEAD_SET.clear();
}

// ---- NiSourceTexture destructor hook ----

/// Inserts `this` into the dead set BEFORE calling the original destructor.
/// The destructor zeroes pixelData fields -- after it runs, the object is
/// destroyed but the texture cache still has a stale entry pointing to it.
pub unsafe extern "fastcall" fn hook_nisourcetexture_dtor(this: *mut c_void) {
    TEXTURE_DEAD_SET.insert(this as usize, ());

    if let Ok(original) = statics::NISOURCETEXTURE_DTOR_HOOK.original() {
        unsafe { original(this) };
    }
}

// ---- Texture cache hash table find hook ----

/// Chain entry layout: { [0]: value_ptr (wrapper), [4]: next_ptr }
/// Wrapper layout:     { [0]: inner_ptr (NiSourceTexture*), [4]: key }
///
/// Fast path: if no dead entries in the bucket, call original directly.
/// Slow path: traverse chain skipping dead entries.
pub unsafe extern "thiscall" fn hook_texture_cache_find(
    this: *mut c_void,
    param_1: i32,
    param_2: i32,
    param_3: *mut *mut i32,
) -> u32 {
    let bucket_head = unsafe {
        *((this as *const u8).add((param_1 as usize) * 4) as *const *const u32)
    };

    if bucket_head.is_null() {
        return 0;
    }

    // with_try_read: main thread runs directly, worker acquires read lock.
    // If drain in progress (worker, lock fails), return 0 (not found).
    super::game_guard::with_try_read(|| {
        unsafe { find_in_chain(this, bucket_head, param_1, param_2, param_3) }
    })
    .unwrap_or(0)
}

unsafe fn find_in_chain(
    this: *mut c_void,
    bucket_head: *const u32,
    param_1: i32,
    param_2: i32,
    param_3: *mut *mut i32,
) -> u32 {
    // Check if any entry in this bucket has a dead inner_ptr.
    // If not, call original directly (zero overhead for clean buckets).
    let has_dead = unsafe { chain_has_dead_entry(bucket_head) };
    if !has_dead {
        if let Ok(original) = statics::TEXTURE_CACHE_FIND_HOOK.original() {
            return unsafe { original(this, param_1, param_2, param_3) };
        }
        return 0;
    }

    // Slow path: traverse chain skipping dead entries
    unsafe { find_skipping_dead(bucket_head, param_2, param_3) }
}

unsafe fn chain_has_dead_entry(mut entry: *const u32) -> bool {
    unsafe {
        loop {
            let value_ptr = *entry as *const i32;
            if !value_ptr.is_null() {
                let inner_ptr = *value_ptr as usize;
                if inner_ptr != 0 && TEXTURE_DEAD_SET.contains_key(&inner_ptr) {
                    return true;
                }
            }
            let next = *(entry.add(1)) as *const u32;
            if next.is_null() {
                return false;
            }
            entry = next;
        }
    }
}

/// Traverse the hash chain, skipping entries with dead NiSourceTextures.
/// Matches the original FUN_00a61a60 logic but adds dead-set filtering.
unsafe fn find_skipping_dead(
    mut entry: *const u32,
    key: i32,
    out: *mut *mut i32,
) -> u32 {
    unsafe {
        loop {
            let value_ptr = *entry as *const i32;

            if !value_ptr.is_null() {
                let inner_ptr = *value_ptr as usize;

                // Skip dead entries (NiSourceTexture destroyed by PDD)
                if inner_ptr == 0 || TEXTURE_DEAD_SET.contains_key(&inner_ptr) {
                    let next = *(entry.add(1)) as *const u32;
                    if next.is_null() {
                        return 0;
                    }
                    entry = next;
                    continue;
                }

                let entry_key = *value_ptr.add(1);
                if key == entry_key {
                    // Found live match -- swap refcounted pointer
                    let old_val = *out;
                    let new_inner = inner_ptr as *mut i32;
                    if old_val != new_inner {
                        if !old_val.is_null() {
                            // DecRef old: InterlockedDecrement(old+4)
                            let rc = std::sync::atomic::AtomicI32::from_ptr(old_val.add(1))
                                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
                                - 1;
                            if rc == 0 {
                                // vtable[1] = destructor (thiscall)
                                let vtable = *(old_val as *const *const usize);
                                let dtor_addr = *vtable.add(1) as *mut c_void;
                                if let Ok(dtor) = FnPtr::<
                                    unsafe extern "thiscall" fn(*mut c_void),
                                >::from_raw(dtor_addr)
                                    && let Ok(f) = dtor.as_fn()
                                {
                                    f(old_val as *mut c_void);
                                }
                            }
                        }
                        *out = new_inner;
                        if !new_inner.is_null() {
                            // AddRef new: InterlockedIncrement(new+4)
                            std::sync::atomic::AtomicI32::from_ptr(new_inner.add(1))
                                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        }
                    }
                    return 1;
                }
            }

            let next = *(entry.add(1)) as *const u32;
            if next.is_null() {
                return 0;
            }
            entry = next;
        }
    }
}
