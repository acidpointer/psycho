//! Shared `ExtraContainerChanges::EntryData` save admission and legacy filter.
//!
//! The scoped inventory-save guard takes precedence inside its owned main save;
//! valid complete lists forward through the original serializer and rejection
//! fails the whole save. Outside that owner, only the configured legacy filter
//! applies. The load filter remains independently controlled by its old setting.
//!
//! The crash at `0x00865DFB` was a save-time dereference of
//! `EntryData.type == 0x00000007`. Ghidra shows the form-ref load resolver
//! returns either a real `TESForm*` or NULL, and vanilla only rejects NULL
//! before appending loaded entries. That makes this a containment boundary:
//! stale or overwritten entries must be filtered before the save writer
//! encodes their form pointer.
//!
//! Do not guard `0x004BED60` directly. The caller `0x004D4090` increments
//! the saved EntryData count only after `0x004BED60` returns, so skipping
//! inside the body-save function would desync the serialized count.

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use libc::c_void;
use libpsycho::{ffi::fnptr::FnPtr, os::windows::winapi::virtual_query};

use super::{
    inventory_save_guard,
    list_validation::{Access, MemoryFailure, RegionReader},
    statics,
};

const ENTRYDATA_EXTEND_LIST_OFFSET: usize = 0x00;
const ENTRYDATA_COUNT_DELTA_OFFSET: usize = 0x04;
const ENTRYDATA_TYPE_OFFSET: usize = 0x08;
const ENTRYDATA_SIZE: usize = 0x0C;

const SAVE_BUFFER_CHANGE_FLAGS_OFFSET: usize = 0x17;
const SAVE_BUFFER_STATE_OFFSET: usize = 0x20;
const ENTRYDATA_CHANGE_FLAGS: u32 = 0x400;

const FNV_TEXT_START: usize = 0x0040_0000;
const FNV_TEXT_END: usize = 0x00E0_0000;
const FNV_RDATA_START: usize = 0x0100_0000;
const FNV_RDATA_END: usize = 0x0110_0000;

const ENTRYDATA_BODY_SAVE_ADDR: usize = 0x004BED60;
const SAVE_COUNT_BEGIN_ADDR: usize = 0x00865F20;
const SAVE_COUNT_END_ADDR: usize = 0x00865FF0;
const LIST_NODE_DATA_ADDR: usize = 0x006815C0;
const LIST_NODE_NEXT_ADDR: usize = 0x00726070;

type SaveGetStateFn = unsafe extern "thiscall" fn(*mut c_void) -> u32;
type SaveCountBeginFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;
type SaveCountEndFn = unsafe extern "thiscall" fn(*mut c_void, u32, u32);
type ListNodeDataFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut *mut EntryData;
type ListNodeNextFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type EntryDataBodySaveFn = unsafe extern "thiscall" fn(*mut EntryData, *mut c_void);

#[repr(C)]
struct EntryData {
    extend_data: *mut c_void,
    count_delta: i32,
    type_form: *mut c_void,
}

static LEGACY_FILTER: AtomicBool = AtomicBool::new(false);

/// Configure the existing filter before its shared hook becomes callable.
pub(super) fn configure_legacy_filter(enabled: bool) {
    LEGACY_FILTER.store(enabled, Ordering::Release);
}

static SAVE_SKIP_COUNT: AtomicU64 = AtomicU64::new(0);
static LOAD_DROP_COUNT: AtomicU64 = AtomicU64::new(0);

pub unsafe extern "thiscall" fn hook_entrydata_list_save(
    list: *mut c_void,
    save_buffer: *mut c_void,
) {
    let filter = LEGACY_FILTER
        .load(Ordering::Acquire)
        .then_some(admit_legacy_entry as inventory_save_guard::EntryFilter);
    if let Some(admitted) =
        inventory_save_guard::admit_list(list as usize, save_buffer as usize, filter)
    {
        if admitted {
            call_original_list_save(list, save_buffer);
        }
        return;
    }
    if !LEGACY_FILTER.load(Ordering::Acquire) || list.is_null() || save_buffer.is_null() {
        call_original_list_save(list, save_buffer);
        return;
    }

    let old_state = read_save_state(save_buffer);
    let old_flags = read_unaligned_u32(save_buffer, SAVE_BUFFER_CHANGE_FLAGS_OFFSET);

    write_unaligned_u32(save_buffer, SAVE_BUFFER_STATE_OFFSET, 0);
    write_unaligned_u32(
        save_buffer,
        SAVE_BUFFER_CHANGE_FLAGS_OFFSET,
        ENTRYDATA_CHANGE_FLAGS,
    );

    let count_marker = save_count_begin(save_buffer);
    let mut saved_count = 0u32;
    let mut node = unsafe { ptr::read_unaligned(list as *const *mut c_void) };

    while !node.is_null() {
        let entry = node_entry(node);
        if !entry.is_null() {
            if is_valid_entry(entry) {
                entrydata_body_save(entry, save_buffer);
                saved_count = saved_count.saturating_add(1);
            } else {
                log_invalid_entry(&SAVE_SKIP_COUNT, "save-skip", entry);
            }
        }
        node = list_node_next(node);
    }

    save_count_end(save_buffer, saved_count, count_marker);

    write_unaligned_u32(save_buffer, SAVE_BUFFER_STATE_OFFSET, old_state);
    write_unaligned_u32(save_buffer, SAVE_BUFFER_CHANGE_FLAGS_OFFSET, old_flags);
}

/// Preserve the old NULL, low-address, single-region and vtable/code predicates
/// within structural admission's existing walk. Every dereference is a fresh
/// guarded copy; only mapping capabilities are reused until the provider call.
fn admit_legacy_entry(
    reader: &mut RegionReader,
    entry: usize,
    image: &[u8; 12],
    form_image: Option<&[u8; 16]>,
) -> Result<bool, MemoryFailure> {
    if entry < 0x10000 || !reader.within_single_region(entry, ENTRYDATA_SIZE, Access::Read)? {
        return Ok(false);
    }
    let form = u32::from_le_bytes([image[8], image[9], image[10], image[11]]) as usize;
    if form < 0x10000 || !reader.within_single_region(form, 0x10, Access::Read)? {
        return Ok(false);
    }
    let Some(form_image) = form_image else {
        return Ok(false);
    };
    let vtable =
        u32::from_le_bytes([form_image[0], form_image[1], form_image[2], form_image[3]]) as usize;
    if !is_rdata_ptr(vtable) || !reader.within_single_region(vtable, 4, Access::Read)? {
        return Ok(false);
    }
    let first_method = u32::from_le_bytes(reader.copy::<4>(vtable, Access::Read)?) as usize;
    Ok(is_text_ptr(first_method))
}

pub unsafe extern "thiscall" fn hook_entrydata_load(entry: *mut c_void, load_buffer: *mut c_void) {
    if let Ok(original) = statics::ENTRYDATA_LOAD_HOOK.original() {
        unsafe { original(entry, load_buffer) };
    }

    if entry.is_null() {
        return;
    }

    let entry = entry as *mut EntryData;
    if !is_readable(entry as usize, ENTRYDATA_SIZE) {
        log_invalid_entry(&LOAD_DROP_COUNT, "load-unreadable-entry", entry);
        return;
    }

    let form = unsafe { ptr::read_unaligned(ptr::addr_of!((*entry).type_form)) };
    if form.is_null() || is_valid_tes_form(form) {
        return;
    }

    log_invalid_entry(&LOAD_DROP_COUNT, "load-invalid-type", entry);
    unsafe {
        ptr::write_unaligned(ptr::addr_of_mut!((*entry).type_form), ptr::null_mut());
    }
}

fn call_original_list_save(list: *mut c_void, save_buffer: *mut c_void) {
    if let Ok(original) = statics::ENTRYDATA_LIST_SAVE_HOOK.original() {
        unsafe { original(list, save_buffer) };
    }
}

fn read_save_state(save_buffer: *mut c_void) -> u32 {
    let vtable = unsafe { ptr::read_unaligned(save_buffer as *const *const usize) };
    let get_state_addr = unsafe { ptr::read_unaligned(vtable) };
    let Ok(get_state) =
        (unsafe { FnPtr::<SaveGetStateFn>::from_raw(get_state_addr as *mut c_void) })
    else {
        return 0;
    };
    unsafe { get_state.as_fn()(save_buffer) }
}

fn save_count_begin(save_buffer: *mut c_void) -> u32 {
    let begin =
        unsafe { FnPtr::<SaveCountBeginFn>::from_address_unchecked(SAVE_COUNT_BEGIN_ADDR) }.as_fn();
    unsafe { begin(save_buffer) }
}

fn save_count_end(save_buffer: *mut c_void, count: u32, marker: u32) {
    let end =
        unsafe { FnPtr::<SaveCountEndFn>::from_address_unchecked(SAVE_COUNT_END_ADDR) }.as_fn();
    unsafe { end(save_buffer, count, marker) };
}

fn node_entry(node: *mut c_void) -> *mut EntryData {
    let get_data =
        unsafe { FnPtr::<ListNodeDataFn>::from_address_unchecked(LIST_NODE_DATA_ADDR) }.as_fn();
    let slot = unsafe { get_data(node) };
    if slot.is_null() {
        ptr::null_mut()
    } else {
        unsafe { ptr::read_unaligned(slot) }
    }
}

fn list_node_next(node: *mut c_void) -> *mut c_void {
    let next =
        unsafe { FnPtr::<ListNodeNextFn>::from_address_unchecked(LIST_NODE_NEXT_ADDR) }.as_fn();
    unsafe { next(node) }
}

fn entrydata_body_save(entry: *mut EntryData, save_buffer: *mut c_void) {
    let save =
        unsafe { FnPtr::<EntryDataBodySaveFn>::from_address_unchecked(ENTRYDATA_BODY_SAVE_ADDR) }
            .as_fn();
    unsafe { save(entry, save_buffer) };
}

fn is_valid_entry(entry: *mut EntryData) -> bool {
    if !is_readable(entry as usize, ENTRYDATA_SIZE) {
        return false;
    }

    let form = unsafe { ptr::read_unaligned(ptr::addr_of!((*entry).type_form)) };
    !form.is_null() && is_valid_tes_form(form)
}

fn is_valid_tes_form(form: *mut c_void) -> bool {
    let form_addr = form as usize;
    if !is_readable(form_addr, 0x10) {
        return false;
    }

    let vtable = unsafe { ptr::read_unaligned(form as *const usize) };
    if !is_rdata_ptr(vtable) || !is_readable(vtable, 4) {
        return false;
    }

    let first_method = unsafe { ptr::read_unaligned(vtable as *const usize) };
    is_text_ptr(first_method)
}

fn read_unaligned_u32(base: *mut c_void, offset: usize) -> u32 {
    unsafe { ptr::read_unaligned((base as *const u8).add(offset) as *const u32) }
}

fn write_unaligned_u32(base: *mut c_void, offset: usize, value: u32) {
    unsafe { ptr::write_unaligned((base as *mut u8).add(offset) as *mut u32, value) };
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
    if !info.is_accessible() {
        return false;
    }
    let end = addr.saturating_add(len);
    let region_end = (info.base_address as usize).saturating_add(info.region_size);
    end <= region_end
}

fn log_invalid_entry(counter: &AtomicU64, reason: &'static str, entry: *mut EntryData) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if !n.is_power_of_two() {
        return;
    }

    let entry_addr = entry as usize;
    let (extend_data, count_delta, form) = if is_readable(entry_addr, ENTRYDATA_SIZE) {
        unsafe {
            (
                ptr::read_unaligned(
                    (entry as *const u8).add(ENTRYDATA_EXTEND_LIST_OFFSET) as *const usize
                ),
                ptr::read_unaligned(
                    (entry as *const u8).add(ENTRYDATA_COUNT_DELTA_OFFSET) as *const i32
                ),
                ptr::read_unaligned((entry as *const u8).add(ENTRYDATA_TYPE_OFFSET) as *const usize),
            )
        }
    } else {
        (0, 0, 0)
    };

    let vtable = if is_readable(form, 4) {
        unsafe { ptr::read_unaligned(form as *const usize) }
    } else {
        0
    };

    log::warn!(
        "[ENTRYDATA] guard={} total={} entry=0x{:08x} type=0x{:08x} vt=0x{:08x} count_delta={} extend=0x{:08x}",
        reason,
        n,
        entry_addr,
        form,
        vtable,
        count_delta,
        extend_data,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpsycho::os::windows::winapi::{
        native_system_layout, virtual_release, virtual_reserve_commit, with_virtual_protect,
    };

    struct Pages(*mut c_void);
    impl Drop for Pages {
        fn drop(&mut self) {
            unsafe { virtual_release(self.0) };
        }
    }

    #[test]
    fn production_fused_legacy_admission_preserves_the_load_predicate() {
        let layout = native_system_layout();
        // Reserve a vacant page in the existing native range when available.
        // A large test image can occupy that range, in which case inspect its
        // real readable storage instead. Never overwrite an occupied image or
        // widen the production predicate to accommodate a fixture allocation.
        let _reservation = (FNV_RDATA_START..FNV_RDATA_END)
            .step_by(layout.allocation_granularity as usize)
            .find_map(|address| {
                let page = unsafe {
                    virtual_reserve_commit(
                        Some(address as *const c_void),
                        layout.page_size as usize,
                    )
                };
                if page.is_null() {
                    None
                } else {
                    unsafe { page.cast::<u32>().write(FNV_TEXT_START as u32) };
                    Some(Pages(page))
                }
            });
        let mut reader = RegionReader::default();
        let mut vtable = None;
        let mut invalid_vtable = None;
        for address in (FNV_RDATA_START..FNV_RDATA_END).step_by(4096) {
            if let Ok(image) = reader.copy::<4096>(address, Access::Read) {
                for (index, word) in image.chunks_exact(4).enumerate() {
                    let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as usize;
                    if is_text_ptr(value) {
                        vtable.get_or_insert(address + index * 4);
                    } else {
                        invalid_vtable.get_or_insert(address + index * 4);
                    }
                }
            }
            if vtable.is_some() && invalid_vtable.is_some() {
                break;
            }
        }
        let vtable = vtable.expect("readable image code-pointer cell in native range");
        let invalid_vtable = invalid_vtable.expect("readable image non-code cell in native range");
        let mut form = [vtable as u32, 0, 0, 0x1234];
        let mut entry = EntryData {
            extend_data: ptr::null_mut(),
            count_delta: -17,
            type_form: form.as_mut_ptr().cast(),
        };
        let check = |entry: *mut EntryData| {
            let node = [entry as u32, 0];
            let data = [node.as_ptr() as u32, 0, 0, 0, 0];
            assert_eq!(
                inventory_save_guard::validate_list(
                    data.as_ptr() as usize,
                    Some(admit_legacy_entry)
                )
                .is_ok(),
                is_valid_entry(entry),
            );
        };
        check(&raw mut entry);
        assert!(is_valid_entry(&raw mut entry));
        for candidate in [0, FNV_RDATA_END, invalid_vtable, vtable] {
            form[0] = candidate as u32;
            std::hint::black_box(&form);
            check(&raw mut entry);
        }
        for form_address in [
            ptr::null_mut(),
            7usize as *mut c_void,
            form.as_mut_ptr().cast(),
        ] {
            entry.type_form = form_address;
            check(&raw mut entry);
        }
        // A NULL form remains legal when the legacy filter is disabled.
        entry.type_form = ptr::null_mut();
        let node = [&entry as *const EntryData as u32, 0];
        let data = [node.as_ptr() as u32, 0, 0, 0, 0];
        assert_eq!(
            inventory_save_guard::validate_list(data.as_ptr() as usize, None),
            Ok(())
        );
        entry.type_form = form.as_mut_ptr().cast();

        let page_size = layout.page_size as usize;
        let pages = Pages(unsafe { virtual_reserve_commit(None, page_size * 2) });
        assert!(!pages.0.is_null());
        let boundary = pages.0 as usize + page_size;
        let crossing = (boundary - 4) as *mut EntryData;
        unsafe { crossing.write(entry) };
        assert!(is_valid_entry(crossing));
        let mut protection = virtual_query(boundary as *mut c_void)
            .expect("query fixture")
            .protect;
        protection.0 = 0x02; // PAGE_READONLY creates a second readable region.
        unsafe {
            with_virtual_protect(boundary as *mut c_void, protection, page_size, || {
                assert!(!is_valid_entry(crossing));
                check(crossing);
                let node = [crossing as u32, 0];
                let data = [node.as_ptr() as u32, 0, 0, 0, 0];
                assert_eq!(
                    inventory_save_guard::validate_list(data.as_ptr() as usize, None),
                    Ok(())
                );
            })
        }
        .expect("scope fixture protection");
    }

    #[test]
    fn production_legacy_admission_keeps_existing_invalid_form_coverage() {
        // Actual owned storage with the proven Data -> node -> EntryData ->
        // form-prefix layout. A readable prefix with a NULL vtable is rejected
        // by the existing predicate; structural admission alone is insufficient.
        let form = [0u32, 0, 0, 0x1234];
        let entry = EntryData {
            extend_data: ptr::null_mut(),
            count_delta: 3,
            type_form: form.as_ptr() as *mut c_void,
        };
        let node = [&entry as *const EntryData as u32, 0];
        let mut data = [0u32; 5];
        data[0] = node.as_ptr() as u32;
        assert_eq!(
            inventory_save_guard::validate_list(data.as_ptr() as usize, Some(admit_legacy_entry)),
            Err(inventory_save_guard::Rejection::LegacyForm(
                &entry as *const EntryData as usize
            ))
        );
        assert_eq!(entry.count_delta, 3);
        data[0] = 7;
        assert!(
            inventory_save_guard::validate_list(data.as_ptr() as usize, Some(admit_legacy_entry))
                .is_err()
        );
    }
}
