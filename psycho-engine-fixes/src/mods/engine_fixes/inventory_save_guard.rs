//! Reject broken inventory-save lists inside the actual main-save owner.
//!
//! A snapshot scope binds the native file and its current record buffer. The
//! early record callsite admits reference extras before dependency collection;
//! typed PlayerCharacter/Projectile entry hooks cover their alternate entry
//! storage. Rejection latches the existing save-integrity transaction: no
//! prefix-only inventory can replace the previous save. Native record/reset,
//! snapshot cleanup, file destruction and failed-save handling remain owned by
//! the engine and save_integrity. No live list or item is repaired or freed.
//!
//! Guarded copies protect the admitted structural fields, not allocation
//! identity, every subtype's unrelated payload fields, or races after admission.
//! Native callers retain stable object/list lifetimes through serialization.
//! Extra admission uses the original reentrant engine lock and cache helpers;
//! it never accesses native TLS directly. Traversal uses constant stack storage,
//! no arbitrary length cap and no routine allocation. OS-copy and lock cost is
//! additional save work; it is not an established gameplay-performance claim.
//! One mapping reader spans each uninterrupted walk, including entry/form reads.
//! Only queried capabilities are reused; every byte read remains guarded. The
//! exact native cache/lock helpers do not mutate those input mappings or invoke
//! providers. No mapping reader survives a serializer/provider invocation.
//! Reference admission does not descend into inventory items: the native
//! inventory flag gates their one complete preflight at the list serializer.
//! Optional legacy form policy shares that walk only in its original list role.

mod native;

use std::{
    ffi::{c_char, c_void},
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering},
    },
};

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    guarded_memory::{prepare_current_process_memory_reader, read_current_process_memory},
    hook::{
        callsite::Rel32CallHookContainer, inline::inlinehook::InlineHookContainer,
        transaction::ModificationTransaction,
    },
    winapi::{get_last_error_code, set_last_error},
};

use super::{
    list_validation::{Access, MemoryFailure, RegionReader},
    save_integrity, statics,
};

type Save = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
type CacheQuery = unsafe extern "cdecl" fn(*mut c_void, u32) -> *mut c_void;
type Lock = unsafe extern "thiscall" fn(*mut c_void, *const c_char);
type Unlock = unsafe extern "thiscall" fn(*mut c_void);

/// Optional original-role policy sharing the immediate entry/form snapshots.
/// No native/provider callback or byte retention is allowed during this check.
pub(super) type EntryFilter =
    fn(&mut RegionReader, usize, &[u8; 12], Option<&[u8; 16]>) -> Result<bool, MemoryFailure>;

const BIND_CALL: usize = 0x00847A86;
const RECORD_SKIP: usize = 0x00847BD9;
const CACHE_ENTRIES: usize = 0x93;
const EXTRA_LOCK: usize = 0x011C3920;

static SNAPSHOT: LazyLock<InlineHookContainer<Save>> = LazyLock::new(InlineHookContainer::new);
static PLAYER: LazyLock<InlineHookContainer<Save>> = LazyLock::new(InlineHookContainer::new);
static PROJECTILE: LazyLock<InlineHookContainer<Save>> = LazyLock::new(InlineHookContainer::new);
static BIND: LazyLock<Rel32CallHookContainer<Save>> = LazyLock::new(Rel32CallHookContainer::new);
static SNAPSHOT_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static PLAYER_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static PROJECTILE_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static BIND_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static PREPARED: AtomicBool = AtomicBool::new(false);
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REJECTIONS: AtomicU32 = AtomicU32::new(0);

/// Preserve the native provider's LastError across all added admission work.
struct LastError(u32);
impl LastError {
    fn preserve() -> Self {
        Self(get_last_error_code())
    }
}
impl Drop for LastError {
    fn drop(&mut self) {
        set_last_error(self.0);
    }
}

/// Verify the shared list serializer before its existing core hook is applied.
pub(super) fn prepare() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "inventory save guard requires the quiescent pre-CRT boundary"
    );
    ensure!(
        save_integrity::save_owner_installed(),
        "Save file integrity is unavailable"
    );
    prepare_current_process_memory_reader()?;
    for (address, expected) in [
        (native::SNAPSHOT_ADDRESS, native::SNAPSHOT),
        (native::LIST_SAVE_ADDRESS, native::LIST_SAVE),
        (native::ENTRY_SAVE_ADDRESS, native::ENTRY_SAVE),
        (native::PLAYER_SAVE_ADDRESS, native::PLAYER_SAVE),
        (native::PROJECTILE_SAVE_ADDRESS, native::PROJECTILE_SAVE),
        (native::CACHE_QUERY_ADDRESS, native::CACHE_QUERY),
        (native::CACHE_GENERATION_ADDRESS, native::CACHE_GENERATION),
        (native::EXTRA_LOCK_ADDRESS, native::EXTRA_LOCK),
        (native::EXTRA_UNLOCK_ADDRESS, native::EXTRA_UNLOCK),
        (native::RECORD_BIND_ADDRESS, native::RECORD_BIND),
        (native::RECORD_RESET_ADDRESS, native::RECORD_RESET),
    ] {
        let mut observed = vec![0; expected.len()];
        read_current_process_memory(address, &mut observed)?;
        ensure!(
            observed == expected,
            "inventory save native contract mismatch at 0x{address:08X}"
        );
    }
    PREPARED.store(true, Ordering::Release);
    Ok(())
}

/// Activate the complete policy after the shared EntryData hook is available.
pub(super) fn install() -> Result<()> {
    ensure!(
        PREPARED.load(Ordering::Acquire),
        "inventory save native contracts were not prepared"
    );
    ensure!(
        statics::ENTRYDATA_LIST_SAVE_HOOK.is_enabled(),
        "shared EntryData save hook is unavailable"
    );
    unsafe {
        SNAPSHOT.init(
            "inventory_save_snapshot",
            native::SNAPSHOT_ADDRESS as *mut c_void,
            snapshot,
        )?;
        PLAYER.init(
            "inventory_save_player",
            native::PLAYER_SAVE_ADDRESS as *mut c_void,
            player,
        )?;
        PROJECTILE.init(
            "inventory_save_projectile",
            native::PROJECTILE_SAVE_ADDRESS as *mut c_void,
            projectile,
        )?;
        BIND.init(
            "inventory_save_record",
            BIND_CALL as *mut c_void,
            bind_record,
        )?;
    }
    SNAPSHOT_PROVIDER.store(SNAPSHOT.original()? as *mut c_void, Ordering::Release);
    PLAYER_PROVIDER.store(PLAYER.original()? as *mut c_void, Ordering::Release);
    PROJECTILE_PROVIDER.store(PROJECTILE.original()? as *mut c_void, Ordering::Release);
    BIND_PROVIDER.store(BIND.original()? as *mut c_void, Ordering::Release);
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&PLAYER)?;
    transaction.enable_inline(&PROJECTILE)?;
    transaction.enable_callsite(&BIND)?;
    // The actual snapshot owner is last; rollback survivors only forward.
    transaction.enable_inline(&SNAPSHOT)?;
    transaction.commit();
    ADMITTED.store(true, Ordering::Release);
    Ok(())
}

unsafe extern "thiscall" fn snapshot(manager: *mut c_void, file: *mut c_void) {
    let original: Save = unsafe { std::mem::transmute(SNAPSHOT_PROVIDER.load(Ordering::Acquire)) };
    if ADMITTED.load(Ordering::Acquire) {
        save_integrity::with_inventory_save_snapshot(file as usize, || unsafe {
            original(manager, file)
        });
    } else {
        unsafe { original(manager, file) };
    }
}

/// Only the verified 0x00847A86 callsite enters this bridge. Its caller EBP and
/// SEH frame remain intact. Rejection consumes this inner return/argument and
/// resumes the existing loop edge, retaining snapshot state clear/destruction.
#[unsafe(naked)]
unsafe extern "thiscall" fn bind_record(_buffer: *mut c_void, _form: *mut c_void) {
    core::arch::naked_asm!(
        "pushfd", "pushad",
        "push dword ptr [esp + 40]",
        "call {admit}",
        "test al, al", "jz 2f",
        "popad", "popfd", "ret 4",
        "2:", "popad", "popfd",
        "lea esp, [esp + 8]",
        "push {skip}", "ret",
        admit = sym bind_and_admit,
        skip = const RECORD_SKIP,
    );
}

unsafe extern "thiscall" fn bind_and_admit(buffer: *mut c_void, form: *mut c_void) -> u8 {
    let original: Save = unsafe { std::mem::transmute(BIND_PROVIDER.load(Ordering::Acquire)) };
    unsafe { original(buffer, form) };
    if !ADMITTED.load(Ordering::Acquire)
        || !save_integrity::bind_inventory_save_record(buffer as usize, form as usize)
    {
        return 1;
    }
    let _error = LastError::preserve();
    match save_integrity::measure_inventory_admission(|| reference_extra_admission(form as usize)) {
        Ok(()) => 1,
        Err(reason) => u8::from(!reject(buffer as usize, "record extras", reason)),
    }
}

unsafe extern "thiscall" fn player(owner: *mut c_void, buffer: *mut c_void) {
    let original: Save = unsafe { std::mem::transmute(PLAYER_PROVIDER.load(Ordering::Acquire)) };
    let rejected = if owns(buffer as usize) {
        let _error = LastError::preserve();
        match save_integrity::measure_inventory_admission(|| player_array_admission(owner as usize))
        {
            Ok(()) => false,
            Err(reason) => reject(buffer as usize, "player entry array", reason),
        }
    } else {
        false
    };
    if !rejected {
        unsafe { original(owner, buffer) };
    }
}

unsafe extern "thiscall" fn projectile(owner: *mut c_void, buffer: *mut c_void) {
    let original: Save =
        unsafe { std::mem::transmute(PROJECTILE_PROVIDER.load(Ordering::Acquire)) };
    let rejected = if owns(buffer as usize) {
        let _error = LastError::preserve();
        match save_integrity::measure_inventory_admission(|| {
            projectile_entry_admission(owner as usize)
        }) {
            Ok(()) => false,
            Err(reason) => reject(buffer as usize, "projectile entry", reason),
        }
    } else {
        false
    };
    if !rejected {
        unsafe { original(owner, buffer) };
    }
}

/// Admit the shared list before its existing wrapper writes any flags/count.
/// None means this is outside the owned main save and must retain old behavior.
pub(super) fn admit_list(list: usize, buffer: usize, filter: Option<EntryFilter>) -> Option<bool> {
    if !owns(buffer) {
        return None;
    }
    let _error = LastError::preserve();
    let result = save_integrity::measure_inventory_admission(|| validate_list(list, filter));
    Some(match result {
        Ok(()) => true,
        Err(reason) => !reject(buffer, "entry list", reason),
    })
}

/// One complete preflight immediately before the native list writes any bytes.
/// No reader or admitted result survives the subsequent provider invocation.
pub(super) fn validate_list(list: usize, filter: Option<EntryFilter>) -> Result<(), Rejection> {
    let mut reader = RegionReader::default();
    let head = word(&mut reader, list)? as usize;
    walk_entries(&mut reader, head, |reader, entry| {
        entry_admission_with_filter(reader, entry, filter)
    })
}

fn owns(buffer: usize) -> bool {
    ADMITTED.load(Ordering::Acquire) && save_integrity::owns_inventory_save_record(buffer)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Rejection {
    Memory(MemoryFailure),
    Cycle(usize),
    Overflow,
    MissingArrayEntry(usize),
    CachedExtraOutsideChain(u32, usize),
    LegacyForm(usize),
}
impl From<MemoryFailure> for Rejection {
    fn from(failure: MemoryFailure) -> Self {
        Self::Memory(failure)
    }
}

#[cold]
fn reject(buffer: usize, context: &'static str, reason: Rejection) -> bool {
    if !save_integrity::reject_inventory_save(buffer) {
        return false;
    }
    let previous = REJECTIONS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            Some(count.saturating_add(1))
        })
        .unwrap_or_else(|count| count);
    let count = previous.saturating_add(1);
    if previous != u32::MAX && (count.is_power_of_two() || count == u32::MAX) {
        log::warn!(
            "[INVENTORY_SAVE] Rejected {context}: {reason:?}; total={count} saturated={} buffer=0x{buffer:08X}; the previous save is kept",
            count == u32::MAX
        );
    }
    true
}

fn offset(address: usize, displacement: usize) -> Result<usize, Rejection> {
    address.checked_add(displacement).ok_or(Rejection::Overflow)
}
fn word(reader: &mut RegionReader, address: usize) -> Result<u32, Rejection> {
    Ok(u32::from_le_bytes(reader.copy::<4>(address, Access::Read)?))
}
fn image_word<const N: usize>(image: &[u8; N], offset: usize) -> u32 {
    u32::from_le_bytes([
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
    ])
}

/// Walk eight-byte nodes; NULL payloads are native skipped slots. Payload
/// admission executes no engine callbacks and may recurse only through the
/// fixed EntryData -> extend-list -> extra-prefix schema below.
fn walk_entries(
    reader: &mut RegionReader,
    mut current: usize,
    mut payload: impl FnMut(&mut RegionReader, usize) -> Result<(), Rejection>,
) -> Result<(), Rejection> {
    let mut checkpoint = current;
    let mut power = 1usize;
    let mut distance = 0usize;
    let mut count = 0u32;
    while current != 0 {
        let (data, next) = reader.node(current, Access::Read)?;
        if data != 0 {
            payload(reader, data as usize)?;
            count = count
                .checked_add(1)
                .filter(|count| *count < 0x40000000)
                .ok_or(Rejection::Overflow)?;
        }
        if next == 0 {
            return Ok(());
        }
        distance = distance.checked_add(1).ok_or(Rejection::Overflow)?;
        if next == checkpoint {
            return Err(Rejection::Cycle(next));
        }
        if distance == power {
            checkpoint = next;
            power = power.saturating_mul(2);
            distance = 0;
        }
        current = next;
    }
    Ok(())
}

#[cfg(test)]
fn entry_list(head: usize) -> Result<(), Rejection> {
    walk_entries(&mut RegionReader::default(), head, entry_admission)
}

fn entry_admission(reader: &mut RegionReader, entry: usize) -> Result<(), Rejection> {
    entry_admission_with_filter(reader, entry, None)
}

fn entry_admission_with_filter(
    reader: &mut RegionReader,
    entry: usize,
    filter: Option<EntryFilter>,
) -> Result<(), Rejection> {
    let image = reader.copy::<12>(entry, Access::Read)?;
    let form = image_word(&image, 8) as usize;
    let form_image = if form != 0 {
        // Native 0x00865DF0 serializes NULL as ID zero; otherwise it reads
        // only the form ID at +0x0C without any virtual dispatch.
        Some(reader.copy::<16>(form, Access::Read)?)
    } else {
        None
    };
    if let Some(filter) = filter
        && !filter(reader, entry, &image, form_image.as_ref())?
    {
        return Err(Rejection::LegacyForm(entry));
    }
    walk_entries(reader, image_word(&image, 0) as usize, |_, list| {
        extra_admission(list, false)
    })
}

fn player_array_admission(owner: usize) -> Result<(), Rejection> {
    let mut reader = RegionReader::default();
    let image = reader.copy::<12>(offset(owner, 0xDF4)?, Access::Read)?;
    let data = image_word(&image, 4) as usize;
    let count = image_word(&image, 8) as usize;
    let length = count.checked_mul(4).ok_or(Rejection::Overflow)?;
    if count >= 0x40000000 {
        return Err(Rejection::Overflow);
    }
    if count != 0 {
        reader.range(data, length, Access::Read)?;
    }
    for index in 0..count {
        let slot = offset(data, index.checked_mul(4).ok_or(Rejection::Overflow)?)?;
        let entry = word(&mut reader, slot)? as usize;
        if entry == 0 {
            return Err(Rejection::MissingArrayEntry(slot));
        }
        entry_admission(&mut reader, entry)?;
    }
    Ok(())
}

fn projectile_entry_admission(owner: usize) -> Result<(), Rejection> {
    let mut reader = RegionReader::default();
    let entry = word(&mut reader, offset(owner, 0x144)?)? as usize;
    if entry != 0 {
        entry_admission(&mut reader, entry)?;
    }
    Ok(())
}

fn reference_extra_admission(form: usize) -> Result<(), Rejection> {
    let image = RegionReader::default().copy::<5>(form, Access::Read)?;
    // The supported engine's reference family: REFR, Character, Creature and
    // the four projectile kinds. All own BaseExtraList at +0x44. No vtable,
    // module identity or third-party-specific classification is performed.
    if (0x3A..=0x40).contains(&image[4]) {
        extra_admission(offset(form, 0x44)?, true)?;
    }
    Ok(())
}

struct ExtraLock;
impl ExtraLock {
    fn acquire() -> Self {
        let acquire: Lock = unsafe { std::mem::transmute(native::EXTRA_LOCK_ADDRESS) };
        // SAFETY: The verified native API is a reentrant engine lock, not a
        // Win32 critical section. The saving game thread has native engine TLS.
        unsafe {
            acquire(
                EXTRA_LOCK as *mut c_void,
                c"Psycho inventory save guard".as_ptr(),
            );
        }
        Self
    }
}
impl Drop for ExtraLock {
    fn drop(&mut self) {
        let release: Unlock = unsafe { std::mem::transmute(native::EXTRA_UNLOCK_ADDRESS) };
        unsafe { release(EXTRA_LOCK as *mut c_void) };
    }
}

fn extra_admission(list: usize, inventory_owner: bool) -> Result<(), Rejection> {
    let _lock = ExtraLock::acquire();
    let mut reader = RegionReader::default();
    let list_image = reader.copy::<32>(list, Access::Read)?;
    let query: CacheQuery = unsafe { std::mem::transmute(native::CACHE_QUERY_ADDRESS) };
    let mut cached = [0usize; CACHE_ENTRIES];
    for (kind, pointer) in cached.iter_mut().enumerate() {
        if list_image[8 + kind / 8] & (1 << (kind % 8)) == 0 {
            continue;
        }
        // The native query never dereferences the returned extra. It owns its
        // existing per-thread generation check; we never inspect TLS storage.
        // Native lookup also gates cache use on this presence bit. Absent
        // types cannot be consumed, including on a completely empty list.
        *pointer = unsafe { query(list as *mut c_void, kind as u32) } as usize;
    }
    extra_image_admission(&mut reader, list, inventory_owner, cached)
}

fn extra_image_admission(
    reader: &mut RegionReader,
    list: usize,
    inventory_owner: bool,
    mut cached: [usize; CACHE_ENTRIES],
) -> Result<(), Rejection> {
    let list_image = reader.copy::<32>(list, Access::Read)?;
    // Cached results are relevant only when the presence gate permits lookup.
    for (kind, pointer) in cached.iter_mut().enumerate() {
        if list_image[8 + kind / 8] & (1 << (kind % 8)) == 0 {
            *pointer = 0;
        }
    }
    let mut current = image_word(&list_image, 4) as usize;
    let mut checkpoint = current;
    let mut power = 1usize;
    let mut distance = 0usize;
    while current != 0 {
        let image = reader.copy::<12>(current, Access::Read)?;
        let kind = image[4] as usize;
        if kind < CACHE_ENTRIES && cached[kind] == current {
            cached[kind] = 0;
        }
        if inventory_owner && matches!(kind, 0x3D | 0x41) {
            // Dependency collection (0x00422B90) and reference pre-dispatch
            // (0x004228F0) read these extras' scalar payload at +0x0C.
            word(reader, offset(current, 12)?)?;
        }
        if inventory_owner && kind == 0x15 {
            let data = word(reader, offset(current, 12)?)? as usize;
            if data != 0 {
                // GetExistingData returns this pointer without walking items.
                // Retain the Data-prefix check, but admit items only when the
                // engine reaches ListSave under its final inventory flags.
                reader.copy::<20>(data, Access::Read)?;
            }
        }
        let next = image_word(&image, 8) as usize;
        if next == 0 {
            break;
        }
        distance = distance.checked_add(1).ok_or(Rejection::Overflow)?;
        if next == checkpoint {
            return Err(Rejection::Cycle(next));
        }
        if distance == power {
            checkpoint = next;
            power = power.saturating_mul(2);
            distance = 0;
        }
        current = next;
    }
    for (kind, pointer) in cached.into_iter().enumerate() {
        if pointer != 0 {
            return Err(Rejection::CachedExtraOutsideChain(kind as u32, pointer));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpsycho::os::windows::winapi::{
        native_system_layout, virtual_query, virtual_release, virtual_reserve_commit,
        with_virtual_protect,
    };

    struct Pages(*mut c_void);
    impl Drop for Pages {
        fn drop(&mut self) {
            unsafe { virtual_release(self.0) }.expect("release owned fixture pages");
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Node {
        data: u32,
        next: u32,
    }
    #[repr(C)]
    struct Entry {
        extend: u32,
        count: i32,
        form: u32,
    }
    #[repr(C)]
    struct Extra {
        vtable: u32,
        kind: u32,
        next: u32,
    }

    #[test]
    #[ignore = "offline production save-admission timing; run serially with --nocapture"]
    fn production_save_admission_timing() {
        use std::{hint::black_box, time::Instant};

        for count in [1, 1024, 65536] {
            let forms = vec![[0u32, 0, 0, 0x1234]; count];
            let entries: Vec<_> = forms
                .iter()
                .map(|form| Entry {
                    extend: 0,
                    count: 1,
                    form: form.as_ptr() as u32,
                })
                .collect();
            let mut nodes: Vec<_> = entries
                .iter()
                .map(|entry| Node {
                    data: entry as *const Entry as u32,
                    next: 0,
                })
                .collect();
            for index in 0..count - 1 {
                nodes[index].next = &nodes[index + 1] as *const Node as u32;
            }
            let mut samples = [0.0; 5];
            for sample in &mut samples {
                let started = Instant::now();
                assert_eq!(entry_list(black_box(nodes.as_ptr() as usize)), Ok(()));
                *sample = started.elapsed().as_secs_f64() * 1e6;
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "save admission: entries={count}, rounds=5, us/call min={:.1} median={:.1} max={:.1}",
                samples[0], samples[2], samples[4]
            );
        }
    }

    #[test]
    fn production_save_admission_keeps_valid_entries_and_borrowed_duplicates() {
        let form = [0u32, 0, 0, 0x1234];
        let mut entry = Entry {
            extend: 0,
            count: -17,
            form: form.as_ptr() as u32,
        };
        assert_eq!(
            entry_admission(
                &mut RegionReader::default(),
                &entry as *const Entry as usize
            ),
            Ok(())
        );
        let mut nodes = vec![
            Node {
                data: &entry as *const Entry as u32,
                next: 0
            };
            4096
        ];
        for i in 0..nodes.len() - 1 {
            nodes[i].next = &nodes[i + 1] as *const Node as u32;
        }
        // NULL outer payloads are skipped by the native serializer, including
        // an empty head with a live successor. Borrowed duplicates are valid.
        nodes[0].data = 0;
        let before = nodes.clone();
        assert_eq!(entry_list(nodes.as_ptr() as usize), Ok(()));
        assert_eq!(nodes, before);
        assert_eq!(entry.count, -17);
        nodes[4095].next = &nodes[1] as *const Node as u32;
        assert!(matches!(
            entry_list(nodes.as_ptr() as usize),
            Err(Rejection::Cycle(_))
        ));
        let mut extend = Node { data: 0, next: 0 };
        extend.next = &extend as *const Node as u32;
        entry.extend = &extend as *const Node as u32;
        assert!(matches!(
            entry_admission(
                &mut RegionReader::default(),
                &entry as *const Entry as usize
            ),
            Err(Rejection::Cycle(_))
        ));
        assert_eq!(entry.count, -17);
    }

    #[test]
    fn production_save_admission_rejects_inaccessible_forms_and_preserves_native_null() {
        let mut entry = Entry {
            extend: 0,
            count: 9,
            form: 7,
        };
        assert!(matches!(
            entry_admission(
                &mut RegionReader::default(),
                &entry as *const Entry as usize
            ),
            Err(Rejection::Memory(_))
        ));
        entry.form = 0;
        // Native 0x00865DF0 explicitly serializes a NULL form as ID zero.
        assert_eq!(
            entry_admission(
                &mut RegionReader::default(),
                &entry as *const Entry as usize
            ),
            Ok(())
        );
        assert_eq!(entry.count, 9);
    }

    #[test]
    fn production_extra_admission_checks_complete_spine_and_cached_membership() {
        let mut extra = Extra {
            vtable: 0,
            kind: 0x16,
            next: 0,
        };
        let mut image = [0u32; 8];
        image[1] = &extra as *const Extra as u32;
        image[2] = 1 << 0x16;
        let mut cached = [0; CACHE_ENTRIES];
        cached[0x16] = &extra as *const Extra as usize;
        assert_eq!(
            extra_image_admission(
                &mut RegionReader::default(),
                image.as_ptr() as usize,
                false,
                cached
            ),
            Ok(())
        );
        cached[0x16] = 7;
        assert_eq!(
            extra_image_admission(
                &mut RegionReader::default(),
                image.as_ptr() as usize,
                false,
                cached
            ),
            Err(Rejection::CachedExtraOutsideChain(0x16, 7))
        );
        cached[0x16] = 0;
        extra.next = &extra as *const Extra as u32;
        std::hint::black_box(&extra);
        assert!(matches!(
            extra_image_admission(
                &mut RegionReader::default(),
                image.as_ptr() as usize,
                false,
                cached
            ),
            Err(Rejection::Cycle(_))
        ));
        extra.next = 7;
        std::hint::black_box(&extra);
        assert!(matches!(
            extra_image_admission(
                &mut RegionReader::default(),
                image.as_ptr() as usize,
                false,
                cached
            ),
            Err(Rejection::Memory(_))
        ));
    }

    #[test]
    fn production_reference_admission_defers_items_until_the_list_consumer() {
        // The early native getters consume the extra payload and Data header,
        // not its item spine. Only the actual list serializer may consume it.
        let data = [7u32, 0, 0, 0, 0];
        let extra = [0u32, 0x15, 0, data.as_ptr() as u32];
        let mut list = [0u32; 8];
        list[1] = extra.as_ptr() as u32;
        assert_eq!(
            extra_image_admission(
                &mut RegionReader::default(),
                list.as_ptr() as usize,
                true,
                [0; CACHE_ENTRIES],
            ),
            Ok(())
        );
        assert!(matches!(
            entry_list(data[0] as usize),
            Err(Rejection::Memory(_))
        ));
        assert_eq!(data[0], 7);
    }

    #[test]
    fn production_reference_admission_covers_pre_serializer_extra_flags() {
        for kind in [0x3D, 0x41] {
            let page_size = native_system_layout().page_size as usize;
            // SAFETY: The fixture exclusively owns both committed pages. The extra
            // prefix ends at their boundary; its flags occupy the second page.
            let pages = Pages(unsafe { virtual_reserve_commit(None, page_size * 2) });
            assert!(!pages.0.is_null());
            let boundary = pages.0 as usize + page_size;
            let extra = (boundary - 12) as *mut Extra;
            unsafe {
                extra.write(Extra {
                    vtable: 0,
                    kind,
                    next: 0,
                });
                (boundary as *mut u32).write(0);
            }
            let mut list = [0u32; 8];
            list[1] = extra as u32;
            let cached = [0; CACHE_ENTRIES];
            assert_eq!(
                extra_image_admission(
                    &mut RegionReader::default(),
                    list.as_ptr() as usize,
                    true,
                    cached
                ),
                Ok(())
            );
            let mut protection = virtual_query(boundary as *mut c_void)
                .expect("query page")
                .protect;
            protection.0 = 0x01;
            // SAFETY: Only the owned flags page changes and protection is restored
            // before the reservation is released. Production admission must stop
            // before the native reference dependency getter reads extra + 0x0C.
            unsafe {
                with_virtual_protect(boundary as *mut c_void, protection, page_size, || {
                    assert!(matches!(
                        extra_image_admission(
                            &mut RegionReader::default(),
                            list.as_ptr() as usize,
                            true,
                            cached
                        ),
                        Err(Rejection::Memory(_))
                    ));
                })
            }
            .expect("scope flags page protection");
        }
    }

    #[test]
    fn production_alternate_entry_owners_preserve_slots_and_optional_absence() {
        let form = [0u32, 0, 0, 0x1234];
        let entry = Entry {
            extend: 0,
            count: 2,
            form: form.as_ptr() as u32,
        };
        let mut slots = [&entry as *const Entry as u32; 3];
        let mut player = vec![0u32; (0xDF4 + 12) / 4];
        player[0xDF8 / 4] = slots.as_ptr() as u32;
        player[0xDFC / 4] = 3;
        let before = player.clone();
        assert_eq!(player_array_admission(player.as_ptr() as usize), Ok(()));
        assert_eq!(player, before);
        slots[1] = 0;
        std::hint::black_box(&slots);
        assert!(matches!(
            player_array_admission(player.as_ptr() as usize),
            Err(Rejection::MissingArrayEntry(_))
        ));
        player[0xDFC / 4] = 0x40000000;
        assert_eq!(
            player_array_admission(player.as_ptr() as usize),
            Err(Rejection::Overflow)
        );
        let mut projectile = [0u32; (0x144 + 4) / 4];
        assert_eq!(
            projectile_entry_admission(projectile.as_ptr() as usize),
            Ok(())
        );
        projectile[0x144 / 4] = &entry as *const Entry as u32;
        assert_eq!(
            projectile_entry_admission(projectile.as_ptr() as usize),
            Ok(())
        );
        projectile[0x144 / 4] = 7;
        assert!(matches!(
            projectile_entry_admission(projectile.as_ptr() as usize),
            Err(Rejection::Memory(_))
        ));
    }
}
