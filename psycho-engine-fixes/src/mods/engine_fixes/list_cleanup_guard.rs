//! Contain invalid successor links at the shared native list-clear boundary.
//!
//! The caller retains the native contract: a live writable eight-byte head and
//! exclusive access to its chain throughout admission and cleanup. Preflight
//! frees nothing. An inaccessible successor is cut at its incoming edge; a
//! cycle is cut at its back edge, preserving each unique reachable entry.
//! Intact chains reach the original provider unchanged. Native clear retains
//! entry deallocation and payload handling; uncertain suffixes may leak.
//!
//! This is not allocation-identity or race protection. Readable stale/foreign
//! storage and mutation after snapshots retain the native lifetime limitations.
//! The pre-CRT owner verifies the complete native body before publishing one
//! transactional inline hook. No third-party implementation is overwritten.
//! Calls allocate and lock nothing. Empty chains bypass OS queries; nonempty
//! chains add linear preflight with constant storage and per-call page caching.
//! Repair counts log sparsely, with the original memory failure evidence. See the fast-travel fade-list contract in docs.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering},
    },
};

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    guarded_memory::{prepare_current_process_memory_reader, read_current_process_memory},
    hook::{inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction},
    winapi::{get_last_error_code, set_last_error},
};

use super::list_validation::{Access, MemoryFailure, RegionReader};

type Clear = unsafe extern "thiscall" fn(*mut Entry);

const ADDRESS: usize = 0x00B4DF30;
// Includes the recursive call, native heap-free call and plain RET. This shared
// primitive has no payload destructor or other callback in its native body.
const BODY: &[u8] = &[
    0x56, 0x8B, 0xF1, 0x83, 0x7E, 0x04, 0x00, 0x74, 0x36, 0x53, 0x57, 0xEB, 0x03, 0x8D, 0x49, 0x00,
    0x8B, 0x46, 0x04, 0x8B, 0x58, 0x04, 0xC7, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x7E, 0x04,
    0x85, 0xFF, 0x74, 0x12, 0x8B, 0xCF, 0xE8, 0xD5, 0xFF, 0xFF, 0xFF, 0x57, 0xB9, 0x38, 0x62, 0x1F,
    0x01, 0xE8, 0xFA, 0x60, 0xF5, 0xFF, 0x89, 0x5E, 0x04, 0x85, 0xDB, 0x75, 0xD3, 0x5F, 0x5B, 0xC7,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x5E, 0xC3,
];

/// Native, non-owning list-entry image; only native clear frees entries.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    data: u32,
    next: u32,
}

static HOOK: LazyLock<InlineHookContainer<Clear>> = LazyLock::new(InlineHookContainer::new);
static PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REPAIRS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];

/// Install only at the existing quiescent core startup boundary.
///
/// Exact native bytes are required; a changed provider leaves this fix inactive.
/// Publish the trampoline before activation so any rollback survivor forwards.
pub(super) fn install() -> Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "list-cleanup installation requires the quiescent pre-CRT boundary"
    );
    prepare_current_process_memory_reader()?;
    let mut observed = [0; BODY.len()];
    read_current_process_memory(ADDRESS, &mut observed)?;
    ensure!(observed == BODY, "native list-clear body mismatch");
    // SAFETY: The exact body establishes thiscall(head in ECX), no stack
    // arguments, void result, and plain RET. Code remains live for the process.
    unsafe { HOOK.init("list_cleanup_guard", ADDRESS as *mut c_void, clear)? };
    PROVIDER.store(HOOK.original()? as *mut c_void, Ordering::Release);
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&*HOOK)?;
    transaction.commit();
    ADMITTED.store(true, Ordering::Release);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reason {
    Inaccessible,
    HeadAlias,
    Cycle,
    ChangedChain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Repair {
    predecessor: usize,
    rejected: usize,
    reason: Reason,
    inspected_steps: usize,
    failure: Option<MemoryFailure>,
}

/// One invocation's writable-region cache and first actual failed operation.
#[derive(Default)]
struct WritableRegion {
    reader: RegionReader,
    failure: Option<MemoryFailure>,
}

impl WritableRegion {
    fn next(&mut self, address: usize) -> Option<usize> {
        match self.reader.node(address, Access::Write) {
            Ok((_, next)) => Some(next),
            Err(failure) => {
                // Keep the original failure, including across cycle recovery.
                if self.failure.is_none() {
                    self.failure = Some(failure);
                }
                None
            }
        }
    }
}

/// Read only the live head supplied under the original native precondition.
unsafe fn head_next(head: *mut Entry) -> usize {
    // SAFETY: The caller owns this live eight-byte head throughout the call.
    unsafe { std::ptr::addr_of!((*head).next).read_unaligned() as usize }
}

/// Sever a verified incoming edge, or abandon the chain at its live head if
/// another required check fails. No rejected address is dereferenced or freed.
unsafe fn cut(
    head: *mut Entry,
    predecessor: usize,
    rejected: usize,
    reason: Reason,
    inspected_steps: usize,
    failure: Option<MemoryFailure>,
) -> Repair {
    let mut check = WritableRegion::default();
    let (predecessor, reason) = if check.next(predecessor) == Some(rejected) {
        (predecessor, reason)
    } else {
        (head as usize, Reason::ChangedChain)
    };
    // SAFETY: The predecessor was just copied from writable entry storage, or
    // is the live caller-owned head. Native clear requires exclusive lifetime
    // through this write and its own later traversal. Queries do not pin it.
    unsafe { ((predecessor + 4) as *mut u32).write_unaligned(0) };
    Repair {
        predecessor,
        rejected,
        reason,
        inspected_steps,
        failure: failure.or(check.failure),
    }
}

/// Find the cycle entry, then its back edge. The observed detection distance
/// bounds this recovery pass for an unchanged chain; it is not a list-size cap.
fn cycle_back_edge(
    first: usize,
    length: usize,
    observed: usize,
    reader: &mut WritableRegion,
) -> Option<(usize, usize)> {
    let mut ahead = first;
    for _ in 0..length {
        ahead = reader.next(ahead)?;
    }
    let mut entry = first;
    for _ in 0..=observed {
        if entry == ahead {
            let mut last = entry;
            for _ in 1..length {
                last = reader.next(last)?;
            }
            return (reader.next(last)? == entry).then_some((last, entry));
        }
        entry = reader.next(entry)?;
        ahead = reader.next(ahead)?;
    }
    None
}

/// Inspect before any native free, using Brent detection and constant storage.
///
/// # Safety
/// The live writable head and chain retain the native caller's exclusive
/// lifetime across inspection, repair, and the subsequent native clear.
unsafe fn prepare_chain(head: *mut Entry, first: usize) -> Option<Repair> {
    let mut reader = WritableRegion::default();
    let mut predecessor = head as usize;
    let mut current = first;
    let mut checkpoint = head as usize;
    let mut power = 1usize;
    let mut length = 1usize;
    let mut observed = 0usize;
    while current != 0 {
        if current == head as usize {
            // SAFETY: Only the known incoming edge is changed, never the head
            // address encountered as a supposed allocated successor.
            return Some(unsafe {
                cut(
                    head,
                    predecessor,
                    current,
                    Reason::HeadAlias,
                    observed,
                    reader.failure,
                )
            });
        }
        let Some(next) = reader.next(current) else {
            // SAFETY: Predecessor is the live head or an inspected entry.
            return Some(unsafe {
                cut(
                    head,
                    predecessor,
                    current,
                    Reason::Inaccessible,
                    observed,
                    reader.failure,
                )
            });
        };
        if current == checkpoint {
            if let Some((last, entry)) = cycle_back_edge(first, length, observed, &mut reader) {
                // SAFETY: Recovering the exact back edge preserves every
                // unique reachable entry for the native cleanup that follows.
                return Some(unsafe {
                    cut(head, last, entry, Reason::Cycle, observed, reader.failure)
                });
            }
            // SAFETY: The cycle could not be revalidated. The live head is the
            // only unconditional mutation boundary; all successors are leaked.
            return Some(unsafe {
                cut(
                    head,
                    head as usize,
                    first,
                    Reason::ChangedChain,
                    observed,
                    reader.failure,
                )
            });
        }
        if power == length {
            checkpoint = current;
            power = power.saturating_mul(2);
            length = 0;
        }
        predecessor = current;
        current = next;
        length = length.saturating_add(1);
        let Some(distance) = observed.checked_add(1) else {
            // SAFETY: Counter overflow cannot describe a healthy disjoint
            // eight-byte chain in 32-bit space; retain only its live head.
            return Some(unsafe {
                cut(
                    head,
                    head as usize,
                    first,
                    Reason::ChangedChain,
                    observed,
                    reader.failure,
                )
            });
        };
        observed = distance;
    }
    None
}

unsafe extern "thiscall" fn clear(head: *mut Entry) {
    if ADMITTED.load(Ordering::Acquire) {
        // SAFETY: The shared native method requires a live writable head.
        let first = unsafe { head_next(head) };
        if first != 0 {
            let last_error = get_last_error_code();
            // SAFETY: The original caller owns the chain throughout this call.
            if let Some(repair) = unsafe { prepare_chain(head, first) } {
                report(head, repair);
            }
            set_last_error(last_error);
        }
    }
    // SAFETY: The exact-ABI trampoline is published before entry activation,
    // including any unadmitted rollback survivor. Native clear retains its
    // own payload writes and heap frees, with no replacement allocator.
    let original: Clear = unsafe { std::mem::transmute(PROVIDER.load(Ordering::Acquire)) };
    unsafe { original(head) };
}

#[cold]
fn report(head: *mut Entry, repair: Repair) {
    let counter = &REPAIRS[repair.reason as usize];
    let previous = counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            Some(count.saturating_add(1))
        })
        .unwrap_or_else(|count| count);
    let count = previous.saturating_add(1);
    if previous == u32::MAX || (!count.is_power_of_two() && count != u32::MAX) {
        return;
    }
    let consequence = match repair.reason {
        Reason::Cycle | Reason::HeadAlias => {
            "all unique successor entries remain reachable for native cleanup"
        }
        Reason::Inaccessible | Reason::ChangedChain => {
            "an unreachable tail may leak; disconnected node/byte count is unknown"
        }
    };
    log::warn!(
        "[LIST_CLEANUP] Cut {:?} link; reason_count={} saturated={} head={head:p}, \
         predecessor=0x{:08X}, rejected=0x{:08X}, inspected_steps={}; \
         native cleanup continues; {consequence}",
        repair.reason,
        count,
        count == u32::MAX,
        repair.predecessor,
        repair.rejected,
        repair.inspected_steps,
    );
    if let Some(failure) = repair.failure {
        log::warn!(
            "[LIST_CLEANUP] First failed operation: {failure}; head={head:p} reason_count={count}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpsycho::os::windows::winapi::{
        native_system_layout, virtual_query, virtual_release, virtual_reserve_commit,
        with_virtual_protect,
    };

    fn link(entries: &mut [Entry]) {
        for index in 0..entries.len() {
            entries[index].data = 0x1234_0000 + index as u32;
            entries[index].next = if index + 1 == entries.len() {
                0
            } else {
                (&entries[index + 1] as *const Entry) as u32
            };
        }
    }

    fn prepare(head: &mut Entry) -> Option<Repair> {
        // SAFETY: Tests own the actual entry storage and OS mappings throughout
        // the production preflight. No native provider/free is simulated.
        unsafe { prepare_chain(head, head_next(head)) }
    }

    #[test]
    fn production_preflight_preserves_empty_single_and_long_intact_chains() {
        for count in [1, 2, 32_768] {
            let mut entries = vec![Entry { data: 0, next: 0 }; count];
            link(&mut entries);
            let before = entries.clone();
            assert_eq!(prepare(&mut entries[0]), None);
            assert_eq!(entries, before);
        }
    }

    #[test]
    #[ignore = "offline production-preflight timing; run serially with --nocapture"]
    fn production_preflight_timing() {
        use std::{hint::black_box, time::Instant};

        for successors in [0, 1, 32, 1_024, 32_768] {
            let mut entries = vec![Entry { data: 0, next: 0 }; successors + 1];
            link(&mut entries);
            assert_eq!(prepare(&mut entries[0]), None);
            let iterations = (100_000 / (successors + 1)).max(16);
            let mut samples = [0.0; 5];
            for sample in &mut samples {
                let start = Instant::now();
                for _ in 0..iterations {
                    let head = black_box(&mut entries[0]);
                    assert_eq!(black_box(prepare(head)), None);
                }
                *sample = start.elapsed().as_secs_f64() * 1e9 / iterations as f64;
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "preflight: successors={successors}, iterations={iterations}, rounds=5, \
                 ns/call min={:.1}, median={:.1}, max={:.1}",
                samples[0], samples[2], samples[4],
            );
        }
    }

    #[test]
    fn production_preflight_cuts_the_reported_bad_successor_without_touching_payloads() {
        let rejected = 0x51BB72C9;
        // The supplied runtime report proves this value was inaccessible there.
        // Check the fixture's OS mapping too; do not model the failed read.
        assert!(
            RegionReader::default()
                .range(rejected, size_of::<Entry>(), Access::Write)
                .is_err()
        );
        let mut entries = [Entry { data: 0, next: 0 }; 3];
        link(&mut entries);
        entries[2].next = rejected as u32;
        let mut expected = entries;
        expected[2].next = 0;
        let repair = prepare(&mut entries[0]).expect("invalid successor is cut");
        assert_eq!(repair.predecessor, &entries[2] as *const Entry as usize);
        assert_eq!(repair.rejected, rejected);
        assert_eq!(repair.reason, Reason::Inaccessible);
        assert_eq!(entries, expected);
    }

    #[test]
    fn production_preflight_cuts_head_aliases_and_exact_cycle_back_edges() {
        for entry_index in 0..12 {
            let mut entries = [Entry { data: 0, next: 0 }; 12];
            link(&mut entries);
            entries[11].next = (&entries[entry_index] as *const Entry) as u32;
            let mut expected = entries;
            expected[11].next = 0;
            let repair = prepare(&mut entries[0]).expect("cycle is cut");
            assert_eq!(repair.predecessor, &entries[11] as *const Entry as usize);
            assert_eq!(
                repair.reason,
                if entry_index == 0 {
                    Reason::HeadAlias
                } else {
                    Reason::Cycle
                }
            );
            assert_eq!(entries, expected);
        }
        let mut head = Entry { data: 7, next: 0 };
        head.next = (&head as *const Entry) as u32;
        assert_eq!(prepare(&mut head).unwrap().reason, Reason::HeadAlias);
        assert_eq!(head, Entry { data: 7, next: 0 });
    }

    struct Pages(*mut c_void);

    impl Drop for Pages {
        fn drop(&mut self) {
            // SAFETY: The test owns this full reservation.
            unsafe { virtual_release(self.0) }.expect("release test pages");
        }
    }

    #[test]
    fn production_preflight_checks_complete_entries_across_real_page_boundaries() {
        let size = native_system_layout().page_size as usize;
        // SAFETY: The test owns both pages until all production access ends.
        let pages = Pages(unsafe { virtual_reserve_commit(None, size * 2) });
        assert!(!pages.0.is_null());
        let edge = pages.0 as usize + size;
        let entry = (edge - 4) as *mut Entry;
        // SAFETY: Initialize both words before changing either page's access.
        unsafe { entry.write_unaligned(Entry { data: 17, next: 0 }) };
        let mut head = Entry {
            data: 9,
            next: entry as u32,
        };
        let mut protection = virtual_query(edge as *mut c_void)
            .expect("query test page")
            .protect;
        // Win32 PAGE_EXECUTE_READWRITE. Distinct writable protections exercise
        // region crossing; the owned page contains data and is never executed.
        protection.0 = 0x40;
        // SAFETY: The test exclusively owns this committed page; the existing
        // wrapper restores its protection after the production preflight.
        unsafe {
            with_virtual_protect(edge as *mut c_void, protection, size, || {
                assert_eq!(prepare(&mut head), None);
                assert_eq!(head.next, entry as u32);
            })
        }
        .expect("temporarily split writable regions");
        // Win32 PAGE_READONLY and PAGE_NOACCESS, each scoped to one preflight.
        for flags in [0x02, 0x01] {
            protection.0 = flags;
            head.next = entry as u32;
            // SAFETY: No concurrent access exists and all entry writes ended.
            unsafe {
                with_virtual_protect(edge as *mut c_void, protection, size, || {
                    assert_eq!(prepare(&mut head).unwrap().reason, Reason::Inaccessible);
                    assert_eq!(head, Entry { data: 9, next: 0 });
                })
            }
            .expect("temporarily protect successor");
        }
        head.next = (usize::MAX - 3) as u32;
        assert_eq!(prepare(&mut head).unwrap().reason, Reason::Inaccessible);
        assert_eq!(head.next, 0);
    }
}
