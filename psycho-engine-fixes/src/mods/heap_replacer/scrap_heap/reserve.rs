//! Protected reusable backing for standard ScrapHeap regions.
//!
//! The supported game is a 32-bit process, so a normal 128 KiB region can
//! fail even when system RAM is available: the process may not have a suitable
//! free virtual-address range. This module removes that dependency for a
//! bounded number of regions by reserving and committing one contiguous range
//! during allocator startup.
//!
//! The range is divided into fixed-size slots. Free slots are `PAGE_NOACCESS`;
//! a lease changes exactly one slot to `PAGE_READWRITE`, and dropping the
//! lease restores `PAGE_NOACCESS` before returning the slot to a FIFO. The
//! protection transition is part of the lifetime contract, not an optimization:
//! it makes stale pointers fault while a slot is idle. A slot whose protection
//! cannot be changed is retired permanently so it cannot be handed to two
//! owners or reused with an unknown protection state.
//!
//! `RegionReserve` owns the mapping and each [`ReservedSlot`] owns an `Arc`
//! reference to the reserve. Therefore the backing mapping cannot be released
//! before every region lease has ended. The reserve mutex protects the slot
//! state machine and FIFO only; it is never held while another heap is purged.

use std::collections::VecDeque;
use std::ptr::NonNull;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc::c_void;
use libpsycho::os::windows::winapi::{
    virtual_make_noaccess, virtual_make_readwrite, virtual_release, virtual_reserve_commit,
};
use parking_lot::Mutex;

use super::heap::REGION_SIZE;

/// Preferred number of standard regions retained for mapping-free growth.
pub const TARGET_REGION_COUNT: usize = 16;

/// Minimum reserve capacity required before ScrapHeap hooks may be activated.
pub const MIN_REGION_COUNT: usize = 8;

/// Point-in-time reserve capacity and safety counters.
///
/// Counters use relaxed or acquire atomic reads and are diagnostic rather than
/// a transactional view. A protection transition may be in progress while the
/// snapshot is collected.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReserveSnapshot {
    /// Slots created in the backing reservation at startup.
    pub total_regions: usize,
    /// Slots not permanently retired after a protection failure.
    pub usable_regions: usize,
    /// Successfully leased slots currently owned by regions.
    pub in_use_regions: usize,
    /// Highest observed number of simultaneously leased slots.
    pub high_water_regions: usize,
    /// Standard-region requests that found no free reserve slot.
    pub misses: usize,
    /// Failed `VirtualProtect` transitions in either direction.
    pub protection_failures: usize,
    /// Slots permanently removed from circulation after protection failure.
    pub retired_regions: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    Leased,
    Retired,
}

struct ReserveState {
    free: VecDeque<usize>,
    slots: Vec<SlotState>,
}

/// Shared owner of the protected fixed-slot reservation.
///
/// Construct this through [`RegionReserve::create`]. Slot ownership is
/// represented by [`ReservedSlot`]; callers must not retain or use a slot
/// pointer after its lease is dropped.
pub struct RegionReserve {
    base: NonNull<u8>,
    region_count: usize,
    state: Mutex<ReserveState>,
    usable_regions: AtomicUsize,
    in_use_regions: AtomicUsize,
    high_water_regions: AtomicUsize,
    misses: AtomicUsize,
    protection_failures: AtomicUsize,
    retired_regions: AtomicUsize,
    #[cfg(test)]
    fail_readwrite: AtomicBool,
    #[cfg(test)]
    fail_noaccess: AtomicBool,
}

// `base` names a reservation owned for Self lifetime. Slot selection and state
// transitions are mutex-protected, while diagnostic counters are atomic.
unsafe impl Send for RegionReserve {}
unsafe impl Sync for RegionReserve {}

impl RegionReserve {
    /// Create the preferred reserve, falling back once to the mandatory minimum.
    ///
    /// The returned mapping is fully committed but inaccessible while idle.
    /// `None` means neither the target nor minimum contiguous reservation could
    /// be established and allocator activation must be rejected.
    pub fn create() -> Option<Arc<Self>> {
        Self::create_with_counts(TARGET_REGION_COUNT, MIN_REGION_COUNT)
    }

    fn create_with_counts(target: usize, minimum: usize) -> Option<Arc<Self>> {
        debug_assert!(target >= minimum);
        debug_assert!(minimum > 0);

        // Use only two bounded attempts. Repeatedly probing smaller mappings
        // would fragment startup VAS and would silently weaken the minimum
        // protection capacity promised by allocator activation.
        let fallback = if target == minimum { 0 } else { minimum };
        for region_count in [target, fallback] {
            if region_count == 0 {
                continue;
            }

            let capacity = region_count.checked_mul(REGION_SIZE)?;
            let ptr = unsafe { virtual_reserve_commit(None, capacity) };
            let Some(base) = NonNull::new(ptr as *mut u8) else {
                continue;
            };

            // Commit once at startup so future leases need only VirtualProtect;
            // an OOM-time allocation must not depend on obtaining fresh VAS.
            if let Err(error) =
                unsafe { virtual_make_noaccess(base.as_ptr().cast::<c_void>(), capacity) }
            {
                log::error!(
                    "[scrap_heap] reserve PAGE_NOACCESS failed: capacity={}KB error={:?}",
                    capacity / 1024,
                    error,
                );
                if let Err(release_error) =
                    unsafe { virtual_release(base.as_ptr().cast::<c_void>()) }
                {
                    log::error!(
                        "[scrap_heap] reserve rollback failed: base=0x{:08x} error={:?}",
                        base.as_ptr() as usize,
                        release_error,
                    );
                }
                continue;
            }

            let mut free = VecDeque::with_capacity(region_count);
            free.extend(0..region_count);
            let slots = vec![SlotState::Free; region_count];
            return Some(Arc::new(Self {
                base,
                region_count,
                state: Mutex::new(ReserveState { free, slots }),
                usable_regions: AtomicUsize::new(region_count),
                in_use_regions: AtomicUsize::new(0),
                high_water_regions: AtomicUsize::new(0),
                misses: AtomicUsize::new(0),
                protection_failures: AtomicUsize::new(0),
                retired_regions: AtomicUsize::new(0),
                #[cfg(test)]
                fail_readwrite: AtomicBool::new(false),
                #[cfg(test)]
                fail_noaccess: AtomicBool::new(false),
            }));
        }

        None
    }

    /// Lease the oldest free slot and make it readable and writable.
    ///
    /// Returns `None` when no usable slot remains. Protection failures retire
    /// the affected slot and acquisition continues with the next free slot.
    pub fn acquire(self: &Arc<Self>) -> Option<ReservedSlot> {
        loop {
            let index = {
                let mut state = self.state.lock();
                let index = state.free.pop_front()?;
                debug_assert_eq!(state.slots[index], SlotState::Free);
                // Publish Leased before dropping the mutex. No other caller can
                // select this slot while VirtualProtect runs.
                state.slots[index] = SlotState::Leased;
                index
            };
            let ptr = unsafe { self.base.as_ptr().add(index * REGION_SIZE) };

            if self.make_readwrite(ptr) {
                let in_use = self.in_use_regions.fetch_add(1, Ordering::AcqRel) + 1;
                self.high_water_regions.fetch_max(in_use, Ordering::Relaxed);
                return Some(ReservedSlot {
                    reserve: Arc::clone(self),
                    index,
                    ptr: NonNull::new(ptr).expect("reserve slot cannot be null"),
                });
            }

            self.retire_failed_slot(index, "PAGE_READWRITE");
        }
    }

    /// Record that an allocation request exhausted the free-slot FIFO.
    ///
    /// Acquisition itself does not increment this counter because callers may
    /// probe for reasons other than a real allocation fallback.
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Read diagnostic reserve capacity and lifetime counters.
    pub fn snapshot(&self) -> ReserveSnapshot {
        ReserveSnapshot {
            total_regions: self.region_count,
            usable_regions: self.usable_regions.load(Ordering::Acquire),
            in_use_regions: self.in_use_regions.load(Ordering::Acquire),
            high_water_regions: self.high_water_regions.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            protection_failures: self.protection_failures.load(Ordering::Relaxed),
            retired_regions: self.retired_regions.load(Ordering::Relaxed),
        }
    }

    fn release(&self, index: usize, ptr: NonNull<u8>) {
        // Protection must be restored before the slot is visible in `free`.
        // Reversing this order would allow a new owner to race a stale writer.
        let protected = self.make_noaccess(ptr.as_ptr());
        self.in_use_regions.fetch_sub(1, Ordering::AcqRel);

        if !protected {
            self.retire_failed_slot(index, "PAGE_NOACCESS");
            return;
        }

        let mut state = self.state.lock();
        debug_assert_eq!(state.slots[index], SlotState::Leased);
        state.slots[index] = SlotState::Free;
        state.free.push_back(index);
    }

    fn retire_failed_slot(&self, index: usize, transition: &str) {
        {
            let mut state = self.state.lock();
            debug_assert_eq!(state.slots[index], SlotState::Leased);
            state.slots[index] = SlotState::Retired;
        }
        // Keep the containing reservation alive, but never expose a slot whose
        // access state is unknown. This intentionally trades 128 KiB of reserve
        // capacity for deterministic ownership and UAF behavior.
        self.usable_regions.fetch_sub(1, Ordering::AcqRel);
        let failures = self.protection_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.retired_regions.fetch_add(1, Ordering::Relaxed);
        log::error!(
            "[scrap_heap] reserve slot retired after {} failure: slot={} failures={}",
            transition,
            index,
            failures,
        );
    }

    fn make_readwrite(&self, ptr: *mut u8) -> bool {
        #[cfg(test)]
        if self.fail_readwrite.load(Ordering::Relaxed) {
            return false;
        }
        unsafe { virtual_make_readwrite(ptr.cast::<c_void>(), REGION_SIZE) }.is_ok()
    }

    fn make_noaccess(&self, ptr: *mut u8) -> bool {
        #[cfg(test)]
        if self.fail_noaccess.load(Ordering::Relaxed) {
            return false;
        }
        unsafe { virtual_make_noaccess(ptr.cast::<c_void>(), REGION_SIZE) }.is_ok()
    }
}

impl Drop for RegionReserve {
    fn drop(&mut self) {
        let capacity = self.region_count * REGION_SIZE;
        if let Err(error) = unsafe { virtual_release(self.base.as_ptr().cast::<c_void>()) } {
            log::error!(
                "[scrap_heap] reserve release failed: base=0x{:08x} capacity={}KB error={:?}",
                self.base.as_ptr() as usize,
                capacity / 1024,
                error,
            );
        }
    }
}

/// Exclusive lease for one readable/writable reserve slot.
///
/// Dropping the lease protects and returns the slot. The raw start pointer is
/// valid only while this value remains owned by its enclosing region.
pub struct ReservedSlot {
    reserve: Arc<RegionReserve>,
    index: usize,
    ptr: NonNull<u8>,
}

// A lease has exclusive slot ownership. Moving or sharing the lease cannot
// create another lease; pointer access remains governed by the enclosing
// Region and its heap lock.
unsafe impl Send for ReservedSlot {}
unsafe impl Sync for ReservedSlot {}

impl ReservedSlot {
    /// Return the base address of the leased 128 KiB slot.
    pub fn start(&self) -> NonNull<u8> {
        self.ptr
    }
}

impl Drop for ReservedSlot {
    fn drop(&mut self) {
        self.reserve.release(self.index, self.ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::{MIN_REGION_COUNT, RegionReserve};
    use libpsycho::os::windows::winapi::virtual_query;

    #[test]
    fn dropped_slot_returns_to_reserve_as_noaccess() {
        let reserve =
            RegionReserve::create_with_counts(MIN_REGION_COUNT, MIN_REGION_COUNT).unwrap();
        let initial = reserve.snapshot().usable_regions;
        let slot = reserve.acquire().unwrap();
        let ptr = slot.start();

        assert_eq!(reserve.snapshot().in_use_regions, 1);
        assert!(virtual_query(ptr.as_ptr().cast()).unwrap().is_accessible());

        drop(slot);

        let snapshot = reserve.snapshot();
        assert_eq!(snapshot.usable_regions, initial);
        assert_eq!(snapshot.in_use_regions, 0);
        assert!(!virtual_query(ptr.as_ptr().cast()).unwrap().is_accessible());
    }

    #[test]
    fn reserve_exhaustion_and_reuse_are_bounded() {
        let reserve =
            RegionReserve::create_with_counts(MIN_REGION_COUNT, MIN_REGION_COUNT).unwrap();
        let mut slots = Vec::new();
        for _ in 0..MIN_REGION_COUNT {
            slots.push(reserve.acquire().unwrap());
        }

        assert!(reserve.acquire().is_none());
        assert_eq!(reserve.snapshot().high_water_regions, MIN_REGION_COUNT);

        let first = slots.remove(0);
        let first_ptr = first.start();
        drop(first);
        let reused = reserve.acquire().unwrap();
        assert_eq!(reused.start(), first_ptr);
    }

    #[test]
    fn failed_release_protection_retires_slot() {
        let reserve =
            RegionReserve::create_with_counts(MIN_REGION_COUNT, MIN_REGION_COUNT).unwrap();
        let slot = reserve.acquire().unwrap();
        reserve
            .fail_noaccess
            .store(true, std::sync::atomic::Ordering::Relaxed);
        drop(slot);

        let snapshot = reserve.snapshot();
        assert_eq!(snapshot.in_use_regions, 0);
        assert_eq!(snapshot.usable_regions, MIN_REGION_COUNT - 1);
        assert_eq!(snapshot.retired_regions, 1);
        assert_eq!(snapshot.protection_failures, 1);
    }

    #[test]
    fn failed_acquire_protection_retires_unusable_capacity() {
        let reserve =
            RegionReserve::create_with_counts(MIN_REGION_COUNT, MIN_REGION_COUNT).unwrap();
        reserve
            .fail_readwrite
            .store(true, std::sync::atomic::Ordering::Relaxed);

        assert!(reserve.acquire().is_none());
        let snapshot = reserve.snapshot();
        assert_eq!(snapshot.usable_regions, 0);
        assert_eq!(snapshot.retired_regions, MIN_REGION_COUNT);
        assert_eq!(snapshot.protection_failures, MIN_REGION_COUNT);
    }
}
