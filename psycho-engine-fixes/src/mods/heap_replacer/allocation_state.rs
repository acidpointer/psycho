//! Cold allocation-state classification for standalone lifetime guards.
//!
//! Gheap exposes exact out-of-band state. Vanilla GameHeap small allocations
//! use SBM pools whose immutable geometry proves cell boundaries and whose
//! native lock stabilizes page commitment, counts, and free-list links.
//! Stable free-list head/backlinks identify individual free cells, but SBM has
//! no allocation bitmap. A remaining cell on a non-empty vanilla page is
//! therefore only structurally plausible; the engine guard must also validate
//! the object's fields before accepting it. No OS readability probe is used.

use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{Ordering, compiler_fence};

use libc::c_void;
use libpsycho::ffi::fnptr::FnPtr;

use super::{AllocatorMode, current_mode, gheap, heap_validate};

const VANILLA_POOL_BY_HIGH_BYTE: usize = 0x011F_63B8;
const VANILLA_POOL_BASE_OFFSET: usize = 0x04;
const VANILLA_POOL_FREE_HEAD_OFFSET: usize = 0x08;
const VANILLA_POOL_LOCK_OFFSET: usize = 0x20;
const VANILLA_POOL_ITEM_SIZE_OFFSET: usize = 0x40;
const VANILLA_POOL_PAGE_COUNTS_OFFSET: usize = 0x48;
const VANILLA_POOL_ARENA_SIZE_OFFSET: usize = 0x50;
const VANILLA_POOL_PAGE_SIZE: usize = 0x1000;
const VANILLA_POOL_PAGE_UNCOMMITTED: u16 = u16::MAX;
const VANILLA_POOL_LOCK_ADDR: usize = gheap::engine::addr::SPIN_LOCK_ACQUIRE;
const ENGINE_WORD_SIZE: usize = 4;
const VALIDATION_LOCK_LABEL: &[u8] = b"Psycho lifetime validation\0";

type VanillaPoolLockFn = unsafe extern "thiscall" fn(*mut c_void, *const u8);

struct VanillaPoolSnapshot {
    lock: *mut u32,
}

impl VanillaPoolSnapshot {
    /// Lock the engine pool whose address came from the fixed ownership table.
    unsafe fn acquire(pool: usize) -> Option<Self> {
        let lock = pool.checked_add(VANILLA_POOL_LOCK_OFFSET)? as *mut u32;
        let acquire =
            unsafe { FnPtr::<VanillaPoolLockFn>::from_address_unchecked(VANILLA_POOL_LOCK_ADDR) }
                .as_fn();
        unsafe { acquire(lock.cast(), VALIDATION_LOCK_LABEL.as_ptr()) };
        Some(Self { lock })
    }
}

struct VanillaPoolCandidate {
    _snapshot: VanillaPoolSnapshot,
    address: usize,
    base: usize,
    free_head: usize,
    item_size: usize,
    page_counts: usize,
    arena_size: usize,
}

impl VanillaPoolCandidate {
    fn acquire(address: usize) -> Option<Self> {
        let table_entry =
            VANILLA_POOL_BY_HIGH_BYTE.checked_add((address >> 24) * ENGINE_WORD_SIZE)?;
        let pool = unsafe { read_owned_u32(table_entry) } as usize;
        if pool == 0 {
            return None;
        }
        let snapshot = unsafe { VanillaPoolSnapshot::acquire(pool)? };

        let base = unsafe { read_pool_u32(pool, VANILLA_POOL_BASE_OFFSET)? } as usize;
        let free_head = unsafe { read_pool_u32(pool, VANILLA_POOL_FREE_HEAD_OFFSET)? } as usize;
        let item_size = unsafe { read_pool_u32(pool, VANILLA_POOL_ITEM_SIZE_OFFSET)? } as usize;
        let page_counts = unsafe { read_pool_u32(pool, VANILLA_POOL_PAGE_COUNTS_OFFSET)? } as usize;
        let arena_size = unsafe { read_pool_u32(pool, VANILLA_POOL_ARENA_SIZE_OFFSET)? } as usize;
        let arena_end = base.checked_add(arena_size)?;
        if address < base || address >= arena_end {
            return None;
        }

        Some(Self {
            _snapshot: snapshot,
            address,
            base,
            free_head,
            item_size,
            page_counts,
            arena_size,
        })
    }

    fn state(&self) -> Option<AllocationState> {
        if self.item_size < ENGINE_WORD_SIZE
            || self.item_size > VANILLA_POOL_PAGE_SIZE
            || self.item_size % ENGINE_WORD_SIZE != 0
        {
            return Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::OwnedUnknown,
            });
        }

        let arena_offset = self.address - self.base;
        let page_index = arena_offset / VANILLA_POOL_PAGE_SIZE;
        let page_offset = arena_offset % VANILLA_POOL_PAGE_SIZE;
        let cells_per_page = VANILLA_POOL_PAGE_SIZE / self.item_size;
        let cell_bytes_per_page = cells_per_page * self.item_size;
        let within_cell = page_offset % self.item_size;
        let cell_start = self.address - within_cell;

        if page_offset >= cell_bytes_per_page || within_cell != 0 {
            return Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::Interior {
                    allocation_start: cell_start,
                    offset: within_cell,
                    usable_size: self.item_size,
                },
            });
        }

        if self.page_counts == 0 {
            return Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::OwnedUnknown,
            });
        }
        let count_address = self
            .page_counts
            .checked_add(page_index * size_of::<u16>())?;
        let page_live = unsafe { ptr::read_unaligned(count_address as *const u16) } as usize;
        if page_live == usize::from(VANILLA_POOL_PAGE_UNCOMMITTED) {
            return Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::Uncommitted,
            });
        }
        if page_live == 0 {
            return Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::Free {
                    usable_size: self.item_size,
                },
            });
        }
        if page_live > cells_per_page {
            return Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::OwnedUnknown,
            });
        }

        let previous_free = unsafe { read_owned_u32(self.address) } as usize;
        let linked_free = vanilla_free_list_contains(
            self.address,
            self.free_head,
            previous_free,
            self.base,
            self.arena_size,
            self.item_size,
            |cell| unsafe {
                vanilla_pool_cell_is_committed(
                    cell,
                    self.base,
                    self.arena_size,
                    self.item_size,
                    self.page_counts,
                )
            },
            |word| Some(unsafe { read_owned_u32(word) }),
        );
        classify_vanilla_pool_cell(
            self.address,
            self.base,
            self.arena_size,
            self.item_size,
            page_live,
            linked_free,
        )
    }

    fn read_words(
        &self,
        minimum_size: usize,
        offsets: &[usize],
        output: &mut [usize],
    ) -> Result<(), AllocationState> {
        let state = self.state().unwrap_or(AllocationState::Unowned);
        let AllocationState::PlausibleVanillaPool { usable_size } = state else {
            return Err(state);
        };
        if !valid_read_ranges(usable_size, minimum_size, offsets, output.len()) {
            return Err(state);
        }
        unsafe { read_owned_words(self.address, offsets, output) };
        Ok(())
    }
}

impl Drop for VanillaPoolSnapshot {
    fn drop(&mut self) {
        unsafe {
            let depth = ptr::read_volatile(self.lock.add(1));
            debug_assert!(depth != 0);
            if depth == 0 {
                return;
            }
            let remaining = depth - 1;
            ptr::write_volatile(self.lock.add(1), remaining);
            if remaining == 0 {
                compiler_fence(Ordering::Release);
                ptr::write_volatile(self.lock, 0);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationTier {
    GheapPool,
    GheapBlock,
    GheapVirtual,
    VanillaPool,
    WindowsHeap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvalidAllocationReason {
    Interior {
        allocation_start: usize,
        offset: usize,
        usable_size: usize,
    },
    Free {
        usable_size: usize,
    },
    Unissued,
    Uncommitted,
    OwnedUnknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationState {
    /// Exact live allocation start proven by authoritative side metadata.
    Live {
        tier: AllocationTier,
        usable_size: usize,
    },
    /// Exact vanilla SBM cell boundary on a page with at least one live cell.
    ///
    /// SBM has no per-cell allocation bitmap, so candidates not identified as
    /// free by a stable free-list snapshot still require field validation.
    PlausibleVanillaPool {
        usable_size: usize,
    },
    InvalidOwned {
        tier: AllocationTier,
        reason: InvalidAllocationReason,
    },
    Unowned,
}

pub(crate) fn allocation_state(ptr: *const c_void) -> AllocationState {
    match current_mode() {
        Some(AllocatorMode::GheapAndScrapHeap) => gheap::allocator::allocation_state(ptr),
        Some(AllocatorMode::ScrapHeap | AllocatorMode::Disabled) => vanilla_allocation_state(ptr),
        None => AllocationState::Unowned,
    }
}

/// Read selected words while the same allocator proof that admits the
/// containing allocation remains valid.
///
/// Vanilla SBM classification and the read share one native pool-lock
/// snapshot, preventing a completely free page from being purged between the
/// two operations. Exact gheap and Windows-heap allocations rely on the
/// calling engine guard's object-lifetime ownership after metadata validation.
pub(crate) fn read_allocation_words(
    ptr: usize,
    minimum_size: usize,
    offsets: &[usize],
    output: &mut [usize],
) -> Result<(), AllocationState> {
    match current_mode() {
        Some(AllocatorMode::GheapAndScrapHeap) => {
            let state = gheap::allocator::allocation_state(ptr as *const c_void);
            let AllocationState::Live { usable_size, .. } = state else {
                return Err(state);
            };
            if !valid_read_ranges(usable_size, minimum_size, offsets, output.len()) {
                return Err(state);
            }
            unsafe { read_owned_words(ptr, offsets, output) };
            Ok(())
        }
        Some(AllocatorMode::ScrapHeap | AllocatorMode::Disabled) => {
            vanilla_allocation_words(ptr, minimum_size, offsets, output)
        }
        None => Err(AllocationState::Unowned),
    }
}

/// Run a cold mutation while the allocation proof that admitted `ptr` remains
/// valid.
///
/// Vanilla SBM keeps its native pool lock for the complete callback so a page
/// cannot be purged or its free-list state changed between validation and the
/// mutation. Exact gheap and Windows-heap allocations rely on the caller's
/// native lifetime ownership after metadata validation.
///
/// # Safety
///
/// `ptr` must be the exact allocation start. The caller must own the native
/// object's lifetime for the complete callback and must ensure that writes made
/// by `operation` satisfy the allocation's engine layout and aliasing contract.
pub(crate) unsafe fn with_allocation_mut<R>(
    ptr: *mut c_void,
    minimum_size: usize,
    operation: impl FnOnce(*mut u8, usize, AllocationState) -> R,
) -> Result<R, AllocationState> {
    match current_mode() {
        Some(AllocatorMode::GheapAndScrapHeap) => {
            let state = gheap::allocator::allocation_state(ptr.cast_const());
            let AllocationState::Live { usable_size, .. } = state else {
                return Err(state);
            };
            if usable_size < minimum_size {
                return Err(state);
            }
            Ok(operation(ptr.cast(), usable_size, state))
        }
        Some(AllocatorMode::ScrapHeap | AllocatorMode::Disabled) => unsafe {
            with_vanilla_allocation_mut(ptr, minimum_size, operation)
        },
        None => Err(AllocationState::Unowned),
    }
}

/// Validate and mutate a vanilla GameHeap allocation under its owning lock
/// when the pointer belongs to an SBM pool.
///
/// # Safety
///
/// `ptr` must be the exact allocation start and remain under the caller's
/// native lifetime ownership for the complete operation. The callback must
/// preserve the allocation's engine layout and aliasing contract.
unsafe fn with_vanilla_allocation_mut<R>(
    ptr: *mut c_void,
    minimum_size: usize,
    operation: impl FnOnce(*mut u8, usize, AllocationState) -> R,
) -> Result<R, AllocationState> {
    if let Some(candidate) = VanillaPoolCandidate::acquire(ptr as usize) {
        let state = candidate.state().unwrap_or(AllocationState::Unowned);
        let AllocationState::PlausibleVanillaPool { usable_size } = state else {
            return Err(state);
        };
        if usable_size < minimum_size {
            return Err(state);
        }
        // `candidate` owns the native pool snapshot until the callback returns.
        return Ok(operation(ptr.cast(), usable_size, state));
    }

    let usable_size = unsafe { heap_validate::heap_validated_size(ptr.cast_const()) };
    if usable_size == usize::MAX {
        return Err(AllocationState::Unowned);
    }
    let state = AllocationState::Live {
        tier: AllocationTier::WindowsHeap,
        usable_size,
    };
    if usable_size < minimum_size {
        return Err(state);
    }
    Ok(operation(ptr.cast(), usable_size, state))
}

fn vanilla_allocation_state(ptr: *const c_void) -> AllocationState {
    if ptr.is_null() {
        return AllocationState::Unowned;
    }

    if let Some(state) = vanilla_pool_state(ptr) {
        return state;
    }

    let usable_size = unsafe { heap_validate::heap_validated_size(ptr) };
    if usable_size != usize::MAX {
        return AllocationState::Live {
            tier: AllocationTier::WindowsHeap,
            usable_size,
        };
    }

    AllocationState::Unowned
}

fn vanilla_pool_state(ptr: *const c_void) -> Option<AllocationState> {
    let address = ptr as usize;
    VanillaPoolCandidate::acquire(address)?.state()
}

fn vanilla_allocation_words(
    ptr: usize,
    minimum_size: usize,
    offsets: &[usize],
    output: &mut [usize],
) -> Result<(), AllocationState> {
    if let Some(candidate) = VanillaPoolCandidate::acquire(ptr) {
        return candidate.read_words(minimum_size, offsets, output);
    }

    let usable_size = unsafe { heap_validate::heap_validated_size(ptr as *const c_void) };
    if usable_size == usize::MAX {
        return Err(AllocationState::Unowned);
    }
    let state = AllocationState::Live {
        tier: AllocationTier::WindowsHeap,
        usable_size,
    };
    if !valid_read_ranges(usable_size, minimum_size, offsets, output.len()) {
        return Err(state);
    }
    unsafe { read_owned_words(ptr, offsets, output) };
    Ok(())
}

fn valid_read_ranges(
    usable_size: usize,
    minimum_size: usize,
    offsets: &[usize],
    output_len: usize,
) -> bool {
    offsets.len() == output_len
        && usable_size >= minimum_size
        && offsets.iter().all(|offset| {
            offset
                .checked_add(ENGINE_WORD_SIZE)
                .is_some_and(|field_end| field_end <= minimum_size && field_end <= usable_size)
        })
}

/// Read fields while native lifetime or the held allocator lock keeps them
/// committed.
unsafe fn read_owned_words(base: usize, offsets: &[usize], output: &mut [usize]) {
    for (offset, slot) in offsets.iter().zip(output) {
        let address = base + offset;
        *slot = unsafe { read_owned_u32(address) as usize };
    }
}

fn classify_vanilla_pool_cell(
    address: usize,
    base: usize,
    arena_size: usize,
    item_size: usize,
    page_live: usize,
    linked_free: bool,
) -> Option<AllocationState> {
    let arena_end = base.checked_add(arena_size)?;
    if address < base || address >= arena_end || item_size == 0 {
        return None;
    }

    let page_offset = (address - base) % VANILLA_POOL_PAGE_SIZE;
    let cells_per_page = VANILLA_POOL_PAGE_SIZE / item_size;
    if cells_per_page == 0 {
        return Some(AllocationState::InvalidOwned {
            tier: AllocationTier::VanillaPool,
            reason: InvalidAllocationReason::OwnedUnknown,
        });
    }
    let within_cell = page_offset % item_size;
    let cell_start = address - within_cell;
    if page_offset >= cells_per_page * item_size || within_cell != 0 {
        return Some(AllocationState::InvalidOwned {
            tier: AllocationTier::VanillaPool,
            reason: InvalidAllocationReason::Interior {
                allocation_start: cell_start,
                offset: within_cell,
                usable_size: item_size,
            },
        });
    }
    if page_live == 0 || linked_free {
        return Some(AllocationState::InvalidOwned {
            tier: AllocationTier::VanillaPool,
            reason: InvalidAllocationReason::Free {
                usable_size: item_size,
            },
        });
    }
    if page_live > cells_per_page {
        return Some(AllocationState::InvalidOwned {
            tier: AllocationTier::VanillaPool,
            reason: InvalidAllocationReason::OwnedUnknown,
        });
    }
    Some(AllocationState::PlausibleVanillaPool {
        usable_size: item_size,
    })
}

fn vanilla_free_list_contains(
    address: usize,
    free_head: usize,
    previous_free: usize,
    base: usize,
    arena_size: usize,
    item_size: usize,
    mut is_committed_cell: impl FnMut(usize) -> bool,
    mut read_word: impl FnMut(usize) -> Option<u32>,
) -> bool {
    if previous_free == 0 {
        return free_head == address;
    }
    if !is_exact_pool_cell(previous_free, base, arena_size, item_size)
        || !is_committed_cell(previous_free)
    {
        return false;
    }
    previous_free
        .checked_add(ENGINE_WORD_SIZE)
        .and_then(&mut read_word)
        .is_some_and(|next| next as usize == address)
}

fn is_exact_pool_cell(address: usize, base: usize, arena_size: usize, item_size: usize) -> bool {
    let Some(arena_end) = base.checked_add(arena_size) else {
        return false;
    };
    if address < base || address >= arena_end || item_size == 0 {
        return false;
    }
    let page_offset = (address - base) % VANILLA_POOL_PAGE_SIZE;
    let cells_per_page = VANILLA_POOL_PAGE_SIZE / item_size;
    cells_per_page != 0 && page_offset < cells_per_page * item_size && page_offset % item_size == 0
}

/// Read pool metadata while its native lock is held.
unsafe fn read_pool_u32(pool: usize, offset: usize) -> Option<u32> {
    let address = pool.checked_add(offset)?;
    Some(unsafe { read_owned_u32(address) })
}

/// Return whether an exact pool cell belongs to a currently committed page.
///
/// The native pool lock must remain held. Purge unlinks every cell on a free
/// page, decommits the page, then publishes 0xFFFF in its count slot.
unsafe fn vanilla_pool_cell_is_committed(
    address: usize,
    base: usize,
    arena_size: usize,
    item_size: usize,
    page_counts: usize,
) -> bool {
    if page_counts == 0 || !is_exact_pool_cell(address, base, arena_size, item_size) {
        return false;
    }
    let page_index = (address - base) / VANILLA_POOL_PAGE_SIZE;
    let Some(count_address) = page_counts.checked_add(page_index * size_of::<u16>()) else {
        return false;
    };
    unsafe { ptr::read_unaligned(count_address as *const u16) != VANILLA_POOL_PAGE_UNCOMMITTED }
}

/// Read memory whose native owner or allocator metadata proves it committed.
unsafe fn read_owned_u32(address: usize) -> u32 {
    unsafe { ptr::read_unaligned(address as *const u32) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vanilla_pool_geometry_accepts_exact_cells_on_nonempty_pages() {
        assert_eq!(
            classify_vanilla_pool_cell(0xD000_0018, 0xD000_0000, 0x40_0000, 12, 1, false),
            Some(AllocationState::PlausibleVanillaPool { usable_size: 12 })
        );
    }

    #[test]
    fn vanilla_pool_geometry_rejects_observed_interior_offset() {
        assert_eq!(
            classify_vanilla_pool_cell(0xD0AC_000D, 0xD080_0000, 0x80_0000, 8, 1, false),
            Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::Interior {
                    allocation_start: 0xD0AC_0008,
                    offset: 5,
                    usable_size: 8,
                },
            })
        );
    }

    #[test]
    fn vanilla_pool_geometry_rejects_cells_on_completely_free_pages() {
        assert_eq!(
            classify_vanilla_pool_cell(0xD000_0018, 0xD000_0000, 0x40_0000, 12, 0, false),
            Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::Free { usable_size: 12 },
            })
        );
    }

    #[test]
    fn vanilla_pool_geometry_rejects_free_head_on_mixed_page() {
        assert_eq!(
            classify_vanilla_pool_cell(0xD000_0018, 0xD000_0000, 0x40_0000, 12, 1, true),
            Some(AllocationState::InvalidOwned {
                tier: AllocationTier::VanillaPool,
                reason: InvalidAllocationReason::Free { usable_size: 12 },
            })
        );
    }

    #[test]
    fn vanilla_free_list_recognizes_head_and_verified_predecessor() {
        let base = 0xD000_0000;
        let cell = base + 0x18;
        let previous = base + 0x0C;

        assert!(vanilla_free_list_contains(
            cell,
            cell,
            0,
            base,
            0x40_0000,
            12,
            |_| true,
            |_| None,
        ));
        assert!(vanilla_free_list_contains(
            cell,
            previous,
            previous,
            base,
            0x40_0000,
            12,
            |_| true,
            |address| (address == previous + ENGINE_WORD_SIZE).then_some(cell as u32),
        ));
        assert!(!vanilla_free_list_contains(
            cell,
            previous,
            previous,
            base,
            0x40_0000,
            12,
            |_| true,
            |_| Some(0),
        ));
        assert!(!vanilla_free_list_contains(
            cell,
            previous,
            previous,
            base,
            0x40_0000,
            12,
            |_| false,
            |_| panic!("uncommitted predecessor must not be read"),
        ));
    }

    #[test]
    fn vanilla_page_sentinel_rejects_uncommitted_cells() {
        let base = 0xD000_0000;
        let counts = [1u16, VANILLA_POOL_PAGE_UNCOMMITTED];

        assert!(unsafe {
            vanilla_pool_cell_is_committed(
                base + 0x18,
                base,
                2 * VANILLA_POOL_PAGE_SIZE,
                12,
                counts.as_ptr() as usize,
            )
        });
        assert!(!unsafe {
            vanilla_pool_cell_is_committed(
                base + VANILLA_POOL_PAGE_SIZE + 0x18,
                base,
                2 * VANILLA_POOL_PAGE_SIZE,
                12,
                counts.as_ptr() as usize,
            )
        });
    }
}
