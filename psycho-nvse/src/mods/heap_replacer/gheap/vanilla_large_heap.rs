//! Telemetry and conservative VAS reclaim for pre-gheap vanilla heaps.
//!
//! FalloutNV.exe constructs the vanilla Default/File large heaps before
//! NVSE can activate gheap. Those two heaps reserve 200 MB + 64 MB of
//! 32-bit address space even if gheap takes over before they are used.
//!
//! Reclaim here is intentionally strict: only heaps with no current
//! live bytes and no historical high-water mark are released. That means
//! "never used", not merely "currently empty", preserving UAF safety for
//! pre-hook allocations that might have been freed before gheap starts.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libc::c_void;
use windows::Win32::System::Diagnostics::Debug::CONTEXT;
use windows::Win32::System::Memory::{
    MEM_RELEASE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualAlloc, VirtualFree,
    VirtualProtect,
};
use windows::Win32::System::Threading::{
    CRITICAL_SECTION, EnterCriticalSection, LeaveCriticalSection,
};

use super::engine::addr;

const DEFAULT_HEAP_OFFSET: usize = 0x110;
const FILE_HEAP_OFFSET: usize = 0x68;

const CAPACITY_OFFSET: usize = 0x14;
const INITIAL_COMMIT_OFFSET: usize = 0x18;
const COMMITTED_LIMIT_OFFSET: usize = 0x1c;
const UNKNOWN_20_OFFSET: usize = 0x20;
const BUMP_END_OFFSET: usize = 0x24;
const HIGH_WATER_OFFSET: usize = 0x28;
const LIVE_BYTES_OFFSET: usize = 0x2c;
const BASE_OFFSET: usize = 0x30;
const BLOCK_COUNT_OFFSET: usize = 0x34;
const FIRST_BLOCK_OFFSET: usize = 0x38;
const LAST_BLOCK_OFFSET: usize = 0x3c;
const FREE_COUNT_OFFSET: usize = 0x40;

const FREE_BUCKETS_OFFSET: usize = 0x44;
const FREE_BUCKETS_BYTES: usize = 0x2000;
const LAST_SMALL_BUCKET_PTR_OFFSET: usize = 0x2044;
const LARGE_BUCKET_OFFSET: usize = 0x2048;
const LARGE_BUCKET_BYTES: usize = 8;
const SEARCH_AUX_0_OFFSET: usize = 0x2050;
const SEARCH_AUX_1_OFFSET: usize = 0x2054;
const SEARCH_GROUPS_OFFSET: usize = 0x2058;
const SEARCH_GROUP_COUNT: usize = 16;
const SEARCH_GROUP_STRIDE: usize = 8;
const SMALL_BUCKET_GROUP_BYTES: usize = 0x200;

const CRITICAL_SECTION_OFFSET: usize = 0x20d8;
const PAGE_SIZE: usize = 0x1000;
const DEFAULT_TAIL_SKIP: usize = 16 * 1024 * 1024;
const DEFAULT_TAIL_POLL_MS: u32 = 5_000;

static RAN: AtomicBool = AtomicBool::new(false);
static DEFAULT_PROBE_ARMED: AtomicBool = AtomicBool::new(false);
static DEFAULT_PROBE_BASE: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_PROBE_LEN: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_PROBE_OLD_PROTECT: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_PROBE_HITS: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_ENABLED: AtomicBool = AtomicBool::new(false);
static DEFAULT_TAIL_DISABLED_LOGGED: AtomicBool = AtomicBool::new(false);
static DEFAULT_TAIL_EXHAUSTED_LOGGED: AtomicBool = AtomicBool::new(false);
static DEFAULT_TAIL_HEAP: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_BASE: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_NEXT: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_END: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_CAPACITY: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_BUMP_END: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_HIGH_WATER: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_BLOCK_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_FIRST_BLOCK: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_LAST_BLOCK: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEFAULT_TAIL_LAST_POLL_MS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
struct Snapshot {
    heap: usize,
    base: usize,
    capacity: usize,
    initial_commit: usize,
    committed_limit: usize,
    bump_end: usize,
    high_water: usize,
    live_bytes: usize,
    block_count: usize,
    first_block: usize,
    last_block: usize,
    free_count: usize,
}

struct HeapLock {
    cs: *mut CRITICAL_SECTION,
}

impl Drop for HeapLock {
    fn drop(&mut self) {
        unsafe { LeaveCriticalSection(self.cs) };
    }
}

/// Log and reclaim pre-gheap Default/File heap reservations once.
///
/// Must be called after gheap activation from the main loop. Reclaim is
/// skipped unless the old heap was never used.
pub fn run_once() {
    if RAN.swap(true, Ordering::AcqRel) {
        return;
    }

    let before = super::vas::sample();
    let mut reclaimed = 0usize;

    reclaimed = reclaimed
        .saturating_add(unsafe { inspect_and_maybe_reclaim("Default", DEFAULT_HEAP_OFFSET) });
    reclaimed =
        reclaimed.saturating_add(unsafe { inspect_and_maybe_reclaim("File", FILE_HEAP_OFFSET) });

    if reclaimed == 0 {
        return;
    }

    if let (Some(before), Some(after)) = (before, super::vas::sample()) {
        log::info!(
            "[VANILLA_HEAP] reclaimed={}MB VAS: free {}MB -> {}MB, largest 0x{:08x}+{}MB -> 0x{:08x}+{}MB",
            reclaimed / super::vas::MB,
            before.total_free / super::vas::MB,
            after.total_free / super::vas::MB,
            before.largest_base,
            before.largest_free / super::vas::MB,
            after.largest_base,
            after.largest_free / super::vas::MB,
        );
    } else {
        log::info!(
            "[VANILLA_HEAP] reclaimed={}MB VAS",
            reclaimed / super::vas::MB
        );
    }
}

unsafe fn inspect_and_maybe_reclaim(label: &str, heap_offset: usize) -> usize {
    let heap = unsafe { read_usize(addr::HEAP_SINGLETON + heap_offset) };
    if heap == 0 {
        log::info!("[VANILLA_HEAP] {}: heap pointer is NULL, skipped", label);
        return 0;
    }

    let _lock = unsafe { lock_heap(heap) };
    let snapshot = unsafe { Snapshot::read(heap) };
    log_snapshot(label, snapshot);

    if let Some(reason) = ineligible_reason(snapshot) {
        if label == "Default" {
            unsafe { maybe_arm_default_heap_probe(snapshot) };
            unsafe { maybe_enable_default_tail_adoption(snapshot) };
        }
        log::info!("[VANILLA_HEAP] {}: reclaim skipped: {}", label, reason);
        return 0;
    }

    if let Err(err) = unsafe { VirtualFree(snapshot.base as *mut c_void, 0, MEM_RELEASE) } {
        log::error!(
            "[VANILLA_HEAP] {}: VirtualFree failed: base=0x{:08x} capacity={}MB err={:?}",
            label,
            snapshot.base,
            snapshot.capacity / super::vas::MB,
            err,
        );
        return 0;
    }

    unsafe { reset_released_heap(heap) };

    log::info!(
        "[VANILLA_HEAP] {}: reclaimed never-used reservation base=0x{:08x} capacity={}MB initial_commit={}MB",
        label,
        snapshot.base,
        snapshot.capacity / super::vas::MB,
        snapshot.initial_commit / super::vas::MB,
    );
    snapshot.capacity
}

impl Snapshot {
    unsafe fn read(heap: usize) -> Self {
        Self {
            heap,
            base: unsafe { read_usize(heap + BASE_OFFSET) },
            capacity: unsafe { read_usize(heap + CAPACITY_OFFSET) },
            initial_commit: unsafe { read_usize(heap + INITIAL_COMMIT_OFFSET) },
            committed_limit: unsafe { read_usize(heap + COMMITTED_LIMIT_OFFSET) },
            bump_end: unsafe { read_usize(heap + BUMP_END_OFFSET) },
            high_water: unsafe { read_usize(heap + HIGH_WATER_OFFSET) },
            live_bytes: unsafe { read_usize(heap + LIVE_BYTES_OFFSET) },
            block_count: unsafe { read_usize(heap + BLOCK_COUNT_OFFSET) },
            first_block: unsafe { read_usize(heap + FIRST_BLOCK_OFFSET) },
            last_block: unsafe { read_usize(heap + LAST_BLOCK_OFFSET) },
            free_count: unsafe { read_usize(heap + FREE_COUNT_OFFSET) },
        }
    }
}

fn log_snapshot(label: &str, s: Snapshot) {
    log::info!(
        "[VANILLA_HEAP] {}: heap=0x{:08x} base=0x{:08x} capacity={}MB initial={}MB committed={}MB bump={}KB high={}KB live={}KB blocks={} free_blocks={} first=0x{:08x} last=0x{:08x}",
        label,
        s.heap,
        s.base,
        s.capacity / super::vas::MB,
        s.initial_commit / super::vas::MB,
        s.committed_limit / super::vas::MB,
        s.bump_end / 1024,
        s.high_water / 1024,
        s.live_bytes / 1024,
        s.block_count,
        s.free_count,
        s.first_block,
        s.last_block,
    );
}

fn ineligible_reason(s: Snapshot) -> Option<&'static str> {
    if s.base == 0 {
        return Some("already released");
    }
    if s.capacity == 0 {
        return Some("capacity is zero");
    }
    if s.live_bytes != 0 {
        return Some("live bytes are nonzero");
    }
    if s.bump_end != 0 {
        return Some("bump/end offset is nonzero");
    }
    if s.high_water != 0 {
        return Some("high-water offset is nonzero");
    }
    if s.block_count != 0 {
        return Some("physical block count is nonzero");
    }
    if s.first_block != 0 || s.last_block != 0 {
        return Some("physical block list is nonempty");
    }
    if s.free_count != 0 {
        return Some("free block count is nonzero");
    }
    None
}

unsafe fn maybe_arm_default_heap_probe(s: Snapshot) {
    let enabled = crate::config::get_config()
        .map(|c| c.memory.gheap_default_heap_probe)
        .unwrap_or(false);
    if !enabled {
        return;
    }
    if DEFAULT_PROBE_ARMED.load(Ordering::Acquire) {
        return;
    }
    if s.base == 0 || s.committed_limit == 0 {
        log::warn!("[VANILLA_HEAP_PROBE] skipped: Default heap has no committed backing");
        return;
    }
    if s.live_bytes == 0 && s.block_count == 0 {
        log::warn!("[VANILLA_HEAP_PROBE] skipped: Default heap has no live blocks");
        return;
    }

    let guard_len = default_probe_len(s);
    if guard_len == 0 {
        log::warn!("[VANILLA_HEAP_PROBE] skipped: computed guard length is zero");
        return;
    }

    DEFAULT_PROBE_BASE.store(s.base, Ordering::Release);
    DEFAULT_PROBE_LEN.store(guard_len, Ordering::Release);
    DEFAULT_PROBE_OLD_PROTECT.store(PAGE_READWRITE.0 as usize, Ordering::Release);
    DEFAULT_PROBE_ARMED.store(true, Ordering::Release);

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    if let Err(err) = unsafe {
        VirtualProtect(
            s.base as *mut c_void,
            guard_len,
            PAGE_NOACCESS,
            &mut old_protect,
        )
    } {
        DEFAULT_PROBE_ARMED.store(false, Ordering::Release);
        log::error!(
            "[VANILLA_HEAP_PROBE] VirtualProtect failed: base=0x{:08x} len={}KB err={:?}",
            s.base,
            guard_len / 1024,
            err,
        );
        return;
    }

    DEFAULT_PROBE_OLD_PROTECT.store(old_protect.0 as usize, Ordering::Release);
    log::warn!(
        "[VANILLA_HEAP_PROBE] armed Default heap live-prefix trap base=0x{:08x} len={}KB live={}KB blocks={} old_protect=0x{:x}",
        s.base,
        guard_len / 1024,
        s.live_bytes / 1024,
        s.block_count,
        old_protect.0,
    );
}

fn default_probe_len(s: Snapshot) -> usize {
    let mut span = PAGE_SIZE
        .max(s.live_bytes)
        .max(s.bump_end)
        .max(s.high_water);
    let committed_end = s.base.saturating_add(s.committed_limit);

    if s.last_block >= s.base && s.last_block < committed_end {
        span = span.max(s.last_block - s.base + 1);
    }

    align_up(span, PAGE_SIZE).min(s.committed_limit)
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Handle the intentional Default heap probe AV.
///
/// Returns true when the fault belongs to the probe and protections were
/// restored, allowing the faulting instruction to be retried.
pub unsafe fn handle_default_heap_probe_fault(
    fault: usize,
    access_kind: usize,
    ctx: &CONTEXT,
) -> bool {
    if !DEFAULT_PROBE_ARMED.load(Ordering::Acquire) {
        return false;
    }

    let base = DEFAULT_PROBE_BASE.load(Ordering::Acquire);
    let len = DEFAULT_PROBE_LEN.load(Ordering::Acquire);
    if len == 0 || fault < base || fault >= base.saturating_add(len) {
        return false;
    }

    let old = PAGE_PROTECTION_FLAGS(DEFAULT_PROBE_OLD_PROTECT.load(Ordering::Acquire) as u32);
    let mut ignored = PAGE_PROTECTION_FLAGS(0);
    if let Err(err) = unsafe { VirtualProtect(base as *mut c_void, len, old, &mut ignored) } {
        log::error!(
            "[VANILLA_HEAP_PROBE] hit but restore failed: access={} addr=0x{:08x} EIP=0x{:08x} err={:?}",
            probe_access_name(access_kind),
            fault,
            ctx.Eip,
            err,
        );
        return false;
    }

    DEFAULT_PROBE_ARMED.store(false, Ordering::Release);
    let hit = DEFAULT_PROBE_HITS.fetch_add(1, Ordering::AcqRel) + 1;
    log::warn!(
        "[VANILLA_HEAP_PROBE] HIT #{}: {} addr=0x{:08x} EIP=0x{:08x} EAX={:08x} EBX={:08x} ECX={:08x} EDX={:08x} ESI={:08x} EDI={:08x} EBP={:08x} ESP={:08x}; restored old_protect=0x{:x} and continued",
        hit,
        probe_access_name(access_kind),
        fault,
        ctx.Eip,
        ctx.Eax,
        ctx.Ebx,
        ctx.Ecx,
        ctx.Edx,
        ctx.Esi,
        ctx.Edi,
        ctx.Ebp,
        ctx.Esp,
        old.0,
    );
    true
}

fn probe_access_name(access_kind: usize) -> &'static str {
    match access_kind {
        0 => "read",
        1 => "write",
        8 => "execute",
        _ => "unknown",
    }
}

unsafe fn maybe_enable_default_tail_adoption(s: Snapshot) {
    if DEFAULT_TAIL_ENABLED.load(Ordering::Acquire) {
        return;
    }
    if s.base == 0 || s.capacity <= DEFAULT_TAIL_SKIP {
        log::warn!("[VANILLA_HEAP_ADOPT] skipped: Default heap tail is too small");
        return;
    }
    if s.bump_end > DEFAULT_TAIL_SKIP || s.high_water > DEFAULT_TAIL_SKIP {
        log::warn!(
            "[VANILLA_HEAP_ADOPT] skipped: Default heap high-water reaches tail (bump={}KB high={}KB skip={}MB)",
            s.bump_end / 1024,
            s.high_water / 1024,
            DEFAULT_TAIL_SKIP / super::vas::MB,
        );
        return;
    }
    let tail_start = s.base.saturating_add(DEFAULT_TAIL_SKIP);
    let tail_end = s.base.saturating_add(s.capacity);
    if (s.first_block >= tail_start && s.first_block < tail_end)
        || (s.last_block >= tail_start && s.last_block < tail_end)
    {
        log::warn!(
            "[VANILLA_HEAP_ADOPT] skipped: Default heap block list reaches tail first=0x{:08x} last=0x{:08x}",
            s.first_block,
            s.last_block,
        );
        return;
    }

    DEFAULT_TAIL_HEAP.store(s.heap, Ordering::Release);
    DEFAULT_TAIL_BASE.store(s.base, Ordering::Release);
    DEFAULT_TAIL_NEXT.store(tail_start, Ordering::Release);
    DEFAULT_TAIL_END.store(tail_end, Ordering::Release);
    DEFAULT_TAIL_CAPACITY.store(s.capacity, Ordering::Release);
    DEFAULT_TAIL_BUMP_END.store(s.bump_end, Ordering::Release);
    DEFAULT_TAIL_HIGH_WATER.store(s.high_water, Ordering::Release);
    DEFAULT_TAIL_LIVE_BYTES.store(s.live_bytes, Ordering::Release);
    DEFAULT_TAIL_BLOCK_COUNT.store(s.block_count, Ordering::Release);
    DEFAULT_TAIL_FIRST_BLOCK.store(s.first_block, Ordering::Release);
    DEFAULT_TAIL_LAST_BLOCK.store(s.last_block, Ordering::Release);
    DEFAULT_TAIL_FREE_COUNT.store(s.free_count, Ordering::Release);
    DEFAULT_TAIL_ENABLED.store(true, Ordering::Release);

    log::warn!(
        "[VANILLA_HEAP_ADOPT] enabled Default tail adoption: base=0x{:08x} tail=0x{:08x}..0x{:08x} usable={}MB skip={}MB",
        s.base,
        tail_start,
        tail_end,
        (tail_end - tail_start) / super::vas::MB,
        DEFAULT_TAIL_SKIP / super::vas::MB,
    );
}

pub fn try_adopt_default_tail_block(size: usize) -> *mut c_void {
    if size == 0 || !DEFAULT_TAIL_ENABLED.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    if !default_tail_contract_intact() {
        disable_default_tail_adoption("Default heap fields changed");
        return std::ptr::null_mut();
    }

    let size = align_up(size, PAGE_SIZE);
    loop {
        let next = DEFAULT_TAIL_NEXT.load(Ordering::Acquire);
        let end = DEFAULT_TAIL_END.load(Ordering::Acquire);
        let Some(new_next) = next.checked_add(size) else {
            disable_default_tail_adoption("Default tail address overflow");
            return std::ptr::null_mut();
        };
        if next == 0 || new_next > end {
            if !DEFAULT_TAIL_EXHAUSTED_LOGGED.swap(true, Ordering::AcqRel) {
                log::info!(
                    "[VANILLA_HEAP_ADOPT] Default tail exhausted: next=0x{:08x} end=0x{:08x} request={}MB",
                    next,
                    end,
                    size / super::vas::MB,
                );
            }
            return std::ptr::null_mut();
        }
        if DEFAULT_TAIL_NEXT
            .compare_exchange(next, new_next, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }

        let ptr = unsafe {
            VirtualAlloc(
                Some(next as *const c_void),
                size,
                windows::Win32::System::Memory::MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if ptr as usize == next {
            log::info!(
                "[VANILLA_HEAP_ADOPT] committed adopted block at 0x{:08x} ({}MB), next=0x{:08x}",
                next,
                size / super::vas::MB,
                new_next,
            );
            return ptr as *mut c_void;
        }

        disable_default_tail_adoption("VirtualAlloc(MEM_COMMIT) failed for Default tail");
        log::error!(
            "[VANILLA_HEAP_ADOPT] commit failed: addr=0x{:08x} size={}MB returned=0x{:08x} err={}",
            next,
            size / super::vas::MB,
            ptr as usize,
            std::io::Error::last_os_error(),
        );
        return std::ptr::null_mut();
    }
}

pub fn poll_default_tail_contract() {
    if !DEFAULT_TAIL_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let now = libpsycho::os::windows::winapi::get_tick_count() as usize;
    let last = DEFAULT_TAIL_LAST_POLL_MS.load(Ordering::Relaxed);
    if now.wrapping_sub(last) < DEFAULT_TAIL_POLL_MS as usize {
        return;
    }
    if DEFAULT_TAIL_LAST_POLL_MS
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    if !default_tail_contract_intact() {
        disable_default_tail_adoption("Default heap fields changed during poll");
    }
}

fn default_tail_contract_intact() -> bool {
    let heap = DEFAULT_TAIL_HEAP.load(Ordering::Acquire);
    if heap == 0 {
        return false;
    }

    let _lock = unsafe { lock_heap(heap) };
    let s = unsafe { Snapshot::read(heap) };
    let ok = s.base == DEFAULT_TAIL_BASE.load(Ordering::Acquire)
        && s.capacity == DEFAULT_TAIL_CAPACITY.load(Ordering::Acquire)
        && s.bump_end == DEFAULT_TAIL_BUMP_END.load(Ordering::Acquire)
        && s.high_water == DEFAULT_TAIL_HIGH_WATER.load(Ordering::Acquire)
        && s.live_bytes == DEFAULT_TAIL_LIVE_BYTES.load(Ordering::Acquire)
        && s.block_count == DEFAULT_TAIL_BLOCK_COUNT.load(Ordering::Acquire)
        && s.first_block == DEFAULT_TAIL_FIRST_BLOCK.load(Ordering::Acquire)
        && s.last_block == DEFAULT_TAIL_LAST_BLOCK.load(Ordering::Acquire)
        && s.free_count == DEFAULT_TAIL_FREE_COUNT.load(Ordering::Acquire);
    if !ok {
        log::error!(
            "[VANILLA_HEAP_ADOPT] contract changed: base 0x{:08x}->0x{:08x}, cap {}MB->{}MB, bump {}KB->{}KB, high {}KB->{}KB, live {}KB->{}KB, blocks {}->{}, free {}->{}, first 0x{:08x}->0x{:08x}, last 0x{:08x}->0x{:08x}",
            DEFAULT_TAIL_BASE.load(Ordering::Acquire),
            s.base,
            DEFAULT_TAIL_CAPACITY.load(Ordering::Acquire) / super::vas::MB,
            s.capacity / super::vas::MB,
            DEFAULT_TAIL_BUMP_END.load(Ordering::Acquire) / 1024,
            s.bump_end / 1024,
            DEFAULT_TAIL_HIGH_WATER.load(Ordering::Acquire) / 1024,
            s.high_water / 1024,
            DEFAULT_TAIL_LIVE_BYTES.load(Ordering::Acquire) / 1024,
            s.live_bytes / 1024,
            DEFAULT_TAIL_BLOCK_COUNT.load(Ordering::Acquire),
            s.block_count,
            DEFAULT_TAIL_FREE_COUNT.load(Ordering::Acquire),
            s.free_count,
            DEFAULT_TAIL_FIRST_BLOCK.load(Ordering::Acquire),
            s.first_block,
            DEFAULT_TAIL_LAST_BLOCK.load(Ordering::Acquire),
            s.last_block,
        );
    }
    ok
}

fn disable_default_tail_adoption(reason: &'static str) {
    DEFAULT_TAIL_ENABLED.store(false, Ordering::Release);
    if !DEFAULT_TAIL_DISABLED_LOGGED.swap(true, Ordering::AcqRel) {
        log::error!("[VANILLA_HEAP_ADOPT] disabled: {}", reason);
    }
}

unsafe fn reset_released_heap(heap: usize) {
    unsafe {
        write_usize(heap + CAPACITY_OFFSET, 0);
        write_usize(heap + INITIAL_COMMIT_OFFSET, 0);
        write_usize(heap + COMMITTED_LIMIT_OFFSET, 0);
        write_usize(heap + UNKNOWN_20_OFFSET, 0);
        write_usize(heap + BUMP_END_OFFSET, 0);
        write_usize(heap + HIGH_WATER_OFFSET, 0);
        write_usize(heap + LIVE_BYTES_OFFSET, 0);
        write_usize(heap + BASE_OFFSET, 0);
        write_usize(heap + BLOCK_COUNT_OFFSET, 0);
        write_usize(heap + FIRST_BLOCK_OFFSET, 0);
        write_usize(heap + LAST_BLOCK_OFFSET, 0);
        write_usize(heap + FREE_COUNT_OFFSET, 0);

        std::ptr::write_bytes(
            (heap + FREE_BUCKETS_OFFSET) as *mut u8,
            0,
            FREE_BUCKETS_BYTES,
        );
        std::ptr::write_bytes(
            (heap + LARGE_BUCKET_OFFSET) as *mut u8,
            0,
            LARGE_BUCKET_BYTES,
        );

        write_usize(heap + LAST_SMALL_BUCKET_PTR_OFFSET, heap + 0x203c);
        write_usize(heap + SEARCH_AUX_0_OFFSET, 0);
        write_usize(heap + SEARCH_AUX_1_OFFSET, 0);

        for i in 0..SEARCH_GROUP_COUNT {
            let group = heap + SEARCH_GROUPS_OFFSET + i * SEARCH_GROUP_STRIDE;
            write_usize(group, 0);
            write_usize(
                group + 4,
                heap + FREE_BUCKETS_OFFSET + i * SMALL_BUCKET_GROUP_BYTES,
            );
        }
    }
}

unsafe fn lock_heap(heap: usize) -> HeapLock {
    let cs = (heap + CRITICAL_SECTION_OFFSET) as *mut CRITICAL_SECTION;
    unsafe { EnterCriticalSection(cs) };
    HeapLock { cs }
}

unsafe fn read_usize(addr: usize) -> usize {
    unsafe { (addr as *const usize).read_volatile() }
}

unsafe fn write_usize(addr: usize, value: usize) {
    unsafe { (addr as *mut usize).write_volatile(value) };
}
