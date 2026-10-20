//! Guarded byte admission shared by owner-specific native list guards.
//!
//! Copies require the requested mapping capability and use libpsycho's local
//! fault-contained reader. A small mapping cache belongs to one uninterrupted
//! owner lifetime; it never pins allocations, proves identity, or survives a
//! provider callback. Embedded-head traversal compares links only and assigns
//! no payload ownership or recovery policy. Work is linear, with constant
//! storage and no arbitrary length cap.
//! Failures retain the original query/copy evidence without a diagnostic retry.

use std::{ffi::c_void, fmt};

use libpsycho::os::windows::{
    guarded_memory::read_local_memory,
    winapi::{MemoryBasicInformation, WinapiError, virtual_query},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Mapping capability required by the consuming operation.
pub(super) enum Access {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Classification of the operation that actually failed admission.
pub(super) enum FailureKind {
    Null,
    Overflow,
    Query,
    Uncommitted,
    Guarded,
    NoAccess,
    NotWritable,
    MalformedRegion,
    Copy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Region {
    base: usize,
    allocation_base: usize,
    size: usize,
    state: u32,
    protection: u32,
    kind: u32,
}

impl From<&MemoryBasicInformation> for Region {
    fn from(info: &MemoryBasicInformation) -> Self {
        Self {
            base: info.base_address as usize,
            allocation_base: info.allocation_base as usize,
            size: info.region_size,
            state: info.state,
            protection: info.protect.0,
            kind: info.r#type,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorCode {
    Win32(u32),
    HResult(i32),
    Other,
}

impl From<WinapiError> for ErrorCode {
    fn from(error: WinapiError) -> Self {
        match error {
            WinapiError::VirtualQuery(code) => Self::Win32(code),
            WinapiError::WindowsCore(error) => Self::HResult(error.code().0),
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Original range/query/copy evidence, without a later diagnostic retry.
pub(super) struct MemoryFailure {
    pub kind: FailureKind,
    pub address: usize,
    pub length: usize,
    pub failed_at: usize,
    region: Option<Region>,
    error: Option<ErrorCode>,
}

impl fmt::Display for MemoryFailure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{:?} address=0x{:08X} length={} failed_at=0x{:08X}",
            self.kind, self.address, self.length, self.failed_at
        )?;
        if let Some(region) = self.region {
            write!(
                out,
                " last_query_base=0x{:08X} allocation_base=0x{:08X} region_size={} state=0x{:X} protect=0x{:X} type=0x{:X}",
                region.base,
                region.allocation_base,
                region.size,
                region.state,
                region.protection,
                region.kind
            )?;
        }
        if let Some(error) = self.error {
            match error {
                ErrorCode::Win32(code) => write!(out, " win32_error={code}")?,
                ErrorCode::HResult(code) => write!(out, " hresult=0x{:08X}", code as u32)?,
                ErrorCode::Other => write!(out, " error=Other")?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct CachedRegion {
    start: usize,
    end: usize,
    access: Access,
    region: Region,
}

impl CachedRegion {
    fn contains(self, address: usize, access: Access) -> bool {
        self.access == access && address >= self.start && address < self.end
    }
}

/// One uninterrupted walk's mapping cache; never shared or retained globally.
/// Four entries cover the alternating node/entry/form mappings without a
/// per-item OS query. Eviction affects cost only, never admission or capacity.
#[derive(Default)]
pub(super) struct RegionReader {
    current: Option<CachedRegion>,
    previous: [Option<CachedRegion>; 3],
    region: Option<Region>,
}

impl RegionReader {
    /// Retain predicates that require a span to fit inside one queried region.
    /// Ordinary structural copies may span adjacent accessible regions instead.
    pub fn within_single_region(
        &mut self,
        address: usize,
        length: usize,
        access: Access,
    ) -> Result<bool, MemoryFailure> {
        self.range(address, length, access)?;
        Ok(self.region.is_some_and(|region| {
            address >= region.base
                && address.checked_add(length).is_some_and(|end| {
                    region
                        .base
                        .checked_add(region.size)
                        .is_some_and(|limit| end <= limit)
                })
        }))
    }

    /// Admit the entire checked span without dereferencing its contents.
    /// The cached capability remains valid only under the owner's stable lifetime.
    pub fn range(
        &mut self,
        address: usize,
        length: usize,
        access: Access,
    ) -> Result<(), MemoryFailure> {
        let failure = |kind, failed_at, region, error| MemoryFailure {
            kind,
            address,
            length,
            failed_at,
            region,
            error,
        };
        let end = address
            .checked_add(length)
            .ok_or_else(|| failure(FailureKind::Overflow, address, None, None))?;
        if address == 0 {
            return Err(failure(FailureKind::Null, address, None, None));
        }
        let mut current = address;
        while current < end {
            if let Some(cached) = self
                .current
                .filter(|cached| cached.contains(current, access))
            {
                self.region = Some(cached.region);
                current = end.min(cached.end);
                continue;
            }
            if let Some(index) = self
                .previous
                .iter()
                .position(|cached| cached.is_some_and(|cached| cached.contains(current, access)))
            {
                let promoted = self.previous[index];
                self.previous.copy_within(0..index, 1);
                self.previous[0] = self.current;
                self.current = promoted;
                continue;
            }
            let info = virtual_query(current as *mut c_void)
                .map_err(|error| failure(FailureKind::Query, current, None, Some(error.into())))?;
            let region = Some(Region::from(&info));
            let start = info.base_address as usize;
            let region_end = start
                .checked_add(info.region_size)
                .ok_or_else(|| failure(FailureKind::Overflow, current, region, None))?;
            let kind = if !info.is_committed() {
                Some(FailureKind::Uncommitted)
            // Win32 PAGE_GUARD and PAGE_NOACCESS, kept as raw diagnostic flags.
            } else if info.protect.0 & 0x100 != 0 {
                Some(FailureKind::Guarded)
            } else if info.protect.0 & 0xff == 0x01 || !info.is_accessible() {
                Some(FailureKind::NoAccess)
            } else if access == Access::Write && !info.is_writable() {
                Some(FailureKind::NotWritable)
            } else if current < start || current >= region_end {
                Some(FailureKind::MalformedRegion)
            } else {
                None
            };
            if let Some(kind) = kind {
                return Err(failure(kind, current, region, None));
            }
            if self.current.is_some() {
                self.previous.rotate_right(1);
                self.previous[0] = self.current;
            }
            self.current = Some(CachedRegion {
                start,
                end: region_end,
                access,
                region: Region::from(&info),
            });
            self.region = region;
            current = end.min(region_end);
        }
        Ok(())
    }

    /// Copy the complete admitted span through the guarded process reader.
    /// Success is a byte snapshot, not allocation identity or a lifetime pin.
    pub fn copy<const N: usize>(
        &mut self,
        address: usize,
        access: Access,
    ) -> Result<[u8; N], MemoryFailure> {
        self.range(address, N, access)?;
        let mut bytes = [0; N];
        read_local_memory(address, &mut bytes).map_err(|error| MemoryFailure {
            kind: FailureKind::Copy,
            address,
            length: N,
            failed_at: address,
            region: self.region,
            error: Some(error.into()),
        })?;
        Ok(bytes)
    }

    /// Copy the native eight-byte payload/next image without following payloads.
    pub fn node(&mut self, address: usize, access: Access) -> Result<(u32, usize), MemoryFailure> {
        let bytes = self.copy::<8>(address, access)?;
        Ok((
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Spine rejection; payload ownership and recovery remain with the caller.
pub(super) enum ChainFailure {
    Memory(MemoryFailure),
    HeadAlias,
    Cycle,
    Overflow,
}

/// Admit an embedded head and successors without reading borrowed payloads.
/// The native owner must keep storage stable until its own operation finishes.
pub(super) fn embedded_chain(head: usize, access: Access) -> Result<usize, ChainFailure> {
    let mut reader = RegionReader::default();
    let mut current = head;
    let mut checkpoint = head;
    let mut power = 1usize;
    let mut distance = 0usize;
    let mut count = 0usize;
    loop {
        let (_, next) = reader.node(current, access).map_err(ChainFailure::Memory)?;
        count = count.checked_add(1).ok_or(ChainFailure::Overflow)?;
        if next == 0 {
            return Ok(count);
        }
        if next == head {
            return Err(ChainFailure::HeadAlias);
        }
        distance = distance.checked_add(1).ok_or(ChainFailure::Overflow)?;
        if next == checkpoint {
            return Err(ChainFailure::Cycle);
        }
        if distance == power {
            checkpoint = next;
            power = power.saturating_mul(2);
            distance = 0;
        }
        current = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpsycho::os::windows::winapi::{
        native_system_layout, virtual_release, virtual_reserve_commit, with_virtual_protect,
    };

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Node {
        data: u32,
        next: u32,
    }

    #[test]
    fn production_child_admission_preserves_null_and_duplicate_borrowed_payloads() {
        for count in [1, 2, 32768] {
            let mut nodes = vec![Node { data: 7, next: 0 }; count];
            for index in 0..count - 1 {
                nodes[index].next = &nodes[index + 1] as *const Node as u32;
            }
            // Native removal permits a NULL head payload with successors and
            // compares the other borrowed values without dereferencing them.
            nodes[0].data = 0;
            let before = nodes.clone();
            assert_eq!(
                embedded_chain(nodes.as_ptr() as usize, Access::Write),
                Ok(count)
            );
            assert_eq!(nodes, before);
            for back in [0, count / 2, count - 1] {
                nodes[count - 1].next = &nodes[back] as *const Node as u32;
                let before = nodes.clone();
                assert_eq!(
                    embedded_chain(nodes.as_ptr() as usize, Access::Write),
                    Err(if back == 0 {
                        ChainFailure::HeadAlias
                    } else {
                        ChainFailure::Cycle
                    })
                );
                assert_eq!(nodes, before);
            }
        }
    }

    struct Pages(*mut c_void);
    impl Drop for Pages {
        fn drop(&mut self) {
            // SAFETY: Tests own this reservation until every copied view ends.
            unsafe { virtual_release(self.0) }.expect("release test pages");
        }
    }

    #[test]
    fn production_reader_retains_exact_mapping_and_cross_region_failure() {
        let size = native_system_layout().page_size as usize;
        // SAFETY: Tests exclusively own both complete pages.
        let pages = Pages(unsafe { virtual_reserve_commit(None, size * 2) });
        assert!(!pages.0.is_null());
        let edge = pages.0 as usize + size;
        let node = edge - 4;
        // SAFETY: Both words are initialized while both pages are writable.
        unsafe { (node as *mut Node).write_unaligned(Node { data: 3, next: 0 }) };
        let mut protection = virtual_query(edge as *mut c_void)
            .expect("query second page")
            .protect;
        for (flags, kind) in [
            (0x02, FailureKind::NotWritable),
            (0x01, FailureKind::NoAccess),
            (0x104, FailureKind::Guarded),
        ] {
            protection.0 = flags;
            // SAFETY: The existing wrapper restores the owned page protection.
            unsafe {
                with_virtual_protect(edge as *mut c_void, protection, size, || {
                    let error = RegionReader::default()
                        .copy::<8>(node, Access::Write)
                        .expect_err("reject unusable successor");
                    assert_eq!(error.kind, kind);
                    assert_eq!(error.address, node);
                    assert_eq!(error.failed_at, edge);
                    assert_eq!(error.length, 8);
                    assert_eq!(
                        error.region.expect("actual failed query region").protection,
                        flags
                    );
                    assert_eq!(error.error, None);
                    if flags == 0x02 {
                        assert!(
                            RegionReader::default()
                                .copy::<8>(node, Access::Read)
                                .is_ok()
                        );
                    }
                })
            }
            .expect("scope page protection");
        }
        let error = RegionReader::default()
            .range(usize::MAX - 3, 8, Access::Write)
            .expect_err("reject overflow before OS access");
        assert_eq!(error.kind, FailureKind::Overflow);
        assert_eq!(error.region, None);
        assert_eq!(error.error, None);
    }

    #[test]
    fn production_reader_reports_real_copy_failure_after_cached_admission() {
        let size = native_system_layout().page_size as usize;
        // SAFETY: The test exclusively owns one initialized committed page.
        let pages = Pages(unsafe { virtual_reserve_commit(None, size) });
        assert!(!pages.0.is_null());
        unsafe { (pages.0 as *mut Node).write(Node { data: 1, next: 0 }) };
        let mut reader = RegionReader::default();
        assert!(reader.copy::<8>(pages.0 as usize, Access::Write).is_ok());
        let mut protection = virtual_query(pages.0).expect("query page").protect;
        protection.0 = 0x01;
        // SAFETY: Only this owned page changes; the failed real OS copy must
        // retain its original error, with no subsequent query or retry.
        unsafe {
            with_virtual_protect(pages.0, protection, size, || {
                let failure = reader
                    .copy::<8>(pages.0 as usize, Access::Write)
                    .expect_err("actual inaccessible process read");
                assert_eq!(failure.kind, FailureKind::Copy);
                assert!(matches!(failure.error, Some(ErrorCode::HResult(_))));
                assert_eq!(failure.address, pages.0 as usize);
                assert_eq!(failure.length, 8);
            })
        }
        .expect("scope inaccessible page");
    }

    #[test]
    fn production_read_admission_preserves_guard_page_policy() {
        let size = native_system_layout().page_size as usize;
        let pages = Pages(unsafe { virtual_reserve_commit(None, size) });
        assert!(!pages.0.is_null());
        let mut protection = virtual_query(pages.0).expect("query page").protect;
        protection.0 = 0x104;
        // SAFETY: The fixture owns the page; the wrapper restores protection.
        // Admission must reject it without consuming its one-shot guard bit.
        unsafe {
            with_virtual_protect(pages.0, protection, size, || {
                assert!(
                    RegionReader::default()
                        .copy::<8>(pages.0 as usize, Access::Read)
                        .is_err()
                );
                assert_eq!(
                    virtual_query(pages.0)
                        .expect("query rejected guard")
                        .protect
                        .0,
                    0x104
                );
            })
        }
        .expect("scope guard page");
    }

    #[test]
    fn production_mapping_reuse_preserves_fresh_bytes_and_eviction() {
        let size = native_system_layout().page_size as usize;
        let pages: Vec<_> = (0..7)
            .map(|_| Pages(unsafe { virtual_reserve_commit(None, size) }))
            .collect();
        let mut reader = RegionReader::default();
        for round in 0u32..3 {
            for (index, page) in pages.iter().enumerate() {
                assert!(!page.0.is_null());
                let value = round * 7 + index as u32;
                // SAFETY: Exclusively owned, initialized committed storage.
                // Mapping reuse must never cache these mutable payload bytes.
                unsafe { page.0.cast::<u32>().write(value) };
                assert_eq!(
                    reader.copy::<4>(page.0 as usize, Access::Read),
                    Ok(value.to_le_bytes())
                );
            }
        }
    }
}
