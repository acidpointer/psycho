//! Exercise the production admission and rejection bridge with real OS pages.
//!
//! Byte buffers expose the audited access ranges; they are not native plane
//! objects or a replacement clipping implementation. No provider is fabricated.
//! The supplied game report remains the native failure evidence.

use super::*;
use libpsycho::os::windows::winapi::{
    native_system_layout, virtual_make_noaccess, virtual_query, virtual_release,
    virtual_reserve_commit, with_virtual_protect,
};

struct Pages {
    base: *mut c_void,
    page_size: usize,
}

impl Pages {
    fn new() -> Self {
        let page_size = native_system_layout().page_size as usize;
        // SAFETY: Own the complete reservation until Drop, without creating
        // native objects or references to its storage.
        let base = unsafe { virtual_reserve_commit(None, page_size * 2) };
        assert!(!base.is_null());
        let pages = Self { base, page_size };
        // SAFETY: The second page belongs to this live reservation.
        unsafe { virtual_make_noaccess(pages.unreadable() as *mut c_void, page_size) }
            .expect("protect the owned second page");
        pages
    }

    fn unreadable(&self) -> usize {
        self.base as usize + self.page_size
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: All guarded reads have ended; this is the reservation base.
        unsafe { virtual_release(self.base) }.expect("release the owned pages");
    }
}

#[test]
fn admission_requires_writable_cache_for_source_and_selected_link() {
    let pages = Pages::new();
    let address = pages.base as usize;
    let mut protection = virtual_query(pages.base).expect("query owned page").protect;
    protection.0 = 0x02; // PAGE_READONLY: readable bytes cannot receive native caches.
    // SAFETY: The complete first page belongs to this reservation. Restore its
    // protection before assertions; no native plane or provider is fabricated.
    let (readable, source_result, link_results) = unsafe {
        with_virtual_protect(pages.base, protection, pages.page_size, || {
            let mut snapshot = [0; PLANE_SIZE];
            let readable = read_current_process_memory(address, &mut snapshot).is_ok();
            let source_result = validate_planes(address);
            let link_results = std::array::from_fn::<_, LINK_COUNT, _>(|index| {
                let mut source = [0u8; PLANE_SIZE];
                let offset = LINK_OFFSET + index * 4;
                source[offset..offset + 4].copy_from_slice(&(address as u32).to_le_bytes());
                validate_planes(source.as_ptr() as usize)
            });
            (readable, source_result, link_results)
        })
    }
    .expect("scope read-only storage");
    assert!(readable, "the defect concerns readable storage");
    assert_eq!(
        source_result,
        Err(Rejection {
            address,
            link: None
        })
    );
    for (index, result) in link_results.into_iter().enumerate() {
        assert_eq!(
            result,
            Err(Rejection {
                address,
                link: Some(index)
            })
        );
    }
    // A fresh invocation must observe the restored writable mapping.
    assert_eq!(validate_planes(address), Ok(()));
}

#[test]
fn cache_writability_covers_each_region_and_only_the_native_write_span() {
    let pages = Pages::new();
    let boundary = pages.unreadable();
    let mut protection = virtual_query(pages.base).expect("query owned page").protect;
    protection.0 = 0x02; // The second page is readable but cannot receive caches.
    // SAFETY: The second page is owned and remains reserved through this test.
    // Observe the production admission while the region boundary is present.
    let results = unsafe {
        with_virtual_protect(boundary as *mut c_void, protection, pages.page_size, || {
            [0xE6usize, 0xE5, 0xA8, 0x44, 0x43].map(|distance| {
                let address = boundary - distance;
                let mut snapshot = [0; PLANE_SIZE];
                assert!(read_current_process_memory(address, &mut snapshot).is_ok());
                (address, validate_planes(address))
            })
        })
    }
    .expect("scope cache-region boundary");
    for (index, (address, result)) in results.into_iter().enumerate() {
        assert_eq!(
            result,
            if index == 0 {
                Ok(())
            } else {
                Err(Rejection {
                    address,
                    link: None,
                })
            },
        );
    }

    // A read-only header is permitted when every actual cache write is in the
    // following writable page. This also exercises two readable regions.
    let mut writable = protection;
    writable.0 = 0x04;
    unsafe {
        with_virtual_protect(boundary as *mut c_void, writable, pages.page_size, || {
            with_virtual_protect(pages.base, protection, pages.page_size, || {
                assert_eq!(validate_planes(boundary - 0x44), Ok(()));
            })
            .expect("scope read-only header");
        })
    }
    .expect("scope writable cache");

    // Unselected read-only targets remain irrelevant to the clipping input.
    unsafe {
        with_virtual_protect(pages.base, protection, pages.page_size, || {
            let mut source = [0u8; PLANE_SIZE];
            let source_address = source.as_ptr() as usize;
            source[LINK_OFFSET..LINK_OFFSET + 4]
                .copy_from_slice(&(source_address as u32).to_le_bytes());
            source[LINK_OFFSET + 4..LINK_OFFSET + 8]
                .copy_from_slice(&(pages.base as u32).to_le_bytes());
            assert_eq!(validate_planes(source_address), Ok(()));
        })
    }
    .expect("scope unused read-only link");
}

#[test]
fn complete_plane_range_uses_guarded_reads_at_page_and_address_boundaries() {
    let pages = Pages::new();
    let mut snapshot = [0; PLANE_SIZE];
    let exact = pages.unreadable() - PLANE_SIZE;
    assert!(copy_plane(exact, &mut snapshot));
    assert!(!copy_plane(exact + 1, &mut snapshot));
    assert!(!copy_plane(pages.unreadable(), &mut snapshot));
    assert!(!copy_plane(0, &mut snapshot));
    assert!(!copy_plane(usize::MAX - PLANE_SIZE + 2, &mut snapshot));
    assert!(!copy_plane(usize::MAX, &mut snapshot));
}

#[test]
fn production_admission_follows_native_link_selection() {
    let pages = Pages::new();
    let readable = pages.base as usize;
    let unreadable = pages.unreadable();
    // C35980 and C47D3A..C47DBE select one non-null slot in order 0, 2, 1, 3.
    // Unused links must not suppress admission, and an unreadable selected link
    // must not fall back to a lower-priority readable one.
    for (links, rejected_slot) in [
        ([readable, unreadable, unreadable, unreadable], None),
        ([0, unreadable, readable, unreadable], None),
        ([0, readable, 0, unreadable], None),
        ([0, 0, 0, readable], None),
        ([unreadable, readable, readable, readable], Some(0)),
        ([0, readable, unreadable, readable], Some(2)),
        ([0, unreadable, 0, readable], Some(1)),
        ([0, 0, 0, unreadable], Some(3)),
    ] {
        let mut source = [0u8; PLANE_SIZE];
        for (index, target) in links.into_iter().enumerate() {
            let offset = LINK_OFFSET + index * 4;
            source[offset..offset + 4].copy_from_slice(&(target as u32).to_le_bytes());
        }
        let expected = match rejected_slot {
            Some(index) => Err(Rejection {
                address: unreadable,
                link: Some(index),
            }),
            None => Ok(()),
        };
        assert_eq!(validate_planes(source.as_ptr() as usize), expected);
    }
}

#[test]
fn production_bridges_reject_unreadable_sources_and_links_without_a_provider() {
    struct RestoreAdmission {
        admitted: bool,
        reported: bool,
    }
    impl Drop for RestoreAdmission {
        fn drop(&mut self) {
            ADMITTED.store(self.admitted, Ordering::Release);
            REJECTION_REPORTED.store(self.reported, Ordering::Relaxed);
        }
    }

    let pages = Pages::new();
    let _restore = RestoreAdmission {
        admitted: ADMITTED.swap(true, Ordering::AcqRel),
        reported: REJECTION_REPORTED.swap(false, Ordering::Relaxed),
    };
    // An unreadable context detects accidental output access on rejection.
    // The unpublished native predecessors are deliberately NULL: forwarding
    // any rejected input would fail instead of silently passing a mock.
    let context = pages.unreadable() as *mut c_void;
    let reject = |source: usize, expected: Rejection| {
        assert_eq!(validate_planes(source), Err(expected));
        for site in &CALLS {
            set_last_error(0x12345678);
            // SAFETY: Production admission must reject before using either
            // the context or unpublished provider. No native object is claimed.
            unsafe { (site.detour)(context, source as *mut c_void) };
            assert_eq!(get_last_error_code(), 0x12345678);
        }
    };
    for source in [
        0,
        pages.unreadable(),
        pages.unreadable() - PLANE_SIZE + 1,
        usize::MAX - 2,
    ] {
        reject(
            source,
            Rejection {
                address: source,
                link: None,
            },
        );
    }

    let mut source = [0u8; PLANE_SIZE];
    // This checks readable storage and native null-link absence only; it is
    // not a claim that a zero byte buffer is a valid native plane.
    assert_eq!(validate_planes(source.as_ptr() as usize), Ok(()));
    for index in 0..LINK_COUNT {
        for target in [
            pages.unreadable(),
            pages.unreadable() - PLANE_SIZE + 1,
            usize::MAX - 2,
        ] {
            let offset = LINK_OFFSET + index * 4;
            source[offset..offset + 4].copy_from_slice(&(target as u32).to_le_bytes());
            let before = source;
            reject(
                source.as_ptr() as usize,
                Rejection {
                    address: target,
                    link: Some(index),
                },
            );
            assert_eq!(source, before, "rejection must not rewrite a link");
            source[offset..offset + 4].fill(0);
        }
    }

    for raw_protection in [0x02, 0x104] {
        // PAGE_READONLY and PAGE_READWRITE | PAGE_GUARD.
        let mut protection = virtual_query(pages.base).expect("query owned page").protect;
        protection.0 = raw_protection;
        // SAFETY: Change only our owned page. Every bridge must reject before
        // forwarding to its unpublished provider or modifying the context.
        unsafe {
            with_virtual_protect(pages.base, protection, pages.page_size, || {
                reject(
                    pages.base as usize,
                    Rejection {
                        address: pages.base as usize,
                        link: None,
                    },
                );
                for index in 0..LINK_COUNT {
                    let offset = LINK_OFFSET + index * 4;
                    source[offset..offset + 4].copy_from_slice(&(pages.base as u32).to_le_bytes());
                    let before = source;
                    reject(
                        source.as_ptr() as usize,
                        Rejection {
                            address: pages.base as usize,
                            link: Some(index),
                        },
                    );
                    assert_eq!(source, before, "rejection preserves source links");
                    source[offset..offset + 4].fill(0);
                }
                assert_eq!(
                    virtual_query(pages.base)
                        .expect("query rejected mapping")
                        .protect
                        .0,
                    raw_protection,
                    "admission must not consume the guard bit or change protection"
                );
            })
        }
        .expect("scope nonwritable native cache");
    }
}
