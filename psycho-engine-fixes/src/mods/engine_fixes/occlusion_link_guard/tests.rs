//! Exercise the production admission and rejection bridge with real OS pages.
//!
//! Byte buffers expose the audited read ranges; they are not native plane
//! objects or a replacement clipping implementation. No provider is fabricated.
//! The supplied game report remains the native failure evidence.

use super::*;
use libpsycho::os::windows::winapi::{
    native_system_layout, virtual_make_noaccess, virtual_release, virtual_reserve_commit,
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
}
