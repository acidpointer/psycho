//! Offline execution of the reported clear boundary, using verified native code.
//!
//! The 110-byte fixture is the unmodified body at native 0x00470470 from the
//! supported executable identified in the owning LowProcess contract. Only the
//! empty and invalid-first-successor paths run here; neither reaches the native
//! node destructor CALL, which therefore needs no relocation or substitute.

use super::*;
use libpsycho::os::windows::winapi::{
    flush_instructions_cache, get_last_error_code, set_last_error, virtual_alloc_rwx,
    virtual_release,
};

type NativeClear = unsafe extern "thiscall" fn(*mut ListNode);

struct NativeImage(*mut c_void);

impl NativeImage {
    fn new() -> Self {
        let bytes = include_bytes!("../lowprocess_clear_native.bin");
        let base = virtual_alloc_rwx(bytes.len()).expect("allocate native clear image");
        // SAFETY: This test exclusively owns the complete writable reservation.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), base.cast(), bytes.len()) };
        flush_instructions_cache(base, bytes.len()).expect("publish native clear code");
        Self(base)
    }

    fn clear(&self) -> NativeClear {
        // SAFETY: The verified body takes only a writable head in ECX, returns
        // with plain RET, and stays mapped until every call has returned.
        unsafe { std::mem::transmute(self.0) }
    }
}

impl Drop for NativeImage {
    fn drop(&mut self) {
        // SAFETY: The test owns the reservation and all calls have returned.
        unsafe { virtual_release(self.0) }.expect("release native clear image");
    }
}

#[test]
fn reported_scalar_successor_is_contained_before_native_clear() {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            CLEAR_ADMITTED.store(false, Ordering::Release);
            PREVIOUS_CLEAR.store(0, Ordering::Release);
        }
    }
    let native = NativeImage::new();
    let _restore = Restore;
    PREVIOUS_CLEAR.store(native.clear() as usize, Ordering::Release);
    CLEAR_ADMITTED.store(true, Ordering::Release);
    let mut borrowed_payload = 0x1234_5678u32;
    for payload in [
        ptr::null_mut(),
        0x0Dusize as *mut c_void,
        ptr::addr_of_mut!(borrowed_payload).cast(),
    ] {
        let mut head = ListNode {
            data: payload,
            next: 5usize as *mut ListNode,
        };
        set_last_error(0x1357_2468);
        // SAFETY: The test owns the writable head. The actual production
        // detour must sever the reported scalar before executing native code.
        // No native node destructor or replacement free is needed or invoked.
        unsafe { checked_generic_location_clear(&mut head) };
        assert!(head.data.is_null());
        assert!(head.next.is_null());
        assert_eq!(get_last_error_code(), 0x1357_2468);
        assert_eq!(borrowed_payload, 0x1234_5678);
        // Native process destruction clears this embedded head again later.
        // The repaired representation must survive that same native operation.
        unsafe { native.clear()(&mut head) };
        assert!(head.data.is_null());
        assert!(head.next.is_null());
    }

    // An unadmitted rollback survivor must chain the retained provider without
    // repair. The native empty-chain path clears its opaque payload directly.
    CLEAR_ADMITTED.store(false, Ordering::Release);
    let mut head = ListNode {
        data: ptr::addr_of_mut!(borrowed_payload).cast(),
        next: ptr::null_mut(),
    };
    unsafe { checked_generic_location_clear(&mut head) };
    assert!(head.data.is_null());
    assert!(head.next.is_null());
    assert_eq!(borrowed_payload, 0x1234_5678);
}

#[test]
fn clear_preflight_retains_long_prefix_and_borrowed_payloads() {
    // More than the live/save sanitizer budget. Teardown must preserve every
    // unique native-owned successor, rather than leak a healthy suffix at 256.
    let mut nodes: Vec<ListNode> = (0..1024)
        .map(|_| ListNode {
            data: 0x0Dusize as *mut c_void,
            next: ptr::null_mut(),
        })
        .collect();
    for i in 0..nodes.len() - 1 {
        nodes[i].next = ptr::addr_of_mut!(nodes[i + 1]);
    }
    // SAFETY: This test owns the head and all successors without concurrency.
    unsafe {
        list_cleanup_guard::prepare_owned_clear(nodes.as_mut_ptr().cast(), "lowprocess-test")
    };
    for i in 0..nodes.len() - 1 {
        let expected_next = ptr::addr_of_mut!(nodes[i + 1]);
        assert_eq!(nodes[i].next, expected_next);
        assert_eq!(nodes[i].data as usize, 0x0D);
    }
    nodes[1023].next = 5usize as *mut ListNode;
    unsafe {
        list_cleanup_guard::prepare_owned_clear(nodes.as_mut_ptr().cast(), "lowprocess-test")
    };
    assert!(nodes[1023].next.is_null());
    for i in 0..nodes.len() - 1 {
        let expected_next = ptr::addr_of_mut!(nodes[i + 1]);
        assert_eq!(nodes[i].next, expected_next);
        assert_eq!(nodes[i].data as usize, 0x0D);
    }
}
