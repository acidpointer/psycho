//! Execute the production accessor detour and its retained native trampoline.
//!
//! The fixture is the complete, unmodified ten-byte native 0x0079C080 body
//! from the supported executable (identity and bytes in the owning contract).
//! It only returns the opaque global-head address; it never dereferences it,
//! so relocation and game initialization are unnecessary. Publication events
//! execute the same Rust operations used by the audited lifecycle bridges.
//! This qualifies the accessor and gate, not native save-load orchestration.

use super::*;
use libpsycho::os::windows::winapi::{
    flush_instructions_cache, virtual_alloc_rwx, virtual_release,
};

struct NativeAccessor(*mut c_void);

impl NativeAccessor {
    fn new() -> Self {
        let bytes = include_bytes!("../found_radio_native.bin");
        let memory = virtual_alloc_rwx(bytes.len()).expect("allocate native radio accessor");
        // SAFETY: This test exclusively owns the writable allocation.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), memory.cast(), bytes.len()) };
        flush_instructions_cache(memory, bytes.len()).expect("publish native radio accessor");
        Self(memory)
    }

    fn function(&self) -> FoundReferencesFn {
        // SAFETY: The actual native body takes no arguments and returns a
        // borrowed pointer in EAX with plain RET. Its mapping outlives calls.
        unsafe { std::mem::transmute(self.0) }
    }
}

impl Drop for NativeAccessor {
    fn drop(&mut self) {
        // SAFETY: The only test using the static hook disables it before this
        // allocation is released. No later test invokes its retained pointer.
        unsafe { virtual_release(self.0) }.expect("release native radio accessor");
    }
}

#[test]
fn native_accessor_withholds_unresolved_ids_and_resumes_original_publication() {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            ADMITTED.store(false, Ordering::Release);
            publish_resolved();
            if ACCESSOR.is_enabled() {
                ACCESSOR.disable().expect("restore native radio accessor");
            }
        }
    }

    let native = NativeAccessor::new();
    let entry = native.function();
    // This is the unchanged native behavior: publication is unconditional,
    // even though the native loader can still be storing integer FormIDs.
    let original_head = unsafe { entry() };
    assert!(!original_head.is_null());
    unsafe {
        ACCESSOR
            .init("native_radio_publication_test", native.0, found_references)
            .expect("capture real native radio accessor");
    }
    let _restore = Restore;
    ACCESSOR
        .enable()
        .expect("install production radio accessor");

    // Before transaction admission, even a rollback survivor forwards through
    // its retained native trampoline without imposing a publication policy.
    begin_unresolved();
    assert_eq!(unsafe { entry() }, original_head);

    ADMITTED.store(true, Ordering::Release);
    set_last_error(0x1357_2468);
    assert!(unsafe { entry() }.is_null());
    assert_eq!(get_last_error_code(), 0x1357_2468);
    // Deserialization return and load rejection have no publication event.
    // A later query and another attempted load must still see unavailable.
    assert!(unsafe { entry() }.is_null());
    begin_unresolved();
    assert!(unsafe { entry() }.is_null());

    // The actual native accessor resumes unchanged after complete fixup.
    publish_resolved();
    assert_eq!(unsafe { entry() }, original_head);
    assert_eq!(get_last_error_code(), 0x1357_2468);

    // Native reset withholds the view while clearing it and republishes only
    // after return. The test never dereferences or fabricates the engine list.
    begin_unresolved();
    assert!(unsafe { entry() }.is_null());
    publish_resolved();
    assert_eq!(unsafe { entry() }, original_head);
}
