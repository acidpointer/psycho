//! Exercise the production math admission boundary against verified code bytes.
//!
//! Inputs are the supported executable extracts and complete installed math
//! leaves plus their untouched native tails. Only the mapping address changes;
//! preparation, volatile comparison and rejection diagnostics are production
//! methods. No engine traversal or math result is modeled by these tests.

use core::ffi::c_void;

use libpsycho::os::windows::winapi::{FreeType, virtual_alloc_rwx, virtual_free};

use super::{NORMALIZE, NativeRange, VECTOR_LENGTH, VECTOR_SQRT};

const CASES: [(&NativeRange, &[u8], &[u8]); 3] = [
    (
        &NORMALIZE,
        include_bytes!("lighting_signatures/normalize.bin"),
        include_bytes!("lighting_signatures/normalize_inlined.bin"),
    ),
    (
        &VECTOR_LENGTH,
        include_bytes!("lighting_signatures/vector_length.bin"),
        include_bytes!("lighting_signatures/vector_length_inlined.bin"),
    ),
    (
        &VECTOR_SQRT,
        include_bytes!("lighting_signatures/vector_sqrt.bin"),
        include_bytes!("lighting_signatures/vector_sqrt_inlined.bin"),
    ),
];

struct CodeMapping {
    address: *mut c_void,
    len: usize,
}

impl CodeMapping {
    fn new(bytes: &[u8]) -> Self {
        let mapping = Self {
            address: virtual_alloc_rwx(bytes.len()).expect("allocate admission code mapping"),
            len: bytes.len(),
        };
        mapping.write(bytes);
        mapping
    }

    fn write(&self, bytes: &[u8]) {
        assert_eq!(bytes.len(), self.len);
        // SAFETY: this test exclusively owns the writable mapping for its full
        // length. It never executes it; all admission reads have returned.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.address.cast(), bytes.len());
        }
    }

    fn range(&self, contract: &NativeRange) -> NativeRange {
        contract.relocated(self.address as usize)
    }
}

impl Drop for CodeMapping {
    fn drop(&mut self) {
        // SAFETY: the checker retains no pointer into the exclusively owned
        // allocation, and all checker calls have completed before release.
        unsafe { virtual_free(self.address, FreeType::Release) }
            .expect("release admission mapping");
    }
}

#[test]
fn prepared_math_admits_verified_post_load_replacement() {
    for (contract, native, inlined) in CASES {
        let mapping = CodeMapping::new(native);
        let range = mapping.range(contract);
        range.prepare(&[]).expect("prepare verified native math");
        // SAFETY: preparation validated this owned mapping, which remains
        // present and quiescent through every comparison below.
        assert!(unsafe { range.matches() });
        mapping.write(inlined);
        assert!(
            unsafe { range.matches() },
            "verified post-load math rejected"
        );
        range.diagnose().expect("supported math snapshot");
        mapping.write(native);
        assert!(unsafe { range.matches() });
    }
}

#[test]
fn preparation_admits_already_installed_verified_math() {
    for (contract, _, inlined) in CASES {
        let mapping = CodeMapping::new(inlined);
        let range = mapping.range(contract);
        range.prepare(&[]).expect("prepare verified installed math");
        // SAFETY: the mapping outlives this read and has no concurrent writer.
        assert!(unsafe { range.matches() });
        range.diagnose().expect("supported installed snapshot");
    }
}

#[test]
fn every_unknown_math_byte_including_native_tail_rejects() {
    for (contract, native, inlined) in CASES {
        let mapping = CodeMapping::new(native);
        let range = mapping.range(contract);
        range.prepare(&[]).expect("prepare verified native math");
        for accepted in [native, inlined] {
            for offset in 0..accepted.len() {
                let mut unknown = accepted.to_vec();
                unknown[offset] ^= 0xFF;
                mapping.write(&unknown);
                // SAFETY: each write has completed, and this owned mapping
                // stays readable for the complete guarded range.
                assert!(
                    !unsafe { range.matches() },
                    "unknown byte admitted at {offset}"
                );
                assert!(range.diagnose().is_err());
                let unprepared = mapping.range(contract);
                assert!(unprepared.prepare(&[]).is_err());
            }
        }
    }
}
