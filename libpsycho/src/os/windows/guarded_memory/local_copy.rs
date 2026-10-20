//! x86 leaf copy with a thread-stack SEH registration, like MinGW's __try1.
//!
//! No Rust code runs inside the protected instruction interval. The dispatcher
//! resumes the assembly cleanup directly; no Rust frame or destructor is
//! skipped. The registration is removed on both success and handled failure.
//! Unknown exceptions continue their normal search. There is no allocation,
//! callback, import, TLS allocation, global handler, or persistent state.

use std::{ffi::c_void, mem::offset_of};

use windows::{
    Win32::{
        Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_GUARD_PAGE, EXCEPTION_IN_PAGE_ERROR},
        System::Diagnostics::Debug::{CONTEXT, EXCEPTION_RECORD},
    },
    core::{Error, HRESULT},
};

use super::{WinapiError, WinapiResult};

#[repr(C)]
struct Frame {
    previous: *mut c_void,
    handler: *const c_void,
    copy_ip: u32,
    recovery_ip: u32,
    source: u32,
    end: u32,
}

// The stack registration prefix is the x86 MinGW/Win32 ABI. Keeping the
// assembly-only frame size explicit also makes the argument offsets auditable.
const _: () = assert!(size_of::<Frame>() == 24 && offset_of!(Frame, handler) == 4);

#[inline]
pub(super) fn read(address: usize, output: &mut [u8]) -> WinapiResult<()> {
    if address == 0 {
        return Err(WinapiError::InputNullPtr());
    }
    if output.is_empty() {
        return Err(WinapiError::ZeroSize());
    }
    if address.checked_add(output.len()).is_none() {
        return Err(WinapiError::IntegerOverflow("local memory source range"));
    }
    // SAFETY: Output is initialized, exclusively borrowed, and valid for the
    // full length. Source reads occur only in the assembly fault boundary,
    // never through a Rust reference. Range arithmetic cannot wrap. The leaf
    // handles overlap in memmove order and restores the x86 ABI on every return.
    let status = unsafe { copy(address, output.as_mut_ptr(), output.len()) };
    if status != 0 {
        return Err(WinapiError::WindowsCore(Error::from_hresult(
            HRESULT::from_nt(status as i32),
        )));
    }
    Ok(())
}

// MinGW's frame handler ABI is cdecl, not the __except filter-expression ABI.
// Dispositions are ExceptionContinueExecution=0, ExceptionContinueSearch=1.
unsafe extern "C" fn handler(
    record: *const EXCEPTION_RECORD,
    frame: *const Frame,
    context: *mut CONTEXT,
    _: *mut c_void,
) -> i32 {
    // SAFETY: The OS dispatcher supplies these records and the active stack
    // registration. No callback or allocation occurs in this handler.
    let (record, frame, context) = unsafe { (&*record, &*frame, &mut *context) };
    if record.ExceptionFlags != 0
        || !matches!(
            record.ExceptionCode,
            EXCEPTION_ACCESS_VIOLATION | EXCEPTION_IN_PAGE_ERROR | EXCEPTION_GUARD_PAGE
        )
        || record.NumberParameters < 2
        || record.ExceptionInformation[0] != 0 // Source reads only.
        || record.ExceptionAddress as u32 != frame.copy_ip
        || context.Eip != frame.copy_ip
        || context.Esp != frame as *const Frame as u32
        || record.ExceptionInformation[1] < frame.source as usize
        || record.ExceptionInformation[1] >= frame.end as usize
    {
        return 1;
    }
    context.Eax = record.ExceptionCode.0 as u32;
    context.Eip = frame.recovery_ip;
    // A backward overlapping copy can fault with DF set. Cleanup uses CLD;
    // clear it in the resumed context too, before any further instruction.
    context.EFlags &= !0x400;
    0
}

/// C ABI leaf. Only REP MOVSB may read source bytes. Source faults resume at
/// label 3 with the exception code in EAX; cleanup restores FS:[0], EDI, ESI,
/// ESP and DF. EBP/EBX are untouched. The handler never changes stack ownership.
#[unsafe(naked)]
unsafe extern "C" fn copy(_source: usize, _output: *mut u8, _length: usize) -> u32 {
    core::arch::naked_asm!(
        "push esi",
        "push edi",
        "sub esp, 24",
        "mov esi, [esp + 36]",
        "mov edi, [esp + 40]",
        "mov ecx, [esp + 44]",
        "mov [esp + {source}], esi",
        "lea eax, [esi + ecx]",
        "mov [esp + {end}], eax",
        "lea eax, [2f]",
        "mov [esp + {copy_ip}], eax",
        "lea eax, [3f]",
        "mov [esp + {recovery_ip}], eax",
        "lea eax, [{handler}]",
        "mov [esp + 4], eax",
        "mov eax, fs:[0]",
        "mov [esp], eax",
        // Windows x86 C ABI enters with DF clear. Reverse only when output
        // starts inside source, preserving memmove semantics for overlap.
        "cmp edi, esi",
        "jbe 4f",
        "cmp edi, [esp + {end}]",
        "jae 4f",
        "lea esi, [esi + ecx - 1]",
        "lea edi, [edi + ecx - 1]",
        "std",
        "4:",
        "mov fs:[0], esp",
        "2:",
        "rep movsb",
        "xor eax, eax",
        "3:",
        "cld",
        "mov edx, [esp]",
        "mov fs:[0], edx",
        "add esp, 24",
        "pop edi",
        "pop esi",
        "ret",
        source = const offset_of!(Frame, source),
        end = const offset_of!(Frame, end),
        copy_ip = const offset_of!(Frame, copy_ip),
        recovery_ip = const offset_of!(Frame, recovery_ip),
        handler = sym handler,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::windows::{
        guarded_memory::read_local_memory,
        winapi::{
            native_system_layout, virtual_query, virtual_release, virtual_reserve_commit,
            with_virtual_protect,
        },
    };

    struct Pages(*mut c_void);
    impl Drop for Pages {
        fn drop(&mut self) {
            unsafe { virtual_release(self.0) }.expect("release owned pages");
        }
    }

    fn thread_state() -> (usize, usize) {
        let (head, flags): (usize, usize);
        // Observe the real ABI state after success/fault, without introducing
        // a handler or changing the exception chain in the fixture.
        unsafe {
            core::arch::asm!(
                "mov {head:e}, fs:[0]",
                "pushfd",
                "pop {flags:e}",
                head = out(reg) head,
                flags = out(reg) flags,
            );
        }
        (head, flags & 0x400)
    }

    #[test]
    fn production_local_copy_preserves_bytes_overlap_and_thread_state() {
        let before = thread_state();
        let source: Vec<u8> = (0..8192).map(|index| index as u8).collect();
        for offset in [0, 1, 3, 4093] {
            for length in [1, 4, 8, 12, 16, 32, 4096] {
                let mut output = vec![0; length];
                read_local_memory(source.as_ptr() as usize + offset, &mut output)
                    .expect("copy owned source");
                assert_eq!(output, source[offset..offset + length]);
                assert_eq!(thread_state(), before);
            }
        }
        let mut bytes = [0, 1, 2, 3, 4, 5, 6, 7];
        read_local_memory(bytes.as_ptr() as usize, &mut bytes[2..]).expect("backward overlap");
        assert_eq!(bytes, [0, 1, 0, 1, 2, 3, 4, 5]);
        read_local_memory(bytes.as_ptr() as usize + 2, &mut bytes[..6]).expect("forward overlap");
        assert_eq!(bytes, [0, 1, 2, 3, 4, 5, 4, 5]);
        let address = bytes.as_ptr() as usize;
        read_local_memory(address, &mut bytes).expect("identical ranges");
        assert_eq!(bytes, [0, 1, 2, 3, 4, 5, 4, 5]);
        assert_eq!(thread_state(), before);
        assert!(read_local_memory(0, &mut bytes).is_err());
        assert!(read_local_memory(address, &mut []).is_err());
        assert!(read_local_memory(usize::MAX - 3, &mut bytes).is_err());
    }

    #[test]
    fn production_local_copy_contains_real_source_faults_on_each_thread() {
        let workers: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let size = native_system_layout().page_size as usize;
                    let pages = Pages(unsafe { virtual_reserve_commit(None, size * 2) });
                    assert!(!pages.0.is_null());
                    unsafe { pages.0.cast::<u8>().write_bytes(0x5a, size * 2) };
                    let edge = pages.0 as usize + size;
                    let before = thread_state();
                    let mut protection = virtual_query(pages.0).expect("owned mapping").protect;
                    protection.0 = 0x01;
                    for _ in 0..32 {
                        // Real forward-copy fault after a readable prefix. The output
                        // remains initialized; a partial result is never admitted.
                        unsafe {
                            with_virtual_protect(edge as *mut c_void, protection, size, || {
                                let mut output = [0; 32];
                                let error = read_local_memory(edge - 16, &mut output)
                                    .expect_err("real forward source fault");
                                assert!(matches!(error, WinapiError::WindowsCore(error)
                            if error.code() == HRESULT::from_nt(EXCEPTION_ACCESS_VIOLATION.0)));
                                assert_eq!(thread_state(), before);
                            })
                        }
                        .expect("scope inaccessible second page");
                        // A backward overlapping copy faults in the inaccessible first
                        // page. Its entire output still belongs to accessible page two.
                        unsafe {
                            with_virtual_protect(pages.0, protection, size, || {
                                let output =
                                    std::slice::from_raw_parts_mut((edge + 8) as *mut u8, 32);
                                assert!(read_local_memory(edge - 8, output).is_err());
                                assert_eq!(thread_state(), before);
                            })
                        }
                        .expect("scope inaccessible first page");
                        let mut output = [0; 16];
                        read_local_memory(pages.0 as usize, &mut output)
                            .expect("copy after restored fault");
                        assert_eq!(output, [0x5a; 16]);
                        assert_eq!(thread_state(), before);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("thread-local fault recovery");
        }
    }
}
