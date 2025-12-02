///! Various FFI helper functions

/// Reads bytes from memory safely.
/// 
/// # What's a Pointer?
/// 
/// A pointer is just a number that represents a location in memory.
/// Think of memory like a huge array of bytes, and a pointer is an index into that array.
/// 
/// This function copies bytes from that location into a Vec (safe Rust storage).
#[cfg(not(target_os = "windows"))]
unsafe fn read_bytes(addr: *mut c_void, size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    
    // Copy 'size' bytes from 'addr' into our Vec
    unsafe { ptr::copy_nonoverlapping(
        addr as *const u8,    // Source (cast to byte pointer)
        bytes.as_mut_ptr(),   // Destination (our Vec)
        size,                 // How many bytes
    ) };
    
    bytes
}
