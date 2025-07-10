/// Size of a JMP instruction (E9 + 4 bytes offset)
pub const JMP_SIZE: usize = 5;

/// Maximum expected VTable size for safety bounds
/// Reasonable upper bound for vtable size
pub const MAX_VTABLE_SIZE: usize = 1024;


/// Absolute jump size: JMP [RIP+0] + 8-byte address = 14 bytes
pub const ABS_JMP_SIZE: usize = 14;

/// Minimum patch size is now 14 bytes for absolute jumps
pub const MIN_PATCH_SIZE: usize = ABS_JMP_SIZE;