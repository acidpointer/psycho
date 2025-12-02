/// Minimum size of instructions in bytes for relative jump
pub const JUMP_REL_MIN_SIZE: usize = 5;

/// Minimum size of instructions in bytes for absolute jump
pub const JUMP_ABS_MIN_SIZE: usize = 14;

#[cfg(target_arch = "x86_64")]
pub const MAX_JUMP_SIZE: usize = JUMP_ABS_MIN_SIZE;

#[cfg(target_arch = "x86")]
pub const MAX_JUMP_SIZE: usize = JUMP_REL_MIN_SIZE;

#[cfg(target_arch = "x86_64")]
pub const BITNESS: u32 = 64;
#[cfg(target_arch = "x86")]
pub const BITNESS: u32 = 32;


