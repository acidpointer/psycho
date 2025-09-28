#[cfg(target_arch = "x86_64")]
pub const MAX_JUMP_SIZE: usize = 14;

#[cfg(target_arch = "x86")]
pub const MAX_JUMP_SIZE: usize = 5;

#[cfg(target_arch = "x86_64")]
pub const BITNESS: u32 = 64;
#[cfg(target_arch = "x86")]
pub const BITNESS: u32 = 32;
