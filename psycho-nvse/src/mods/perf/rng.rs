//! Modern RNG replacement for Fallout: New Vegas.
//!
//! The game uses a 20+ year old Mersenne Twister with a 2.5KB state array.
//! This replaces it with SmallRng (WyRand) -- tiny state, extremely fast,
//! and statistically better for game use cases.

use std::cell::RefCell;
use std::sync::LazyLock;

use libc::c_void;
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;
use rand::rngs::SmallRng;
use rand::{Rng, RngExt};

/// RNG function address (Fallout: New Vegas).
const RNG_ADDRESS: usize = 0x00AA5230;

/// RNG function signature: `uint __thiscall rng(void* this, uint range)`.
type RngFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> u32;

static RNG_HOOK: LazyLock<InlineHookContainer<RngFn>> =
    LazyLock::new(InlineHookContainer::new);

thread_local! {
    static RNG: RefCell<SmallRng> = RefCell::new(rand::make_rng());
}

unsafe extern "thiscall" fn hook_rng(_this: *mut c_void, param_1: u32) -> u32 {
    if param_1 == 0 {
        return 0;
    }

    RNG.with(|rng_cell| {
        let mut rng = rng_cell.borrow_mut();

        if param_1 == 0xFFFFFFFF {
            rng.next_u32()
        } else if param_1 == 0x7FFF {
            rng.next_u32() & 0x7FFF
        } else {
            rng.random_range(0..param_1)
        }
    })
}

pub fn install_rng_hook() -> anyhow::Result<()> {
    RNG_HOOK.init("rng", RNG_ADDRESS as *mut c_void, hook_rng)?;
    RNG_HOOK.enable()?;
    Ok(())
}
