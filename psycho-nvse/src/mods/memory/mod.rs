mod crt_iat;
mod crt_inline;
mod gheap;

mod heap_replacer;
pub use crt_iat::*;
pub use crt_inline::*;
pub use heap_replacer::*;
use libmimalloc::{mi_collect, mi_option_set, mi_option_set_enabled};
use parking_lot::Once;

static CONFIG_MIMALLOC: Once = Once::new();

pub(super) fn configure_mimalloc() {
    CONFIG_MIMALLOC.call_once(|| unsafe {
        // Option 5: Enable decommit on purge (return memory to OS instead of just reset)
        mi_option_set_enabled(5, true);
        log::info!("[MIMALLOC] Enabled purge_decommits (option 5)");

        // Option 15: Set purge delay to 0 (immediate purging instead of 10ms delay)
        mi_option_set(15, 0);
        log::info!("[MIMALLOC] Set purge_delay to 0ms (option 15)");

        // Perform initial collection to establish baseline
        mi_collect(true);
        log::info!("[MIMALLOC] Performed initial aggressive collection");
    });
}
