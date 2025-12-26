use std::{collections::VecDeque, sync::LazyLock, thread};
use parking_lot::Mutex;

static LOG_MESSAGES: LazyLock<Mutex<VecDeque<String>>> = LazyLock::new(|| Mutex::new(VecDeque::new()));

pub fn init_logger() {
    thread::spawn(|| {
        loop {
            if let Some(msg) = &LOG_MESSAGES.lock().pop_back() {

            }

        }
    });
}
