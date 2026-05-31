//! Fixed-size UTF-16 path buffer.
//!
//! The loader runs before any mod infrastructure exists, so it avoids heap
//! allocation entirely. `WidePath` is intentionally small and copyable.

use core::cmp::Ordering;

const MAX_PATH_CHARS: usize = 1024;

#[derive(Clone, Copy)]
pub struct WidePath {
    len: usize,
    buf: [u16; MAX_PATH_CHARS],
}

impl WidePath {
    pub const fn new() -> Self {
        Self {
            len: 0,
            buf: [0; MAX_PATH_CHARS],
        }
    }

    pub fn append_component_ascii(&mut self, component: &str) -> bool {
        self.push_separator_if_needed() && self.push_ascii(component)
    }

    pub fn append_component_wide(&mut self, component: &[u16]) -> bool {
        self.push_separator_if_needed() && self.push_wide(component)
    }

    pub fn as_mut_ptr(&mut self) -> *mut u16 {
        self.buf.as_mut_ptr()
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.buf[..self.len]
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn parent_directory(mut self) -> Option<Self> {
        for index in (0..self.len).rev() {
            if is_separator(self.buf[index]) {
                self.len = index;
                return Some(self);
            }
        }

        None
    }

    pub fn set_len_from_win32(&mut self, len: usize) -> bool {
        if len == 0 || len >= self.buf.len() {
            return false;
        }

        self.len = len;
        true
    }

    pub fn with_nul(&self) -> Option<Self> {
        let mut path = *self;
        if path.push(0) { Some(path) } else { None }
    }

    fn last(&self) -> u16 {
        if self.len == 0 {
            0
        } else {
            self.buf[self.len - 1]
        }
    }

    fn push(&mut self, ch: u16) -> bool {
        if self.len >= self.buf.len() {
            return false;
        }

        self.buf[self.len] = ch;
        self.len += 1;
        true
    }

    fn push_ascii(&mut self, text: &str) -> bool {
        for byte in text.bytes() {
            if !self.push(u16::from(byte)) {
                return false;
            }
        }

        true
    }

    fn push_separator_if_needed(&mut self) -> bool {
        if self.len == 0 || is_separator(self.last()) {
            true
        } else {
            self.push(b'\\' as u16)
        }
    }

    fn push_wide(&mut self, text: &[u16]) -> bool {
        for &ch in text {
            if !self.push(ch) {
                return false;
            }
        }

        true
    }
}

pub fn compare_case_insensitive(left: &WidePath, right: &WidePath) -> Ordering {
    for index in 0..left.len.min(right.len) {
        let a = ascii_lower(left.buf[index]);
        let b = ascii_lower(right.buf[index]);
        match a.cmp(&b) {
            Ordering::Equal => {}
            order => return order,
        }
    }

    left.len.cmp(&right.len)
}

pub fn nul_trimmed(data: &[u16]) -> &[u16] {
    let mut len = 0usize;
    while len < data.len() && data[len] != 0 {
        len += 1;
    }

    &data[..len]
}

fn ascii_lower(ch: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&ch) {
        ch + 32
    } else {
        ch
    }
}

fn is_separator(ch: u16) -> bool {
    ch == b'\\' as u16 || ch == b'/' as u16
}
