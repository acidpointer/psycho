//! Fixed-size UTF-16 path buffer.
//!
//! The loader runs before any mod infrastructure exists, so it avoids heap
//! allocation entirely. `WidePath` is copyable so the loader can keep path
//! ownership explicit while supporting Windows extended-length paths.

const MAX_PATH_CHARS: usize = 32_768;
const MAX_LEGACY_PATH_CHARS: usize = 260;

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

    /// Long paths need the extended namespace prefix for legacy Win32 APIs.
    /// Short paths retain their original spelling for Wine compatibility.
    pub fn with_extended_prefix_if_needed(&self) -> Option<Self> {
        if self.len < MAX_LEGACY_PATH_CHARS || self.has_extended_prefix() {
            return Some(*self);
        }

        let mut path = Self::new();
        if self.is_unc_path() {
            if !path.push_ascii("\\\\?\\UNC\\") || !path.push_wide(&self.buf[2..self.len]) {
                return None;
            }
        } else if !path.push_ascii("\\\\?\\") || !path.push_wide(self.as_slice()) {
            return None;
        }
        Some(path)
    }

    fn last(&self) -> u16 {
        if self.len == 0 {
            0
        } else {
            self.buf[self.len - 1]
        }
    }

    fn has_extended_prefix(&self) -> bool {
        self.len >= 4
            && self.buf[0] == b'\\' as u16
            && self.buf[1] == b'\\' as u16
            && self.buf[2] == b'?' as u16
            && self.buf[3] == b'\\' as u16
    }

    fn is_unc_path(&self) -> bool {
        self.len >= 2 && self.buf[0] == b'\\' as u16 && self.buf[1] == b'\\' as u16
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

pub fn nul_trimmed(data: &[u16]) -> &[u16] {
    let mut len = 0usize;
    while len < data.len() && data[len] != 0 {
        len += 1;
    }

    &data[..len]
}

fn is_separator(ch: u16) -> bool {
    ch == b'\\' as u16 || ch == b'/' as u16
}
