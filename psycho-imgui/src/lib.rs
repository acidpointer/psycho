//! Dear ImGui wrapper for Psycho D3D overlays.
//!
//! This crate owns the vendored Dear ImGui sources and backend bindings. Game
//! modules should use this API instead of calling ImGui C++ backends directly.

use std::{
    ffi::{CStr, c_char, c_void},
    marker::PhantomData,
    ptr::NonNull,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid null HWND")]
    NullWindow,
    #[error("invalid null Direct3D9 device")]
    NullDevice,
    #[error("Dear ImGui Direct3D9 backend initialization failed")]
    InitFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default)]
pub struct IoState {
    pub want_capture_mouse: bool,
    pub want_capture_keyboard: bool,
}

#[derive(Debug)]
pub struct Dx9Context {
    _not_send_sync: PhantomData<*mut ()>,
}

// Safety: this owns Dear ImGui backend state for a D3D9 device, but all actual
// backend calls must still run on the render thread through `Dx9Context`.
unsafe impl Send for Dx9Context {}

impl Dx9Context {
    /// Initialize Dear ImGui with the Win32 platform backend and D3D9 renderer backend.
    ///
    /// # Safety
    ///
    /// `hwnd` must be the live game window and `device` must be a live
    /// `IDirect3DDevice9*`. All methods on this context must run on the render
    /// thread that owns the D3D device.
    pub unsafe fn new(hwnd: *mut c_void, device: *mut c_void) -> Result<Self> {
        NonNull::new(hwnd).ok_or(Error::NullWindow)?;
        NonNull::new(device).ok_or(Error::NullDevice)?;

        if unsafe { ffi::psycho_imgui_init_dx9(hwnd, device) } {
            Ok(Self {
                _not_send_sync: PhantomData,
            })
        } else {
            Err(Error::InitFailed)
        }
    }

    pub fn invalidate_device_objects(&mut self) {
        unsafe { ffi::psycho_imgui_invalidate_device_objects() };
    }

    pub fn create_device_objects(&mut self) -> bool {
        unsafe { ffi::psycho_imgui_create_device_objects() }
    }

    pub fn new_frame(&mut self, menu_open: bool) -> Ui<'_> {
        unsafe { ffi::psycho_imgui_new_frame(menu_open) };
        Ui {
            _context: PhantomData,
        }
    }

    pub fn render(&mut self) {
        unsafe { ffi::psycho_imgui_render() };
    }

    pub fn io_state(&self) -> IoState {
        unsafe { ffi::psycho_imgui_io_state().into() }
    }
}

impl Drop for Dx9Context {
    fn drop(&mut self) {
        unsafe { ffi::psycho_imgui_shutdown() };
    }
}

pub struct Ui<'a> {
    _context: PhantomData<&'a mut Dx9Context>,
}

impl Ui<'_> {
    pub fn window(&mut self, title: &CStr, open: Option<&mut bool>) -> Window {
        let visible = unsafe {
            ffi::psycho_imgui_begin_window(
                title.as_ptr(),
                open.map_or(std::ptr::null_mut(), |open| open as *mut bool),
            )
        };

        Window { visible }
    }

    pub fn text(&mut self, text: &CStr) {
        unsafe { ffi::psycho_imgui_text_unformatted(text.as_ptr()) };
    }

    pub fn separator(&mut self) {
        unsafe { ffi::psycho_imgui_separator() };
    }

    pub fn checkbox(&mut self, label: &CStr, value: &mut bool) -> bool {
        unsafe { ffi::psycho_imgui_checkbox(label.as_ptr(), value as *mut bool) }
    }

    pub fn slider_float(&mut self, label: &CStr, value: &mut f32, min: f32, max: f32) -> bool {
        unsafe { ffi::psycho_imgui_slider_float(label.as_ptr(), value as *mut f32, min, max) }
    }

    pub fn button(&mut self, label: &CStr) -> bool {
        unsafe { ffi::psycho_imgui_button(label.as_ptr()) }
    }

    pub fn same_line(&mut self) {
        unsafe { ffi::psycho_imgui_same_line() };
    }
}

#[must_use]
pub struct Window {
    visible: bool,
}

impl Window {
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        unsafe { ffi::psycho_imgui_end_window() };
    }
}

pub fn wndproc(hwnd: *mut c_void, msg: u32, wparam: usize, lparam: isize) -> isize {
    unsafe { ffi::psycho_imgui_wndproc(hwnd, msg, wparam, lparam) }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawIoState {
    want_capture_mouse: bool,
    want_capture_keyboard: bool,
}

impl From<RawIoState> for IoState {
    fn from(value: RawIoState) -> Self {
        Self {
            want_capture_mouse: value.want_capture_mouse,
            want_capture_keyboard: value.want_capture_keyboard,
        }
    }
}

mod ffi {
    use super::{RawIoState, c_char, c_void};

    unsafe extern "C" {
        pub fn psycho_imgui_init_dx9(hwnd: *mut c_void, device: *mut c_void) -> bool;
        pub fn psycho_imgui_shutdown();
        pub fn psycho_imgui_invalidate_device_objects();
        pub fn psycho_imgui_create_device_objects() -> bool;
        pub fn psycho_imgui_new_frame(menu_open: bool);
        pub fn psycho_imgui_render();
        pub fn psycho_imgui_wndproc(
            hwnd: *mut c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
        ) -> isize;
        pub fn psycho_imgui_io_state() -> RawIoState;
        pub fn psycho_imgui_begin_window(title: *const c_char, open: *mut bool) -> bool;
        pub fn psycho_imgui_end_window();
        pub fn psycho_imgui_text_unformatted(text: *const c_char);
        pub fn psycho_imgui_separator();
        pub fn psycho_imgui_checkbox(label: *const c_char, value: *mut bool) -> bool;
        pub fn psycho_imgui_slider_float(
            label: *const c_char,
            value: *mut f32,
            min: f32,
            max: f32,
        ) -> bool;
        pub fn psycho_imgui_button(label: *const c_char) -> bool;
        pub fn psycho_imgui_same_line();
    }
}
