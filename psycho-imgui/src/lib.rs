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

#[derive(Clone, Copy, Debug)]
#[repr(i32)]
pub enum Condition {
    Always = 1 << 0,
    Once = 1 << 1,
    FirstUseEver = 1 << 2,
    Appearing = 1 << 3,
}

impl Ui<'_> {
    pub fn set_next_window_size(&mut self, width: f32, height: f32, condition: Condition) {
        unsafe {
            ffi::psycho_imgui_set_next_window_size(width, height, condition as i32);
        }
    }

    pub fn set_next_window_pos(&mut self, x: f32, y: f32, condition: Condition) {
        unsafe {
            ffi::psycho_imgui_set_next_window_pos(x, y, condition as i32);
        }
    }

    pub fn window(&mut self, title: &CStr, open: Option<&mut bool>) -> Window {
        let visible = unsafe {
            ffi::psycho_imgui_begin_window(
                title.as_ptr(),
                open.map_or(std::ptr::null_mut(), |open| open as *mut bool),
            )
        };

        Window { visible }
    }

    pub fn child(&mut self, id: &CStr, width: f32, height: f32, border: bool) -> Child {
        let visible = unsafe { ffi::psycho_imgui_begin_child(id.as_ptr(), width, height, border) };
        Child { visible }
    }

    pub fn text(&mut self, text: &CStr) {
        unsafe { ffi::psycho_imgui_text_unformatted(text.as_ptr()) };
    }

    pub fn text_wrapped(&mut self, text: &CStr) {
        unsafe { ffi::psycho_imgui_text_wrapped(text.as_ptr()) };
    }

    pub fn text_colored(&mut self, rgba: [f32; 4], text: &CStr) {
        unsafe {
            ffi::psycho_imgui_text_colored(rgba[0], rgba[1], rgba[2], rgba[3], text.as_ptr())
        };
    }

    pub fn separator(&mut self) {
        unsafe { ffi::psycho_imgui_separator() };
    }

    pub fn separator_text(&mut self, label: &CStr) {
        unsafe { ffi::psycho_imgui_separator_text(label.as_ptr()) };
    }

    pub fn spacing(&mut self) {
        unsafe { ffi::psycho_imgui_spacing() };
    }

    pub fn checkbox(&mut self, label: &CStr, value: &mut bool) -> bool {
        unsafe { ffi::psycho_imgui_checkbox(label.as_ptr(), value as *mut bool) }
    }

    pub fn slider_float(&mut self, label: &CStr, value: &mut f32, min: f32, max: f32) -> bool {
        unsafe { ffi::psycho_imgui_slider_float(label.as_ptr(), value as *mut f32, min, max) }
    }

    pub fn slider_int(&mut self, label: &CStr, value: &mut i32, min: i32, max: i32) -> bool {
        unsafe { ffi::psycho_imgui_slider_int(label.as_ptr(), value as *mut i32, min, max) }
    }

    pub fn selectable(&mut self, label: &CStr, selected: bool) -> bool {
        unsafe { ffi::psycho_imgui_selectable(label.as_ptr(), selected) }
    }

    pub fn button(&mut self, label: &CStr) -> bool {
        unsafe { ffi::psycho_imgui_button(label.as_ptr()) }
    }

    pub fn button_colored(
        &mut self,
        label: &CStr,
        color: [f32; 4],
        hovered: [f32; 4],
        active: [f32; 4],
    ) -> bool {
        unsafe {
            ffi::psycho_imgui_button_colored(
                label.as_ptr(),
                color[0],
                color[1],
                color[2],
                color[3],
                hovered[0],
                hovered[1],
                hovered[2],
                hovered[3],
                active[0],
                active[1],
                active[2],
                active[3],
            )
        }
    }

    pub fn progress_bar(&mut self, fraction: f32, width: f32, height: f32, overlay: &CStr) {
        unsafe { ffi::psycho_imgui_progress_bar(fraction, width, height, overlay.as_ptr()) };
    }

    pub fn plot_lines(
        &mut self,
        label: &CStr,
        values: &[f32],
        scale_min: f32,
        scale_max: f32,
        width: f32,
        height: f32,
    ) {
        unsafe {
            ffi::psycho_imgui_plot_lines(
                label.as_ptr(),
                values.as_ptr(),
                values.len() as i32,
                scale_min,
                scale_max,
                width,
                height,
            )
        };
    }

    pub fn push_item_width(&mut self, width: f32) -> ItemWidth {
        unsafe { ffi::psycho_imgui_push_item_width(width) };
        ItemWidth {
            _context: PhantomData,
        }
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

#[must_use]
pub struct Child {
    visible: bool,
}

impl Child {
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        unsafe { ffi::psycho_imgui_end_child() };
    }
}

#[must_use]
pub struct ItemWidth {
    _context: PhantomData<*mut ()>,
}

impl Drop for ItemWidth {
    fn drop(&mut self) {
        unsafe { ffi::psycho_imgui_pop_item_width() };
    }
}

/// Forward a Win32 window message to Dear ImGui.
///
/// # Safety
/// `hwnd`, `msg`, `wparam`, and `lparam` must be the live message packet passed
/// to the game's window procedure.
pub unsafe fn wndproc(hwnd: *mut c_void, msg: u32, wparam: usize, lparam: isize) -> isize {
    unsafe { ffi::psycho_imgui_wndproc(hwnd, msg, wparam, lparam) }
}

pub fn queue_mouse_wheel_delta(vertical: i32, horizontal: i32) {
    unsafe { ffi::psycho_imgui_queue_mouse_wheel_delta(vertical, horizontal) };
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
        pub fn psycho_imgui_queue_mouse_wheel_delta(vertical: i32, horizontal: i32);
        pub fn psycho_imgui_set_next_window_size(width: f32, height: f32, condition: i32);
        pub fn psycho_imgui_set_next_window_pos(x: f32, y: f32, condition: i32);
        pub fn psycho_imgui_begin_window(title: *const c_char, open: *mut bool) -> bool;
        pub fn psycho_imgui_end_window();
        pub fn psycho_imgui_begin_child(
            id: *const c_char,
            width: f32,
            height: f32,
            border: bool,
        ) -> bool;
        pub fn psycho_imgui_end_child();
        pub fn psycho_imgui_text_unformatted(text: *const c_char);
        pub fn psycho_imgui_text_wrapped(text: *const c_char);
        pub fn psycho_imgui_text_colored(r: f32, g: f32, b: f32, a: f32, text: *const c_char);
        pub fn psycho_imgui_separator();
        pub fn psycho_imgui_separator_text(label: *const c_char);
        pub fn psycho_imgui_spacing();
        pub fn psycho_imgui_checkbox(label: *const c_char, value: *mut bool) -> bool;
        pub fn psycho_imgui_slider_float(
            label: *const c_char,
            value: *mut f32,
            min: f32,
            max: f32,
        ) -> bool;
        pub fn psycho_imgui_slider_int(
            label: *const c_char,
            value: *mut i32,
            min: i32,
            max: i32,
        ) -> bool;
        pub fn psycho_imgui_selectable(label: *const c_char, selected: bool) -> bool;
        pub fn psycho_imgui_button(label: *const c_char) -> bool;
        pub fn psycho_imgui_button_colored(
            label: *const c_char,
            r: f32,
            g: f32,
            b: f32,
            a: f32,
            hovered_r: f32,
            hovered_g: f32,
            hovered_b: f32,
            hovered_a: f32,
            active_r: f32,
            active_g: f32,
            active_b: f32,
            active_a: f32,
        ) -> bool;
        pub fn psycho_imgui_progress_bar(
            fraction: f32,
            width: f32,
            height: f32,
            overlay: *const c_char,
        );
        pub fn psycho_imgui_plot_lines(
            label: *const c_char,
            values: *const f32,
            count: i32,
            scale_min: f32,
            scale_max: f32,
            width: f32,
            height: f32,
        );
        pub fn psycho_imgui_push_item_width(width: f32);
        pub fn psycho_imgui_pop_item_width();
        pub fn psycho_imgui_same_line();
    }
}
