//! Native headless ImGui frames for offline behavioral tests.
//!
//! Uses the shipped widget implementations and real input events. The guard
//! serializes ImGui's process-global context. No DX9 backend or game is needed.

use std::{
    ffi::CStr,
    marker::PhantomData,
    sync::{Mutex, MutexGuard},
};

use crate::Ui;

static CONTEXT: Mutex<()> = Mutex::new(());

/// Owns one serialized native ImGui test context.
pub struct TestContext {
    _guard: MutexGuard<'static, ()>,
}

impl Default for TestContext {
    fn default() -> Self {
        let guard = CONTEXT.lock().unwrap_or_else(|error| error.into_inner());
        // The guard gives exclusive ownership of the native global context.
        unsafe { psycho_imgui_test_create() };
        Self { _guard: guard }
    }
}

impl TestContext {
    /// Starts an ordinary ImGui frame at the supplied display dimensions.
    pub fn new_frame(&mut self, width: f32, height: f32) -> Ui<'_> {
        unsafe { psycho_imgui_test_begin(width, height) };
        Ui {
            _context: PhantomData,
        }
    }

    /// Finishes layout and draw generation without a platform renderer.
    pub fn render(&mut self) {
        unsafe { psycho_imgui_test_end() };
    }

    /// Queues a real mouse position/button event for the following frame.
    pub fn pointer(&mut self, x: f32, y: f32, down: bool) {
        unsafe { psycho_imgui_test_pointer(x, y, down) };
    }

    /// Queues UTF-8 text for the focused native input widget.
    pub fn text(&mut self, text: &CStr) {
        unsafe { psycho_imgui_test_text(text.as_ptr()) };
    }

    /// Returns the center of a visible button from the completed frame.
    pub fn button_center(&self, label: &CStr) -> Option<[f32; 2]> {
        let mut position = [0.0; 2];
        unsafe { psycho_imgui_test_item(label.as_ptr(), &mut position[0], &mut position[1]) }
            .then_some(position)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        unsafe { psycho_imgui_test_destroy() };
    }
}

unsafe extern "C" {
    fn psycho_imgui_test_create();
    fn psycho_imgui_test_destroy();
    fn psycho_imgui_test_begin(width: f32, height: f32);
    fn psycho_imgui_test_end();
    fn psycho_imgui_test_pointer(x: f32, y: f32, down: bool);
    fn psycho_imgui_test_text(text: *const std::ffi::c_char);
    fn psycho_imgui_test_item(label: *const std::ffi::c_char, x: *mut f32, y: *mut f32) -> bool;
}
