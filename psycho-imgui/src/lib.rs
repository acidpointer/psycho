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
    /// The D3D render-target window handle was null.
    #[error("invalid null HWND")]
    NullWindow,
    /// The top-level foreground/input window handle was null.
    #[error("invalid null foreground HWND")]
    NullForegroundWindow,
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
    /// Initialize Dear ImGui when one window owns both rendering and foreground input.
    ///
    /// # Safety
    ///
    /// `hwnd` must be the live game window and `device` must be a live
    /// `IDirect3DDevice9*`. All methods on this context must run on the render
    /// thread that owns the D3D device.
    pub unsafe fn new(hwnd: *mut c_void, device: *mut c_void) -> Result<Self> {
        unsafe { Self::new_with_foreground_window(hwnd, hwnd, device) }
    }

    /// Initialize Dear ImGui with separate render-target and foreground windows.
    ///
    /// Use this for a child D3D render window whose top-level parent owns
    /// activation and keyboard input. Dear ImGui sizes and positions the overlay
    /// in `render_hwnd` client coordinates, while per-frame input polling is
    /// enabled only while `foreground_hwnd` owns the foreground.
    ///
    /// # Safety
    ///
    /// Both HWNDs must remain live for the context lifetime and belong to the
    /// same application window tree. `device` must be the live
    /// `IDirect3DDevice9*` rendering into `render_hwnd`. All methods on this
    /// context must run on the render thread that owns the D3D device.
    pub unsafe fn new_with_foreground_window(
        render_hwnd: *mut c_void,
        foreground_hwnd: *mut c_void,
        device: *mut c_void,
    ) -> Result<Self> {
        NonNull::new(render_hwnd).ok_or(Error::NullWindow)?;
        NonNull::new(foreground_hwnd).ok_or(Error::NullForegroundWindow)?;
        NonNull::new(device).ok_or(Error::NullDevice)?;

        if unsafe { ffi::psycho_imgui_init_dx9(render_hwnd, foreground_hwnd, device) } {
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

/// Presentation data for the compact diagnostics timeline component.
pub struct TelemetryChart<'a> {
    pub values: &'a [f32],
    pub scale_min: f32,
    pub scale_max: f32,
    pub width: f32,
    pub height: f32,
    pub warning_threshold: f32,
    pub critical_threshold: f32,
    pub danger_below: bool,
    /// Seconds represented by one sample. Values at or below zero select a
    /// frame-index axis and frame-relative hover labels.
    pub sample_interval_seconds: f32,
    /// Draw independent impulses from zero instead of connecting samples.
    pub impulse_from_zero: bool,
    /// Color connected segments from the warning and critical thresholds.
    /// When false, preserve the caller-provided line and fill colors.
    pub color_by_threshold: bool,
    pub line_color: [f32; 4],
    pub fill_color: [f32; 4],
    pub warning_label: &'a CStr,
    pub critical_label: &'a CStr,
    pub value_suffix: &'a CStr,
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

    #[allow(clippy::too_many_arguments)]
    pub fn set_next_window_centered(
        &mut self,
        width_ratio: f32,
        height_ratio: f32,
        min_width: f32,
        min_height: f32,
        preferred_max_width: f32,
        preferred_max_height: f32,
        condition: Condition,
    ) {
        unsafe {
            ffi::psycho_imgui_set_next_window_centered(
                width_ratio,
                height_ratio,
                min_width,
                min_height,
                preferred_max_width,
                preferred_max_height,
                condition as i32,
            );
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

    /// Begin a fixed card that cannot expose or respond to scrollbars.
    pub fn child_static(&mut self, id: &CStr, width: f32, height: f32, border: bool) -> Child {
        let visible =
            unsafe { ffi::psycho_imgui_begin_static_child(id.as_ptr(), width, height, border) };
        Child { visible }
    }

    pub fn child_horizontal(&mut self, id: &CStr, width: f32, height: f32, border: bool) -> Child {
        let visible =
            unsafe { ffi::psycho_imgui_begin_child_horizontal(id.as_ptr(), width, height, border) };
        Child { visible }
    }

    /// Paint the current child as a low-contrast gradient card.
    ///
    /// Call immediately after beginning the child so later widgets are drawn
    /// over the background.
    pub fn panel_background(&mut self, accent: [f32; 4]) {
        unsafe {
            ffi::psycho_imgui_panel_background(accent[0], accent[1], accent[2], accent[3]);
        }
    }

    pub fn tab_bar(&mut self, id: &CStr) -> TabBar {
        let visible = unsafe { ffi::psycho_imgui_begin_tab_bar(id.as_ptr()) };
        TabBar { visible }
    }

    pub fn tab_item(&mut self, label: &CStr) -> TabItem {
        let visible = unsafe { ffi::psycho_imgui_begin_tab_item(label.as_ptr()) };
        TabItem { visible }
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

    pub fn label_value(&mut self, label: &CStr, value: &CStr, rgba: [f32; 4]) {
        unsafe {
            ffi::psycho_imgui_label_value(
                label.as_ptr(),
                value.as_ptr(),
                rgba[0],
                rgba[1],
                rgba[2],
                rgba[3],
            )
        };
    }

    /// Show delayed, wrapped help when the most recently drawn item is hovered.
    pub fn hover_help(&mut self, text: &CStr) {
        unsafe { ffi::psycho_imgui_hover_help(text.as_ptr()) };
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

    pub fn radio_button(&mut self, label: &CStr, active: bool) -> bool {
        unsafe { ffi::psycho_imgui_radio_button(label.as_ptr(), active) }
    }

    pub fn radio_button_wrapped(
        &mut self,
        label: &CStr,
        active: bool,
        first_in_group: bool,
    ) -> bool {
        unsafe { ffi::psycho_imgui_radio_button_wrapped(label.as_ptr(), active, first_in_group) }
    }

    pub fn content_region_available_width(&self) -> f32 {
        unsafe { ffi::psycho_imgui_content_region_available_width() }
    }

    /// Return the vertical space remaining in the current ImGui content region.
    pub fn content_region_available_height(&self) -> f32 {
        unsafe { ffi::psycho_imgui_content_region_available_height() }
    }

    pub fn vertical_splitter(
        &mut self,
        id: &CStr,
        leading_width: &mut f32,
        min_width: f32,
        max_width: f32,
        height: f32,
    ) -> bool {
        unsafe {
            ffi::psycho_imgui_vertical_splitter(
                id.as_ptr(),
                leading_width,
                min_width,
                max_width,
                height,
            )
        }
    }

    /// Return Dear ImGui's rolling frame-rate estimate for the active context.
    pub fn frame_rate(&self) -> f32 {
        unsafe { ffi::psycho_imgui_frame_rate() }
    }

    pub fn slider_float(&mut self, label: &CStr, value: &mut f32, min: f32, max: f32) -> bool {
        unsafe { ffi::psycho_imgui_slider_float(label.as_ptr(), value as *mut f32, min, max) }
    }

    pub fn slider_int(&mut self, label: &CStr, value: &mut i32, min: i32, max: i32) -> bool {
        unsafe { ffi::psycho_imgui_slider_int(label.as_ptr(), value as *mut i32, min, max) }
    }

    pub fn input_text(&mut self, label: &CStr, buffer: &mut [u8]) -> bool {
        if buffer.is_empty() {
            return false;
        }
        buffer[buffer.len() - 1] = 0;
        unsafe {
            ffi::psycho_imgui_input_text(
                label.as_ptr(),
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
            )
        }
    }

    pub fn input_text_multiline(&mut self, label: &CStr, buffer: &mut [u8], height: f32) -> bool {
        if buffer.is_empty() {
            return false;
        }
        buffer[buffer.len() - 1] = 0;
        unsafe {
            ffi::psycho_imgui_input_text_multiline(
                label.as_ptr(),
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
                height,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn precise_float(
        &mut self,
        label: &CStr,
        id: &CStr,
        value: &mut f32,
        min: f32,
        max: f32,
        step: f32,
        fast_step: f32,
        logarithmic: bool,
    ) -> bool {
        unsafe {
            ffi::psycho_imgui_precise_float(
                label.as_ptr(),
                id.as_ptr(),
                value as *mut f32,
                min,
                max,
                step,
                fast_step,
                logarithmic,
            )
        }
    }

    pub fn precise_int(
        &mut self,
        label: &CStr,
        id: &CStr,
        value: &mut i32,
        min: i32,
        max: i32,
        fast_step: i32,
    ) -> bool {
        unsafe {
            ffi::psycho_imgui_precise_int(
                label.as_ptr(),
                id.as_ptr(),
                value as *mut i32,
                min,
                max,
                fast_step,
            )
        }
    }

    pub fn selectable(&mut self, label: &CStr, selected: bool) -> bool {
        unsafe { ffi::psycho_imgui_selectable(label.as_ptr(), selected) }
    }

    pub fn begin_combo(&mut self, label: &CStr, preview: &CStr) -> bool {
        unsafe { ffi::psycho_imgui_begin_combo(label.as_ptr(), preview.as_ptr()) }
    }

    pub fn end_combo(&mut self) {
        unsafe { ffi::psycho_imgui_end_combo() };
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

    pub fn telemetry_chart(&mut self, id: &CStr, chart: &TelemetryChart<'_>) {
        let raw = RawTelemetryChart {
            values: chart.values.as_ptr(),
            count: chart.values.len() as i32,
            scale_min: chart.scale_min,
            scale_max: chart.scale_max,
            width: chart.width,
            height: chart.height,
            warning_threshold: chart.warning_threshold,
            critical_threshold: chart.critical_threshold,
            danger_below: i32::from(chart.danger_below),
            sample_interval_seconds: chart.sample_interval_seconds,
            impulse_from_zero: i32::from(chart.impulse_from_zero),
            color_by_threshold: i32::from(chart.color_by_threshold),
            line_color: chart.line_color,
            fill_color: chart.fill_color,
            warning_label: chart.warning_label.as_ptr(),
            critical_label: chart.critical_label.as_ptr(),
            value_suffix: chart.value_suffix.as_ptr(),
        };
        unsafe { ffi::psycho_imgui_telemetry_chart(id.as_ptr(), &raw) };
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

    /// Scroll the current window/child to its bottom edge.
    pub fn scroll_to_bottom(&mut self) {
        unsafe { ffi::psycho_imgui_scroll_to_bottom() };
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
pub struct TabBar {
    visible: bool,
}

impl TabBar {
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Drop for TabBar {
    fn drop(&mut self) {
        if self.visible {
            unsafe { ffi::psycho_imgui_end_tab_bar() };
        }
    }
}

#[must_use]
pub struct TabItem {
    visible: bool,
}

impl TabItem {
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Drop for TabItem {
    fn drop(&mut self) {
        if self.visible {
            unsafe { ffi::psycho_imgui_end_tab_item() };
        }
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

#[repr(C)]
struct RawTelemetryChart {
    values: *const f32,
    count: i32,
    scale_min: f32,
    scale_max: f32,
    width: f32,
    height: f32,
    warning_threshold: f32,
    critical_threshold: f32,
    danger_below: i32,
    sample_interval_seconds: f32,
    impulse_from_zero: i32,
    color_by_threshold: i32,
    line_color: [f32; 4],
    fill_color: [f32; 4],
    warning_label: *const c_char,
    critical_label: *const c_char,
    value_suffix: *const c_char,
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
    use super::{RawIoState, RawTelemetryChart, c_char, c_void};

    unsafe extern "C" {
        pub fn psycho_imgui_init_dx9(
            render_hwnd: *mut c_void,
            foreground_hwnd: *mut c_void,
            device: *mut c_void,
        ) -> bool;
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
        pub fn psycho_imgui_set_next_window_centered(
            width_ratio: f32,
            height_ratio: f32,
            min_width: f32,
            min_height: f32,
            max_width: f32,
            max_height: f32,
            condition: i32,
        );
        pub fn psycho_imgui_begin_window(title: *const c_char, open: *mut bool) -> bool;
        pub fn psycho_imgui_end_window();
        pub fn psycho_imgui_begin_child(
            id: *const c_char,
            width: f32,
            height: f32,
            border: bool,
        ) -> bool;
        pub fn psycho_imgui_begin_static_child(
            id: *const c_char,
            width: f32,
            height: f32,
            border: bool,
        ) -> bool;
        pub fn psycho_imgui_begin_child_horizontal(
            id: *const c_char,
            width: f32,
            height: f32,
            border: bool,
        ) -> bool;
        pub fn psycho_imgui_panel_background(r: f32, g: f32, b: f32, a: f32);
        pub fn psycho_imgui_end_child();
        pub fn psycho_imgui_begin_tab_bar(id: *const c_char) -> bool;
        pub fn psycho_imgui_end_tab_bar();
        pub fn psycho_imgui_begin_tab_item(label: *const c_char) -> bool;
        pub fn psycho_imgui_end_tab_item();
        pub fn psycho_imgui_text_unformatted(text: *const c_char);
        pub fn psycho_imgui_text_wrapped(text: *const c_char);
        pub fn psycho_imgui_text_colored(r: f32, g: f32, b: f32, a: f32, text: *const c_char);
        pub fn psycho_imgui_label_value(
            label: *const c_char,
            value: *const c_char,
            r: f32,
            g: f32,
            b: f32,
            a: f32,
        );
        pub fn psycho_imgui_hover_help(text: *const c_char);
        pub fn psycho_imgui_separator();
        pub fn psycho_imgui_separator_text(label: *const c_char);
        pub fn psycho_imgui_spacing();
        pub fn psycho_imgui_checkbox(label: *const c_char, value: *mut bool) -> bool;
        pub fn psycho_imgui_radio_button(label: *const c_char, active: bool) -> bool;
        pub fn psycho_imgui_radio_button_wrapped(
            label: *const c_char,
            active: bool,
            first_in_group: bool,
        ) -> bool;
        pub fn psycho_imgui_content_region_available_width() -> f32;
        pub fn psycho_imgui_content_region_available_height() -> f32;
        pub fn psycho_imgui_vertical_splitter(
            id: *const c_char,
            leading_width: *mut f32,
            min_width: f32,
            max_width: f32,
            height: f32,
        ) -> bool;
        pub fn psycho_imgui_frame_rate() -> f32;
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
        pub fn psycho_imgui_input_text(
            label: *const c_char,
            buffer: *mut c_char,
            buffer_size: usize,
        ) -> bool;
        pub fn psycho_imgui_input_text_multiline(
            label: *const c_char,
            buffer: *mut c_char,
            buffer_size: usize,
            height: f32,
        ) -> bool;
        pub fn psycho_imgui_precise_float(
            label: *const c_char,
            id: *const c_char,
            value: *mut f32,
            min: f32,
            max: f32,
            step: f32,
            fast_step: f32,
            logarithmic: bool,
        ) -> bool;
        pub fn psycho_imgui_precise_int(
            label: *const c_char,
            id: *const c_char,
            value: *mut i32,
            min: i32,
            max: i32,
            fast_step: i32,
        ) -> bool;
        pub fn psycho_imgui_selectable(label: *const c_char, selected: bool) -> bool;
        pub fn psycho_imgui_begin_combo(label: *const c_char, preview: *const c_char) -> bool;
        pub fn psycho_imgui_end_combo();
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
        pub fn psycho_imgui_telemetry_chart(id: *const c_char, chart: *const RawTelemetryChart);
        pub fn psycho_imgui_push_item_width(width: f32);
        pub fn psycho_imgui_pop_item_width();
        pub fn psycho_imgui_same_line();
        pub fn psycho_imgui_scroll_to_bottom();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn psycho_theme_explicitly_colors_every_tab_state() {
        let bridge = include_str!("bridge.cpp");
        let style = bridge
            .split_once("static void apply_psycho_style()")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("bool psycho_imgui_init_dx9"))
            .map(|(body, _)| body)
            .expect("Psycho ImGui style body");

        for color in [
            "ImGuiCol_Tab]",
            "ImGuiCol_TabHovered]",
            "ImGuiCol_TabSelected]",
            "ImGuiCol_TabSelectedOverline]",
            "ImGuiCol_TabDimmed]",
            "ImGuiCol_TabDimmedSelected]",
            "ImGuiCol_TabDimmedSelectedOverline]",
        ] {
            assert!(
                style.contains(color),
                "missing explicit theme color {color}"
            );
        }
    }

    #[test]
    fn text_entry_bridge_supports_preset_metadata_without_unsafe_sizes() {
        let bridge = include_str!("bridge.cpp");
        assert!(bridge.contains("ImGui::InputText(label, buffer, buffer_size)"));
        assert!(bridge.contains("ImGui::InputTextMultiline("));
        assert!(bridge.contains("buffer_size < 2"));
    }

    #[test]
    fn vertical_splitter_has_direct_resize_feedback_and_clamped_width() {
        let bridge = include_str!("bridge.cpp");
        let splitter = bridge
            .split_once("bool psycho_imgui_vertical_splitter(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("float psycho_imgui_frame_rate()"))
            .map(|(body, _)| body)
            .expect("vertical splitter body");

        assert!(splitter.contains("ImGui::InvisibleButton"));
        assert!(splitter.contains("ImGuiMouseCursor_ResizeEW"));
        assert!(splitter.contains("ImGui::GetIO().MouseDelta.x"));
        assert!(splitter.contains("clamp_float("));
    }

    #[test]
    fn panel_background_is_fixed_draw_list_geometry() {
        let bridge = include_str!("bridge.cpp");
        let panel = bridge
            .split_once("void psycho_imgui_panel_background(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("void psycho_imgui_end_child()"))
            .map(|(body, _)| body)
            .expect("panel background body");

        assert!(panel.contains("AddRectFilledMultiColor"));
        assert!(panel.contains("AddLine"));
        assert!(panel.contains("AddRect"));
        assert!(!panel.contains("CreateTexture"));
        assert!(!panel.contains("new "));
    }

    #[test]
    fn static_child_explicitly_disables_scrolling() {
        let bridge = include_str!("bridge.cpp");
        let child = bridge
            .split_once("bool psycho_imgui_begin_static_child(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("bool psycho_imgui_begin_child_horizontal("))
            .map(|(body, _)| body)
            .expect("static child body");

        assert!(child.contains("ImGuiWindowFlags_NoScrollbar"));
        assert!(child.contains("ImGuiWindowFlags_NoScrollWithMouse"));
        assert!(!child.contains("ImGuiWindowFlags_HorizontalScrollbar"));
    }

    #[test]
    fn telemetry_chart_draws_budget_colored_raw_segments_and_live_marker() {
        let bridge = include_str!("bridge.cpp");
        let chart = bridge
            .split_once("void psycho_imgui_telemetry_chart(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("void psycho_imgui_push_item_width"))
            .map(|(body, _)| body)
            .expect("telemetry chart body");

        assert!(chart.contains("AddRectFilledMultiColor"));
        assert!(chart.contains("telemetry_frame_time_color"));
        assert!(chart.contains("segment_glow"));
        assert!(chart.contains("last_glow"));
        assert!(chart.contains("\"%d frame%s ago  %.1f%s\""));
        assert!(!chart.contains("ImGui::PlotLines"));
    }
}
