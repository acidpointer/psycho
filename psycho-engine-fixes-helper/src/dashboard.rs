//! In-game Psycho control deck.

use std::{
    cell::RefCell,
    ffi::{CString, c_void},
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use libpsycho::{common::helpers::format_bytes, os::windows::directx9::Device9Ref};
use parking_lot::{Condvar, Mutex, RwLock};
use psycho_imgui::{Condition, Dx9Context, TelemetryChart, Ui};

use crate::{dashboard_config::ConfigEditor, engine_fixes, hooks, input};

const NIDX9_RENDERER_SINGLETON_PTR: usize = 0x011C73B4;
const NIDX9_RENDERER_DEVICE_OFFSET: usize = 0x288;
const RENDERER_CHILD_HWND_PTR: usize = 0x011C6FBC;
const TOP_LEVEL_HWND_PTR: usize = 0x011C6FC0;
const DASHBOARD_KEY: usize = 0x79; // F10
const VK_ESCAPE: usize = 0x1B;

const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_MBUTTONDOWN: u32 = 0x0207;
const WM_MBUTTONUP: u32 = 0x0208;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_MOUSEHWHEEL: u32 = 0x020E;

const SAMPLE_INTERVAL: Duration = Duration::from_millis(1_500);
const LOG_PATH: &str = "./psycho-engine-fixes-latest.log";
const LOG_TAIL_BYTES: u64 = 160 * 1024;
const MAX_LOG_LINES: usize = 320;
const MAX_LOG_LINE_CHARS: usize = 8 * 1024;
const HISTORY: usize = 120;

const MUTED: [f32; 4] = [0.49, 0.58, 0.54, 1.0];
const GOOD: [f32; 4] = [0.38, 0.94, 0.62, 1.0];
const ACCENT: [f32; 4] = [0.44, 0.88, 0.77, 1.0];
const BLUE: [f32; 4] = [0.51, 0.78, 1.0, 1.0];
const WARN: [f32; 4] = [1.0, 0.70, 0.27, 1.0];
const ERROR: [f32; 4] = [1.0, 0.37, 0.35, 1.0];
const SAVE_BUTTON: [f32; 4] = [0.08, 0.39, 0.25, 1.0];
const SAVE_HOVERED: [f32; 4] = [0.12, 0.59, 0.35, 1.0];
const SAVE_ACTIVE: [f32; 4] = [0.09, 0.72, 0.42, 1.0];
const RELOAD_BUTTON: [f32; 4] = [0.40, 0.25, 0.07, 1.0];
const RELOAD_HOVERED: [f32; 4] = [0.62, 0.39, 0.10, 1.0];
const RELOAD_ACTIVE: [f32; 4] = [0.82, 0.51, 0.12, 1.0];

const HOVER_HELP_HINT: &str =
    "Hover a setting or technical label for a plain-language explanation.";

const ENGINE_FIX_HELP: [(&str, &str); 19] = [
    (
        "Display / Alt-Tab repair",
        "Keeps fullscreen startup, renderer resets, focus changes, and Alt-Tab from using broken window size or placement. Leave it on unless another window mod has a confirmed conflict.",
    ),
    (
        "Durable save integrity",
        "Replaces the previous save only after the new file is fully written. It also rejects malformed load records before they can overrun memory.",
    ),
    (
        "NavMesh low-pointer guard",
        "Stops pathfinding from treating a tiny invalid number as a real navigation object. Normal pathfinding is unchanged.",
    ),
    (
        "Container EntryData guard",
        "Drops only a broken inventory entry when its item form is invalid, preventing that entry from crashing save or load.",
    ),
    (
        "Dynamic actor container guard",
        "Checks the inventory list of a generated NPC or creature while an old live game is being replaced. A corrupt list is detached instead of followed and freed.",
    ),
    (
        "ExtraOwnership guard",
        "Treats corrupt item ownership data as 'no owner' instead of letting the game or xNVSE follow an invalid owner pointer.",
    ),
    (
        "Linked-ref stale child guard",
        "Ignores a stale linked-reference child list left behind by a deleted or unloading object during a save transition.",
    ),
    (
        "Linked-ref target guard",
        "Skips an optional linked reference when its target has a broken base form, avoiding activation and linked-reference crashes.",
    ),
    (
        "Ragdoll bone-table guard",
        "Skips one ragdoll update while its bone table is incomplete. A later frame tries again once the skeleton is ready.",
    ),
    (
        "Detached phantom guard",
        "Returns 'no hit' for one ragdoll raycast when its collision phantom has already left the physics world.",
    ),
    (
        "Havok add-batch guard",
        "Removes empty entity slots from a Havok add batch while preserving every valid physics entity in that batch.",
    ),
    (
        "Havok pending-add guard",
        "Removes empty slots before Havok flushes its pending-add list. Valid pending physics objects continue normally.",
    ),
    (
        "Havok narrowphase guard",
        "Rejects a broken collision pair before Havok chooses a collision handler. Valid collision work is unchanged.",
    ),
    (
        "Havok post-add guard",
        "Skips the impossible AddedToWorld callback when Havok supplies no entity. Normal post-add callbacks still run.",
    ),
    (
        "Havok remove-agent guard",
        "Removes an unnecessary second read of a physics slot that may already be empty, while keeping the required unlock operation.",
    ),
    (
        "Allocator NULL memset guard",
        "Stops two known out-of-memory paths from writing through address zero when an allocation fails. It is not a global memset hook.",
    ),
    (
        "LowProcess ownership repair",
        "Keeps unloaded-actor location lists from freeing references they only borrow, and contains corrupt entries while saving.",
    ),
    (
        "Model postprocess serialization",
        "Prevents concurrent model loads from replacing shared EditorMarker traversal state between a safety check and use. It remains active with vanilla IO.",
    ),
    (
        "Queued-task lifetime guard",
        "Stops a dead texture or background task before the game calls or releases it again. Useful with every allocator mode.",
    ),
];

static READY: AtomicBool = AtomicBool::new(false);
static OPEN_REQUESTED: AtomicBool = AtomicBool::new(false);
static OPEN: AtomicBool = AtomicBool::new(false);
static SHARED: OnceLock<Arc<RwLock<SharedData>>> = OnceLock::new();
static SAMPLING: OnceLock<Arc<SamplingControl>> = OnceLock::new();

thread_local! {
    static RUNTIME: RefCell<DashboardRuntime> = RefCell::new(DashboardRuntime::new());
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warning,
    Error,
}

struct LogLine {
    level: LogLevel,
    timestamp: String,
    source: String,
    text: String,
}

#[derive(Default)]
struct SharedData {
    core: Option<engine_fixes::DashboardSnapshot>,
    core_misses: u32,
    logs: Vec<LogLine>,
    log_generation: u64,
    log_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SamplingState {
    active: bool,
    logs: bool,
    refresh_vas: bool,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SamplingRequest {
    logs: bool,
    refresh_vas: bool,
    generation: u64,
}

impl SamplingState {
    fn request(self) -> Option<SamplingRequest> {
        self.active.then_some(SamplingRequest {
            logs: self.logs,
            refresh_vas: self.refresh_vas,
            generation: self.generation,
        })
    }
}

#[derive(Default)]
struct SamplingControl {
    state: Mutex<SamplingState>,
    changed: Condvar,
}

impl SamplingControl {
    fn set(&self, active: bool, logs: bool) {
        let mut state = self.state.lock();
        let logs = active && logs;
        if state.active == active && state.logs == logs {
            return;
        }
        state.active = active;
        state.logs = logs;
        if !active {
            state.refresh_vas = false;
        }
        state.generation = state.generation.wrapping_add(1);
        self.changed.notify_one();
    }

    fn request_vas_refresh(&self) {
        let mut state = self.state.lock();
        if !state.active {
            return;
        }
        state.refresh_vas = true;
        state.generation = state.generation.wrapping_add(1);
        self.changed.notify_one();
    }

    fn wait_for_request(&self) -> SamplingRequest {
        let mut state = self.state.lock();
        loop {
            if let Some(request) = state.request() {
                return request;
            }
            self.changed.wait(&mut state);
        }
    }

    fn complete_and_wait(&self, request: SamplingRequest) {
        let mut state = self.state.lock();
        if state.generation == request.generation {
            state.refresh_vas = false;
        }
        if state.active && state.generation == request.generation {
            self.changed.wait_for(&mut state, SAMPLE_INTERVAL);
        }
    }
}

#[derive(Default)]
struct LogTailReader {
    offset: u64,
    pending: Vec<u8>,
    initialized: bool,
}

struct LogRefresh {
    reset: bool,
    lines: Vec<LogLine>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Page {
    #[default]
    Overview,
    Memory,
    Runtime,
    Configuration,
    Logs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogFilters {
    trace: bool,
    debug: bool,
    info: bool,
    warning: bool,
    error: bool,
}

impl Default for LogFilters {
    fn default() -> Self {
        Self::all()
    }
}

struct History {
    values: [f32; HISTORY],
    count: usize,
}

impl Default for History {
    fn default() -> Self {
        Self {
            values: [0.0; HISTORY],
            count: 0,
        }
    }
}

impl History {
    fn push(&mut self, value: f32) {
        if self.count < HISTORY {
            self.values[self.count] = value;
            self.count += 1;
        } else {
            self.values.copy_within(1..HISTORY, 0);
            self.values[HISTORY - 1] = value;
        }
    }

    fn values(&self) -> &[f32] {
        &self.values[..self.count]
    }

    fn last(&self) -> Option<f32> {
        self.values().last().copied()
    }

    fn min(&self) -> Option<f32> {
        self.values().iter().copied().reduce(f32::min)
    }

    fn max(&self) -> Option<f32> {
        self.values().iter().copied().reduce(f32::max)
    }

    fn delta(&self) -> f32 {
        match (self.values().first(), self.values().last()) {
            (Some(first), Some(last)) => last - first,
            _ => 0.0,
        }
    }
}

struct DashboardRuntime {
    imgui: Option<Dx9Context>,
    imgui_device: usize,
    imgui_render_hwnd: usize,
    imgui_input_hwnd: usize,
    needs_device_objects: bool,
    open: bool,
    page: Page,
    config: ConfigEditor,
    commit_history: History,
    hole_history: History,
    last_core_sample_ms: u64,
    texture_memory_estimate: u64,
    texture_sample_time_ms: u32,
    texture_query_last_us: u64,
    texture_query_max_us: u64,
    texture_refresh_requested: bool,
    log_filters: LogFilters,
    log_show_context: bool,
    log_auto_follow: bool,
    last_log_generation: u64,
    ui_error: Option<String>,
}

impl DashboardRuntime {
    fn new() -> Self {
        Self {
            imgui: None,
            imgui_device: 0,
            imgui_render_hwnd: 0,
            imgui_input_hwnd: 0,
            needs_device_objects: false,
            open: false,
            page: Page::Overview,
            config: ConfigEditor::load(),
            commit_history: History::default(),
            hole_history: History::default(),
            last_core_sample_ms: 0,
            texture_memory_estimate: 0,
            texture_sample_time_ms: 0,
            texture_query_last_us: 0,
            texture_query_max_us: 0,
            texture_refresh_requested: false,
            log_filters: LogFilters::default(),
            log_show_context: false,
            log_auto_follow: true,
            last_log_generation: 0,
            ui_error: None,
        }
    }

    fn set_open(&mut self, open: bool) {
        if self.open == open {
            return;
        }
        self.open = open;
        if open && self.page == Page::Overview {
            self.texture_refresh_requested = true;
        }
        OPEN.store(open, Ordering::Release);
        input::set_blocked(open);
        self.publish_sampling_state();
    }

    fn publish_sampling_state(&self) {
        if let Some(control) = SAMPLING.get() {
            control.set(self.open, self.page == Page::Logs);
        }
    }

    fn request_vas_refresh(&self) {
        if let Some(control) = SAMPLING.get() {
            control.request_vas_refresh();
        }
    }

    fn render_present(&mut self, handles: GameRenderHandles) {
        if OPEN_REQUESTED.swap(false, Ordering::AcqRel) {
            self.set_open(true);
        }
        if !self.open {
            return;
        }

        let Some(device) = (unsafe { Device9Ref::from_raw_void(handles.device) }) else {
            self.ui_error = Some("The Direct3D9 device is unavailable.".to_owned());
            return;
        };
        if self.imgui_device != handles.device as usize
            || self.imgui_render_hwnd != handles.render_hwnd as usize
            || self.imgui_input_hwnd != handles.input_hwnd as usize
        {
            self.imgui = None;
            self.imgui_device = handles.device as usize;
            self.imgui_render_hwnd = handles.render_hwnd as usize;
            self.imgui_input_hwnd = handles.input_hwnd as usize;
            self.needs_device_objects = false;
            if self.page == Page::Overview {
                self.texture_refresh_requested = true;
            }
        }
        if self.imgui.is_none() {
            if let Err(error) = hooks::ensure_reset_hook(handles.device) {
                self.ui_error = Some(format!("Device reset bridge failed: {error:#}"));
                return;
            }
            match unsafe {
                Dx9Context::new_with_foreground_window(
                    handles.render_hwnd,
                    handles.input_hwnd,
                    handles.device,
                )
            } {
                Ok(context) => {
                    self.imgui = Some(context);
                    self.ui_error = None;
                    log::info!(
                        "[DASHBOARD] Psycho control deck initialized: render_hwnd={:#010X} input_hwnd={:#010X} relation={}",
                        handles.render_hwnd as usize,
                        handles.input_hwnd as usize,
                        if handles.windows_are_aliased() {
                            "shared"
                        } else {
                            "child-render"
                        }
                    );
                }
                Err(error) => {
                    self.ui_error = Some(format!("ImGui initialization failed: {error}"));
                    return;
                }
            }
        }
        if self.needs_device_objects {
            let Some(imgui) = self.imgui.as_mut() else {
                return;
            };
            if !imgui.create_device_objects() {
                return;
            }
            self.needs_device_objects = false;
        }

        if take_driver_refresh(self.page, &mut self.texture_refresh_requested) {
            let started = Instant::now();
            self.texture_memory_estimate = u64::from(device.available_texture_mem());
            self.texture_sample_time_ms = libpsycho::os::windows::winapi::get_tick_count();
            self.texture_query_last_us = started.elapsed().as_micros() as u64;
            self.texture_query_max_us = self.texture_query_max_us.max(self.texture_query_last_us);
        }

        let Some(mut imgui) = self.imgui.take() else {
            return;
        };
        let mut ui = imgui.new_frame(true);
        let keep_open = self.draw(&mut ui);
        drop(ui);
        imgui.render();
        self.imgui = Some(imgui);
        if !keep_open {
            self.set_open(false);
        }
    }

    fn update_core_history(&mut self, core: engine_fixes::DashboardSnapshot) {
        if core.sample_time_ms == self.last_core_sample_ms {
            return;
        }
        self.last_core_sample_ms = core.sample_time_ms;
        if core.flags & engine_fixes::DASHBOARD_FLAG_PROCESS_SAMPLE_VALID != 0 {
            self.commit_history
                .push(core.process_commit_bytes as f32 / (1024.0 * 1024.0));
        }
        if core.flags & engine_fixes::DASHBOARD_FLAG_VAS_VALID != 0 {
            self.hole_history
                .push(core.vas_largest_hole_bytes as f32 / (1024.0 * 1024.0));
        }
    }

    fn draw(&mut self, ui: &mut Ui<'_>) -> bool {
        ui.set_next_window_centered(
            0.88,
            0.88,
            900.0,
            600.0,
            1360.0,
            920.0,
            Condition::FirstUseEver,
        );
        let mut open = true;
        let title = cstring("Psycho Engine Fixes Dashboard");
        let window = ui.window(&title, Some(&mut open));
        if !window.is_visible() {
            return open;
        }

        let shared = SHARED.get().cloned();
        let guard = shared.as_ref().and_then(|shared| shared.try_read());
        let core = guard.as_ref().and_then(|data| data.core);
        if let Some(core) = core {
            self.update_core_history(core);
        }

        self.draw_header(ui, core);
        ui.separator();
        let available = ui.content_region_available_width().max(1.0);
        let nav_width = (available * 0.18).clamp(170.0, 225.0);
        {
            let id = cstring("dashboard_nav");
            let child = ui.child(&id, nav_width, 0.0, true);
            if child.is_visible() {
                self.draw_navigation(ui);
            }
        }
        ui.same_line();
        {
            let id = cstring("dashboard_content");
            let child = ui.child(&id, 0.0, 0.0, false);
            if child.is_visible() {
                match self.page {
                    Page::Overview => self.draw_overview(ui, core),
                    Page::Memory => self.draw_memory(ui, core),
                    Page::Runtime => self.draw_runtime(ui, core),
                    Page::Configuration => draw_configuration(ui, &mut self.config),
                    Page::Logs => self.draw_logs(ui, guard.as_deref()),
                }
            }
        }
        open
    }

    fn draw_header(&self, ui: &mut Ui<'_>, core: Option<engine_fixes::DashboardSnapshot>) {
        ui.text_colored(ACCENT, &cstring("PSYCHO ENGINE FIXES"));
        ui.same_line();
        let linked =
            core.is_some_and(|core| core.flags & engine_fixes::DASHBOARD_FLAG_CORE_READY != 0);
        ui.text_colored(
            if linked { GOOD } else { ERROR },
            &cstring(if linked { "CONNECTED" } else { "CORE OFFLINE" }),
        );
        if self.config.is_dirty() {
            ui.same_line();
            ui.text_colored(WARN, &cstring("UNSAVED SETTINGS"));
        }
        ui.text_colored(
            MUTED,
            &cstring("Live diagnostics, support telemetry, logs, and next-launch configuration."),
        );
        if let Some(error) = &self.ui_error {
            ui.text_colored(ERROR, &cstring(error));
        }
    }

    fn draw_navigation(&mut self, ui: &mut Ui<'_>) {
        ui.text_colored(MUTED, &cstring("DASHBOARD"));
        ui.spacing();
        let previous_page = self.page;
        for (page, label) in [
            (Page::Overview, "Overview"),
            (Page::Memory, "Memory dashboard"),
            (Page::Runtime, "Runtime fixes"),
            (Page::Configuration, "Configuration"),
            (Page::Logs, "Log browser"),
        ] {
            if ui.selectable(&cstring(label), self.page == page) {
                self.page = page;
            }
        }
        if self.page != previous_page {
            if self.page == Page::Overview {
                self.texture_refresh_requested = true;
            }
            self.publish_sampling_state();
        }
        ui.spacing();
        ui.separator_text(&cstring("Session"));
        ui.text_wrapped(&cstring(
            "Telemetry refreshes every 1.5 seconds. Settings are saved for the next full game launch.",
        ));
        ui.spacing();
        ui.text_colored(MUTED, &cstring("F10 or Esc closes the dashboard"));
    }

    fn draw_overview(&mut self, ui: &mut Ui<'_>, core: Option<engine_fixes::DashboardSnapshot>) {
        page_heading(
            ui,
            "Overview",
            "A concise health check for the current game session.",
        );
        ui.text_colored(MUTED, &cstring(HOVER_HELP_HINT));
        ui.separator_text(&cstring("Session status"));
        let Some(core) = core else {
            ui.text_colored(
                ERROR,
                &cstring("Waiting for psycho_engine_fixes.dll telemetry..."),
            );
            return;
        };
        let health = MemoryHealth::from_snapshot(&core);
        let width = ((ui.content_region_available_width() - 18.0) / 3.0).max(170.0);
        metric_card(
            ui,
            "health_card",
            "MEMORY HEADROOM",
            health.label(),
            health.color(),
            health.detail(&core),
            width,
            "A simple rating of the remaining 32-bit address-space headroom. It emphasizes the largest continuous free opening because large assets must fit in one piece.",
        );
        ui.same_line();
        metric_card(
            ui,
            "allocator_card",
            "ALLOCATOR MODE",
            allocator_name(core.allocator_mode),
            ACCENT,
            format!("{} live pool cells", core.pool_live_cells),
            width,
            "Which main memory allocator Psycho selected at startup. Vanilla uses the original heaps, scrap-only replaces temporary heaps, and full gheap replaces both.",
        );
        ui.same_line();
        metric_card(
            ui,
            "guard_card",
            "SAFETY INTERVENTIONS",
            &compact_count(
                core.task_release_guards
                    .saturating_add(core.task_tombstones)
                    .saturating_add(core.save_rejections),
            ),
            BLUE,
            "Prevented unsafe lifetime/save paths",
            width,
            "How many known unsafe task or save situations Psycho stopped this session. A nonzero value means a guard did useful work, not necessarily that the session is unstable.",
        );

        ui.spacing();
        ui.separator_text(&cstring("Current memory state"));
        draw_value_help(
            ui,
            "Process commit",
            bytes(core.process_commit_bytes),
            ACCENT,
            "Memory Windows has promised to back for this game with RAM or the page file. It includes more than what is physically in RAM right now.",
        );
        draw_value_help(
            ui,
            "Largest VAS opening",
            bytes(core.vas_largest_hole_bytes),
            health.color(),
            "The biggest single unused range in New Vegas' 32-bit virtual address space. Large textures and models need one opening big enough to contain them.",
        );
        draw_value_help(
            ui,
            "Current RSS",
            bytes(core.process_rss_bytes),
            BLUE,
            "Resident Set Size: the game's memory currently held in physical RAM. It can be lower than process commit because some committed pages are not resident.",
        );
        let texture_estimate = if self.texture_sample_time_ms == 0 {
            "Not sampled".to_owned()
        } else {
            format!(
                "{} ({}s old)",
                bytes(self.texture_memory_estimate),
                sample_age_seconds(u64::from(self.texture_sample_time_ms)),
            )
        };
        draw_value_help(
            ui,
            "Driver texture estimate",
            texture_estimate,
            WARN,
            "The D3D9 driver's estimate of texture memory in use. Treat it as a directional estimate, not an exact VRAM meter.",
        );
        draw_value_help(
            ui,
            "Early startup boundary",
            if core.flags & engine_fixes::DASHBOARD_FLAG_PRE_CRT_BOUNDARY != 0 {
                "CONFIRMED"
            } else {
                "NOT REACHED"
            },
            if core.flags & engine_fixes::DASHBOARD_FLAG_PRE_CRT_BOUNDARY != 0 {
                GOOD
            } else {
                ERROR
            },
            "Confirms Psycho loaded before the game's normal C runtime and allocators started. Full gheap requires this early ownership boundary.",
        );

        if ui.button(&cstring("Refresh driver estimate")) {
            self.texture_refresh_requested = true;
        }
        hover_help(
            ui,
            "Requests a fresh D3D9 driver estimate. The query runs only on demand because drivers may make it relatively expensive.",
        );
        ui.same_line();
        if ui.button(&cstring("Refresh VAS map")) {
            self.request_vas_refresh();
        }
        hover_help(
            ui,
            "Walks the game's complete 32-bit address map now. Use it after loading or travelling when you want a current fragmentation reading.",
        );

        ui.spacing();
        let explanation = match health {
            MemoryHealth::Stable => {
                "Address-space shape is healthy for ordinary streaming. Keep watching the largest opening on extreme texture lists."
            }
            MemoryHealth::Watch => {
                "The process is becoming fragmented. Large texture or model allocations have less contiguous room even when total free space looks adequate."
            }
            MemoryHealth::Critical => {
                "The largest contiguous opening is below Psycho's critical threshold. A large texture/model allocation may fail before total memory is exhausted."
            }
            MemoryHealth::Unknown => {
                "The current VirtualQuery address-space sample is unavailable. Memory health cannot be rated safely."
            }
        };
        notice_card(ui, "overview_memory_note", explanation, health.color());
    }

    fn draw_memory(&mut self, ui: &mut Ui<'_>, core: Option<engine_fixes::DashboardSnapshot>) {
        page_heading(
            ui,
            "Memory dashboard",
            "Address-space headroom and allocator pressure for texture-heavy setups.",
        );
        ui.text_colored(MUTED, &cstring(HOVER_HELP_HINT));
        ui.separator_text(&cstring("32-bit address space"));
        let Some(core) = core else {
            ui.text_colored(
                ERROR,
                &cstring("Structured memory telemetry is unavailable."),
            );
            return;
        };
        let health = MemoryHealth::from_snapshot(&core);
        draw_value_help(
            ui,
            "Free address space",
            bytes(core.vas_free_bytes),
            health.color(),
            "All unused ranges added together inside New Vegas' 32-bit virtual address space. Fragmentation can make this look healthy even when no large opening remains.",
        );
        draw_value_help(
            ui,
            "Largest contiguous opening",
            bytes(core.vas_largest_hole_bytes),
            health.color(),
            "The largest single unused address range. This is the most useful number for judging whether one large texture or model mapping can still fit.",
        );
        draw_value_help(
            ui,
            "Committed mappings",
            bytes(core.vas_committed_bytes),
            ACCENT,
            "Address ranges with storage promised by Windows. Committed memory may be in RAM or the page file and is not the same as current physical RAM use.",
        );
        draw_value_help(
            ui,
            "Reserved mappings",
            bytes(core.vas_reserved_bytes),
            MUTED,
            "Address ranges set aside for future use but not yet backed by RAM or the page file. Reservation consumes address space, not physical memory by itself.",
        );
        draw_value_help(
            ui,
            "Free-region count",
            core.vas_holes,
            MUTED,
            "How many separate free openings exist. More openings can indicate fragmentation; their sizes matter more than the count alone.",
        );
        draw_value_help(
            ui,
            "VAS sample age",
            if core.flags & engine_fixes::DASHBOARD_FLAG_VAS_VALID != 0 {
                format!("{}s", sample_age_seconds(core.vas_sample_time_ms))
            } else {
                "Unavailable".to_owned()
            },
            MUTED,
            "How long ago Psycho last walked the full virtual address space. Refresh after a major load when current fragmentation matters.",
        );
        if ui.button(&cstring("Refresh VAS map")) {
            self.request_vas_refresh();
        }
        hover_help(
            ui,
            "Walks the game's complete 32-bit address map now. The normal fast snapshot reuses the last full map to avoid repeated frame stalls.",
        );
        ui.text_colored(MUTED, &cstring("Largest opening predicts big texture/model allocation viability better than total free bytes."));

        ui.spacing();
        ui.separator_text(&cstring("Recent pressure trends"));
        self.draw_memory_charts(ui);

        ui.spacing();
        ui.separator_text(&cstring("Allocator usage"));
        tier_bar_help(
            ui,
            "Cell pools",
            core.pool_committed_bytes,
            core.pool_reserved_bytes,
            format!("{} live cells", core.pool_live_cells),
            "Fixed-size storage for small game objects. Psycho groups equal-size allocations so common object creation and destruction stay fast.",
        );
        tier_bar_help(
            ui,
            "Pool metadata",
            core.pool_metadata_bytes,
            core.pool_metadata_reserved_bytes,
            "Out-of-band zombie-safe freelists".to_owned(),
            "Bookkeeping kept outside game objects: which small cells exist, are free, or remain readable for stale-pointer protection.",
        );
        tier_bar_help(
            ui,
            "Block heap",
            core.block_live_bytes,
            core.block_committed_bytes,
            format!(
                "{} allocations across {} slots",
                core.block_live_allocations, core.block_slots
            ),
            "Storage for medium-sized allocations that do not fit a small fixed-size pool. Slots are independent 16 MiB regions.",
        );
        if core.flags & engine_fixes::DASHBOARD_FLAG_BLOCK_SAMPLE_VALID == 0 {
            ui.text_colored(
                MUTED,
                &cstring("Block heap was busy; the cached row is intentionally non-blocking."),
            );
        }
        tier_bar_help(
            ui,
            "Direct VA",
            core.direct_live_bytes,
            core.direct_peak_bytes.max(core.direct_live_bytes),
            format!(
                "Largest request {}",
                bytes(core.direct_max_allocation_bytes)
            ),
            "Very large allocations mapped directly through Windows virtual memory instead of passing through a small or medium heap.",
        );
        draw_value_help(
            ui,
            "Scrap heap live",
            bytes(core.scrap_live_bytes),
            BLUE,
            "Short-lived temporary memory used during loading and frame work. Psycho can discard complete retired scrap regions together.",
        );

        ui.spacing();
        ui.separator_text(&cstring("Allocation fallbacks and failures"));
        draw_value_help(
            ui,
            "Pool exhaustion fallbacks",
            core.pool_exhaustions,
            counter_color(core.pool_exhaustions),
            "A small-object pool had no immediately available cell, so Psycho served the request through a larger fallback tier. Occasional events are recoverable.",
        );
        draw_value_help(
            ui,
            "Block-tier overflows",
            core.block_overflows,
            counter_color(core.block_overflows),
            "A medium allocation could not fit in the existing block slots and had to use another supported allocation path.",
        );
        draw_value_help(
            ui,
            "Block reserve/commit failures",
            core.block_failures,
            counter_color(core.block_failures),
            "Windows refused to reserve address space or back pages for a medium block. Any nonzero count is important in a memory-related bug report.",
        );
        draw_value_help(
            ui,
            "Direct VA failures",
            core.direct_failures,
            counter_color(core.direct_failures),
            "Windows could not map one very large allocation. This usually means insufficient contiguous address space, not simply low free RAM.",
        );
        draw_value_help(
            ui,
            "Direct VA lifecycle",
            format!(
                "{} alloc / {} free",
                core.direct_allocations, core.direct_frees
            ),
            MUTED,
            "How many very large direct mappings Psycho created and released this session. The difference is the currently live mapping count.",
        );
    }

    fn draw_memory_charts(&self, ui: &mut Ui<'_>) {
        let available = ui.content_region_available_width().max(1.0);
        let width = ((available - 10.0) / 2.0).max(280.0);
        let (commit_min, commit_max) = padded_history_bounds(&self.commit_history, 64.0, 0.0);
        telemetry_card(
            ui,
            "commit_chart_card",
            "PROCESS COMMIT",
            self.commit_history.last().map_or_else(
                || "Collecting...".to_owned(),
                |value| format!("{value:.0} MiB"),
            ),
            history_delta_label(self.commit_history.delta()),
            history_delta_color(self.commit_history.delta(), false),
            &self.commit_history,
            commit_min,
            commit_max,
            f32::NAN,
            f32::NAN,
            false,
            ACCENT,
            [0.18, 0.72, 0.56, 0.16],
            "",
            "",
            "Committed process memory. Rising is normal during loading; sustained growth needs attention.",
            width,
        );
        ui.same_line();

        let hole_max = self.hole_history.max().unwrap_or(512.0).max(512.0) * 1.08;
        telemetry_card(
            ui,
            "vas_chart_card",
            "LARGEST VAS OPENING",
            self.hole_history.last().map_or_else(
                || "Collecting...".to_owned(),
                |value| format!("{value:.0} MiB"),
            ),
            history_delta_label(self.hole_history.delta()),
            history_delta_color(self.hole_history.delta(), true),
            &self.hole_history,
            0.0,
            hole_max,
            384.0,
            128.0,
            true,
            BLUE,
            [0.28, 0.61, 0.92, 0.15],
            "WATCH 384 MiB",
            "CRITICAL 128 MiB",
            "Contiguous headroom for large texture and model mappings. Higher is safer.",
            width,
        );
    }

    fn draw_runtime(&self, ui: &mut Ui<'_>, core: Option<engine_fixes::DashboardSnapshot>) {
        page_heading(
            ui,
            "Runtime fixes",
            "Installed protections and the work they have performed this session.",
        );
        ui.text_colored(MUTED, &cstring(HOVER_HELP_HINT));
        ui.separator_text(&cstring("Installed protections"));
        let Some(core) = core else {
            ui.text_colored(ERROR, &cstring("Runtime-fix telemetry is unavailable."));
            return;
        };
        for (name, bit, detail, help) in [
            (
                "Display transition repair",
                engine_fixes::DASHBOARD_FEATURE_DISPLAY,
                "Fullscreen, reset and Alt-Tab ownership",
                ENGINE_FIX_HELP[0].1,
            ),
            (
                "Durable save integrity",
                engine_fixes::DASHBOARD_FEATURE_SAVE_INTEGRITY,
                "Atomic promotion and malformed-record rejection",
                ENGINE_FIX_HELP[1].1,
            ),
            (
                "Queued-task lifetime guard",
                engine_fixes::DASHBOARD_FEATURE_TASK_GUARD,
                "Dispatch and final-release ownership",
                ENGINE_FIX_HELP[18].1,
            ),
            (
                "Dynamic actor container guard",
                engine_fixes::DASHBOARD_FEATURE_ACTOR_CONTAINER_GUARD,
                "Validates retiring runtime actor inventory lists",
                ENGINE_FIX_HELP[4].1,
            ),
            (
                "Model postprocess serialization",
                engine_fixes::DASHBOARD_FEATURE_MODEL_POSTPROCESS,
                "Process-global EditorMarker traversal ownership",
                ENGINE_FIX_HELP[17].1,
            ),
            (
                "Parallel native IO",
                engine_fixes::DASHBOARD_FEATURE_PARALLEL_IO,
                "Two-worker audited topology",
                "Uses two game-owned loading workers while serializing engine state that is unsafe to build concurrently.",
            ),
            (
                "LOD prefetch",
                engine_fixes::DASHBOARD_FEATURE_LOD_PREFETCH,
                "Early native terrain/object/tree demand",
                "Requests distant terrain, trees, and objects slightly before visibility to reduce pop-in while moving.",
            ),
            (
                "LOD handoff",
                engine_fixes::DASHBOARD_FEATURE_LOD_HANDOFF,
                "Current identity instead of lifetime totals",
                "Prevents distant scenery from being retired from stale counters while it switches to the nearby full-detail version.",
            ),
            (
                "SpeedTree lifetime",
                engine_fixes::DASHBOARD_FEATURE_TREE_LIFETIME,
                "Serialized materialization and process-global Compute state",
                "Coordinates tree creation and SpeedTree's shared compute state so loading workers cannot use it concurrently in an unsafe order.",
            ),
            (
                "Static vertex buffers",
                engine_fixes::DASHBOARD_FEATURE_VERTEX_BUFFERS,
                "Safe allocation/publication lifetime",
                "Publishes static geometry buffers only after their storage is complete, preventing loading workers from seeing a half-built buffer.",
            ),
        ] {
            feature_status(ui, name, core.active_features & bit != 0, detail, help);
        }

        ui.spacing();
        ui.separator_text(&cstring("Save and task safety"));
        draw_value_help(
            ui,
            "Saves",
            format!(
                "{} committed / {} tried",
                core.save_commits, core.save_attempts
            ),
            GOOD,
            "How many save attempts reached a durable final file. A commit means the completed temporary save safely replaced the previous save.",
        );
        draw_value_help(
            ui,
            "Save aborts",
            core.save_aborts,
            counter_color(core.save_aborts),
            "Save attempts stopped because writing, flushing, closing, backup rotation, or final replacement could not complete safely.",
        );
        draw_value_help(
            ui,
            "Rejected unsafe save/load data",
            core.save_rejections,
            counter_color(core.save_rejections),
            "Malformed or unavailable changed records skipped through the game's supported rejection path instead of being trusted.",
        );
        draw_value_help(
            ui,
            "Task dispatches",
            core.task_dispatches,
            ACCENT,
            "Background game tasks checked at the audited dispatch boundary before their virtual work begins.",
        );
        draw_value_help(
            ui,
            "Rejected unsafe tasks",
            core.task_rejections,
            counter_color(core.task_rejections),
            "Tasks already known to be dead or invalid that Psycho stopped before another callback could run.",
        );
        draw_value_help(
            ui,
            "Release guards / tombstones",
            format!("{} / {}", core.task_release_guards, core.task_tombstones),
            BLUE,
            "Release guards stop an unsafe final release. Tombstones are compact records of already-dead tasks used to reject later stale references.",
        );

        ui.spacing();
        ui.separator_text(&cstring("Streaming activity"));
        draw_value_help(
            ui,
            "IO workers",
            core.io_workers,
            ACCENT,
            "The number of native game loading workers Psycho configured. The supported parallel layout uses exactly two.",
        );
        draw_value_help(
            ui,
            "Serialized cell loads",
            core.io_transactions,
            BLUE,
            "Exterior-cell loading operations passed through the ownership gate that protects shared engine state.",
        );
        draw_value_help(
            ui,
            "Cell-load contentions",
            core.io_contentions,
            counter_color(core.io_contentions),
            "Times one loading worker briefly waited because another worker owned the protected exterior-cell loading section.",
        );
        draw_value_help(
            ui,
            "IO fallbacks",
            core.io_fallbacks,
            counter_color(core.io_fallbacks),
            "Times parallel loading could not satisfy its proven safety contract and used the compatible fallback path instead.",
        );
        draw_value_help(
            ui,
            "Tree materializations",
            format!(
                "{} completed / {} started",
                core.speedtree_completions, core.speedtree_materializations
            ),
            BLUE,
            "Tree resources fully built versus builds started. A short-lived difference is normal while work is still in flight.",
        );
        draw_value_help(
            ui,
            "Tree materialization contentions",
            core.speedtree_materialization_contentions,
            BLUE,
            "Times tree creation had to wait because another worker owned SpeedTree's process-wide construction state.",
        );
        draw_value_help(
            ui,
            "SpeedTree Compute",
            format!(
                "{} runs / {} contentions",
                core.speedtree_compute_transactions, core.speedtree_compute_contentions
            ),
            BLUE,
            "Runs of SpeedTree's shared Compute stage and times another worker found that stage busy.",
        );
        draw_value_help(
            ui,
            "SpeedTree waiters / max waits",
            format!(
                "{} / {} us materialize / {} us Compute",
                core.speedtree_waiters,
                core.speedtree_max_materialization_wait_us,
                core.speedtree_max_compute_wait_us
            ),
            if core.speedtree_waiters == 0 {
                GOOD
            } else {
                WARN
            },
            "Current waiting workers and the longest observed waits for tree materialization and the shared Compute stage, measured in microseconds.",
        );
        draw_value_help(
            ui,
            "LOD demand / early / retained",
            format!(
                "{} / {} / {}",
                core.lod_demands, core.lod_early_demands, core.lod_retained_demands
            ),
            ACCENT,
            "Distant-world requests seen, requests issued early by prefetch, and resources deliberately kept a little longer to reduce reload churn.",
        );
        draw_value_help(
            ui,
            "Tracked cells / references",
            format!(
                "{} / {}",
                core.lod_current_cells, core.lod_current_references
            ),
            BLUE,
            "Current distant-world cells and object references whose ownership Psycho is tracking for safe handoff and retirement.",
        );
        draw_value_help(
            ui,
            "Stale retirements prevented",
            core.lod_stale_retirements_prevented,
            GOOD,
            "Distant resources kept alive because an old lifetime counter no longer matched their current ownership.",
        );

        ui.spacing();
        ui.separator_text(&cstring("Dashboard overhead"));
        draw_value_help(
            ui,
            "Fast snapshots",
            format!(
                "{} calls, {} us last / {} us max",
                core.dashboard_queries, core.dashboard_query_last_us, core.dashboard_query_max_us,
            ),
            GOOD,
            "Cheap dashboard telemetry reads and their last/slowest duration. A microsecond is one millionth of a second.",
        );
        draw_value_help(
            ui,
            "VAS refreshes",
            format!(
                "{} calls, {} us last / {} us max",
                core.dashboard_vas_refreshes,
                core.dashboard_vas_refresh_last_us,
                core.dashboard_vas_refresh_max_us,
            ),
            WARN,
            "Complete virtual-address-space walks requested by the dashboard and their cost. These are intentionally manual and cached.",
        );
        draw_value_help(
            ui,
            "Driver estimate queries",
            format!(
                "{} us last / {} us max",
                self.texture_query_last_us, self.texture_query_max_us,
            ),
            WARN,
            "D3D9 texture-memory estimate calls and their cost. The query is manual because driver implementations may make it expensive.",
        );
    }

    fn draw_logs(&mut self, ui: &mut Ui<'_>, shared: Option<&SharedData>) {
        page_heading(
            ui,
            "Log browser",
            "Recent Psycho messages with noisy prefixes hidden by default.",
        );
        ui.text_colored(MUTED, &cstring(LOG_PATH));

        if ui.button(&cstring("Show all")) {
            self.log_filters = LogFilters::all();
        }
        ui.same_line();
        if ui.button(&cstring("Warnings + errors")) {
            self.log_filters = LogFilters::important();
        }
        ui.spacing();
        ui.text_colored(MUTED, &cstring("Levels:"));
        ui.same_line();
        ui.checkbox(&cstring("ERROR"), &mut self.log_filters.error);
        ui.same_line();
        ui.checkbox(&cstring("WARN"), &mut self.log_filters.warning);
        ui.same_line();
        ui.checkbox(&cstring("INFO"), &mut self.log_filters.info);
        ui.same_line();
        ui.checkbox(&cstring("DEBUG"), &mut self.log_filters.debug);
        ui.same_line();
        ui.checkbox(&cstring("TRACE"), &mut self.log_filters.trace);

        ui.checkbox(
            &cstring("Show compact time + source"),
            &mut self.log_show_context,
        );
        ui.same_line();
        ui.checkbox(
            &cstring("Follow newest messages"),
            &mut self.log_auto_follow,
        );

        let Some(shared) = shared else {
            ui.text_colored(
                WARN,
                &cstring("Log sampler is busy; keeping the previous frame."),
            );
            return;
        };
        if let Some(error) = &shared.log_error {
            ui.text_colored(WARN, &cstring(error));
        }
        let visible_count = shared
            .logs
            .iter()
            .filter(|line| self.log_filters.accepts(line.level))
            .count();
        ui.text_colored(
            MUTED,
            &cstring(format!(
                "Showing {visible_count} of {} recent lines",
                shared.logs.len()
            )),
        );
        let new_generation = shared.log_generation != self.last_log_generation;
        self.last_log_generation = shared.log_generation;
        let id = cstring("recent_log_lines");
        let child = ui.child_horizontal(&id, 0.0, 0.0, true);
        if child.is_visible() {
            if visible_count == 0 {
                ui.text_colored(MUTED, &cstring("No messages match the selected levels."));
            }
            for line in &shared.logs {
                if !self.log_filters.accepts(line.level) {
                    continue;
                }
                ui.text_colored(log_color(line.level), &cstring(line.level.label()));
                ui.same_line();
                if self.log_show_context && (!line.timestamp.is_empty() || !line.source.is_empty())
                {
                    ui.text_colored(MUTED, &cstring(log_context(line)));
                    ui.same_line();
                }
                ui.text_colored(log_message_color(line.level), &cstring(&line.text));
            }
            if new_generation && self.log_auto_follow {
                ui.scroll_to_bottom();
            }
        }
    }
}

impl LogFilters {
    const fn all() -> Self {
        Self {
            trace: true,
            debug: true,
            info: true,
            warning: true,
            error: true,
        }
    }

    const fn important() -> Self {
        Self {
            trace: false,
            debug: false,
            info: false,
            warning: true,
            error: true,
        }
    }

    fn accepts(self, level: LogLevel) -> bool {
        match level {
            LogLevel::Trace => self.trace,
            LogLevel::Debug => self.debug,
            LogLevel::Info => self.info,
            LogLevel::Warning => self.warning,
            LogLevel::Error => self.error,
        }
    }
}

impl LogLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warning => "WARN ",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryHealth {
    Stable,
    Watch,
    Critical,
    Unknown,
}

impl MemoryHealth {
    fn from_snapshot(snapshot: &engine_fixes::DashboardSnapshot) -> Self {
        if snapshot.flags & engine_fixes::DASHBOARD_FLAG_VAS_VALID == 0 {
            return Self::Unknown;
        }
        const MB: u64 = 1024 * 1024;
        if snapshot.vas_largest_hole_bytes < 128 * MB {
            Self::Critical
        } else if snapshot.vas_largest_hole_bytes < 384 * MB || snapshot.vas_free_bytes < 512 * MB {
            Self::Watch
        } else {
            Self::Stable
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Stable => "STABLE",
            Self::Watch => "WATCH",
            Self::Critical => "CRITICAL",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn color(self) -> [f32; 4] {
        match self {
            Self::Stable => GOOD,
            Self::Watch => WARN,
            Self::Critical | Self::Unknown => ERROR,
        }
    }

    fn detail(self, snapshot: &engine_fixes::DashboardSnapshot) -> String {
        match self {
            Self::Unknown => "VAS walk unavailable".to_owned(),
            _ => format!("Largest opening {}", bytes(snapshot.vas_largest_hole_bytes)),
        }
    }
}

pub(crate) fn deferred_init() {
    if READY.swap(true, Ordering::AcqRel) {
        return;
    }
    if !engine_fixes::has_dashboard_api() {
        log::warn!("[DASHBOARD] Core dashboard API unavailable; helper remains passive");
        READY.store(false, Ordering::Release);
        return;
    }

    let shared = Arc::new(RwLock::new(SharedData::default()));
    let sampling = Arc::new(SamplingControl::default());
    let _ = SHARED.set(shared.clone());
    let _ = SAMPLING.set(sampling.clone());
    if let Err(error) = thread::Builder::new()
        .name("psycho-dashboard".to_owned())
        .spawn(move || sampling_worker(shared, sampling))
    {
        log::warn!("[DASHBOARD] Sampling worker unavailable: {error}");
    }
    RUNTIME.with(|runtime| {
        let _ = runtime.borrow();
    });
    log::info!("[DASHBOARD] Ready; press F10 or run PsychoInfo");
}

pub(crate) fn request_open() -> bool {
    if !READY.load(Ordering::Acquire) {
        return false;
    }
    OPEN_REQUESTED.store(true, Ordering::Release);
    true
}

pub(crate) fn on_frame_present() {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    if hooks::window_proc_installed()
        && !OPEN.load(Ordering::Acquire)
        && !OPEN_REQUESTED.load(Ordering::Acquire)
    {
        return;
    }
    let Some(handles) = game_render_handles() else {
        return;
    };
    if let Err(error) = hooks::ensure_window_proc(handles.input_hwnd) {
        log::warn!("[DASHBOARD] Input bridge unavailable: {error:#}");
        return;
    }
    RUNTIME.with(|runtime| {
        if let Ok(mut runtime) = runtime.try_borrow_mut() {
            runtime.render_present(handles);
        }
    });
}

pub(crate) fn before_device_reset(device: *mut c_void) {
    RUNTIME.with(|runtime| {
        let Ok(mut runtime) = runtime.try_borrow_mut() else {
            return;
        };
        if runtime.imgui_device == device as usize
            && let Some(imgui) = runtime.imgui.as_mut()
        {
            imgui.invalidate_device_objects();
            runtime.needs_device_objects = true;
        }
    });
}

pub(crate) fn after_device_reset(device: *mut c_void, succeeded: bool) {
    if !succeeded {
        return;
    }
    RUNTIME.with(|runtime| {
        let Ok(mut runtime) = runtime.try_borrow_mut() else {
            return;
        };
        if runtime.imgui_device == device as usize {
            runtime.needs_device_objects = true;
            if runtime.page == Page::Overview {
                runtime.texture_refresh_requested = true;
            }
        }
    });
}

pub(crate) fn handle_window_message(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> Option<isize> {
    if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) && wparam == DASHBOARD_KEY {
        RUNTIME.with(|runtime| {
            if let Ok(mut runtime) = runtime.try_borrow_mut() {
                let open = !runtime.open;
                runtime.set_open(open);
            }
        });
        return Some(0);
    }

    let mut captured = None;
    RUNTIME.with(|runtime| {
        let Ok(mut runtime) = runtime.try_borrow_mut() else {
            return;
        };
        if !runtime.open {
            return;
        }
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) && wparam == VK_ESCAPE {
            runtime.set_open(false);
            captured = Some(0);
            return;
        }
        if runtime.imgui.is_some() {
            let handled = unsafe { psycho_imgui::wndproc(hwnd, msg, wparam, lparam) };
            if handled != 0 || is_input_message(msg) {
                captured = Some(1);
            }
        } else if is_input_message(msg) {
            captured = Some(1);
        }
    });
    captured
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GameRenderHandles {
    device: *mut c_void,
    render_hwnd: *mut c_void,
    input_hwnd: *mut c_void,
}

impl GameRenderHandles {
    fn from_raw(
        device: *mut c_void,
        render_hwnd: *mut c_void,
        input_hwnd: *mut c_void,
    ) -> Option<Self> {
        (!device.is_null() && !render_hwnd.is_null() && !input_hwnd.is_null()).then_some(Self {
            device,
            render_hwnd,
            input_hwnd,
        })
    }

    fn windows_are_aliased(self) -> bool {
        self.render_hwnd == self.input_hwnd
    }
}

fn game_render_handles() -> Option<GameRenderHandles> {
    unsafe {
        let renderer = (NIDX9_RENDERER_SINGLETON_PTR as *const *mut c_void).read();
        if renderer.is_null() {
            return None;
        }
        let device =
            ((renderer as usize + NIDX9_RENDERER_DEVICE_OFFSET) as *const *mut c_void).read();
        let render_hwnd = (RENDERER_CHILD_HWND_PTR as *const *mut c_void).read();
        let input_hwnd = (TOP_LEVEL_HWND_PTR as *const *mut c_void).read();

        // Exclusive fullscreen aliases the renderer slot to the top-level
        // window. Windowed mode instead stores a WS_CHILD render target in the
        // renderer slot while keyboard/focus messages remain owned by the
        // top-level HWND. Keep both identities so neither mode accidentally
        // applies the other's input contract.
        GameRenderHandles::from_raw(device, render_hwnd, input_hwnd)
    }
}

fn sampling_worker(shared: Arc<RwLock<SharedData>>, control: Arc<SamplingControl>) {
    let mut log_reader = LogTailReader::default();
    loop {
        let request = control.wait_for_request();
        if request.refresh_vas {
            let _ = engine_fixes::request_dashboard_refresh(engine_fixes::DASHBOARD_REFRESH_VAS);
        }
        let core = engine_fixes::query_dashboard();
        let logs = request.logs.then(|| log_reader.refresh());
        {
            let mut output = shared.write();
            if core.is_some() {
                output.core = core;
                output.core_misses = 0;
            } else {
                output.core_misses = output.core_misses.saturating_add(1);
                if output.core_misses >= 3 {
                    output.core = None;
                }
            }
            if let Some(logs) = logs {
                match logs {
                    Ok(refresh) => {
                        let changed = refresh.reset || !refresh.lines.is_empty();
                        if refresh.reset {
                            output.logs.clear();
                        }
                        output.logs.extend(refresh.lines);
                        if output.logs.len() > MAX_LOG_LINES {
                            let excess = output.logs.len() - MAX_LOG_LINES;
                            output.logs.drain(..excess);
                        }
                        if changed {
                            output.log_generation = output.log_generation.wrapping_add(1);
                        }
                        output.log_error = None;
                    }
                    Err(error) => {
                        output.log_error = Some(format!("Log tail unavailable: {error:#}"));
                    }
                }
            }
        }
        control.complete_and_wait(request);
    }
}

impl LogTailReader {
    fn refresh(&mut self) -> anyhow::Result<LogRefresh> {
        let mut file = File::open(LOG_PATH)?;
        let length = file.metadata()?.len();
        let reset = !self.initialized
            || length < self.offset
            || length.saturating_sub(self.offset) > LOG_TAIL_BYTES;
        let start = if reset {
            length.saturating_sub(LOG_TAIL_BYTES)
        } else {
            self.offset
        };

        if reset {
            self.pending.clear();
        }
        file.seek(SeekFrom::Start(start))?;
        let read_limit = (length - start).min(LOG_TAIL_BYTES);
        let mut bytes = Vec::with_capacity(read_limit as usize);
        file.take(read_limit).read_to_end(&mut bytes)?;
        self.offset = start.saturating_add(bytes.len() as u64);
        self.initialized = true;

        let mut lines = self.ingest(&bytes, reset && start != 0);
        if lines.len() > MAX_LOG_LINES {
            lines.drain(..lines.len() - MAX_LOG_LINES);
        }
        Ok(LogRefresh { reset, lines })
    }

    fn ingest(&mut self, bytes: &[u8], skip_partial_prefix: bool) -> Vec<LogLine> {
        let bytes = if skip_partial_prefix {
            bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(&[][..], |index| &bytes[index + 1..])
        } else {
            bytes
        };

        self.pending.extend_from_slice(bytes);
        let Some(complete_len) = self
            .pending
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|index| index + 1)
        else {
            return Vec::new();
        };

        let remainder = self.pending.split_off(complete_len);
        let complete = std::mem::replace(&mut self.pending, remainder);
        String::from_utf8_lossy(&complete)
            .lines()
            .map(parse_log_line)
            .collect()
    }
}

fn parse_log_line(line: &str) -> LogLine {
    let Some((timestamp, after_timestamp)) = line.split_once(' ') else {
        return fallback_log_line(line);
    };
    let after_timestamp = after_timestamp.trim_start();
    let Some(level_end) = after_timestamp.find(char::is_whitespace) else {
        return fallback_log_line(line);
    };
    let Some(level) = parse_log_level(&after_timestamp[..level_end]) else {
        return fallback_log_line(line);
    };

    let mut message = after_timestamp[level_end..].trim_start();
    let mut source = String::new();
    if let Some(module_path) = message.strip_prefix('[')
        && let Some(module_end) = module_path.find(']')
    {
        source = compact_log_source(&module_path[..module_end]);
        message = module_path[module_end + 1..].trim_start();
    }

    LogLine {
        level,
        timestamp: compact_log_timestamp(timestamp),
        source,
        text: truncate_chars(message, MAX_LOG_LINE_CHARS),
    }
}

fn parse_log_level(level: &str) -> Option<LogLevel> {
    match level {
        "TRACE" => Some(LogLevel::Trace),
        "DEBUG" => Some(LogLevel::Debug),
        "INFO" => Some(LogLevel::Info),
        "WARN" | "WARNING" => Some(LogLevel::Warning),
        "ERROR" => Some(LogLevel::Error),
        _ => None,
    }
}

fn compact_log_timestamp(timestamp: &str) -> String {
    let time = timestamp
        .split_once('T')
        .map_or(timestamp, |(_, time)| time)
        .trim_end_matches('Z');
    time.split_once('.')
        .map_or(time, |(time, _)| time)
        .to_owned()
}

fn compact_log_source(source: &str) -> String {
    source.rsplit("::").next().unwrap_or(source).to_owned()
}

fn fallback_log_line(line: &str) -> LogLine {
    let level = if line.contains("[ERROR]") || line.contains(" error:") {
        LogLevel::Error
    } else if line.contains("[WARN]") || line.contains(" warning:") {
        LogLevel::Warning
    } else if line.contains("[TRACE]") {
        LogLevel::Trace
    } else if line.contains("[DEBUG]") {
        LogLevel::Debug
    } else {
        LogLevel::Info
    };
    LogLine {
        level,
        timestamp: String::new(),
        source: String::new(),
        text: truncate_chars(line, MAX_LOG_LINE_CHARS),
    }
}

fn truncate_chars(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let mut output: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        output.push_str(" ...");
    }
    output
}

fn draw_configuration(ui: &mut Ui<'_>, editor: &mut ConfigEditor) {
    page_heading(
        ui,
        "Configuration",
        "Edit Psycho settings safely without implying that they change the current session.",
    );
    notice_card(
        ui,
        "restart_configuration_notice",
        "Changes are not live. Saving updates the TOML file for the next full game launch; the current process keeps its startup configuration.",
        WARN,
    );
    ui.text_colored(MUTED, &cstring(editor.path.display().to_string()));

    let save = cstring("Save for next launch");
    if ui.button_colored(&save, SAVE_BUTTON, SAVE_HOVERED, SAVE_ACTIVE) {
        editor.save();
    }
    ui.same_line();
    let reload = cstring("Reload from disk");
    if ui.button_colored(&reload, RELOAD_BUTTON, RELOAD_HOVERED, RELOAD_ACTIVE) {
        editor.reload();
    }
    ui.same_line();
    ui.text_colored(
        if editor.is_dirty() { WARN } else { GOOD },
        &cstring(if editor.is_dirty() {
            "Unsaved changes"
        } else {
            "Saved file matches"
        }),
    );
    if let Some(error) = &editor.error {
        ui.text_colored(ERROR, &cstring(error));
    } else if let Some(notice) = &editor.notice {
        ui.text_colored(GOOD, &cstring(notice));
    }

    let config = &mut editor.draft;
    ui.spacing();
    ui.separator_text(&cstring("Memory allocator"));
    ui.text_colored(
        MUTED,
        &cstring("Takes effect only during the next early startup."),
    );
    ui.text_colored(MUTED, &cstring(HOVER_HELP_HINT));
    for (index, label, help) in [
        (
            0,
            "Vanilla allocators",
            "Uses the original New Vegas main and temporary heaps. Choose this only for an allocator-free compatibility comparison.",
        ),
        (
            1,
            "Scrap heap only",
            "Replaces short-lived temporary allocations but leaves the main game-object heap original. This is the lower-risk compatibility mode.",
        ),
        (
            2,
            "Full gheap + scrap heap",
            "Uses Psycho's complete main and temporary heap replacement for the best allocator performance. Validate it with your modlist.",
        ),
    ] {
        if index != 0 {
            ui.same_line();
        }
        if radio_help(ui, label, config.allocator == index, help) {
            config.allocator = index;
        }
    }
    checkbox_help(
        ui,
        "Periodic full PDD purge (experimental)",
        &mut config.gheap_periodic_pdd_purge,
        "PDD means Process Deferred Destruction: the game's queues for objects waiting to be destroyed. A forced full drain can stall, so keep this experiment off for normal play.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Engine safety"));
    ui.text_colored(
        MUTED,
        &cstring("Keep these enabled unless isolating a confirmed conflict."),
    );
    let engine_fix_values: [&mut bool; ENGINE_FIX_HELP.len()] = [
        &mut config.display_alt_tab,
        &mut config.save_integrity_fix,
        &mut config.navmesh_low_pointer_guard,
        &mut config.entrydata_invalid_form_guard,
        &mut config.actor_container_retirement_guard,
        &mut config.extraownership_invalid_owner_guard,
        &mut config.linked_ref_children_stale_list_guard,
        &mut config.linked_ref_target_base_form_guard,
        &mut config.ragdoll_null_bone_guard,
        &mut config.ragdoll_detached_phantom_guard,
        &mut config.havok_add_entity_batch_null_guard,
        &mut config.havok_pending_add_null_guard,
        &mut config.havok_narrowphase_invalid_pair_guard,
        &mut config.havok_post_add_null_entity_guard,
        &mut config.havok_remove_agent_null_reread_guard,
        &mut config.memset_null_dst_guard,
        &mut config.lowprocess_generic_locations_fix,
        &mut config.model_postprocess_serialization_fix,
        &mut config.queued_task_lifetime_guard,
    ];
    for ((label, help), value) in ENGINE_FIX_HELP.into_iter().zip(engine_fix_values) {
        checkbox_help(ui, label, value, help);
    }

    ui.spacing();
    ui.separator_text(&cstring("IO and LOD streaming"));
    checkbox_help(
        ui,
        "Parallel native IO",
        &mut config.parallel_io,
        "Uses two game-owned loading workers while serializing engine state that is unsafe to build concurrently.",
    );
    checkbox_help(
        ui,
        "LOD system",
        &mut config.lod_enabled,
        "Enables Psycho's distant-world streaming fixes. LOD means the lower-detail terrain, trees, and objects shown far away.",
    );
    checkbox_help(
        ui,
        "LOD prefetch",
        &mut config.lod_prefetch_enabled,
        "Requests distant terrain, trees, and objects slightly before they become visible to reduce pop-in while moving.",
    );
    checkbox_help(
        ui,
        "LOD handoff repair",
        &mut config.lod_handoff_fix_enabled,
        "Prevents stale lifetime counters from retiring distant scenery during its switch to the nearby full-detail version.",
    );
    checkbox_help(
        ui,
        "LOD priority boost",
        &mut config.lod_priority_boost_enabled,
        "Raises native distant-world loading tasks within the game's own queue so visible scenery is prepared sooner.",
    );
    precise_multiplier(
        ui,
        "Object prefetch",
        "object_prefetch",
        &mut config.object_prefetch_multiplier,
        "How early distant buildings and other objects are requested. Higher reduces pop-in but keeps more work in flight.",
    );
    precise_multiplier(
        ui,
        "Object retention",
        "object_retention",
        &mut config.object_retention_multiplier,
        "How long distant objects remain loaded behind the player. Higher reduces reload churn but uses more memory.",
    );
    precise_multiplier(
        ui,
        "Tree prefetch",
        "tree_prefetch",
        &mut config.tree_prefetch_multiplier,
        "How early distant trees are requested. Higher reduces tree pop-in but keeps more work in flight.",
    );
    precise_multiplier(
        ui,
        "Tree retention",
        "tree_retention",
        &mut config.tree_retention_multiplier,
        "How long distant trees remain loaded after leaving view. Higher reduces reload churn but uses more memory.",
    );
    precise_multiplier(
        ui,
        "Terrain prefetch",
        "terrain_prefetch",
        &mut config.terrain_prefetch_multiplier,
        "How early distant landscape is requested. Higher can smooth fast travel through the world at a memory and loading cost.",
    );
    precise_multiplier(
        ui,
        "Terrain retention",
        "terrain_retention",
        &mut config.terrain_retention_multiplier,
        "How long distant landscape remains loaded behind the player. Higher reduces reloads but uses more memory.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Performance"));
    checkbox_help(
        ui,
        "Fast RNG",
        &mut config.rng,
        "Uses a faster random-number generator for compatible engine calls. It changes the random sequence, not the intended probability.",
    );
    checkbox_help(
        ui,
        "Fast zlib",
        &mut config.zlib,
        "Uses faster compatible decompression for save and archive data, reducing CPU time while loading compressed content.",
    );
    checkbox_help(
        ui,
        "Post-load reconciliation prepass",
        &mut config.post_load_reconciliation_prepass,
        "Performs one focused cleanup pass before normal post-load work so stale references are reconciled in a safer order.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Diagnostics"));
    checkbox_help(
        ui,
        "Detailed debug log",
        &mut config.debug_log,
        "Writes detailed startup, memory, loading, and safety information for troubleshooting. Recommended for useful bug reports.",
    );
    checkbox_help(
        ui,
        "Separate Windows console",
        &mut config.console,
        "Opens a separate live text console for Psycho logs. It is mainly useful while actively debugging.",
    );
    checkbox_help(
        ui,
        "Hitch profiling",
        &mut config.hitch_profiling,
        "Records timing details for slow frames and allocator waits. Enable only while investigating stutter because it adds diagnostics.",
    );
    checkbox_help(
        ui,
        "Queued-task lifetime trace",
        &mut config.task_lifetime_trace,
        "Adds verbose task ownership events to the log. Enable only when investigating a queued-task crash.",
    );
    checkbox_help(
        ui,
        "LOD streaming trace",
        &mut config.lod_streaming_trace,
        "Adds verbose distant-world streaming events to the log. Enable only when investigating LOD pop-in or lifetime issues.",
    );
}

fn precise_multiplier(ui: &mut Ui<'_>, label: &str, id: &str, value: &mut f32, help: &str) {
    ui.precise_float(
        &cstring(label),
        &cstring(id),
        value,
        1.0,
        2.0,
        0.01,
        0.1,
        false,
    );
    hover_help(ui, help);
}

fn page_heading(ui: &mut Ui<'_>, title: &str, subtitle: &str) {
    ui.text_colored(ACCENT, &cstring(title));
    ui.text_colored(MUTED, &cstring(subtitle));
    ui.spacing();
}

fn notice_card(ui: &mut Ui<'_>, id: &str, text: &str, color: [f32; 4]) {
    let child = ui.child(&cstring(id), 0.0, 82.0, true);
    if child.is_visible() {
        ui.text_colored(color, &cstring("GUIDANCE"));
        ui.text_wrapped(&cstring(text));
    }
}

#[allow(clippy::too_many_arguments)]
fn telemetry_card(
    ui: &mut Ui<'_>,
    id: &str,
    title: &str,
    value: String,
    delta: String,
    delta_color: [f32; 4],
    history: &History,
    scale_min: f32,
    scale_max: f32,
    warning_threshold: f32,
    critical_threshold: f32,
    danger_below: bool,
    line_color: [f32; 4],
    fill_color: [f32; 4],
    warning_label: &str,
    critical_label: &str,
    detail: &str,
    width: f32,
) {
    let child = ui.child(&cstring(id), width, 226.0, true);
    if !child.is_visible() {
        return;
    }

    ui.text_colored(MUTED, &cstring(title));
    hover_help(ui, detail);
    ui.text_colored(line_color, &cstring(value));
    ui.same_line();
    ui.text_colored(delta_color, &cstring(delta));

    if history.values().len() > 1 {
        let warning_label = cstring(warning_label);
        let critical_label = cstring(critical_label);
        let suffix = cstring(" MiB");
        let chart = TelemetryChart {
            values: history.values(),
            scale_min,
            scale_max,
            width: 0.0,
            height: 112.0,
            warning_threshold,
            critical_threshold,
            danger_below,
            sample_interval_seconds: SAMPLE_INTERVAL.as_secs_f32(),
            impulse_from_zero: false,
            line_color,
            fill_color,
            warning_label: &warning_label,
            critical_label: &critical_label,
            value_suffix: &suffix,
        };
        ui.telemetry_chart(&cstring(format!("##{id}_timeline")), &chart);
    } else {
        let collecting = ui.child(&cstring(format!("##{id}_empty")), 0.0, 112.0, true);
        if collecting.is_visible() {
            ui.text_colored(MUTED, &cstring("Collecting trend samples..."));
        }
    }
    ui.text_wrapped(&cstring(detail));
}

fn padded_history_bounds(history: &History, minimum_span: f32, floor: f32) -> (f32, f32) {
    let minimum = history.min().unwrap_or(floor).max(floor);
    let maximum = history.max().unwrap_or(floor + minimum_span).max(minimum);
    let span = (maximum - minimum).max(minimum_span);
    ((minimum - span * 0.15).max(floor), maximum + span * 0.15)
}

fn history_delta_label(delta: f32) -> String {
    if delta.abs() < 0.5 {
        return "No net change".to_owned();
    }
    format!("{delta:+.0} MiB over window")
}

fn history_delta_color(delta: f32, good_when_positive: bool) -> [f32; 4] {
    if delta.abs() < 0.5 {
        MUTED
    } else if (delta > 0.0) == good_when_positive {
        GOOD
    } else {
        WARN
    }
}

fn metric_card(
    ui: &mut Ui<'_>,
    id: &str,
    label: &str,
    value: &str,
    color: [f32; 4],
    detail: impl AsRef<str>,
    width: f32,
    help: &str,
) {
    let child = ui.child(&cstring(id), width, 104.0, true);
    if child.is_visible() {
        ui.text_colored(MUTED, &cstring(label));
        hover_help(ui, help);
        ui.text_colored(color, &cstring(value));
        ui.text_wrapped(&cstring(detail));
    }
}

fn draw_value(ui: &mut Ui<'_>, label: &str, value: impl std::fmt::Display, color: [f32; 4]) {
    ui.label_value(&cstring(label), &cstring(value.to_string()), color);
}

fn draw_value_help(
    ui: &mut Ui<'_>,
    label: &str,
    value: impl std::fmt::Display,
    color: [f32; 4],
    help: &str,
) {
    draw_value(ui, label, value, color);
    hover_help(ui, help);
}

fn tier_bar_help(
    ui: &mut Ui<'_>,
    label: &str,
    live: u64,
    capacity: u64,
    detail: String,
    help: &str,
) {
    let fraction = if capacity == 0 {
        0.0
    } else {
        (live as f64 / capacity as f64).clamp(0.0, 1.0) as f32
    };
    ui.label_value(&cstring(label), &cstring(detail), MUTED);
    hover_help(ui, help);
    let overlay = cstring(format!("{} / {}", bytes(live), bytes(capacity)));
    ui.progress_bar(fraction, ui.content_region_available_width(), 0.0, &overlay);
    hover_help(ui, help);
}

fn checkbox_help(ui: &mut Ui<'_>, label: &str, value: &mut bool, help: &str) -> bool {
    let changed = ui.checkbox(&cstring(label), value);
    hover_help(ui, help);
    changed
}

fn radio_help(ui: &mut Ui<'_>, label: &str, active: bool, help: &str) -> bool {
    let clicked = ui.radio_button(&cstring(label), active);
    hover_help(ui, help);
    clicked
}

fn hover_help(ui: &mut Ui<'_>, help: &str) {
    ui.hover_help(&cstring(help));
}

fn log_context(line: &LogLine) -> String {
    match (line.timestamp.is_empty(), line.source.is_empty()) {
        (false, false) => format!("{}  {}", line.timestamp, line.source),
        (false, true) => line.timestamp.clone(),
        (true, false) => line.source.clone(),
        (true, true) => String::new(),
    }
}

fn feature_status(ui: &mut Ui<'_>, name: &str, active: bool, detail: &str, help: &str) {
    ui.text_colored(ACCENT, &cstring(name));
    hover_help(ui, help);
    ui.same_line();
    ui.text_colored(
        if active { GOOD } else { WARN },
        &cstring(if active { "Active" } else { "Not active" }),
    );
    ui.text_colored(MUTED, &cstring(detail));
    ui.spacing();
}

fn allocator_name(mode: u32) -> &'static str {
    match mode {
        0 => "VANILLA",
        1 => "SCRAP ONLY",
        2 => "FULL GHEAP",
        _ => "STARTING",
    }
}

fn bytes(value: u64) -> String {
    format_bytes(value.min(usize::MAX as u64) as usize)
}

fn sample_age_seconds(sample_time_ms: u64) -> u64 {
    if sample_time_ms == 0 {
        return 0;
    }
    u64::from(libpsycho::os::windows::winapi::get_tick_count().wrapping_sub(sample_time_ms as u32))
        / 1_000
}

fn take_driver_refresh(page: Page, requested: &mut bool) -> bool {
    if page != Page::Overview || !*requested {
        return false;
    }
    *requested = false;
    true
}

fn compact_count(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.1}M", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}K", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

fn counter_color(value: u64) -> [f32; 4] {
    if value == 0 { GOOD } else { WARN }
}

fn log_color(level: LogLevel) -> [f32; 4] {
    match level {
        LogLevel::Error => ERROR,
        LogLevel::Warning => WARN,
        LogLevel::Info => GOOD,
        LogLevel::Debug => BLUE,
        LogLevel::Trace => MUTED,
    }
}

fn log_message_color(level: LogLevel) -> [f32; 4] {
    match level {
        LogLevel::Error => [1.0, 0.72, 0.70, 1.0],
        LogLevel::Warning => [0.94, 0.84, 0.65, 1.0],
        LogLevel::Info => [0.80, 0.87, 0.83, 1.0],
        LogLevel::Debug => [0.68, 0.77, 0.74, 1.0],
        LogLevel::Trace => [0.53, 0.61, 0.58, 1.0],
    }
}

fn is_input_message(msg: u32) -> bool {
    matches!(
        msg,
        WM_KEYDOWN
            | WM_SYSKEYDOWN
            | WM_KEYUP
            | WM_SYSKEYUP
            | WM_CHAR
            | WM_MOUSEMOVE
            | WM_LBUTTONDOWN
            | WM_LBUTTONUP
            | WM_RBUTTONDOWN
            | WM_RBUTTONUP
            | WM_MBUTTONDOWN
            | WM_MBUTTONUP
            | WM_MOUSEWHEEL
            | WM_MOUSEHWHEEL
    )
}

fn cstring(text: impl AsRef<str>) -> CString {
    let mut bytes = text.as_ref().as_bytes().to_vec();
    for byte in &mut bytes {
        if *byte == 0 {
            *byte = b' ';
        }
    }
    bytes.push(0);
    unsafe { CString::from_vec_with_nul_unchecked(bytes) }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use super::{
        ENGINE_FIX_HELP, GameRenderHandles, LogFilters, LogLevel, LogTailReader, MemoryHealth,
        Page, SamplingState, parse_log_line, take_driver_refresh,
    };
    use crate::engine_fixes::{DASHBOARD_FLAG_VAS_VALID, DashboardSnapshot};

    #[test]
    fn health_uses_contiguous_vas_not_only_total_free() {
        let mut snapshot = DashboardSnapshot {
            flags: DASHBOARD_FLAG_VAS_VALID,
            vas_free_bytes: 900 * 1024 * 1024,
            vas_largest_hole_bytes: 96 * 1024 * 1024,
            ..DashboardSnapshot::default()
        };
        assert_eq!(
            MemoryHealth::from_snapshot(&snapshot),
            MemoryHealth::Critical
        );
        snapshot.vas_largest_hole_bytes = 256 * 1024 * 1024;
        assert_eq!(MemoryHealth::from_snapshot(&snapshot), MemoryHealth::Watch);
        snapshot.vas_largest_hole_bytes = 512 * 1024 * 1024;
        assert_eq!(MemoryHealth::from_snapshot(&snapshot), MemoryHealth::Stable);
    }

    #[test]
    fn windowed_dashboard_retains_distinct_render_and_input_windows() {
        let device = 0x1000usize as *mut c_void;
        let render_hwnd = 0x2000usize as *mut c_void;
        let input_hwnd = 0x3000usize as *mut c_void;
        let handles = GameRenderHandles::from_raw(device, render_hwnd, input_hwnd)
            .expect("all live handles form a usable dashboard target");

        assert_eq!(handles.render_hwnd, render_hwnd);
        assert_eq!(handles.input_hwnd, input_hwnd);
        assert!(!handles.windows_are_aliased());

        let fullscreen = GameRenderHandles::from_raw(device, input_hwnd, input_hwnd)
            .expect("fullscreen aliases both window roles");
        assert!(fullscreen.windows_are_aliased());
        assert!(GameRenderHandles::from_raw(device, render_hwnd, std::ptr::null_mut()).is_none());
    }

    #[test]
    fn every_engine_fix_has_concise_unique_hover_help() {
        assert_eq!(ENGINE_FIX_HELP.len(), 19);
        let mut labels = std::collections::BTreeSet::new();
        for (label, help) in ENGINE_FIX_HELP {
            assert!(!label.trim().is_empty());
            assert!(labels.insert(label), "duplicate engine-fix label: {label}");
            assert!(
                (40..=240).contains(&help.len()),
                "hover help should be concise and useful: {label} ({})",
                help.len(),
            );
            assert!(
                help.is_ascii(),
                "hover help must remain safe for the game UI font: {label}",
            );
        }
    }

    #[test]
    fn log_parser_extracts_readable_context_and_all_levels() {
        let parsed = parse_log_line(
            "2026-07-20T23:40:03.467Z DEBUG [psycho_engine_fixes::mods::heap_replacer::gheap::watchdog] [MEM] Pool status",
        );
        assert_eq!(parsed.level, LogLevel::Debug);
        assert_eq!(parsed.timestamp, "23:40:03");
        assert_eq!(parsed.source, "watchdog");
        assert_eq!(parsed.text, "[MEM] Pool status");

        for (name, expected) in [
            ("TRACE", LogLevel::Trace),
            ("DEBUG", LogLevel::Debug),
            ("INFO", LogLevel::Info),
            ("WARN", LogLevel::Warning),
            ("ERROR", LogLevel::Error),
        ] {
            let parsed = parse_log_line(&format!("2026-07-20T23:40:03Z {name} [module] text"));
            assert_eq!(parsed.level, expected);
        }
    }

    #[test]
    fn log_filters_can_isolate_verbose_and_important_messages() {
        let important = LogFilters::important();
        assert!(important.accepts(LogLevel::Error));
        assert!(important.accepts(LogLevel::Warning));
        assert!(!important.accepts(LogLevel::Info));
        assert!(!important.accepts(LogLevel::Debug));
        assert!(!important.accepts(LogLevel::Trace));

        assert!(LogFilters::all().accepts(LogLevel::Trace));
    }

    #[test]
    fn closed_dashboard_has_no_sampling_request() {
        let closed = SamplingState::default();
        assert_eq!(closed.request(), None);

        let telemetry = SamplingState {
            active: true,
            logs: false,
            refresh_vas: false,
            generation: 1,
        }
        .request()
        .expect("open dashboard requests telemetry");
        assert!(!telemetry.logs);

        let logs = SamplingState {
            active: true,
            logs: true,
            refresh_vas: false,
            generation: 2,
        }
        .request()
        .expect("log page requests telemetry");
        assert!(logs.logs);

        let refresh = SamplingState {
            active: true,
            logs: false,
            refresh_vas: true,
            generation: 3,
        }
        .request()
        .expect("manual VAS refresh wakes the sampler");
        assert!(refresh.refresh_vas);
    }

    #[test]
    fn driver_estimate_is_page_and_request_driven() {
        let mut requested = true;
        assert!(!take_driver_refresh(Page::Memory, &mut requested));
        assert!(requested);
        assert!(take_driver_refresh(Page::Overview, &mut requested));
        assert!(!requested);
        assert!(!take_driver_refresh(Page::Overview, &mut requested));
    }

    #[test]
    fn log_tail_parses_only_complete_incremental_lines() {
        let mut reader = LogTailReader::default();
        let first = reader.ingest(b"first\npart", false);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].text, "first");

        let second = reader.ingest(b"ial\nsecond\n", false);
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].text, "partial");
        assert_eq!(second[1].text, "second");

        let tailed = reader.ingest(b"discarded prefix\nkept\n", true);
        assert_eq!(tailed.len(), 1);
        assert_eq!(tailed[0].text, "kept");
    }
}
