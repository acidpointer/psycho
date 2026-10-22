//! In-game Psycho control deck.
//!
//! The helper renders core-owned, read-only telemetry and edits a separate
//! restart-only configuration draft. Runtime data arrives through the
//! late-bound fixed-width ABI in `engine_fixes`; the UI never loads the core,
//! initializes it, or mutates live engine-fix state. Expensive process and log
//! work stays on the dashboard worker.

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
    time::Duration,
};

use libpsycho::os::windows::directx9::Device9Ref;
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

const HOVER_HELP_HINT: &str = "Hover any setting for a short, plain-language explanation.";

const ENGINE_FIX_HELP: [(&str, &str); 32] = [
    (
        "Fullscreen / Alt-Tab fix",
        "Fixes broken fullscreen size, placement, and Alt-Tab behavior. Normal window handling stays unchanged.",
    ),
    (
        "Save file integrity",
        "Writes saves durably and rejects corrupt load records. A failed save never replaces your previous save.",
    ),
    (
        "Pathfinding pointer guard",
        "Treats a tiny invalid pathfinding pointer as no path instead of crashing. Valid paths are unchanged.",
    ),
    (
        "Inventory entry guard",
        "Drops broken inventory entries during save or load. Inventory save guard rejects the whole save instead when active.",
    ),
    (
        "Inventory save guard",
        "Rejects broken inventory saves instead of crashing. Valid inventories are unchanged; a failed save keeps your previous save. Requires Save file integrity.",
    ),
    (
        "Actor container guard",
        "Detaches a corrupt generated-actor inventory list before destruction. Valid lists are untouched; a corrupt list may leak.",
    ),
    (
        "Inventory reset guard",
        "Skips inventory resets with broken base-item lists instead of crashing. Valid inventories are unchanged; rejected resets leave items untouched.",
    ),
    (
        "Animation cleanup guard",
        "Prevents a crash when a broken animation is cleaned up. Valid animations are unchanged.",
    ),
    (
        "Ownership data guard",
        "Treats an invalid item owner as no owner instead of following a bad pointer. Valid ownership is unchanged.",
    ),
    (
        "Encounter-zone guard",
        "Removes an invalid encounter-zone link and falls back to a valid cell or worldspace zone.",
    ),
    (
        "Patrol owner guard",
        "Ignores a stale patrol owner ID that now belongs to a different kind of form. Valid patrols are unchanged.",
    ),
    (
        "Cell cleanup fix",
        "Removes a dead reference from its cell render list before it is used. Live references are untouched.",
    ),
    (
        "Linked-reference cleanup",
        "Ignores a stale linked-reference child list during a save transition. Valid links are unchanged.",
    ),
    (
        "Linked-reference target guard",
        "Skips a linked reference whose target has a broken base form. Valid links still work.",
    ),
    (
        "Object fading guard",
        "Skips unreadable actor links during object fading instead of crashing. Normal fading is unchanged.",
    ),
    (
        "Scene owner guard",
        "Skips unreadable object links during physics lookups instead of crashing. Valid links are unchanged.",
    ),
    (
        "Occlusion link guard",
        "Skips occlusion-plane data without native read and cache-write access during visibility checks. Valid occlusion is unchanged.",
    ),
    (
        "List cleanup guard",
        "Stops cleanup at broken list links instead of crashing. Valid lists are unchanged; a damaged tail may leak.",
    ),
    (
        "Ragdoll bone guard",
        "Skips a ragdoll update until its bone table is ready, then retries. Normal ragdolls are unchanged.",
    ),
    (
        "Ragdoll raycast guard",
        "Treats a ragdoll raycast against a detached physics body as no hit for that frame.",
    ),
    (
        "Physics add-batch guard",
        "Skips empty slots when adding physics entities. Valid entities still load.",
    ),
    (
        "Physics pending-add guard",
        "Skips empty slots in the pending physics add list. Valid pending objects still load.",
    ),
    (
        "Physics collision-pair guard",
        "Drops an invalid collision pair before physics dispatch. Valid collisions are unchanged.",
    ),
    (
        "Physics callback guard",
        "Skips the AddedToWorld callback when physics supplies no entity. Valid callbacks still run.",
    ),
    (
        "Physics unlock guard",
        "Removes an unsafe second read during physics-agent removal. The required unlock is preserved.",
    ),
    (
        "Out-of-memory write guard",
        "Stops two out-of-memory paths from writing through a null pointer. It also aborts an incomplete texture conversion instead of crashing.",
    ),
    (
        "Actor location-list guard",
        "Keeps actor location lists from freeing references they do not own, and contains corrupt entries while saving.",
    ),
    (
        "Model load serialization",
        "Prevents model loading from racing over shared model-processing state. Model output is unchanged.",
    ),
    (
        "Model cache guard",
        "Ignores a model-cache entry with a missing name instead of crashing. Valid model lookups are unchanged.",
    ),
    (
        "Queued-task guard",
        "Rejects dead or malformed background tasks before dispatch or release. Valid tasks are unchanged.",
    ),
    (
        "Texture cache guard",
        "Rejects an invalid texture-cache object before its callbacks are used. Valid textures are unchanged.",
    ),
    (
        "Tile cleanup guard",
        "Removes empty slots from a UI tile value list before lookup. Valid tile values are untouched.",
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

/// Header-level connection state for the core telemetry.
///
/// A never-seen core is still starting, which is not an error; only a core
/// that produced telemetry and then stopped is reported as offline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoreLink {
    Connecting,
    Starting,
    Connected,
    Offline,
}

impl CoreLink {
    fn from_parts(core: Option<engine_fixes::DashboardSnapshot>, ever_linked: bool) -> Self {
        match core {
            Some(core) if core.flags & engine_fixes::DASHBOARD_FLAG_CORE_READY != 0 => {
                Self::Connected
            }
            Some(_) => Self::Starting,
            None if ever_linked => Self::Offline,
            None => Self::Connecting,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Connecting => "CONNECTING",
            Self::Starting => "STARTING",
            Self::Connected => "CONNECTED",
            Self::Offline => "CORE OFFLINE",
        }
    }

    fn color(self) -> [f32; 4] {
        match self {
            Self::Connected => GOOD,
            Self::Starting | Self::Connecting => MUTED,
            Self::Offline => ERROR,
        }
    }
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
    /// Last successfully published core snapshot.
    ///
    /// A momentary shared-lock miss while the sampling worker publishes must
    /// not be presented as a nested telemetry failure, so the render thread
    /// keeps rendering this snapshot until the worker reports real offline
    /// state.
    last_core: Option<engine_fixes::DashboardSnapshot>,
    /// Whether the core has ever produced a snapshot this session.
    ///
    /// Distinguishes the initial "connecting" state from a core that stopped
    /// responding, which the header reports differently.
    ever_linked: bool,
    texture_memory_estimate: u64,
    texture_sample_time_ms: u32,
    texture_refresh_requested: bool,
    log_filters: LogFilters,
    log_show_context: bool,
    log_auto_follow: bool,
    log_query: String,
    last_log_generation: u64,
    /// A first Reload click that is waiting for a confirming second click.
    pending_reload: bool,
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
            last_core: None,
            ever_linked: false,
            texture_memory_estimate: 0,
            texture_sample_time_ms: 0,
            texture_refresh_requested: false,
            log_filters: LogFilters::default(),
            log_show_context: false,
            log_auto_follow: true,
            log_query: String::new(),
            last_log_generation: 0,
            pending_reload: false,
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

    /// Abandon an open request that cannot produce a drawable frame.
    ///
    /// Blocking the game's DirectInput with no visible overlay is worse than a
    /// failed open, so a hard initialization failure restores input and logs
    /// once. A later F10 retries cleanly.
    fn fail_open(&mut self, message: String) {
        if self.ui_error.as_deref() != Some(message.as_str()) {
            log::warn!("[DASHBOARD] Cannot show dashboard: {message}");
        }
        self.ui_error = Some(message);
        self.set_open(false);
    }

    fn render_present(&mut self, handles: GameRenderHandles) {
        if OPEN_REQUESTED.swap(false, Ordering::AcqRel) {
            self.set_open(true);
        }
        if !self.open {
            return;
        }

        let Some(device) = (unsafe { Device9Ref::from_raw_void(handles.device) }) else {
            self.fail_open("The Direct3D9 device is unavailable.".to_owned());
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
                self.fail_open(format!("Device reset bridge failed: {error:#}"));
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
                    self.fail_open(format!("ImGui initialization failed: {error}"));
                    return;
                }
            }
        }
        if self.needs_device_objects {
            let Some(imgui) = self.imgui.as_mut() else {
                return;
            };
            // Device-object creation can fail transiently across a Reset or
            // Alt-Tab. Keep the request open and retry on the next frame
            // instead of cancelling the overlay.
            if !imgui.create_device_objects() {
                return;
            }
            self.needs_device_objects = false;
        }

        if take_driver_refresh(self.page, &mut self.texture_refresh_requested) {
            self.texture_memory_estimate = u64::from(device.available_texture_mem());
            self.texture_sample_time_ms = libpsycho::os::windows::winapi::get_tick_count();
        }

        let Some(mut imgui) = self.imgui.take() else {
            return;
        };
        let mut ui = imgui.new_frame(self.open);
        let keep_open = if self.open { self.draw(&mut ui) } else { true };
        drop(ui);
        imgui.render();
        self.imgui = Some(imgui);
        if self.open && !keep_open {
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
        // A `try_read` miss only means the sampling worker held the lock for a
        // few microseconds. Render the last published snapshot instead of
        // flashing the offline state. Only a real "no snapshot" publication
        // (the worker's own offline escalation) clears it.
        let lock_busy = shared.is_some() && guard.is_none();
        let sampled = guard.as_ref().and_then(|data| data.core);
        let core = if lock_busy {
            self.last_core
        } else {
            if sampled.is_some() {
                self.ever_linked = true;
            }
            self.last_core = sampled;
            sampled
        };
        if let Some(core) = core {
            self.update_core_history(core);
        }
        let link = CoreLink::from_parts(core, self.ever_linked);

        self.draw_header(ui, link);
        ui.separator();
        let available = ui.content_region_available_width().max(1.0);
        let nav_width = (available * 0.20).clamp(190.0, 250.0);
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
                    Page::Overview => self.draw_overview(ui, core, link),
                    Page::Memory => self.draw_memory(ui, core),
                    Page::Runtime => self.draw_runtime(ui, core),
                    Page::Configuration => {
                        draw_configuration(ui, &mut self.config, &mut self.pending_reload)
                    }
                    Page::Logs => self.draw_logs(ui, guard.as_deref()),
                }
            }
        }
        open
    }

    fn draw_header(&self, ui: &mut Ui<'_>, link: CoreLink) {
        ui.text_colored(ACCENT, &cstring("PSYCHO ENGINE FIXES"));
        ui.same_line();
        ui.text_colored(link.color(), &cstring(link.label()));
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
        ui.separator_text(&cstring("Pages"));
        let previous_page = self.page;
        for (page, label) in [
            (Page::Overview, "Overview"),
            (Page::Memory, "Memory"),
            (Page::Runtime, "Runtime"),
            (Page::Configuration, "Configuration"),
            (Page::Logs, "Logs"),
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
            "Telemetry refreshes every 1.5 seconds. Settings apply after a full game restart.",
        ));
        ui.spacing();
        ui.text_wrapped_colored(
            MUTED,
            &cstring("F10 toggles this dashboard. Esc closes it."),
        );
        ui.text_wrapped_colored(MUTED, &cstring("Reopen any time with F10 or PsychoInfo."));
    }

    fn draw_overview(
        &mut self,
        ui: &mut Ui<'_>,
        core: Option<engine_fixes::DashboardSnapshot>,
        link: CoreLink,
    ) {
        page_heading(
            ui,
            "Overview",
            "A concise health check for the current game session.",
        );
        ui.text_colored(MUTED, &cstring(HOVER_HELP_HINT));
        ui.separator_text(&cstring("Session status"));
        let Some(core) = core else {
            let message = match link {
                CoreLink::Offline => {
                    "Core telemetry stopped responding. Check psycho-engine-fixes-latest.log."
                }
                _ => "Waiting for psycho_engine_fixes.dll telemetry...",
            };
            ui.text_colored(link.color(), &cstring(message));
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
            MUTED,
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
        ui.text_colored(
            MUTED,
            &cstring(
                "For the full address-space and allocator breakdown, open the Memory dashboard.",
            ),
        );
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
            activity_color(core.pool_exhaustions),
            "A small-object pool had no immediately available cell, so Psycho served the request through a larger fallback tier. Occasional events are recoverable.",
        );
        draw_value_help(
            ui,
            "Block-tier overflows",
            core.block_overflows,
            activity_color(core.block_overflows),
            "A medium allocation could not fit in the existing block slots and had to use another supported allocation path.",
        );
        draw_value_help(
            ui,
            "Block reserve/commit failures",
            core.block_failures,
            alert_color(core.block_failures),
            "Windows refused to reserve address space or back pages for a medium block. Any nonzero count is important in a memory-related bug report.",
        );
        draw_value_help(
            ui,
            "Direct VA failures",
            core.direct_failures,
            alert_color(core.direct_failures),
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
            "Runtime dashboard",
            "Live counters for the protections and streaming fixes Psycho installed this session.",
        );
        ui.text_colored(MUTED, &cstring(HOVER_HELP_HINT));
        let Some(core) = core else {
            ui.text_colored(ERROR, &cstring("Runtime telemetry is unavailable."));
            return;
        };

        draw_occlusion_board(ui, &core);
        draw_safety_board(ui, &core);
        draw_streaming_board(ui, &core);
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
        hover_help(
            ui,
            "Follows the newest line only while you are already at the bottom, so scrolling back does not fight the stream.",
        );
        input_text_string(
            ui,
            "Filter",
            &mut self.log_query,
            "Case-insensitive text filter over the message, module, and compact timestamp.",
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

        let query = self.log_query.trim().to_ascii_lowercase();
        let visible_count = shared
            .logs
            .iter()
            .filter(|line| log_line_visible(line, self.log_filters, &query))
            .count();
        ui.text_colored(
            MUTED,
            &cstring(format!(
                "Showing {visible_count} of {} buffered lines (newest {})",
                shared.logs.len(),
                MAX_LOG_LINES
            )),
        );
        ui.same_line();
        if ui.button(&cstring("Copy visible")) {
            let report = collect_visible_log(
                &shared.logs,
                self.log_filters,
                &query,
                self.log_show_context,
            );
            ui.set_clipboard_text(&cstring(report));
        }
        hover_help(
            ui,
            "Copies the currently visible lines to the clipboard for a support report.",
        );

        let new_generation = shared.log_generation != self.last_log_generation;
        self.last_log_generation = shared.log_generation;
        let id = cstring("recent_log_lines");
        let child = ui.child_horizontal(&id, 0.0, 0.0, true);
        if child.is_visible() {
            // Read the previous frame's scroll position before adding lines.
            let at_bottom = ui.is_scrolled_to_bottom();
            if visible_count == 0 {
                ui.text_colored(
                    MUTED,
                    &cstring("No messages match the selected levels and filter."),
                );
            }
            for line in &shared.logs {
                if !log_line_visible(line, self.log_filters, &query) {
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
            if new_generation && self.log_auto_follow && at_bottom {
                ui.scroll_to_bottom();
            }
        }
    }
}

/// Whether a log line passes the level filters and the free-text query.
fn log_line_visible(line: &LogLine, filters: LogFilters, query_lower: &str) -> bool {
    filters.accepts(line.level)
        && (query_lower.is_empty()
            || contains_ignore_ascii_case(&line.text, query_lower)
            || contains_ignore_ascii_case(&line.source, query_lower)
            || contains_ignore_ascii_case(&line.timestamp, query_lower))
}

/// ASCII-case-insensitive substring search without allocating a lowercase copy
/// of every line on every frame.
fn contains_ignore_ascii_case(haystack: &str, needle_lower: &str) -> bool {
    let needle = needle_lower.as_bytes();
    if needle.is_empty() {
        return true;
    }
    haystack.as_bytes().windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(byte, lower)| byte.to_ascii_lowercase() == *lower)
    })
}

/// Build the clipboard text for the currently visible log lines.
fn collect_visible_log(
    lines: &[LogLine],
    filters: LogFilters,
    query_lower: &str,
    show_context: bool,
) -> String {
    let mut report = String::new();
    for line in lines {
        if !log_line_visible(line, filters, query_lower) {
            continue;
        }
        if show_context {
            let context = log_context(line);
            if !context.is_empty() {
                report.push_str(&context);
                report.push_str("  ");
            }
        }
        report.push_str(line.level.label().trim_end());
        report.push(' ');
        report.push_str(&line.text);
        report.push('\n');
    }
    report
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
        // Ignore keyboard auto-repeat so holding F10 does not flicker the
        // dashboard open and closed. Bit 30 of lParam is the prior-key-state
        // flag: set on a repeat, clear on the first press.
        if (lparam as usize) & (1 << 30) == 0 {
            RUNTIME.with(|runtime| {
                if let Ok(mut runtime) = runtime.try_borrow_mut() {
                    let open = !runtime.open;
                    runtime.set_open(open);
                }
            });
        }
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
            // While a text field is active, Esc must cancel the edit instead
            // of closing the whole dashboard and losing the draft.
            let editing_text = runtime.imgui.is_some() && psycho_imgui::want_text_input();
            if !editing_text {
                runtime.set_open(false);
                captured = Some(0);
                return;
            }
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

/// Shared header for a Runtime dashboard board.
fn board_heading(ui: &mut Ui<'_>, title: &str, subtitle: &str) {
    ui.spacing();
    ui.separator_text(&cstring(title));
    ui.text_colored(MUTED, &cstring(subtitle));
    ui.spacing();
}

/// Width of one of the three equal cards in a board row.
fn board_card_widths(ui: &Ui<'_>) -> f32 {
    let gap = 18.0;
    ((ui.content_region_available_width() - 2.0 * gap) / 3.0).max(150.0)
}

/// Save, form and task safety board.
fn draw_safety_board(ui: &mut Ui<'_>, core: &engine_fixes::DashboardSnapshot) {
    board_heading(
        ui,
        "Save, form and task safety",
        "Protections that keep saves, forms and background tasks inside proven lifetimes.",
    );
    let width = board_card_widths(ui);
    let commits = core.save_commits.to_string();
    let aborts = core.save_aborts.to_string();
    let rejections = core.save_rejections.to_string();
    metric_card(
        ui,
        "safety_saves_card",
        "SAVES COMMITTED",
        &commits,
        GOOD,
        format!("{} attempted", core.save_attempts),
        width,
        "Save attempts that reached a durable final file. A commit means the completed temporary save safely replaced the previous save.",
    );
    ui.same_line();
    metric_card(
        ui,
        "safety_aborts_card",
        "SAVE ABORTS",
        &aborts,
        alert_color(core.save_aborts),
        "Stopped before an unsafe write",
        width,
        "Save attempts stopped because writing, flushing, closing, backup rotation, or final replacement could not complete safely.",
    );
    ui.same_line();
    metric_card(
        ui,
        "safety_rejects_card",
        "REJECTED DATA",
        &rejections,
        activity_color(core.save_rejections),
        "Unsafe save/load records skipped",
        width,
        "Malformed or unavailable changed records skipped through the game's supported rejection path instead of being trusted.",
    );

    ui.spacing();
    let encounter_zone_rejections = core
        .encounter_zone_load_rejections
        .saturating_add(core.encounter_zone_access_rejections);
    draw_value_help(
        ui,
        "Encounter-zone rejects",
        format!(
            "{} runtime · {} load",
            core.encounter_zone_access_rejections, core.encounter_zone_load_rejections
        ),
        activity_color(encounter_zone_rejections),
        "Invalid zone-form results stopped before RTTI or a consumer dereference. Runtime counts can include more than one native fallback level for one owner.",
    );
    draw_value_help(
        ui,
        "Encounter-zone source repairs",
        core.encounter_zone_repairs,
        activity_color(core.encounter_zone_repairs),
        "Exact corrupt reference, cell, or worldspace sources removed or cleared before Psycho re-ran the native fallback order.",
    );
    draw_value_help(
        ui,
        "Cell render forced cleanups",
        core.cell_render_forced_cleanups,
        ACCENT,
        "False-predicate retirements that would have skipped render-list removal. Psycho sent each one through the executable's canonical native remover.",
    );
    draw_value_help(
        ui,
        "Cell render ownership losses",
        core.cell_render_patch_ownership_losses,
        alert_color(core.cell_render_patch_ownership_losses),
        "Active dispatch blocks replaced after startup, meaning another writer removed this protection.",
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
        activity_color(core.task_rejections),
        "Tasks already known to be dead or invalid that Psycho stopped before another callback could run.",
    );
    draw_value_help(
        ui,
        "Release guards / tombstones",
        format!("{} / {}", core.task_release_guards, core.task_tombstones),
        BLUE,
        "Release guards stop an unsafe final release. Tombstones are compact records of already-dead tasks used to reject later stale references.",
    );
}

/// Streaming and distant-world board.
fn draw_streaming_board(ui: &mut Ui<'_>, core: &engine_fixes::DashboardSnapshot) {
    board_heading(
        ui,
        "Streaming activity",
        "Background loading, distant-world ownership and safe handoff work.",
    );
    let width = board_card_widths(ui);
    let workers = core.io_workers.to_string();
    let cells = core.lod_current_cells.to_string();
    let stale = core.lod_stale_retirements_prevented.to_string();
    metric_card(
        ui,
        "stream_workers_card",
        "IO WORKERS",
        &workers,
        ACCENT,
        "primary + supplemental",
        width,
        "The native game loading workers Psycho configured. The bounded layout uses one primary worker and one supplemental worker.",
    );
    ui.same_line();
    metric_card(
        ui,
        "stream_cells_card",
        "TRACKED CELLS",
        &cells,
        BLUE,
        format!("{} references", core.lod_current_references),
        width,
        "Current distant-world cells whose ownership Psycho is tracking for safe handoff and retirement.",
    );
    ui.same_line();
    metric_card(
        ui,
        "stream_stale_card",
        "STALE RETIREMENTS PREVENTED",
        &stale,
        GOOD,
        "kept alive safely",
        width,
        "Distant resources kept alive because an old lifetime counter no longer matched their current ownership.",
    );

    ui.spacing();
    draw_value_help(
        ui,
        "IO scheduler",
        "primary-first · one supplemental task",
        BLUE,
        "The supplemental worker is admitted only while the primary is active, runs below normal priority, and returns to wait after one task.",
    );
    draw_value_help(
        ui,
        "IO fallbacks",
        core.io_fallbacks,
        activity_color(core.io_fallbacks),
        "Times parallel loading could not satisfy its proven safety contract and used the compatible fallback path instead.",
    );
    draw_value_help(
        ui,
        "LOD demands",
        format!(
            "{} early · {} retained",
            core.lod_early_demands, core.lod_retained_demands
        ),
        MUTED,
        "Distant terrain, tree and object requests. This is recorded only while the LOD streaming trace is enabled in Diagnostics.",
    );
}

/// Occlusion-plane board for the Runtime dashboard.
///
/// Every value comes from the sampled dashboard snapshot, so this renders a
/// handful of strings per open frame and never touches the engine or blocks the
/// event thread.
fn draw_occlusion_board(ui: &mut Ui<'_>, core: &engine_fixes::DashboardSnapshot) {
    board_heading(
        ui,
        "Occlusion planes",
        "Runtime-built rectangles that let the engine skip scenery hidden behind solid geometry.",
    );
    let configured = core.occlusion_configured != 0;
    let ready = core.occlusion_ready != 0;
    let cell = match core.occlusion_cell_kind {
        1 => format!("Interior 0x{:08X}", core.occlusion_cell_form_id),
        2 => format!(
            "Exterior ({}, {})",
            core.occlusion_cell_x, core.occlusion_cell_y
        ),
        _ => "No cell measured yet".to_owned(),
    };
    let (state, state_color, state_detail) = if !configured {
        ("Disabled", MUTED, "Turned off in Configuration".to_owned())
    } else if ready {
        ("Active", GOOD, cell)
    } else {
        ("Starting", WARN, "Waiting for the game to load".to_owned())
    };

    let tracked = core.occlusion_tracked_planes;
    let active = core.occlusion_active_planes;
    let cached = core.occlusion_cached_cells;
    let active_value = active.to_string();
    let cached_value = cached.to_string();
    let active_detail = if tracked == 0 {
        "No rectangles placed".to_owned()
    } else {
        format!("of {tracked} placed")
    };

    // Hero row: the three facts most users come for, mirroring the Overview
    // page's cards.
    let width = board_card_widths(ui);
    metric_card(
        ui,
        "occlusion_state_card",
        "STATUS",
        state,
        state_color,
        state_detail,
        width,
        "Whether runtime occluders are on. Psycho rebuilds them automatically as you move between cells.",
    );
    ui.same_line();
    metric_card(
        ui,
        "occlusion_active_card",
        "IN VIEW NOW",
        &active_value,
        if active > 0 { GOOD } else { ACCENT },
        active_detail,
        width,
        "Rectangles the engine admits for the current camera. Rectangles facing away are not tested, so this is normally lower than the placed count.",
    );
    ui.same_line();
    metric_card(
        ui,
        "occlusion_cache_card",
        "CELLS CACHED",
        &cached_value,
        BLUE,
        "Reused when you return",
        width,
        "Cells whose rectangles are saved to disk. Revisiting one reuses them instead of measuring the meshes again. The cache is dropped when your mod list changes.",
    );

    if !ready {
        return;
    }

    // Occupancy bar: what fraction of the placed set the current camera tests.
    ui.spacing();
    let occupancy = if tracked == 0 {
        0.0
    } else {
        (active as f64 / tracked as f64).clamp(0.0, 1.0) as f32
    };
    ui.label_value(
        &cstring("Facing the camera"),
        &cstring(if tracked == 0 {
            "No rectangles placed yet".to_owned()
        } else {
            format!("{active} of {tracked} rectangles")
        }),
        if active > 0 { GOOD } else { MUTED },
    );
    hover_help(
        ui,
        "How many of the placed rectangles the engine admits for the current camera. A rectangle only culls while it faces the camera, so the rest stay idle.",
    );
    let overlay = cstring(format!("{active} / {tracked}"));
    ui.progress_bar(
        occupancy,
        ui.content_region_available_width(),
        0.0,
        &overlay,
    );
    hover_help(
        ui,
        "Admitted rectangles over placed rectangles. A lower ratio is normal: it only counts what the current view can use.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Last rebuild"));
    if core.occlusion_generation_running != 0 {
        draw_value_help(
            ui,
            "Status",
            "Measuring this cell's geometry…",
            WARN,
            "Psycho walks the cell's static meshes in small per-frame slices, so this never stalls the game. The rectangles appear when the walk finishes.",
        );
    } else if core.occlusion_rebuilds == 0 {
        draw_value_help(
            ui,
            "Status",
            "Waiting for the first cell",
            MUTED,
            "The first rebuild happens once the game has loaded a cell with static geometry.",
        );
    } else if core.occlusion_last_from_cache != 0 {
        draw_value_help(
            ui,
            "Source",
            "Saved cache",
            GOOD,
            "This cell's rectangles came from the saved cache, so no meshes were walked.",
        );
        draw_value_help(
            ui,
            "Rectangles",
            format!("{} kept", core.occlusion_last_selected),
            ACCENT,
            "How many rectangles this rebuild installed.",
        );
    } else {
        draw_value_help(
            ui,
            "Source",
            "Freshly measured",
            ACCENT,
            "This cell's rectangles were derived from its live static meshes.",
        );
        draw_value_help(
            ui,
            "Rectangles",
            format!(
                "{} kept of {} candidates",
                core.occlusion_last_selected, core.occlusion_last_candidates
            ),
            ACCENT,
            "Candidate rectangles the geometry produced, and how many survived the safety checks and the per-cell budget.",
        );
        draw_value_help(
            ui,
            "Changes",
            format!(
                "{} created · {} removed",
                core.occlusion_last_created, core.occlusion_last_removed
            ),
            BLUE,
            "Native rectangles added and removed during the last rebuild.",
        );
        draw_value_help(
            ui,
            "Time",
            format!("{} ms", core.occlusion_last_generation_ms),
            MUTED,
            "Total walk time, summed across its per-frame slices. It is spread over several frames, not spent in one.",
        );
    }

    ui.spacing();
    ui.separator_text(&cstring("This session"));
    draw_value_help(
        ui,
        "Rebuilds",
        format!(
            "{} total · {} from cache",
            core.occlusion_rebuilds, core.occlusion_cache_hits
        ),
        ACCENT,
        "Completed cell rebuilds and how many reused the saved cache instead of re-measuring.",
    );
    draw_value_help(
        ui,
        "Rectangles created / removed",
        format!(
            "{} / {}",
            core.occlusion_planes_created, core.occlusion_planes_removed
        ),
        BLUE,
        "Total native occlusion rectangles created and removed this session.",
    );
    draw_value_help(
        ui,
        "Per-cell budget",
        format!(
            "up to {} rectangles · grid radius {}",
            core.occlusion_max_per_cell, core.occlusion_grid_radius,
        ),
        MUTED,
        "The most rectangles Psycho keeps for the area. A larger grid radius also reuses cached rectangles from the loaded neighbouring cells.",
    );
}

fn draw_configuration(ui: &mut Ui<'_>, editor: &mut ConfigEditor, pending_reload: &mut bool) {
    page_heading(
        ui,
        "Configuration",
        "Edit settings for the next launch. Nothing here changes the current session.",
    );
    notice_card(
        ui,
        "restart_configuration_notice",
        "Saving updates the TOML file for the next full game launch. The current session keeps its startup settings.",
        WARN,
    );
    ui.text_colored(MUTED, &cstring(HOVER_HELP_HINT));
    ui.text_colored(MUTED, &cstring(resolved_config_path(editor)));

    config_actions(ui, editor, pending_reload, "top");

    let config = &mut editor.draft;
    ui.spacing();
    ui.separator_text(&cstring("Memory allocator"));
    ui.text_colored(
        MUTED,
        &cstring("Takes effect only during the next early startup."),
    );
    for (index, label, help) in [
        (
            0,
            "Vanilla allocators",
            "Uses the original game heaps. Diagnostic only; no allocator speed or safety benefit.",
        ),
        (
            1,
            "Scrap heap only",
            "Replaces short-lived allocations but leaves the main object heap vanilla. Lower-risk fallback.",
        ),
        (
            2,
            "Full gheap + scrap heap",
            "Replaces the main and temporary heaps with Psycho's fast allocators. Best performance; test with your modlist.",
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
        "Periodic full cleanup purge (experimental)",
        &mut config.gheap_periodic_pdd_purge,
        "Forces the game's cleanup queue to fully drain every 10 seconds in mode 2. May cause hitches; leave off for normal play.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Installation paths"));
    checkbox_help(
        ui,
        "Repair Fallout install paths",
        &mut config.install_path_registry_repair,
        "Repairs the 32-bit Bethesda install-path registry values at startup. FalloutNV always uses its own folder.",
    );
    ui.text_colored(
        MUTED,
        &cstring("Leave Fallout 3 empty to repair only FalloutNV."),
    );
    input_text_string(
        ui,
        "Fallout 3 path",
        &mut config.fallout3_install_path,
        "Optional Fallout 3 folder for TTW and tools. Use a Windows-visible path or a path relative to FalloutNV.exe.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Window and input"));
    checkbox_help(
        ui,
        "Borderless windowed",
        &mut config.display_borderless_windowed,
        "Removes the window frame when bFull Screen=0. bFull Screen=1 stays native fullscreen.",
    );
    checkbox_help(
        ui,
        "Resolution fixes",
        &mut config.resolution_fixes,
        "Improves Pip-Boy, terminal, and character creation screen resolution and fade coverage at all resolutions.",
    );
    checkbox_help(
        ui,
        "Lock cursor to game window",
        &mut config.window_cursor_lock,
        "Keeps the mouse inside the game window while active. Framed title bars and resize borders stay usable; the cursor is released when the game loses focus.",
    );
    checkbox_help(
        ui,
        "Allow system and media keys",
        &mut config.input_system_key_passthrough,
        "Lets Windows receive the Windows key, PrintScreen, and media keys while playing. Normal game input still works.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Engine fixes"));
    ui.text_colored(
        MUTED,
        &cstring("These prevent known crashes. Leave them on unless testing a conflict."),
    );
    let engine_fix_values: [&mut bool; ENGINE_FIX_HELP.len()] = [
        &mut config.display_alt_tab,
        &mut config.save_integrity_fix,
        &mut config.navmesh_low_pointer_guard,
        &mut config.entrydata_invalid_form_guard,
        &mut config.inventory_list_save_guard,
        &mut config.actor_container_retirement_guard,
        &mut config.inventory_reset_guard,
        &mut config.animation_sequence_idtag_retirement_guard,
        &mut config.extraownership_invalid_owner_guard,
        &mut config.encounter_zone_invalid_form_guard,
        &mut config.patrol_owner_form_id_guard,
        &mut config.cell_render_reference_retirement_fix,
        &mut config.linked_ref_children_stale_list_guard,
        &mut config.linked_ref_target_base_form_guard,
        &mut config.fade_linked_owner_guard,
        &mut config.scene_reference_owner_guard,
        &mut config.occlusion_link_guard,
        &mut config.list_cleanup_guard,
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
        &mut config.model_cache_keys,
        &mut config.queued_task_lifetime_guard,
        &mut config.source_texture_cache_publication_guard,
        &mut config.tile_value_null_slot_guard,
    ];
    for (index, ((label, help), value)) in ENGINE_FIX_HELP
        .into_iter()
        .zip(engine_fix_values)
        .enumerate()
    {
        if let Some(header) = engine_fix_group(index) {
            ui.spacing();
            ui.separator_text(&cstring(header));
        }
        checkbox_help(ui, label, value, help);
    }

    ui.spacing();
    ui.separator_text(&cstring("Loading and distant world"));
    checkbox_help(
        ui,
        "Parallel loading",
        &mut config.parallel_io,
        "Uses two game loading workers while guarding shared state. Faster loading with the same content.",
    );
    checkbox_help(
        ui,
        "Distant-world streaming",
        &mut config.lod_enabled,
        "Enables Psycho's distant-world streaming fixes.",
    );
    checkbox_help(
        ui,
        "Distant prefetch",
        &mut config.lod_prefetch_enabled,
        "Requests distant scenery slightly earlier to reduce pop-in.",
    );
    checkbox_help(
        ui,
        "Distant handoff repair",
        &mut config.lod_handoff_fix_enabled,
        "Stops stale lifetime counters from unloading distant scenery that is still needed.",
    );
    checkbox_help(
        ui,
        "Visible-load priority",
        &mut config.lod_priority_boost_enabled,
        "Gives visible distant loading priority over background prefetch work.",
    );
    checkbox_help(
        ui,
        "Attachment budget",
        &mut config.lod_attachment_budget_enabled,
        "Limits ordinary model attachment work at the game's loading deadline. Restart required.",
    );
    precise_multiplier(
        ui,
        "Object prefetch",
        "object_prefetch",
        &mut config.object_prefetch_multiplier,
        "How early distant objects load. Higher reduces pop-in and uses more CPU.",
    );
    precise_multiplier(
        ui,
        "Object retention",
        "object_retention",
        &mut config.object_retention_multiplier,
        "How long distant objects stay loaded. Higher reduces reloads and uses more memory.",
    );
    precise_multiplier(
        ui,
        "Tree prefetch",
        "tree_prefetch",
        &mut config.tree_prefetch_multiplier,
        "How early distant trees load. Higher reduces pop-in and uses more CPU.",
    );
    precise_multiplier(
        ui,
        "Tree retention",
        "tree_retention",
        &mut config.tree_retention_multiplier,
        "How long distant trees stay loaded. Higher reduces reloads and uses more memory.",
    );
    precise_multiplier(
        ui,
        "Terrain prefetch",
        "terrain_prefetch",
        &mut config.terrain_prefetch_multiplier,
        "How early distant landscape loads. Higher reduces pop-in and uses more memory.",
    );
    precise_multiplier(
        ui,
        "Terrain retention",
        "terrain_retention",
        &mut config.terrain_retention_multiplier,
        "How long distant landscape stays loaded. Higher reduces reloads and uses more memory.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Performance"));
    checkbox_help(
        ui,
        "Faster random numbers",
        &mut config.rng,
        "Faster random numbers. Ranges and game cases match vanilla; the exact sequence does not.",
    );
    checkbox_help(
        ui,
        "Faster decompression",
        &mut config.zlib,
        "Faster decompression for saves and archives. Content is unchanged.",
    );
    checkbox_help(
        ui,
        "Post-load cleanup",
        &mut config.post_load_reconciliation_prepass,
        "Finishes post-load cleanup before the first playable frame, reducing the initial stall.",
    );
    checkbox_help(
        ui,
        "Light sorting speedup",
        &mut config.light_property_score_reuse,
        "Removes repeated light math inside one object's light sort. The final lighting is unchanged.",
    );
    checkbox_help(
        ui,
        "Light list search speedup",
        &mut config.scene_light_sequential_scan,
        "Searches each light list once instead of restarting. The selected lights are unchanged.",
    );
    checkbox_help(
        ui,
        "Bounds visibility speedup",
        &mut config.multibound_frustum_tests,
        "Removes redundant setup in object-bounds visibility checks. Visibility results are unchanged.",
    );
    checkbox_help(
        ui,
        "Compound visibility speedup",
        &mut config.multibound_vertex_setup,
        "Removes redundant setup in compound and portal visibility bounds. Rendered geometry is unchanged.",
    );
    checkbox_help(
        ui,
        "Compound loop speedup",
        &mut config.multibound_loop_bookkeeping,
        "Reduces repeated bookkeeping in compound visibility loops. Visibility decisions are unchanged.",
    );
    checkbox_help(
        ui,
        "Room lookup speedup",
        &mut config.scene_root_admission,
        "Combines the room lookup and insert, avoiding a duplicate search for the same room.",
    );
    checkbox_help(
        ui,
        "Transform index speedup",
        &mut config.inverse_world_index_setup,
        "Removes redundant index work in the game's transform expansion. Object placement is unchanged.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Occlusion planes"));
    checkbox_help(
        ui,
        "Generated occlusion planes",
        &mut config.occlusion_planes,
        "Adds invisible occluders to cells without authored visibility data. Hidden objects behind large solid buildings are rejected earlier.",
    );
    precise_count(
        ui,
        "Planes per cell",
        "occlusion_planes_max_per_cell",
        &mut config.occlusion_planes_max_per_cell,
        1,
        256,
        "Shared budget and per-cell cap. Higher rejects more hidden geometry but costs more visibility work.",
    );
    precise_count(
        ui,
        "Neighbor grid radius",
        "occlusion_planes_grid_radius",
        &mut config.occlusion_planes_grid_radius,
        0,
        2,
        "0 uses only the player's cell. 1-2 also reuse cached occluders from nearby loaded cells.",
    );
    input_text_string(
        ui,
        "Plane cache path",
        &mut config.occlusion_planes_cache_path,
        "Where generated planes are cached, relative to the game folder or absolute.",
    );

    ui.spacing();
    ui.separator_text(&cstring("Diagnostics"));
    checkbox_help(
        ui,
        "Detailed debug log",
        &mut config.debug_log,
        "Writes the details support needs for bug reports. Keep on.",
    );
    checkbox_help(
        ui,
        "Occlusion-plane diagnostics",
        &mut config.occlusion_planes_debug_log,
        "Adds verbose occlusion-plane diagnostics. Requires the detailed debug log.",
    );
    checkbox_help(
        ui,
        "Separate Windows console",
        &mut config.console,
        "Opens a separate live log console. Off for normal play.",
    );
    checkbox_help(
        ui,
        "Queued-task trace",
        &mut config.task_lifetime_trace,
        "Records queued-task events. Enable only for crash research.",
    );
    checkbox_help(
        ui,
        "Distant-world trace",
        &mut config.lod_streaming_trace,
        "Records distant-world streaming events. Enable only while troubleshooting distant loading.",
    );

    // Repeat the save/reload controls at the end so they stay reachable after
    // scrolling through the long settings list.
    ui.spacing();
    ui.separator();
    config_actions(ui, editor, pending_reload, "bottom");
}

/// Section headers for the engine-fix checkboxes.
///
/// The indexes match `ENGINE_FIX_HELP` and keep related fixes together without
/// duplicating the checkbox catalog.
fn engine_fix_group(index: usize) -> Option<&'static str> {
    match index {
        0 => Some("Display and saves"),
        5 => Some("Actors and world"),
        18 => Some("Physics"),
        25 => Some("Memory and tasks"),
        _ => None,
    }
}

/// Draw the Save / Reload / Discard controls shared by the top and bottom of
/// the Configuration page.
///
/// Reloading discards the restart draft, so a dirty draft requires a second,
/// explicit confirmation click instead of losing edits on a single press.
/// `anchor` makes the duplicate top and bottom widgets distinct to Dear ImGui.
fn config_actions(
    ui: &mut Ui<'_>,
    editor: &mut ConfigEditor,
    pending_reload: &mut bool,
    anchor: &str,
) {
    let save = cstring(format!("Save for next launch##config_{anchor}"));
    if ui.button_colored(&save, SAVE_BUTTON, SAVE_HOVERED, SAVE_ACTIVE) {
        editor.save();
        *pending_reload = false;
    }
    ui.same_line();
    if *pending_reload {
        let confirm = cstring(format!("Confirm reload (discards edits)##config_{anchor}"));
        if ui.button_colored(&confirm, RELOAD_BUTTON, RELOAD_HOVERED, RELOAD_ACTIVE) {
            editor.reload();
            *pending_reload = false;
        }
        ui.same_line();
        if ui.button(&cstring(format!("Cancel##config_{anchor}"))) {
            *pending_reload = false;
        }
    } else {
        let reload = cstring(format!("Reload from disk##config_{anchor}"));
        if ui.button_colored(&reload, RELOAD_BUTTON, RELOAD_HOVERED, RELOAD_ACTIVE) {
            if editor.is_dirty() {
                *pending_reload = true;
            } else {
                editor.reload();
            }
        }
        if editor.is_dirty() {
            ui.same_line();
            if ui.button(&cstring(format!("Discard changes##config_{anchor}"))) {
                editor.discard();
                *pending_reload = false;
            }
        }
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
}

/// Absolute path of the configuration file being edited.
///
/// The editor keeps a path relative to the game working directory; showing the
/// resolved location helps a user find the file outside the game.
fn resolved_config_path(editor: &ConfigEditor) -> String {
    match std::env::current_dir() {
        Ok(directory) => directory.join(&editor.path).display().to_string(),
        Err(_) => editor.path.display().to_string(),
    }
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

fn precise_count(
    ui: &mut Ui<'_>,
    label: &str,
    id: &str,
    value: &mut i32,
    min: i32,
    max: i32,
    help: &str,
) {
    let fast_step = if max.saturating_sub(min) <= 10 { 1 } else { 10 };
    ui.precise_int(&cstring(label), &cstring(id), value, min, max, fast_step);
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
            color_by_threshold: false,
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

fn input_text_string(ui: &mut Ui<'_>, label: &str, value: &mut String, help: &str) -> bool {
    const BUFFER_BYTES: usize = 1024;

    let mut buffer = [0u8; BUFFER_BYTES];
    let mut copy_len = value.len().min(buffer.len() - 1);
    while !value.is_char_boundary(copy_len) {
        copy_len -= 1;
    }
    buffer[..copy_len].copy_from_slice(&value.as_bytes()[..copy_len]);

    let changed = ui.input_text(&cstring(label), &mut buffer);
    hover_help(ui, help);
    if changed {
        let length = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        *value = String::from_utf8_lossy(&buffer[..length]).into_owned();
    }
    changed
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

fn allocator_name(mode: u32) -> &'static str {
    match mode {
        0 => "VANILLA",
        1 => "SCRAP ONLY",
        2 => "FULL GHEAP",
        _ => "STARTING",
    }
}

/// Format a byte count with binary (1024-based) IEC units.
///
/// The dashboard charts, thresholds, and delta labels all display MiB, so the
/// scalar rows use the same family to avoid mixing "MB" and "MiB" on one page.
fn bytes(value: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let value = value as f64;
    if value >= GIB {
        format!("{:.1} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.1} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{} B", value as u64)
    }
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

/// Zero is nominal; nonzero fallback or guard activity is informational.
///
/// Recoverable allocator fallbacks and guard rejections are expected during
/// heavy streaming, so they must not read as failures.
fn activity_color(value: u64) -> [f32; 4] {
    if value == 0 { GOOD } else { BLUE }
}

/// Zero is nominal; any nonzero value is support-relevant failure evidence.
fn alert_color(value: u64) -> [f32; 4] {
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
        CoreLink, ENGINE_FIX_HELP, GameRenderHandles, LogFilters, LogLevel, LogLine, LogTailReader,
        MemoryHealth, Page, SamplingState, bytes, contains_ignore_ascii_case, engine_fix_group,
        log_line_visible, parse_log_line, take_driver_refresh,
    };
    use crate::engine_fixes::{
        DASHBOARD_FLAG_CORE_READY, DASHBOARD_FLAG_VAS_VALID, DashboardSnapshot,
    };

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
        assert_eq!(ENGINE_FIX_HELP.len(), 32);
        for (index, expected) in [
            (0, "Fullscreen / Alt-Tab fix"),
            (1, "Save file integrity"),
            (2, "Pathfinding pointer guard"),
            (3, "Inventory entry guard"),
            (4, "Inventory save guard"),
            (5, "Actor container guard"),
            (7, "Animation cleanup guard"),
            (8, "Ownership data guard"),
            (9, "Encounter-zone guard"),
            (10, "Patrol owner guard"),
            (11, "Cell cleanup fix"),
            (12, "Linked-reference cleanup"),
            (13, "Linked-reference target guard"),
            (17, "List cleanup guard"),
            (18, "Ragdoll bone guard"),
            (19, "Ragdoll raycast guard"),
            (20, "Physics add-batch guard"),
            (21, "Physics pending-add guard"),
            (22, "Physics collision-pair guard"),
            (23, "Physics callback guard"),
            (24, "Physics unlock guard"),
            (25, "Out-of-memory write guard"),
            (26, "Actor location-list guard"),
            (27, "Model load serialization"),
            (29, "Queued-task guard"),
            (30, "Texture cache guard"),
            (31, "Tile cleanup guard"),
        ] {
            assert_eq!(ENGINE_FIX_HELP[index].0, expected);
        }
        assert_eq!(engine_fix_group(0), Some("Display and saves"));
        assert_eq!(engine_fix_group(5), Some("Actors and world"));
        assert_eq!(engine_fix_group(18), Some("Physics"));
        assert_eq!(engine_fix_group(25), Some("Memory and tasks"));
        assert_eq!(engine_fix_group(1), None);
        assert_eq!(engine_fix_group(26), None);
        let mut labels = std::collections::BTreeSet::new();
        for (label, help) in ENGINE_FIX_HELP {
            assert!(!label.trim().is_empty());
            assert!(labels.insert(label), "duplicate engine-fix label: {label}");
            assert!(
                (40..=160).contains(&help.len()),
                "hover help should stay short and useful: {label} ({})",
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
    fn log_query_matches_text_module_and_timestamp_case_insensitively() {
        let line = LogLine {
            level: LogLevel::Info,
            timestamp: "23:40:03".to_owned(),
            source: "Watchdog".to_owned(),
            text: "[MEM] Pool Status".to_owned(),
        };
        let all = LogFilters::all();
        assert!(log_line_visible(&line, all, "pool"));
        assert!(log_line_visible(&line, all, "watchdog"));
        assert!(log_line_visible(&line, all, "23:40"));
        assert!(!log_line_visible(&line, all, "allocator"));
        // Level filtering still applies alongside the text query.
        assert!(!log_line_visible(&line, LogFilters::important(), "pool"));
        assert!(contains_ignore_ascii_case("Hello World", "o w"));
        assert!(!contains_ignore_ascii_case("Hello World", "xyz"));
    }

    #[test]
    fn core_link_does_not_report_offline_before_the_first_sample() {
        assert_eq!(CoreLink::from_parts(None, false), CoreLink::Connecting);
        assert_eq!(CoreLink::from_parts(None, true), CoreLink::Offline);

        let ready = DashboardSnapshot {
            flags: DASHBOARD_FLAG_CORE_READY,
            ..DashboardSnapshot::default()
        };
        assert_eq!(CoreLink::from_parts(Some(ready), true), CoreLink::Connected);
        assert_eq!(
            CoreLink::from_parts(Some(DashboardSnapshot::default()), true),
            CoreLink::Starting
        );
    }

    #[test]
    fn byte_values_use_the_same_binary_units_as_the_charts() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(bytes(1024 * 1024 * 1024), "1.0 GiB");
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
