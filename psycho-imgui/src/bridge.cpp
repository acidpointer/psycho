#include <stdint.h>
#include <cmath>
#include <cstdio>
#include <windows.h>
#include <d3d9.h>

#include "imgui.h"
#include "backends/imgui_impl_dx9.h"
#include "backends/imgui_impl_win32.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

extern "C" {

struct PsychoImguiIoState {
	bool want_capture_mouse;
	bool want_capture_keyboard;
};

struct PsychoImguiTelemetryChart {
	const float* values;
	int32_t count;
	float scale_min;
	float scale_max;
	float width;
	float height;
	float warning_threshold;
	float critical_threshold;
	int32_t danger_below;
	float sample_interval_seconds;
	int32_t impulse_from_zero;
	float line_color[4];
	float fill_color[4];
	const char* warning_label;
	const char* critical_label;
	const char* value_suffix;
};

static HWND g_hwnd = nullptr;
static volatile LONG g_pending_mouse_wheel_y = 0;
static volatile LONG g_pending_mouse_wheel_x = 0;

static const float k_mouse_wheel_delta = 120.0f;
static const char* k_precise_control_tooltip =
	"Drag for quick tuning. Ctrl-click the slider to type an exact value. "
	"Hold the -/+ buttons to repeat; hold Ctrl for a larger step.";

static bool is_mouse_button_down(int virtual_key) {
	return (::GetAsyncKeyState(virtual_key) & 0x8000) != 0;
}

static void poll_mouse_state(ImGuiIO& io) {
	if (g_hwnd == nullptr || ::GetForegroundWindow() != g_hwnd) {
		return;
	}

	POINT pos = {};
	if (::GetCursorPos(&pos) && ::ScreenToClient(g_hwnd, &pos)) {
		io.AddMousePosEvent(static_cast<float>(pos.x), static_cast<float>(pos.y));
	}

	io.AddMouseSourceEvent(ImGuiMouseSource_Mouse);
	io.AddMouseButtonEvent(0, is_mouse_button_down(VK_LBUTTON));
	io.AddMouseButtonEvent(1, is_mouse_button_down(VK_RBUTTON));
	io.AddMouseButtonEvent(2, is_mouse_button_down(VK_MBUTTON));
	io.AddMouseButtonEvent(3, is_mouse_button_down(VK_XBUTTON1));
	io.AddMouseButtonEvent(4, is_mouse_button_down(VK_XBUTTON2));
}

static void consume_queued_mouse_wheel(ImGuiIO& io) {
	LONG vertical = ::InterlockedExchange(&g_pending_mouse_wheel_y, 0);
	LONG horizontal = ::InterlockedExchange(&g_pending_mouse_wheel_x, 0);
	if (vertical != 0 || horizontal != 0) {
		io.AddMouseWheelEvent(
			static_cast<float>(horizontal) / k_mouse_wheel_delta,
			static_cast<float>(vertical) / k_mouse_wheel_delta);
	}
}

static void configure_font(ImGuiIO& io) {
	ImFontConfig font_config;
	font_config.SizePixels = 16.0f;
	font_config.OversampleH = 2;
	font_config.OversampleV = 1;
	io.Fonts->AddFontDefaultVector(&font_config);
}

static float clamp_float(float value, float min, float max) {
	if (value < min) {
		return min;
	}
	if (value > max) {
		return max;
	}
	return value;
}

static int32_t clamp_int(int32_t value, int32_t min, int32_t max) {
	if (value < min) {
		return min;
	}
	if (value > max) {
		return max;
	}
	return value;
}

static void precise_control_tooltip() {
	if (!ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
		return;
	}

	ImGui::BeginTooltip();
	ImGui::PushTextWrapPos(ImGui::GetFontSize() * 28.0f);
	ImGui::TextUnformatted(k_precise_control_tooltip);
	ImGui::PopTextWrapPos();
	ImGui::EndTooltip();
}

static void precise_control_label(const char* label, const char* range) {
	ImGui::AlignTextToFramePadding();
	ImGui::TextUnformatted(label);
	ImGui::SameLine();
	ImGui::TextDisabled("%s", range);
}

static float precise_control_slider_width() {
	const ImGuiStyle& style = ImGui::GetStyle();
	const float available = ImGui::GetContentRegionAvail().x;
	const float button_width = ImGui::GetFrameHeight();
	const float controls_width = (button_width + style.ItemSpacing.x) * 2.0f;
	const float slider_width = available - controls_width;
	return slider_width > 110.0f ? slider_width : 110.0f;
}

static void apply_psycho_style() {
	ImGui::StyleColorsDark();

	ImGuiStyle& style = ImGui::GetStyle();
	style.WindowPadding = ImVec2(16.0f, 14.0f);
	style.FramePadding = ImVec2(9.0f, 6.0f);
	style.ItemSpacing = ImVec2(9.0f, 8.0f);
	style.ItemInnerSpacing = ImVec2(7.0f, 5.0f);
	style.ScrollbarSize = 16.0f;
	style.GrabMinSize = 14.0f;
	style.WindowRounding = 8.0f;
	style.ChildRounding = 6.0f;
	style.FrameRounding = 5.0f;
	style.PopupRounding = 6.0f;
	style.ScrollbarRounding = 6.0f;
	style.GrabRounding = 5.0f;
	style.TabRounding = 5.0f;
	style.WindowBorderSize = 1.0f;
	style.ChildBorderSize = 1.0f;
	style.FrameBorderSize = 1.0f;
	style.DisabledAlpha = 0.58f;
	style.SeparatorTextBorderSize = 1.0f;
	style.SeparatorTextAlign = ImVec2(0.0f, 0.5f);
	style.SeparatorTextPadding = ImVec2(8.0f, 5.0f);
	style.WindowMenuButtonPosition = ImGuiDir_None;

	ImVec4* colors = style.Colors;
	colors[ImGuiCol_Text] = ImVec4(0.88f, 0.93f, 0.89f, 1.00f);
	colors[ImGuiCol_TextDisabled] = ImVec4(0.42f, 0.50f, 0.46f, 1.00f);
	colors[ImGuiCol_WindowBg] = ImVec4(0.025f, 0.033f, 0.031f, 0.98f);
	colors[ImGuiCol_ChildBg] = ImVec4(0.038f, 0.052f, 0.048f, 0.96f);
	colors[ImGuiCol_PopupBg] = ImVec4(0.030f, 0.045f, 0.041f, 0.99f);
	colors[ImGuiCol_Border] = ImVec4(0.16f, 0.34f, 0.29f, 0.86f);
	colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	colors[ImGuiCol_FrameBg] = ImVec4(0.060f, 0.115f, 0.100f, 0.95f);
	colors[ImGuiCol_FrameBgHovered] = ImVec4(0.090f, 0.230f, 0.190f, 1.00f);
	colors[ImGuiCol_FrameBgActive] = ImVec4(0.110f, 0.350f, 0.275f, 1.00f);
	colors[ImGuiCol_InputTextCursor] = ImVec4(0.58f, 1.00f, 0.76f, 1.00f);
	colors[ImGuiCol_TitleBg] = ImVec4(0.035f, 0.075f, 0.064f, 1.00f);
	colors[ImGuiCol_TitleBgActive] = ImVec4(0.060f, 0.190f, 0.155f, 1.00f);
	colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.025f, 0.045f, 0.039f, 0.94f);
	colors[ImGuiCol_MenuBarBg] = ImVec4(0.040f, 0.085f, 0.072f, 1.00f);
	colors[ImGuiCol_ScrollbarBg] = ImVec4(0.015f, 0.025f, 0.023f, 0.80f);
	colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.130f, 0.300f, 0.250f, 0.92f);
	colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.190f, 0.470f, 0.370f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.240f, 0.620f, 0.460f, 1.00f);
	colors[ImGuiCol_CheckMark] = ImVec4(0.44f, 0.93f, 0.58f, 1.00f);
	colors[ImGuiCol_SliderGrab] = ImVec4(0.30f, 0.76f, 0.62f, 1.00f);
	colors[ImGuiCol_SliderGrabActive] = ImVec4(0.46f, 0.96f, 0.72f, 1.00f);
	colors[ImGuiCol_Button] = ImVec4(0.080f, 0.205f, 0.170f, 0.95f);
	colors[ImGuiCol_ButtonHovered] = ImVec4(0.115f, 0.355f, 0.275f, 1.00f);
	colors[ImGuiCol_ButtonActive] = ImVec4(0.120f, 0.500f, 0.355f, 1.00f);
	colors[ImGuiCol_Header] = ImVec4(0.075f, 0.185f, 0.155f, 0.84f);
	colors[ImGuiCol_HeaderHovered] = ImVec4(0.110f, 0.340f, 0.260f, 0.94f);
	colors[ImGuiCol_HeaderActive] = ImVec4(0.140f, 0.470f, 0.340f, 1.00f);
	colors[ImGuiCol_Separator] = ImVec4(0.230f, 0.480f, 0.380f, 0.78f);
	colors[ImGuiCol_SeparatorHovered] = ImVec4(0.380f, 0.720f, 0.520f, 0.90f);
	colors[ImGuiCol_SeparatorActive] = ImVec4(0.500f, 0.900f, 0.640f, 1.00f);
	colors[ImGuiCol_ResizeGrip] = ImVec4(0.240f, 0.570f, 0.430f, 0.38f);
	colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.350f, 0.760f, 0.540f, 0.72f);
	colors[ImGuiCol_ResizeGripActive] = ImVec4(0.480f, 0.930f, 0.650f, 0.96f);
	colors[ImGuiCol_PlotLines] = ImVec4(0.93f, 0.67f, 0.25f, 1.00f);
	colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.82f, 0.40f, 1.00f);
	colors[ImGuiCol_PlotHistogram] = ImVec4(0.92f, 0.66f, 0.26f, 1.00f);
	colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.78f, 0.32f, 1.00f);
	colors[ImGuiCol_TextSelectedBg] = ImVec4(0.18f, 0.62f, 0.44f, 0.42f);
	colors[ImGuiCol_NavCursor] = ImVec4(0.52f, 0.96f, 0.70f, 0.95f);
}

bool psycho_imgui_init_dx9(void* hwnd, void* device) {
	if (hwnd == nullptr || device == nullptr) {
		return false;
	}

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();

	ImGuiIO& io = ImGui::GetIO();
	io.IniFilename = nullptr;
	io.LogFilename = nullptr;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
	io.ConfigWindowsResizeFromEdges = true;
	configure_font(io);
	apply_psycho_style();

	if (!ImGui_ImplWin32_Init(hwnd)) {
		ImGui::DestroyContext();
		return false;
	}

	if (!ImGui_ImplDX9_Init(static_cast<IDirect3DDevice9*>(device))) {
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();
		return false;
	}

	g_hwnd = static_cast<HWND>(hwnd);
	return true;
}

void psycho_imgui_shutdown() {
	if (ImGui::GetCurrentContext() == nullptr) {
		return;
	}

	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	g_hwnd = nullptr;
}

void psycho_imgui_invalidate_device_objects() {
	if (ImGui::GetCurrentContext() != nullptr) {
		ImGui_ImplDX9_InvalidateDeviceObjects();
	}
}

bool psycho_imgui_create_device_objects() {
	if (ImGui::GetCurrentContext() == nullptr) {
		return false;
	}

	return ImGui_ImplDX9_CreateDeviceObjects();
}

void psycho_imgui_new_frame(bool menu_open) {
	ImGuiIO& io = ImGui::GetIO();
	io.MouseDrawCursor = menu_open;

	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	if (menu_open) {
		poll_mouse_state(io);
		consume_queued_mouse_wheel(io);
	}
	ImGui::NewFrame();
}

void psycho_imgui_render() {
	ImGui::Render();
	ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
}

intptr_t psycho_imgui_wndproc(void* hwnd, uint32_t msg, uintptr_t wparam, intptr_t lparam) {
	return ImGui_ImplWin32_WndProcHandler(
		static_cast<HWND>(hwnd),
		static_cast<UINT>(msg),
		static_cast<WPARAM>(wparam),
		static_cast<LPARAM>(lparam));
}

PsychoImguiIoState psycho_imgui_io_state() {
	PsychoImguiIoState state = {};
	if (ImGui::GetCurrentContext() == nullptr) {
		return state;
	}

	ImGuiIO& io = ImGui::GetIO();
	state.want_capture_mouse = io.WantCaptureMouse;
	state.want_capture_keyboard = io.WantCaptureKeyboard;
	return state;
}

void psycho_imgui_queue_mouse_wheel_delta(int32_t vertical, int32_t horizontal) {
	if (vertical != 0) {
		::InterlockedExchangeAdd(&g_pending_mouse_wheel_y, static_cast<LONG>(vertical));
	}
	if (horizontal != 0) {
		::InterlockedExchangeAdd(&g_pending_mouse_wheel_x, static_cast<LONG>(horizontal));
	}
}

void psycho_imgui_set_next_window_size(float width, float height, int condition) {
	ImGui::SetNextWindowSize(ImVec2(width, height), static_cast<ImGuiCond>(condition));
}

void psycho_imgui_set_next_window_pos(float x, float y, int condition) {
	ImGui::SetNextWindowPos(ImVec2(x, y), static_cast<ImGuiCond>(condition));
}

void psycho_imgui_set_next_window_centered(
	float width_ratio,
	float height_ratio,
	float min_width,
	float min_height,
	float preferred_max_width,
	float preferred_max_height,
	int condition) {
	ImGuiViewport* viewport = ImGui::GetMainViewport();
	const float available_width = viewport->WorkSize.x > 32.0f ? viewport->WorkSize.x - 32.0f : 1.0f;
	const float available_height = viewport->WorkSize.y > 32.0f ? viewport->WorkSize.y - 32.0f : 1.0f;
	const float constrained_min_width = min_width < available_width ? min_width : available_width;
	const float constrained_min_height = min_height < available_height ? min_height : available_height;
	const float initial_max_width =
		clamp_float(preferred_max_width, constrained_min_width, available_width);
	const float initial_max_height =
		clamp_float(preferred_max_height, constrained_min_height, available_height);
	const float width = clamp_float(
		viewport->WorkSize.x * width_ratio,
		constrained_min_width,
		initial_max_width);
	const float height = clamp_float(
		viewport->WorkSize.y * height_ratio,
		constrained_min_height,
		initial_max_height);

	ImGui::SetNextWindowSizeConstraints(
		ImVec2(constrained_min_width, constrained_min_height),
		ImVec2(available_width, available_height));
	ImGui::SetNextWindowSize(ImVec2(width, height), static_cast<ImGuiCond>(condition));
	ImGui::SetNextWindowPos(
		viewport->GetWorkCenter(), static_cast<ImGuiCond>(condition), ImVec2(0.5f, 0.5f));
}

bool psycho_imgui_begin_window(const char* title, bool* open) {
	return ImGui::Begin(title, open);
}

void psycho_imgui_end_window() {
	ImGui::End();
}

bool psycho_imgui_begin_child(const char* id, float width, float height, bool border) {
	return ImGui::BeginChild(id, ImVec2(width, height), border);
}

bool psycho_imgui_begin_child_horizontal(const char* id, float width, float height, bool border) {
	return ImGui::BeginChild(
		id,
		ImVec2(width, height),
		border,
		ImGuiWindowFlags_HorizontalScrollbar);
}

void psycho_imgui_end_child() {
	ImGui::EndChild();
}

void psycho_imgui_text_unformatted(const char* text) {
	ImGui::TextUnformatted(text);
}

void psycho_imgui_text_wrapped(const char* text) {
	ImGui::TextWrapped("%s", text);
}

void psycho_imgui_text_colored(float r, float g, float b, float a, const char* text) {
	ImGui::TextColored(ImVec4(r, g, b, a), "%s", text);
}

void psycho_imgui_label_value(
	const char* label,
	const char* value,
	float r,
	float g,
	float b,
	float a) {
	ImGui::TextDisabled("%s", label);
	ImGui::SameLine();
	const float value_width = ImGui::CalcTextSize(value).x;
	const float target_x = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - value_width;
	if (target_x > ImGui::GetCursorPosX()) {
		ImGui::SetCursorPosX(target_x);
	}
	ImGui::TextColored(ImVec4(r, g, b, a), "%s", value);
}

void psycho_imgui_separator() {
	ImGui::Separator();
}

void psycho_imgui_separator_text(const char* label) {
	ImGui::SeparatorText(label);
}

void psycho_imgui_spacing() {
	ImGui::Spacing();
}

bool psycho_imgui_checkbox(const char* label, bool* value) {
	return ImGui::Checkbox(label, value);
}

bool psycho_imgui_radio_button(const char* label, bool active) {
	return ImGui::RadioButton(label, active);
}

bool psycho_imgui_radio_button_wrapped(const char* label, bool active, bool first_in_group) {
	if (!first_in_group) {
		const ImGuiStyle& style = ImGui::GetStyle();
		const ImVec2 label_size = ImGui::CalcTextSize(label, nullptr, true);
		const float radio_size = ImGui::GetFrameHeight();
		const float item_width = radio_size
			+ (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f);
		const float content_right =
			ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x;
		const float next_right =
			ImGui::GetItemRectMax().x + style.ItemSpacing.x + item_width;
		if (next_right <= content_right) {
			ImGui::SameLine();
		}
	}
	return ImGui::RadioButton(label, active);
}

float psycho_imgui_content_region_available_width() {
	return ImGui::GetContentRegionAvail().x;
}

bool psycho_imgui_slider_float(const char* label, float* value, float min, float max) {
	return ImGui::SliderFloat(label, value, min, max, "%.7g");
}

bool psycho_imgui_slider_int(const char* label, int32_t* value, int32_t min, int32_t max) {
	return ImGui::SliderInt(label, value, min, max);
}

bool psycho_imgui_precise_float(
	const char* label,
	const char* id,
	float* value,
	float min,
	float max,
	float step,
	float fast_step,
	bool logarithmic) {
	if (label == nullptr || id == nullptr || value == nullptr || !std::isfinite(min)
		|| !std::isfinite(max) || min >= max || step <= 0.0f || fast_step < step) {
		return false;
	}

	if (!std::isfinite(*value)) {
		*value = min;
	}
	*value = clamp_float(*value, min, max);

	char range[128];
	std::snprintf(
		range, sizeof(range), "range %.7g - %.7g | +/- %.7g (Ctrl %.7g)",
		min, max, step, fast_step);
	precise_control_label(label, range);

	ImGui::PushID(id);
	ImGui::SetNextItemWidth(precise_control_slider_width());
	ImGuiSliderFlags flags = ImGuiSliderFlags_AlwaysClamp;
	if (logarithmic) {
		flags |= ImGuiSliderFlags_Logarithmic;
	}
	bool changed = ImGui::SliderFloat("##slider", value, min, max, "%.7g", flags);
	precise_control_tooltip();

	const float button_width = ImGui::GetFrameHeight();
	ImGui::PushButtonRepeat(true);
	ImGui::SameLine();
	if (ImGui::Button("-##decrement", ImVec2(button_width, 0.0f))) {
		const float amount = ImGui::GetIO().KeyCtrl ? fast_step : step;
		*value = clamp_float(*value - amount, min, max);
		changed = true;
	}
	precise_control_tooltip();
	ImGui::SameLine();
	if (ImGui::Button("+##increment", ImVec2(button_width, 0.0f))) {
		const float amount = ImGui::GetIO().KeyCtrl ? fast_step : step;
		*value = clamp_float(*value + amount, min, max);
		changed = true;
	}
	precise_control_tooltip();
	ImGui::PopButtonRepeat();

	const float clamped = std::isfinite(*value) ? clamp_float(*value, min, max) : min;
	if (clamped != *value) {
		*value = clamped;
		changed = true;
	}
	ImGui::PopID();
	return changed;
}

bool psycho_imgui_precise_int(
	const char* label,
	const char* id,
	int32_t* value,
	int32_t min,
	int32_t max,
	int32_t fast_step) {
	if (label == nullptr || id == nullptr || value == nullptr || min >= max || fast_step < 1) {
		return false;
	}

	*value = clamp_int(*value, min, max);
	char range[128];
	std::snprintf(
		range, sizeof(range), "range %d - %d | +/- 1 (Ctrl %d)", min, max, fast_step);
	precise_control_label(label, range);

	ImGui::PushID(id);
	ImGui::SetNextItemWidth(precise_control_slider_width());
	bool changed = ImGui::SliderInt(
		"##slider", value, min, max, "%d", ImGuiSliderFlags_AlwaysClamp);
	precise_control_tooltip();

	const float button_width = ImGui::GetFrameHeight();
	ImGui::PushButtonRepeat(true);
	ImGui::SameLine();
	if (ImGui::Button("-##decrement", ImVec2(button_width, 0.0f))) {
		const int32_t amount = ImGui::GetIO().KeyCtrl ? fast_step : 1;
		const int64_t next = static_cast<int64_t>(*value) - amount;
		*value = next < min ? min : static_cast<int32_t>(next);
		changed = true;
	}
	precise_control_tooltip();
	ImGui::SameLine();
	if (ImGui::Button("+##increment", ImVec2(button_width, 0.0f))) {
		const int32_t amount = ImGui::GetIO().KeyCtrl ? fast_step : 1;
		const int64_t next = static_cast<int64_t>(*value) + amount;
		*value = next > max ? max : static_cast<int32_t>(next);
		changed = true;
	}
	precise_control_tooltip();
	ImGui::PopButtonRepeat();

	const int32_t clamped = clamp_int(*value, min, max);
	if (clamped != *value) {
		*value = clamped;
		changed = true;
	}
	ImGui::PopID();
	return changed;
}

bool psycho_imgui_selectable(const char* label, bool selected) {
	return ImGui::Selectable(label, selected);
}

bool psycho_imgui_begin_combo(const char* label, const char* preview) {
	return ImGui::BeginCombo(label, preview);
}

void psycho_imgui_end_combo() {
	ImGui::EndCombo();
}

bool psycho_imgui_button(const char* label) {
	return ImGui::Button(label);
}

bool psycho_imgui_button_colored(
	const char* label,
	float r, float g, float b, float a,
	float hovered_r, float hovered_g, float hovered_b, float hovered_a,
	float active_r, float active_g, float active_b, float active_a) {
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(r, g, b, a));
	ImGui::PushStyleColor(
		ImGuiCol_ButtonHovered,
		ImVec4(hovered_r, hovered_g, hovered_b, hovered_a));
	ImGui::PushStyleColor(
		ImGuiCol_ButtonActive,
		ImVec4(active_r, active_g, active_b, active_a));
	const bool pressed = ImGui::Button(label);
	ImGui::PopStyleColor(3);
	return pressed;
}

void psycho_imgui_progress_bar(float fraction, float width, float height, const char* overlay) {
	ImGui::ProgressBar(fraction, ImVec2(width, height), overlay);
}

void psycho_imgui_plot_lines(
	const char* label,
	const float* values,
	int32_t count,
	float scale_min,
	float scale_max,
	float width,
	float height) {
	if (values == nullptr || count <= 0) {
		return;
	}

	ImGui::PlotLines(label, values, count, 0, nullptr, scale_min, scale_max, ImVec2(width, height));
}

static ImU32 telemetry_color(const float color[4]) {
	return ImGui::ColorConvertFloat4ToU32(ImVec4(color[0], color[1], color[2], color[3]));
}

static float telemetry_y(float value, float scale_min, float scale_max, float top, float bottom) {
	const float normalized = clamp_float((value - scale_min) / (scale_max - scale_min), 0.0f, 1.0f);
	return bottom - normalized * (bottom - top);
}

static void telemetry_dashed_line(
	ImDrawList* draw_list,
	float left,
	float right,
	float y,
	ImU32 color) {
	const float dash = 5.0f;
	const float gap = 4.0f;
	for (float x = left; x < right; x += dash + gap) {
		const float end = x + dash < right ? x + dash : right;
		draw_list->AddLine(ImVec2(x, y), ImVec2(end, y), color, 1.0f);
	}
}

static void telemetry_threshold_label(
	ImDrawList* draw_list,
	const char* label,
	float right,
	float y,
	ImU32 color) {
	if (label == nullptr || label[0] == '\0') {
		return;
	}

	const ImVec2 size = ImGui::CalcTextSize(label);
	const ImVec2 text_pos(right - size.x - 4.0f, y - size.y - 2.0f);
	draw_list->AddRectFilled(
		ImVec2(text_pos.x - 3.0f, text_pos.y - 1.0f),
		ImVec2(text_pos.x + size.x + 3.0f, text_pos.y + size.y + 1.0f),
		IM_COL32(8, 13, 12, 218),
		3.0f);
	draw_list->AddText(text_pos, color, label);
}

void psycho_imgui_telemetry_chart(const char* id, const PsychoImguiTelemetryChart* chart) {
	if (id == nullptr || chart == nullptr || chart->values == nullptr || chart->count <= 0) {
		return;
	}

	const float width = chart->width > 0.0f
		? chart->width
		: ImGui::GetContentRegionAvail().x;
	const float height = chart->height > 0.0f ? chart->height : 112.0f;
	if (width <= 1.0f || height <= 1.0f || chart->scale_max <= chart->scale_min) {
		return;
	}

	ImGui::InvisibleButton(id, ImVec2(width, height));
	const ImVec2 frame_min = ImGui::GetItemRectMin();
	const ImVec2 frame_max = ImGui::GetItemRectMax();
	const ImVec2 plot_min(frame_min.x + 9.0f, frame_min.y + 8.0f);
	const ImVec2 plot_max(frame_max.x - 9.0f, frame_max.y - 23.0f);
	ImDrawList* draw_list = ImGui::GetWindowDrawList();

	draw_list->AddRectFilled(frame_min, frame_max, IM_COL32(5, 13, 11, 235), 5.0f);
	draw_list->AddRect(frame_min, frame_max, IM_COL32(34, 83, 68, 180), 5.0f);

	const float elapsed_seconds = static_cast<float>(chart->count - 1)
		* chart->sample_interval_seconds;
	const bool frame_timeline = chart->sample_interval_seconds <= 0.0f;
	char elapsed_label[32] = {};
	if (frame_timeline) {
		std::snprintf(
			elapsed_label,
			sizeof(elapsed_label),
			"%d FRAMES AGO",
			chart->count - 1);
	} else if (elapsed_seconds >= 60.0f) {
		std::snprintf(
			elapsed_label,
			sizeof(elapsed_label),
			"%d MIN AGO",
			static_cast<int32_t>((elapsed_seconds + 30.0f) / 60.0f));
	} else {
		std::snprintf(
			elapsed_label,
			sizeof(elapsed_label),
			"%d SEC AGO",
			static_cast<int32_t>(elapsed_seconds + 0.5f));
	}
	const ImU32 axis_color = IM_COL32(115, 144, 132, 170);
	const ImVec2 elapsed_size = ImGui::CalcTextSize(elapsed_label);
	const ImVec2 now_size = ImGui::CalcTextSize("NOW");
	const float axis_y = frame_max.y - elapsed_size.y - 3.0f;
	draw_list->AddText(ImVec2(plot_min.x, axis_y), axis_color, elapsed_label);
	draw_list->AddText(ImVec2(plot_max.x - now_size.x, axis_y), axis_color, "NOW");

	for (int32_t row = 1; row < 4; ++row) {
		const float y = plot_min.y + (plot_max.y - plot_min.y) * static_cast<float>(row) / 4.0f;
		draw_list->AddLine(
			ImVec2(plot_min.x, y),
			ImVec2(plot_max.x, y),
			IM_COL32(75, 111, 98, 34));
	}
	for (int32_t column = 1; column < 6; ++column) {
		const float x = plot_min.x
			+ (plot_max.x - plot_min.x) * static_cast<float>(column) / 6.0f;
		draw_list->AddLine(
			ImVec2(x, plot_min.y),
			ImVec2(x, plot_max.y),
			IM_COL32(75, 111, 98, 24));
	}

	const bool has_warning = std::isfinite(chart->warning_threshold);
	const bool has_critical = std::isfinite(chart->critical_threshold);
	const float warning_y = has_warning
		? telemetry_y(
			chart->warning_threshold,
			chart->scale_min,
			chart->scale_max,
			plot_min.y,
			plot_max.y)
		: plot_max.y;
	const float critical_y = has_critical
		? telemetry_y(
			chart->critical_threshold,
			chart->scale_min,
			chart->scale_max,
			plot_min.y,
			plot_max.y)
		: plot_max.y;

	if (has_warning && has_critical) {
		if (chart->danger_below != 0) {
			draw_list->AddRectFilled(
				ImVec2(plot_min.x, warning_y),
				ImVec2(plot_max.x, critical_y),
				IM_COL32(255, 174, 54, 18));
			draw_list->AddRectFilled(
				ImVec2(plot_min.x, critical_y),
				plot_max,
				IM_COL32(255, 68, 63, 22));
		} else {
			draw_list->AddRectFilled(
				ImVec2(plot_min.x, critical_y),
				ImVec2(plot_max.x, warning_y),
				IM_COL32(255, 174, 54, 18));
			draw_list->AddRectFilled(
				plot_min,
				ImVec2(plot_max.x, critical_y),
				IM_COL32(255, 68, 63, 22));
		}
	}

	if (has_warning) {
		telemetry_dashed_line(
			draw_list,
			plot_min.x,
			plot_max.x,
			warning_y,
			IM_COL32(255, 181, 69, 130));
		telemetry_threshold_label(
			draw_list,
			chart->warning_label,
			plot_max.x,
			warning_y,
			IM_COL32(255, 191, 90, 220));
	}
	if (has_critical) {
		telemetry_dashed_line(
			draw_list,
			plot_min.x,
			plot_max.x,
			critical_y,
			IM_COL32(255, 83, 78, 145));
		telemetry_threshold_label(
			draw_list,
			chart->critical_label,
			plot_max.x,
			critical_y,
			IM_COL32(255, 108, 103, 230));
	}

	const ImU32 line_color = telemetry_color(chart->line_color);
	const ImU32 fill_color = telemetry_color(chart->fill_color);
	const float denominator = static_cast<float>(chart->count > 1 ? chart->count - 1 : 1);
	if (chart->impulse_from_zero != 0) {
		const float zero_y = telemetry_y(
			0.0f,
			chart->scale_min,
			chart->scale_max,
			plot_min.y,
			plot_max.y);
		for (int32_t index = 0; index < chart->count; ++index) {
			if (std::fabs(chart->values[index]) <= 0.0001f) {
				continue;
			}
			const float x = plot_min.x
				+ (plot_max.x - plot_min.x) * static_cast<float>(index) / denominator;
			const float y = telemetry_y(
				chart->values[index],
				chart->scale_min,
				chart->scale_max,
				plot_min.y,
				plot_max.y);
			draw_list->AddLine(ImVec2(x, zero_y), ImVec2(x, y), line_color, 2.0f);
			draw_list->AddCircleFilled(ImVec2(x, y), 2.4f, line_color);
		}
	} else {
		for (int32_t index = 1; index < chart->count; ++index) {
			const float x0 = plot_min.x
				+ (plot_max.x - plot_min.x) * static_cast<float>(index - 1) / denominator;
			const float x1 = plot_min.x
				+ (plot_max.x - plot_min.x) * static_cast<float>(index) / denominator;
			const float y0 = telemetry_y(
				chart->values[index - 1],
				chart->scale_min,
				chart->scale_max,
				plot_min.y,
				plot_max.y);
			const float y1 = telemetry_y(
				chart->values[index],
				chart->scale_min,
				chart->scale_max,
				plot_min.y,
				plot_max.y);
			draw_list->AddQuadFilled(
				ImVec2(x0, y0),
				ImVec2(x1, y1),
				ImVec2(x1, plot_max.y),
				ImVec2(x0, plot_max.y),
				fill_color);
			draw_list->AddLine(ImVec2(x0, y0), ImVec2(x1, y1), line_color, 2.0f);
		}

		const float last_y = telemetry_y(
			chart->values[chart->count - 1],
			chart->scale_min,
			chart->scale_max,
			plot_min.y,
			plot_max.y);
		draw_list->AddCircleFilled(ImVec2(plot_max.x, last_y), 3.2f, line_color);
	}

	const ImU32 overflow_color = IM_COL32(255, 101, 91, 235);
	for (int32_t index = 0; index < chart->count; ++index) {
		const float x = plot_min.x
			+ (plot_max.x - plot_min.x) * static_cast<float>(index) / denominator;
		if (chart->values[index] > chart->scale_max) {
			draw_list->AddTriangleFilled(
				ImVec2(x, plot_min.y + 1.0f),
				ImVec2(x - 4.0f, plot_min.y + 8.0f),
				ImVec2(x + 4.0f, plot_min.y + 8.0f),
				overflow_color);
		} else if (chart->values[index] < chart->scale_min) {
			draw_list->AddTriangleFilled(
				ImVec2(x, plot_max.y - 1.0f),
				ImVec2(x - 4.0f, plot_max.y - 8.0f),
				ImVec2(x + 4.0f, plot_max.y - 8.0f),
				overflow_color);
		}
	}

	if (ImGui::IsItemHovered()) {
		const float mouse_fraction = clamp_float(
			(ImGui::GetIO().MousePos.x - plot_min.x) / (plot_max.x - plot_min.x),
			0.0f,
			1.0f);
		const int32_t index = static_cast<int32_t>(
			mouse_fraction * static_cast<float>(chart->count - 1) + 0.5f);
		const float x = plot_min.x
			+ (plot_max.x - plot_min.x) * static_cast<float>(index) / denominator;
		const float y = telemetry_y(
			chart->values[index],
			chart->scale_min,
			chart->scale_max,
			plot_min.y,
			plot_max.y);
		draw_list->AddLine(
			ImVec2(x, plot_min.y),
			ImVec2(x, plot_max.y),
			IM_COL32(185, 229, 207, 95));
		draw_list->AddCircleFilled(ImVec2(x, y), 4.0f, line_color);
		ImGui::BeginTooltip();
		const int32_t frames_ago = chart->count - 1 - index;
		const float seconds_ago = static_cast<float>(frames_ago)
			* chart->sample_interval_seconds;
		if (frame_timeline && frames_ago > 0) {
			ImGui::Text(
				"%d frame%s ago  %.1f%s",
				frames_ago,
				frames_ago == 1 ? "" : "s",
				chart->values[index],
				chart->value_suffix != nullptr ? chart->value_suffix : "");
		} else if (!frame_timeline && seconds_ago >= 0.5f) {
			ImGui::Text(
				"%.0f sec ago  %.1f%s",
				seconds_ago,
				chart->values[index],
				chart->value_suffix != nullptr ? chart->value_suffix : "");
		} else {
			ImGui::Text(
				"Now  %.1f%s",
				chart->values[index],
				chart->value_suffix != nullptr ? chart->value_suffix : "");
		}
		ImGui::EndTooltip();
	}
}

void psycho_imgui_push_item_width(float width) {
	ImGui::PushItemWidth(width);
}

void psycho_imgui_pop_item_width() {
	ImGui::PopItemWidth();
}

void psycho_imgui_same_line() {
	ImGui::SameLine();
}

void psycho_imgui_scroll_to_bottom() {
	ImGui::SetScrollHereY(1.0f);
}

} // extern "C"
