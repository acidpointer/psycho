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
	float max_width,
	float max_height,
	int condition) {
	ImGuiViewport* viewport = ImGui::GetMainViewport();
	const float available_width = viewport->WorkSize.x > 32.0f ? viewport->WorkSize.x - 32.0f : 1.0f;
	const float available_height = viewport->WorkSize.y > 32.0f ? viewport->WorkSize.y - 32.0f : 1.0f;
	const float constrained_min_width = min_width < available_width ? min_width : available_width;
	const float constrained_min_height = min_height < available_height ? min_height : available_height;
	const float constrained_max_width = max_width < available_width ? max_width : available_width;
	const float constrained_max_height = max_height < available_height ? max_height : available_height;
	const float width = clamp_float(
		viewport->WorkSize.x * width_ratio, constrained_min_width, constrained_max_width);
	const float height = clamp_float(
		viewport->WorkSize.y * height_ratio, constrained_min_height, constrained_max_height);

	ImGui::SetNextWindowSizeConstraints(
		ImVec2(constrained_min_width, constrained_min_height),
		ImVec2(constrained_max_width, constrained_max_height));
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

void psycho_imgui_push_item_width(float width) {
	ImGui::PushItemWidth(width);
}

void psycho_imgui_pop_item_width() {
	ImGui::PopItemWidth();
}

void psycho_imgui_same_line() {
	ImGui::SameLine();
}

} // extern "C"
