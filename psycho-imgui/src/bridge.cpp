#include <stdint.h>
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
	font_config.SizePixels = 15.0f;
	font_config.OversampleH = 2;
	font_config.OversampleV = 1;
	io.Fonts->AddFontDefaultVector(&font_config);
}

static void apply_psycho_style() {
	ImGui::StyleColorsDark();

	ImGuiStyle& style = ImGui::GetStyle();
	style.WindowPadding = ImVec2(12.0f, 10.0f);
	style.FramePadding = ImVec2(8.0f, 5.0f);
	style.ItemSpacing = ImVec2(8.0f, 7.0f);
	style.ItemInnerSpacing = ImVec2(7.0f, 5.0f);
	style.ScrollbarSize = 15.0f;
	style.GrabMinSize = 12.0f;
	style.WindowRounding = 6.0f;
	style.ChildRounding = 5.0f;
	style.FrameRounding = 4.0f;
	style.PopupRounding = 4.0f;
	style.ScrollbarRounding = 8.0f;
	style.GrabRounding = 4.0f;
	style.TabRounding = 4.0f;
	style.WindowBorderSize = 1.0f;
	style.ChildBorderSize = 1.0f;
	style.FrameBorderSize = 1.0f;

	ImVec4* colors = style.Colors;
	colors[ImGuiCol_Text] = ImVec4(0.90f, 0.93f, 0.95f, 1.00f);
	colors[ImGuiCol_TextDisabled] = ImVec4(0.44f, 0.49f, 0.54f, 1.00f);
	colors[ImGuiCol_WindowBg] = ImVec4(0.055f, 0.065f, 0.075f, 0.96f);
	colors[ImGuiCol_ChildBg] = ImVec4(0.070f, 0.083f, 0.095f, 0.92f);
	colors[ImGuiCol_PopupBg] = ImVec4(0.070f, 0.083f, 0.095f, 0.98f);
	colors[ImGuiCol_Border] = ImVec4(0.22f, 0.30f, 0.36f, 0.80f);
	colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	colors[ImGuiCol_FrameBg] = ImVec4(0.105f, 0.145f, 0.180f, 0.92f);
	colors[ImGuiCol_FrameBgHovered] = ImVec4(0.145f, 0.245f, 0.310f, 1.00f);
	colors[ImGuiCol_FrameBgActive] = ImVec4(0.120f, 0.330f, 0.420f, 1.00f);
	colors[ImGuiCol_TitleBg] = ImVec4(0.070f, 0.105f, 0.130f, 1.00f);
	colors[ImGuiCol_TitleBgActive] = ImVec4(0.080f, 0.185f, 0.245f, 1.00f);
	colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.050f, 0.060f, 0.070f, 0.90f);
	colors[ImGuiCol_MenuBarBg] = ImVec4(0.080f, 0.100f, 0.115f, 1.00f);
	colors[ImGuiCol_ScrollbarBg] = ImVec4(0.030f, 0.040f, 0.050f, 0.72f);
	colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.180f, 0.285f, 0.350f, 0.90f);
	colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.240f, 0.410f, 0.490f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.280f, 0.520f, 0.610f, 1.00f);
	colors[ImGuiCol_CheckMark] = ImVec4(0.30f, 0.85f, 0.92f, 1.00f);
	colors[ImGuiCol_SliderGrab] = ImVec4(0.25f, 0.62f, 0.78f, 1.00f);
	colors[ImGuiCol_SliderGrabActive] = ImVec4(0.34f, 0.82f, 0.95f, 1.00f);
	colors[ImGuiCol_Button] = ImVec4(0.105f, 0.210f, 0.285f, 0.92f);
	colors[ImGuiCol_ButtonHovered] = ImVec4(0.145f, 0.335f, 0.430f, 1.00f);
	colors[ImGuiCol_ButtonActive] = ImVec4(0.095f, 0.430f, 0.520f, 1.00f);
	colors[ImGuiCol_Header] = ImVec4(0.100f, 0.215f, 0.280f, 0.78f);
	colors[ImGuiCol_HeaderHovered] = ImVec4(0.145f, 0.340f, 0.430f, 0.88f);
	colors[ImGuiCol_HeaderActive] = ImVec4(0.165f, 0.460f, 0.560f, 1.00f);
	colors[ImGuiCol_Separator] = ImVec4(0.20f, 0.30f, 0.36f, 0.70f);
	colors[ImGuiCol_SeparatorHovered] = ImVec4(0.28f, 0.54f, 0.62f, 0.78f);
	colors[ImGuiCol_SeparatorActive] = ImVec4(0.34f, 0.70f, 0.78f, 1.00f);
	colors[ImGuiCol_ResizeGrip] = ImVec4(0.22f, 0.55f, 0.62f, 0.35f);
	colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.30f, 0.72f, 0.80f, 0.67f);
	colors[ImGuiCol_ResizeGripActive] = ImVec4(0.35f, 0.82f, 0.90f, 0.95f);
	colors[ImGuiCol_PlotLines] = ImVec4(0.30f, 0.80f, 0.92f, 1.00f);
	colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.55f, 0.93f, 1.00f, 1.00f);
	colors[ImGuiCol_PlotHistogram] = ImVec4(0.92f, 0.66f, 0.26f, 1.00f);
	colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.78f, 0.32f, 1.00f);
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

void psycho_imgui_spacing() {
	ImGui::Spacing();
}

bool psycho_imgui_checkbox(const char* label, bool* value) {
	return ImGui::Checkbox(label, value);
}

bool psycho_imgui_slider_float(const char* label, float* value, float min, float max) {
	return ImGui::SliderFloat(label, value, min, max);
}

bool psycho_imgui_slider_int(const char* label, int32_t* value, int32_t min, int32_t max) {
	return ImGui::SliderInt(label, value, min, max);
}

bool psycho_imgui_selectable(const char* label, bool selected) {
	return ImGui::Selectable(label, selected);
}

bool psycho_imgui_button(const char* label) {
	return ImGui::Button(label);
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
