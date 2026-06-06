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

bool psycho_imgui_begin_window(const char* title, bool* open) {
	return ImGui::Begin(title, open);
}

void psycho_imgui_end_window() {
	ImGui::End();
}

void psycho_imgui_text_unformatted(const char* text) {
	ImGui::TextUnformatted(text);
}

void psycho_imgui_separator() {
	ImGui::Separator();
}

bool psycho_imgui_checkbox(const char* label, bool* value) {
	return ImGui::Checkbox(label, value);
}

bool psycho_imgui_slider_float(const char* label, float* value, float min, float max) {
	return ImGui::SliderFloat(label, value, min, max);
}

bool psycho_imgui_button(const char* label) {
	return ImGui::Button(label);
}

void psycho_imgui_same_line() {
	ImGui::SameLine();
}

} // extern "C"
