// Offline tests execute the same widgets with real ImGui input. This header is
// compiled only by the test-support feature; release backends do not include it.
#include <string>
#include <vector>

struct PsychoTestItem {
	std::string label;
	ImVec2 min;
	ImVec2 max;
};
static std::vector<PsychoTestItem> psycho_test_items;
static bool psycho_test_active = false;

static void psycho_test_record(const char* label) {
	if (psycho_test_active && ImGui::IsItemVisible()) {
		psycho_test_items.push_back({label, ImGui::GetItemRectMin(), ImGui::GetItemRectMax()});
	}
}
#define PSYCHO_IMGUI_RECORD(label) psycho_test_record(label)

extern "C" {
void psycho_imgui_test_create() {
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.IniFilename = nullptr;
	io.LogFilename = nullptr;
	io.Fonts->AddFontDefaultBitmap();
	unsigned char* pixels;
	int width, height;
	io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
	psycho_test_active = true;
}
void psycho_imgui_test_destroy() {
	ImGui::DestroyContext();
	psycho_test_active = false;
	psycho_test_items.clear();
}
void psycho_imgui_test_begin(float width, float height) {
	psycho_test_items.clear();
	ImGuiIO& io = ImGui::GetIO();
	io.DisplaySize = ImVec2(width, height);
	io.DeltaTime = 1.0f / 60.0f;
	ImGui::NewFrame();
}
void psycho_imgui_test_end() { ImGui::Render(); }
void psycho_imgui_test_pointer(float x, float y, bool down) {
	ImGui::GetIO().AddMousePosEvent(x, y);
	ImGui::GetIO().AddMouseButtonEvent(0, down);
}
void psycho_imgui_test_text(const char* text) {
	ImGui::GetIO().AddInputCharactersUTF8(text);
}
bool psycho_imgui_test_item(const char* label, float* x, float* y) {
	for (const auto& item : psycho_test_items) {
		if (item.label == label) {
			*x = (item.min.x + item.max.x) * 0.5f;
			*y = (item.min.y + item.max.y) * 0.5f;
			return true;
		}
	}
	return false;
}
}
