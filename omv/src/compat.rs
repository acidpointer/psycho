//! Graphics mod dependency and hook-owner detection.

use libpsycho::os::windows::winapi::get_module_handle_w;

#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphicsCompatibility {
    pub(crate) vanilla_plus_terrain: bool,
    pub(crate) fallout_shader_loader: bool,
    pub(crate) lod_flicker_fix: bool,
}

impl GraphicsCompatibility {
    pub(crate) fn detect() -> Self {
        Self {
            vanilla_plus_terrain: module_loaded("VanillaPlusTerrain.dll"),
            fallout_shader_loader: module_loaded("Fallout Shader Loader.dll"),
            lod_flicker_fix: module_loaded("LODFlickerFix.dll"),
        }
    }

    pub(crate) fn has_vpt_terrain_contract(self) -> bool {
        self.vanilla_plus_terrain && self.fallout_shader_loader && self.lod_flicker_fix
    }

    pub(crate) fn log_report(self) {
        log::info!(
            "[COMPAT] Modules: VanillaPlusTerrain={}, FalloutShaderLoader={}, LODFlickerFix={}",
            present(self.vanilla_plus_terrain),
            present(self.fallout_shader_loader),
            present(self.lod_flicker_fix),
        );

        if self.has_vpt_terrain_contract() {
            log::info!("[COMPAT] VPT terrain contract is available for future terrain PBR work");
        } else {
            log::info!(
                "[COMPAT] VPT terrain contract is unavailable; terrain PBR features must stay disabled"
            );
        }
    }
}

fn module_loaded(name: &str) -> bool {
    get_module_handle_w(Some(name)).is_ok()
}

fn present(value: bool) -> &'static str {
    if value { "present" } else { "absent" }
}
