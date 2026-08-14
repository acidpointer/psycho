//! Read-only graphics-module inventory for startup diagnostics.
//!
//! Module names never admit an effect or select hook behavior. Runtime
//! capabilities are established from engine instructions, live dispatch
//! slots, resources, and ABIs by their owning subsystems.

use libpsycho::os::windows::winapi::get_module_handle_w;

#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphicsCompatibility {
    pub(crate) vanilla_plus_terrain: bool,
    pub(crate) fallout_shader_loader: bool,
    pub(crate) lod_flicker_fix: bool,
    pub(crate) depth_resolve: bool,
}

impl GraphicsCompatibility {
    pub(crate) fn detect() -> Self {
        Self {
            vanilla_plus_terrain: module_loaded("VanillaPlusTerrain.dll"),
            fallout_shader_loader: module_loaded("Fallout Shader Loader.dll"),
            lod_flicker_fix: module_loaded("LODFlickerFix.dll"),
            depth_resolve: module_loaded("DepthResolve.dll"),
        }
    }

    pub(crate) fn log_report(self) {
        log::info!(
            "[COMPAT] Modules: VanillaPlusTerrain={}, FalloutShaderLoader={}, LODFlickerFix={}, DepthResolve={}",
            present(self.vanilla_plus_terrain),
            present(self.fallout_shader_loader),
            present(self.lod_flicker_fix),
            present(self.depth_resolve),
        );

        log::info!(
            "[COMPAT] Module inventory is diagnostic only; graphics capabilities use functional probes"
        );
    }
}

fn module_loaded(name: &str) -> bool {
    get_module_handle_w(Some(name)).is_ok()
}

fn present(value: bool) -> &'static str {
    if value { "present" } else { "absent" }
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_inventory_cannot_admit_graphics_behavior() {
        let source = include_str!("compat.rs");
        assert!(!source.contains(&["has_vpt_", "terrain_contract"].concat()));
        assert!(!source.contains(&["TERRAIN_CONTRACT_", "AVAILABLE"].concat()));
        assert!(source.contains("functional probes"));
    }
}
