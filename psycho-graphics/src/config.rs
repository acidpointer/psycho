//! Graphics module configuration.

use std::sync::OnceLock;

use libpsycho::config::Config;
use serde::{Deserialize, Serialize};

pub(crate) const CONFIG_PATH: &str = "mods/psycho_graphics.toml";

static CONFIG: OnceLock<PsychoGraphicsConfig> = OnceLock::new();

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct PsychoGraphicsConfig {
    pub(crate) graphics: GraphicsConfig,
    pub(crate) diagnostics: DiagnosticsConfig,
}

impl Default for PsychoGraphicsConfig {
    fn default() -> Self {
        Self {
            graphics: GraphicsConfig::default(),
            diagnostics: DiagnosticsConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GraphicsConfig {
    pub(crate) screen_space_shaders: bool,
    pub(crate) depth_provider: DepthProviderConfig,
    pub(crate) imgui_menu: bool,
    pub(crate) menu_toggle_key: u32,
    pub(crate) shader_scan_interval_ms: u64,
}

impl Default for GraphicsConfig {
    fn default() -> Self {
        Self {
            screen_space_shaders: true,
            depth_provider: DepthProviderConfig::default(),
            imgui_menu: true,
            menu_toggle_key: 0x2D,
            shader_scan_interval_ms: 200,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DepthProviderConfig {
    None,
    #[default]
    #[serde(alias = "d3d9_auto")]
    #[serde(alias = "fallout_new_vegas_image_space")]
    #[serde(alias = "fallout_new_vegas_d3d_depth")]
    FalloutNewVegas,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct DiagnosticsConfig {
    pub(crate) debug_log: bool,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self { debug_log: true }
    }
}

pub(crate) fn load_config() -> &'static PsychoGraphicsConfig {
    CONFIG.get_or_init(|| Config::load_readonly::<PsychoGraphicsConfig>(CONFIG_PATH))
}
