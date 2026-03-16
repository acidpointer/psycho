mod critical_sections;
mod sleep_patches;

pub use critical_sections::install_critical_section_hooks;
pub use sleep_patches::install_sleep_patches;
