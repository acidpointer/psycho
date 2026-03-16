mod critical_sections;
mod deferred_task_patch;
mod sleep_patches;
mod thread_priority;
mod timer_resolution;

pub use critical_sections::install_critical_section_hooks;
pub use deferred_task_patch::patch_deferred_task_budget;
pub use sleep_patches::install_sleep_patches;
pub use thread_priority::boost_main_thread_priority;
pub use timer_resolution::set_timer_resolution;
