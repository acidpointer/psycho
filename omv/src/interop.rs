//! Read-only graphics interoperability reporting.
//!
//! Hook owners retain their own process-lifetime storage because moving those
//! statics would change the already-sensitive pre-Deferred PE/static footprint.
//! This module only takes atomic/lock-free snapshots after `DeferredInit`. It
//! never installs hooks, discovers modules for behavior, or feeds a capability
//! result back into rendering policy. Module names are resolved lazily for the
//! visible diagnostics UI and serve only as ownership evidence.

use libpsycho::os::windows::patch::module_address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InteropState {
    Active,
    Unavailable,
    DependencyBlocked,
    Disabled,
}

impl InteropState {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Unavailable => "unavailable",
            Self::DependencyBlocked => "dependency-blocked",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct InteropCapability {
    pub(crate) name: &'static str,
    pub(crate) state: InteropState,
    pub(crate) reason: &'static str,
    pub(crate) predecessors: [Option<usize>; 3],
}

impl InteropCapability {
    fn route(
        name: &'static str,
        ready: bool,
        active_reason: &'static str,
        unavailable_reason: &'static str,
        predecessors: [Option<usize>; 3],
    ) -> Self {
        Self {
            name,
            state: if ready {
                InteropState::Active
            } else {
                InteropState::Unavailable
            },
            reason: if ready {
                active_reason
            } else {
                unavailable_reason
            },
            predecessors,
        }
    }
}

/// Snapshot every interception contract without probing modules or D3D.
///
/// The vector allocation is intentional and bounded: callers are the single
/// post-Deferred startup log and the already-visible Diagnostics UI. Render
/// and configuration callbacks never call this function.
pub(crate) fn capability_snapshot() -> Vec<InteropCapability> {
    let engine = crate::hooks::interoperability_status();
    let scene = crate::fnv_render::interoperability_status();
    let pbr = crate::effects::pbr::interoperability_status();
    let sky = crate::effects::sky::interoperability_status();
    let lights = crate::fnv_local_lights::interoperability_status();

    vec![
        InteropCapability::route(
            "Presentation",
            crate::startup::deferred_graphics_ready(),
            "xNVSE OnFramePresent owns final servicing and epoch completion",
            "DeferredInit has not published the presentation route",
            [None; 3],
        ),
        InteropCapability::route(
            "Reset",
            engine.reset_ready,
            "the unique Recreate caller chains its captured predecessor",
            "the Recreate caller could not be chained safely",
            [engine.reset_predecessor, None, None],
        ),
        InteropCapability::route(
            "Image space",
            scene.image_space_ready,
            "the outer image-space caller is chained",
            "the image-space caller contract is unavailable",
            [scene.image_space_predecessor, None, None],
        ),
        InteropCapability::route(
            "Water classification",
            scene.water_ready,
            "all three water callers are chained as one group",
            "at least one required water caller is unavailable",
            scene.water_predecessors,
        ),
        InteropCapability::route(
            "World phase",
            scene.world_ready,
            "both world callers are chained as one group",
            "at least one required world caller is unavailable",
            [
                scene.world_predecessors[0],
                scene.world_predecessors[1],
                None,
            ],
        ),
        InteropCapability::route(
            "First person",
            scene.first_person_ready,
            "all three first-person callers are chained as one group",
            "at least one required first-person caller is unavailable",
            scene.first_person_predecessors,
        ),
        InteropCapability::route(
            "Pre-alpha",
            scene.pre_alpha_ready,
            "both opaque-world callers are chained as one group",
            "at least one required pre-alpha caller is unavailable",
            [
                scene.pre_alpha_predecessors[0],
                scene.pre_alpha_predecessors[1],
                None,
            ],
        ),
        InteropCapability::route(
            "Geometry",
            engine.geometry_ready,
            "both live renderer submission slots are chained",
            "one or both renderer submission slots are unavailable",
            [
                engine.geometry_predecessors[0],
                engine.geometry_predecessors[1],
                None,
            ],
        ),
        InteropCapability::route(
            "Texture mirror",
            pbr.texture_ready,
            "the live render-state SetTexture slot is chained",
            "the render-state SetTexture slot is unavailable",
            [pbr.texture_predecessor, None, None],
        ),
        InteropCapability::route(
            "PBR selection",
            pbr.selection_ready,
            "the common selector-setup caller is chained",
            "the common selector-setup caller is unavailable",
            [pbr.selection_predecessor, None, None],
        ),
        InteropCapability::route(
            "PBR package",
            pbr.package_ready,
            "both package callers and the lifetime contract are active",
            "the package transition/lifetime transaction is unavailable",
            [
                pbr.package_predecessors[0],
                pbr.package_predecessors[1],
                None,
            ],
        ),
        InteropCapability::route(
            "PBR terrain",
            pbr.terrain_ready,
            "the consumed shader rows and native resources passed the functional probe",
            "the consumed terrain shader/resource contract did not validate",
            [None; 3],
        ),
        InteropCapability::route(
            "Sky constants",
            sky.constants_ready,
            "the live SkyShader selector slot is chained",
            "the SkyShader selector slot is unavailable",
            [sky.constants_predecessor, None, None],
        ),
        InteropCapability::route(
            "Local-light epoch",
            lights.epoch_ready,
            "all three scene-light callers are chained as one group",
            "at least one required scene-light caller is unavailable",
            lights.epoch_predecessors,
        ),
        InteropCapability::route(
            "Completed shadow",
            lights.completed_shadow_ready,
            "the completed-shadow caller is chained",
            "completed-shadow enrichment is unavailable; scalar lights remain usable",
            [lights.completed_shadow_predecessor, None, None],
        ),
        InteropCapability::route(
            "Native shadow replacement",
            lights.native_shadow_replacement_ready,
            "the common native implementation matches the exclusive replacement contract",
            "the common implementation differs; cooperative observation remains independent",
            [None; 3],
        ),
    ]
}

/// Classify the user-facing PBR feature without collapsing its independent
/// engine contracts into a global OMV-ready switch.
pub(crate) fn pbr_feature_status(configured: bool) -> InteropCapability {
    let engine = crate::hooks::interoperability_status();
    let pbr = crate::effects::pbr::interoperability_status();
    if !configured {
        return InteropCapability {
            name: "Native PBR feature",
            state: InteropState::Disabled,
            reason: "disabled by user configuration",
            predecessors: [None; 3],
        };
    }
    if !pbr.selection_ready || !pbr.texture_ready {
        return InteropCapability {
            name: "Native PBR feature",
            state: InteropState::Unavailable,
            reason: "a mandatory PBR engine slot could not be chained safely",
            predecessors: [None; 3],
        };
    }
    if !engine.geometry_ready || !pbr.package_ready {
        return InteropCapability {
            name: "Native PBR feature",
            state: InteropState::DependencyBlocked,
            reason: "geometry or shader-package ownership is unavailable",
            predecessors: [None; 3],
        };
    }
    InteropCapability {
        name: "Native PBR feature",
        state: InteropState::Active,
        reason: if pbr.terrain_ready {
            "object and terrain interception contracts are available"
        } else {
            "object contracts are available; terrain remains independently unavailable"
        },
        predecessors: [None; 3],
    }
}

pub(crate) fn sky_feature_status(configured: bool) -> InteropCapability {
    let engine = crate::hooks::interoperability_status();
    let pbr = crate::effects::pbr::interoperability_status();
    let sky = crate::effects::sky::interoperability_status();
    if !configured {
        return InteropCapability {
            name: "Native sky feature",
            state: InteropState::Disabled,
            reason: "disabled by user configuration",
            predecessors: [None; 3],
        };
    }
    if !sky.constants_ready {
        return InteropCapability {
            name: "Native sky feature",
            state: InteropState::Unavailable,
            reason: "the SkyShader constants slot could not be chained safely",
            predecessors: [None; 3],
        };
    }
    if !engine.geometry_ready || !pbr.texture_ready {
        return InteropCapability {
            name: "Native sky feature",
            state: InteropState::DependencyBlocked,
            reason: "geometry submission or the shared texture mirror is unavailable",
            predecessors: [None; 3],
        };
    }
    InteropCapability {
        name: "Native sky feature",
        state: InteropState::Active,
        reason: "sky constants, texture observation, and geometry ownership are available",
        predecessors: [None; 3],
    }
}

/// Resolve captured addresses to human-readable owners for presentation only.
pub(crate) fn predecessor_label(capability: &InteropCapability) -> Option<String> {
    let labels = capability
        .predecessors
        .into_iter()
        .flatten()
        .map(|address| {
            module_address(address).unwrap_or_else(|| format!("unknown!0x{address:08X}"))
        })
        .collect::<Vec<_>>();
    (!labels.is_empty()).then(|| labels.join(" // "))
}

pub(crate) fn log_startup_matrix() {
    let matrix = capability_snapshot()
        .into_iter()
        .map(|capability| format!("{}={}", capability.name, capability.state.label()))
        .collect::<Vec<_>>()
        .join(", ");
    log::info!("[INTEROP] Deferred capability matrix: {matrix}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_labels_distinguish_all_required_diagnostic_classes() {
        assert_eq!(InteropState::Active.label(), "active");
        assert_eq!(InteropState::Unavailable.label(), "unavailable");
        assert_eq!(
            InteropState::DependencyBlocked.label(),
            "dependency-blocked"
        );
        assert_eq!(InteropState::Disabled.label(), "disabled");
    }

    #[test]
    fn module_ownership_is_formatting_only() {
        let source = include_str!("interop.rs");
        let snapshot = source
            .split_once("pub(crate) fn capability_snapshot()")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn pbr_feature_status"))
            .map(|(body, _)| body)
            .expect("capability snapshot");
        assert!(!snapshot.contains("module_address("));
        assert!(!snapshot.contains("get_module"));

        let formatter = source
            .split_once("pub(crate) fn predecessor_label")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn log_startup_matrix"))
            .map(|(body, _)| body)
            .expect("diagnostic predecessor formatter");
        assert!(formatter.contains("module_address(address)"));
    }

    #[test]
    fn ownership_reporting_stays_after_deferred_and_behind_visible_diagnostics() {
        let startup = include_str!("startup.rs");
        let complete = startup
            .find("install_attempt.complete()")
            .expect("DeferredInit completion publication");
        let matrix = startup
            .find("interop::log_startup_matrix()")
            .expect("one startup capability matrix");
        assert!(complete < matrix);

        let runtime = include_str!("runtime.rs");
        let diagnostics_marker = ["\nfn draw_diagnostics_", "tab("].concat();
        let system_marker = ["\nfn draw_system_at_a_", "glance("].concat();
        let diagnostics = runtime
            .split_once(&diagnostics_marker)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once(&system_marker))
            .map(|(body, _)| body)
            .expect("diagnostics tab body");
        let visibility_gate = diagnostics
            .find("if !diagnostics.is_visible()")
            .expect("visible child gate");
        let ownership_ui = diagnostics
            .find("draw_interoperability_diagnostics")
            .expect("interoperability panel");
        assert!(visibility_gate < ownership_ui);
    }
}
