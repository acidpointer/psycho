//! Fast, bounded hardware and compatibility-runtime detection.
//!
//! The cached [`system_profile`] contains stable CPU identity and features,
//! startup memory capacity, and Wine/Proton evidence. Dynamic memory pressure
//! remains available through [`memory_status`], while SMBIOS memory devices
//! and Direct3D 9 GPU profiles are explicit lazy operations because firmware
//! parsing and graphics calls are not appropriate on every startup path.
//!
//! Detection never starts workers, launches subprocesses, queries WMI, reads
//! the registry, or performs network I/O. Partial core detection is preserved:
//! optional Windows failures are recorded as [`DetectionIssue`] values instead
//! of discarding otherwise valid CPU or runtime information.
//! Live D3D9 diagnostics use [`d3d9_device_profile_report`] when optional DXVK
//! identity enrichment must not discard otherwise valid D3D9 evidence; the
//! original [`d3d9_device_profile`] contract remains strict and source
//! compatible.

#![deny(missing_docs)]

mod cpu;
mod gpu;
mod memory;
mod runtime;

use std::sync::OnceLock;

use thiserror::Error;

use crate::os::windows::winapi;

pub use cpu::{CpuCache, CpuCacheKind, CpuEfficiencyClass, CpuFeatures, CpuInfo, CpuVendor};
pub use gpu::{
    D3d9ActiveGpuIdentity, D3d9AdapterProfile, D3d9Capabilities, D3d9DeviceKind, D3d9DeviceProfile,
    D3d9DeviceProfileReport, D3d9FeatureFlags, D3d9FormatFeatures, D3d9ProfileGpuIdentity,
    DxvkPhysicalDeviceIdentity, GpuIdentity, ShaderModel, VulkanDeviceKind, d3d9_adapter_profiles,
    d3d9_device_profile, d3d9_device_profile_report,
};
pub use memory::{
    MemoryArray, MemoryArrayLocation, MemoryArrayUse, MemoryDevice, MemoryDeviceProfile,
    MemoryErrorCorrection, MemoryFormFactor, MemoryStatus, MemoryTechnology, MemoryType,
    MemoryTypeDetail, SmbiosVersion, SystemMemoryInfo, memory_device_profile, memory_status,
};
pub use runtime::{CompatibilityRuntime, RuntimeInfo, WineInfo};

/// Result type used by fallible hardware queries.
pub type HardwareResult<T> = Result<T, HardwareError>;

/// High-level subsystem associated with a recoverable detection issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareComponent {
    /// CPU topology or feature detection.
    Cpu,
    /// Physical or virtual memory detection.
    Memory,
    /// SMBIOS memory-device parsing.
    Firmware,
    /// Wine or Proton runtime detection.
    Runtime,
    /// Direct3D 9 adapter or device detection.
    Gpu,
}

/// A recoverable problem encountered while collecting the cached profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectionIssue {
    /// Subsystem whose optional data could not be collected.
    pub component: HardwareComponent,
    /// Operation and error text suitable for diagnostics.
    pub message: String,
}

impl DetectionIssue {
    pub(crate) fn new(component: HardwareComponent, error: impl std::fmt::Display) -> Self {
        Self {
            component,
            message: error.to_string(),
        }
    }
}

/// Failure returned by an explicit hardware query.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HardwareError {
    /// A platform or Direct3D operation failed.
    #[error("{operation} failed: {message}")]
    Operation {
        /// Stable operation name.
        operation: &'static str,
        /// Owned platform error text.
        message: String,
    },
    /// Firmware or another external binary record was structurally invalid.
    #[error("malformed {data_source}: {reason}")]
    MalformedData {
        /// Name of the data source.
        data_source: &'static str,
        /// Boundary or field validation that failed.
        reason: &'static str,
    },
}

impl HardwareError {
    pub(crate) fn operation(operation: &'static str, error: impl std::fmt::Display) -> Self {
        Self::Operation {
            operation,
            message: error.to_string(),
        }
    }

    pub(crate) const fn malformed(data_source: &'static str, reason: &'static str) -> Self {
        Self::MalformedData {
            data_source,
            reason,
        }
    }
}

/// Stable hardware and runtime data cached for the process lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemProfile {
    /// CPU identity, topology, caches, and instruction features.
    pub cpu: CpuInfo,
    /// Native page layout and startup memory capacities.
    pub memory: SystemMemoryInfo,
    /// Native Windows, Wine, or Proton runtime evidence.
    pub runtime: RuntimeInfo,
    /// Optional fields that could not be collected.
    pub issues: Vec<DetectionIssue>,
}

static SYSTEM_PROFILE: OnceLock<SystemProfile> = OnceLock::new();

/// Return the process-wide cached system profile.
///
/// The first call performs bounded CPUID and Win32 queries. Later calls are
/// lock-free reads from `OnceLock`. GPU and detailed SMBIOS queries are not
/// included; call [`d3d9_device_profile`], [`d3d9_device_profile_report`], or
/// [`memory_device_profile`] at an appropriate subsystem boundary.
pub fn system_profile() -> &'static SystemProfile {
    SYSTEM_PROFILE.get_or_init(collect_system_profile)
}

fn collect_system_profile() -> SystemProfile {
    let mut issues = Vec::new();
    let layout = winapi::native_system_layout();
    let cpu = cpu::detect(layout, &mut issues);
    let memory = memory::detect_system_memory(layout, &mut issues);
    let runtime = runtime::detect(&mut issues);
    SystemProfile {
        cpu,
        memory,
        runtime,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_profile_preserves_core_invariants() {
        let first = system_profile();
        let second = system_profile();
        assert!(std::ptr::eq(first, second));
        assert!(!first.cpu.vendor_id.is_empty());
        assert!(first.cpu.logical_processor_count > 0);
        assert!(
            first
                .cpu
                .advertised_features
                .contains(first.cpu.usable_features)
        );
        assert!(first.memory.page_size > 0);
        assert!(first.memory.allocation_granularity >= first.memory.page_size);
        if let Some(status) = first.memory.startup_status {
            assert!(status.available_physical_bytes <= status.total_physical_bytes);
            assert!(status.available_page_file_bytes <= status.total_page_file_bytes);
            assert!(status.available_virtual_bytes <= status.total_virtual_bytes);
        }
    }
}
