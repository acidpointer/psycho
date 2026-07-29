//! Human-readable startup hardware reporting.
//!
//! This module is a presentation layer over `libpsycho::hardware`; detection
//! policy and Win32 ownership stay in libpsycho. The report runs after allocator
//! selection has completed, so its temporary formatting allocations use the
//! allocator retained for the session and cannot straddle an allocator
//! transition. It is diagnostic only: missing topology or SMBIOS data is logged
//! as unavailable and never changes an engine fix or allocator decision.

use libpsycho::hardware::{
    self, CompatibilityRuntime, CpuCache, CpuCacheKind, CpuFeatures, HardwareComponent,
    MemoryArrayUse, MemoryDevice, MemoryErrorCorrection, MemoryFormFactor, MemoryTechnology,
    MemoryType, MemoryTypeDetail, RuntimeInfo,
};

/// Write the process runtime, CPU, and RAM profile at INFO level.
pub(crate) fn log_startup_hardware() {
    let profile = hardware::system_profile();

    log::info!("[HARDWARE] --------------------------------------------------------");
    log::info!("[HARDWARE] System profile");
    log::info!("[HARDWARE] Runtime  : {}", format_runtime(&profile.runtime));
    log::info!(
        "[HARDWARE] CPU      : {}",
        profile
            .cpu
            .brand
            .as_deref()
            .unwrap_or(profile.cpu.vendor_id.as_str())
    );
    log::info!(
        "[HARDWARE] CPU ID   : {}; family {}, model {}, stepping {}",
        profile.cpu.vendor_id,
        profile.cpu.family,
        profile.cpu.model,
        profile.cpu.stepping
    );
    if profile.cpu.hypervisor_present {
        log::info!(
            "[HARDWARE] CPU VM   : hypervisor {}",
            profile
                .cpu
                .hypervisor_vendor
                .as_deref()
                .unwrap_or("unknown")
        );
    }
    log::info!(
        "[HARDWARE] Topology : {} / {}; {}; {}; process parallelism {}",
        format_optional_quantity(
            profile.cpu.physical_core_count,
            "physical core",
            "physical cores"
        ),
        format_quantity(
            profile.cpu.logical_processor_count,
            "logical processor",
            "logical processors"
        ),
        format_optional_quantity(profile.cpu.package_count, "package", "packages"),
        format_optional_quantity(profile.cpu.numa_node_count, "NUMA node", "NUMA nodes"),
        profile.cpu.available_parallelism
    );
    log::info!(
        "[HARDWARE] Caches   : {}",
        format_caches(&profile.cpu.caches)
    );
    log::info!(
        "[HARDWARE] CPU SIMD : {}",
        format_features(profile.cpu.usable_features, SIMD_FEATURES)
    );
    log::info!(
        "[HARDWARE] CPU ISA  : {}",
        format_features(profile.cpu.usable_features, SCALAR_FEATURES)
    );
    if profile.cpu.usable_features != profile.cpu.advertised_features {
        log::info!(
            "[HARDWARE] CPU note : AVX-family features advertised by CPUID were filtered to the state enabled by the operating system"
        );
    }

    log::info!(
        "[HARDWARE] RAM      : {}",
        format_system_memory(&profile.memory)
    );
    log::info!(
        "[HARDWARE] Layout   : {} pages; {} allocation granularity",
        format_capacity(u64::from(profile.memory.page_size)),
        format_capacity(u64::from(profile.memory.allocation_granularity))
    );
    log_memory_devices();

    for issue in &profile.issues {
        log::info!(
            "[HARDWARE] Note     : {} detection unavailable: {}",
            component_name(issue.component),
            issue.message
        );
    }
    log::info!("[HARDWARE] --------------------------------------------------------");
}

const SIMD_FEATURES: &[(CpuFeatures, &str)] = &[
    (CpuFeatures::MMX, "MMX"),
    (CpuFeatures::SSE, "SSE"),
    (CpuFeatures::SSE2, "SSE2"),
    (CpuFeatures::SSE3, "SSE3"),
    (CpuFeatures::SSSE3, "SSSE3"),
    (CpuFeatures::SSE4_1, "SSE4.1"),
    (CpuFeatures::SSE4_2, "SSE4.2"),
    (CpuFeatures::SSE4A, "SSE4a"),
    (CpuFeatures::AVX, "AVX"),
    (CpuFeatures::AVX2, "AVX2"),
    (CpuFeatures::F16C, "F16C"),
    (CpuFeatures::FMA, "FMA"),
    (CpuFeatures::AVX512F, "AVX-512F"),
    (CpuFeatures::AVX512BW, "AVX-512BW"),
    (CpuFeatures::AVX512DQ, "AVX-512DQ"),
    (CpuFeatures::AVX512CD, "AVX-512CD"),
    (CpuFeatures::AVX512VL, "AVX-512VL"),
];

const SCALAR_FEATURES: &[(CpuFeatures, &str)] = &[
    (CpuFeatures::AES, "AES"),
    (CpuFeatures::PCLMULQDQ, "PCLMULQDQ"),
    (CpuFeatures::SHA, "SHA"),
    (CpuFeatures::POPCNT, "POPCNT"),
    (CpuFeatures::LZCNT, "LZCNT"),
    (CpuFeatures::BMI1, "BMI1"),
    (CpuFeatures::BMI2, "BMI2"),
    (CpuFeatures::ADX, "ADX"),
    (CpuFeatures::MOVBE, "MOVBE"),
    (CpuFeatures::ERMS, "ERMS"),
    (CpuFeatures::RDTSCP, "RDTSCP"),
    (CpuFeatures::RDRAND, "RDRAND"),
    (CpuFeatures::RDSEED, "RDSEED"),
    (CpuFeatures::CLFLUSHOPT, "CLFLUSHOPT"),
    (CpuFeatures::CLWB, "CLWB"),
];

fn format_runtime(runtime: &RuntimeInfo) -> String {
    let Some(wine) = runtime.wine.as_ref() else {
        return "Native Windows (Wine not detected)".to_owned();
    };
    let version = wine.version.as_deref().unwrap_or("version unknown");
    let mut value = match runtime.compatibility {
        CompatibilityRuntime::Proton => format!("Proton environment / Wine {version}"),
        CompatibilityRuntime::Wine => format!("Wine {version}"),
        // The detector's invariant makes this branch unreachable for a
        // published profile, but preserving it keeps formatting total if a
        // future test constructs partial evidence directly.
        CompatibilityRuntime::NativeWindows => format!("Wine {version}"),
    };
    if let Some(build_id) = wine.build_id.as_deref()
        && Some(build_id) != wine.version.as_deref()
    {
        value.push_str(&format!("; build {build_id}"));
    }
    if let Some(host_system) = wine.host_system.as_deref() {
        value.push_str(&format!("; host {host_system}"));
        if let Some(host_release) = wine.host_release.as_deref() {
            value.push(' ');
            value.push_str(host_release);
        }
    }
    if let Some(app_id) = runtime.steam_app_id.as_deref() {
        value.push_str(&format!("; Steam App {app_id}"));
    }
    value
}

fn format_features(features: CpuFeatures, ordered: &[(CpuFeatures, &str)]) -> String {
    let names: Vec<_> = ordered
        .iter()
        .filter_map(|(feature, name)| features.contains(*feature).then_some(*name))
        .collect();
    if names.is_empty() {
        "none reported".to_owned()
    } else {
        names.join(", ")
    }
}

fn format_caches(caches: &[CpuCache]) -> String {
    let mut groups: Vec<(CpuCache, usize)> = Vec::new();
    for cache in caches {
        if let Some((_, count)) = groups.iter_mut().find(|(known, _)| known == cache) {
            *count += 1;
        } else {
            groups.push((*cache, 1));
        }
    }
    groups.sort_by_key(|(cache, _)| {
        (
            cache.level,
            cache_kind_order(cache.kind),
            cache.size_bytes,
            cache.shared_logical_processor_count,
        )
    });
    if groups.is_empty() {
        return "unavailable".to_owned();
    }
    groups
        .into_iter()
        .map(|(cache, count)| {
            let sharing = match cache.shared_logical_processor_count {
                0 => "sharing unknown".to_owned(),
                1 => "private".to_owned(),
                threads => format!("shared by {threads} logical processors"),
            };
            format!(
                "{count}x L{}{} {} ({} B line, {sharing})",
                cache.level,
                cache_kind_suffix(cache.kind),
                format_capacity(u64::from(cache.size_bytes)),
                cache.line_size
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn cache_kind_order(kind: CpuCacheKind) -> u8 {
    match kind {
        CpuCacheKind::Data => 0,
        CpuCacheKind::Instruction => 1,
        CpuCacheKind::Unified => 2,
        CpuCacheKind::Trace => 3,
        CpuCacheKind::Unknown(_) => 4,
    }
}

fn cache_kind_suffix(kind: CpuCacheKind) -> &'static str {
    match kind {
        CpuCacheKind::Data => "D",
        CpuCacheKind::Instruction => "I",
        CpuCacheKind::Unified => "",
        CpuCacheKind::Trace => "T",
        CpuCacheKind::Unknown(_) => "?",
    }
}

fn format_system_memory(memory: &hardware::SystemMemoryInfo) -> String {
    let installed = memory
        .installed_physical_bytes
        .map(format_capacity)
        .unwrap_or_else(|| "unavailable".to_owned());
    match memory.startup_status {
        Some(status) => format!(
            "{} OS-visible / {installed} physically installed; {} available ({}% load)",
            format_capacity(status.total_physical_bytes),
            format_capacity(status.available_physical_bytes),
            status.memory_load_percent
        ),
        None => format!("OS-visible status unavailable / {installed} physically installed"),
    }
}

fn log_memory_devices() {
    let profile = match hardware::memory_device_profile() {
        Ok(profile) => profile,
        Err(error) => {
            log::info!("[HARDWARE] Modules  : SMBIOS memory details unavailable: {error}");
            return;
        }
    };

    // Type 16/17 may also describe video or cache memory. Prefer devices owned
    // by System Memory arrays; firmware that omits Type 16 associations falls
    // back to all Type 17 records rather than hiding otherwise useful data.
    let system_array_handles: Vec<_> = profile
        .arrays
        .iter()
        .filter(|array| array.use_kind == MemoryArrayUse::SystemMemory)
        .map(|array| array.handle)
        .collect();
    let devices: Vec<_> = profile
        .devices
        .iter()
        .filter(|device| {
            system_array_handles.is_empty() || system_array_handles.contains(&device.array_handle)
        })
        .collect();
    let populated = devices.iter().filter(|device| device.populated).count();
    let declared_slots = profile
        .arrays
        .iter()
        .filter(|array| {
            system_array_handles.is_empty() || system_array_handles.contains(&array.handle)
        })
        .map(|array| usize::from(array.device_slot_count))
        .sum::<usize>();
    let slots = declared_slots.max(devices.len());
    let described_capacity = devices
        .iter()
        .filter_map(|device| device.size_bytes)
        .try_fold(0u64, u64::checked_add);
    let capacity = described_capacity
        .map(format_capacity)
        .unwrap_or_else(|| "capacity overflow".to_owned());
    log::info!(
        "[HARDWARE] Modules  : {populated}/{slots} slots populated; {capacity} described; SMBIOS {}.{}",
        profile.version.major,
        profile.version.minor
    );

    let ecc_modes = profile
        .arrays
        .iter()
        .filter(|array| {
            system_array_handles.is_empty() || system_array_handles.contains(&array.handle)
        })
        .map(|array| error_correction_name(array.error_correction))
        .fold(Vec::<&str>::new(), |mut modes, mode| {
            if !modes.contains(&mode) {
                modes.push(mode);
            }
            modes
        });
    if !ecc_modes.is_empty() {
        log::info!("[HARDWARE] RAM ECC  : {}", ecc_modes.join(", "));
    }

    for (index, device) in devices
        .into_iter()
        .filter(|device| device.populated)
        .enumerate()
    {
        let locator = device
            .device_locator
            .as_deref()
            .or(device.bank_locator.as_deref())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("Slot {}", index + 1));
        log::info!(
            "[HARDWARE]   {:<8}: {}",
            truncate_locator(&locator),
            format_memory_device(device)
        );
    }
}

fn format_memory_device(device: &MemoryDevice) -> String {
    let mut fields = Vec::new();
    fields.push(
        device
            .size_bytes
            .map(format_capacity)
            .unwrap_or_else(|| "unknown capacity".to_owned()),
    );
    fields.push(memory_type_name(device.memory_type).to_owned());

    match (device.speed_mts, device.configured_speed_mts) {
        (Some(rated), Some(configured)) if rated != configured => {
            fields.push(format!("rated {rated} / configured {configured} MT/s"));
        }
        (_, Some(configured)) => fields.push(format!("{configured} MT/s configured")),
        (Some(rated), None) => fields.push(format!("{rated} MT/s rated")),
        (None, None) => {}
    }
    if let Some(form) = form_factor_name(device.form_factor) {
        fields.push(form.to_owned());
    }
    match (device.total_width_bits, device.data_width_bits) {
        (Some(total), Some(data)) if total > data => {
            fields.push(format!("{total}-bit total / {data}-bit data (ECC width)"));
        }
        (_, Some(data)) => fields.push(format!("{data}-bit data width")),
        (Some(total), None) => fields.push(format!("{total}-bit total width")),
        (None, None) => {}
    }
    if let Some(rank) = device.rank {
        fields.push(format!("{rank} rank{}", if rank == 1 { "" } else { "s" }));
    }
    if let Some(detail) = module_detail(device.type_detail) {
        fields.push(detail.to_owned());
    }
    if let Some(technology) = device.technology
        && technology != MemoryTechnology::Dram
        && technology != MemoryTechnology::Unknown
    {
        fields.push(memory_technology_name(technology).to_owned());
    }
    if let Some(millivolts) = device.configured_voltage_mv {
        fields.push(format!(
            "{}.{:02} V",
            millivolts / 1000,
            (millivolts % 1000) / 10
        ));
    }
    let identity = match (
        device.manufacturer.as_deref(),
        device.part_number.as_deref(),
    ) {
        (Some(manufacturer), Some(part)) => Some(format!("{manufacturer} {part}")),
        (Some(manufacturer), None) => Some(manufacturer.to_owned()),
        (None, Some(part)) => Some(part.to_owned()),
        (None, None) => None,
    };
    if let Some(identity) = identity {
        fields.push(identity);
    }
    fields.join(", ")
}

fn module_detail(detail: MemoryTypeDetail) -> Option<&'static str> {
    if detail.contains(MemoryTypeDetail::LRDIMM) {
        Some("load-reduced")
    } else if detail.contains(MemoryTypeDetail::REGISTERED) {
        Some("registered")
    } else if detail.contains(MemoryTypeDetail::UNBUFFERED) {
        Some("unbuffered")
    } else {
        None
    }
}

fn memory_type_name(kind: MemoryType) -> &'static str {
    match kind {
        MemoryType::Other => "other memory",
        MemoryType::Unknown => "unknown memory type",
        MemoryType::Dram => "DRAM",
        MemoryType::Sdram => "SDRAM",
        MemoryType::Rdram => "RDRAM",
        MemoryType::Ddr => "DDR",
        MemoryType::Ddr2 => "DDR2",
        MemoryType::Ddr2FbDimm => "DDR2 FB-DIMM",
        MemoryType::Ddr3 => "DDR3",
        MemoryType::Ddr4 => "DDR4",
        MemoryType::Lpddr => "LPDDR",
        MemoryType::Lpddr2 => "LPDDR2",
        MemoryType::Lpddr3 => "LPDDR3",
        MemoryType::Lpddr4 => "LPDDR4",
        MemoryType::LogicalNonVolatile => "logical non-volatile memory",
        MemoryType::Hbm => "HBM",
        MemoryType::Hbm2 => "HBM2",
        MemoryType::Ddr5 => "DDR5",
        MemoryType::Lpddr5 => "LPDDR5",
        MemoryType::Hbm3 => "HBM3",
        MemoryType::UnknownValue(_) => "unrecognized memory type",
    }
}

fn form_factor_name(form: MemoryFormFactor) -> Option<&'static str> {
    match form {
        MemoryFormFactor::Other | MemoryFormFactor::Unknown | MemoryFormFactor::UnknownValue(_) => {
            None
        }
        MemoryFormFactor::Simm => Some("SIMM"),
        MemoryFormFactor::Sip => Some("SIP"),
        MemoryFormFactor::Chip => Some("chip"),
        MemoryFormFactor::Dip => Some("DIP"),
        MemoryFormFactor::Zip => Some("ZIP"),
        MemoryFormFactor::ProprietaryCard => Some("proprietary card"),
        MemoryFormFactor::Dimm => Some("DIMM"),
        MemoryFormFactor::Tsop => Some("TSOP"),
        MemoryFormFactor::RowOfChips => Some("row of chips"),
        MemoryFormFactor::Rimm => Some("RIMM"),
        MemoryFormFactor::Sodimm => Some("SO-DIMM"),
        MemoryFormFactor::Srimm => Some("SRIMM"),
        MemoryFormFactor::FbDimm => Some("FB-DIMM"),
        MemoryFormFactor::Die => Some("die"),
    }
}

fn memory_technology_name(technology: MemoryTechnology) -> &'static str {
    match technology {
        MemoryTechnology::Other => "other technology",
        MemoryTechnology::Unknown => "unknown technology",
        MemoryTechnology::Dram => "DRAM technology",
        MemoryTechnology::NvdimmN => "NVDIMM-N",
        MemoryTechnology::NvdimmF => "NVDIMM-F",
        MemoryTechnology::NvdimmP => "NVDIMM-P",
        MemoryTechnology::IntelOptanePersistent => "Intel Optane persistent memory",
        MemoryTechnology::Mrdimm => "MRDIMM",
        MemoryTechnology::UnknownValue(_) => "unrecognized memory technology",
    }
}

fn error_correction_name(mode: MemoryErrorCorrection) -> &'static str {
    match mode {
        MemoryErrorCorrection::Other => "other",
        MemoryErrorCorrection::Unknown => "unknown",
        MemoryErrorCorrection::None => "none",
        MemoryErrorCorrection::Parity => "parity",
        MemoryErrorCorrection::SingleBitEcc => "single-bit ECC",
        MemoryErrorCorrection::MultiBitEcc => "multi-bit ECC",
        MemoryErrorCorrection::Crc => "CRC",
        MemoryErrorCorrection::UnknownValue(_) => "unrecognized",
    }
}

fn component_name(component: HardwareComponent) -> &'static str {
    match component {
        HardwareComponent::Cpu => "CPU",
        HardwareComponent::Memory => "memory",
        HardwareComponent::Firmware => "firmware",
        HardwareComponent::Runtime => "runtime",
        HardwareComponent::Gpu => "GPU",
    }
}

fn format_optional_quantity(value: Option<u32>, singular: &str, plural: &str) -> String {
    value
        .map(|value| format_quantity(value, singular, plural))
        .unwrap_or_else(|| format!("{plural} unknown"))
}

fn format_quantity(value: u32, singular: &str, plural: &str) -> String {
    format!("{value} {}", if value == 1 { singular } else { plural })
}

fn truncate_locator(locator: &str) -> String {
    const MAX_CHARACTERS: usize = 8;
    if locator.chars().count() <= MAX_CHARACTERS {
        return locator.to_owned();
    }
    let mut shortened: String = locator.chars().take(MAX_CHARACTERS - 1).collect();
    shortened.push('~');
    shortened
}

fn format_capacity(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacities_use_binary_units_without_x86_truncation() {
        assert_eq!(format_capacity(32 * 1024 * 1024 * 1024), "32.0 GiB");
        assert_eq!(format_capacity(32 * 1024), "32.0 KiB");
    }

    #[test]
    fn feature_output_is_stable_and_only_contains_usable_features() {
        let features = CpuFeatures::SSE2 | CpuFeatures::AVX2 | CpuFeatures::FMA;
        assert_eq!(format_features(features, SIMD_FEATURES), "SSE2, AVX2, FMA");
    }

    #[test]
    fn long_firmware_locators_are_bounded_for_aligned_logs() {
        assert_eq!(truncate_locator("DIMM_A1"), "DIMM_A1");
        assert_eq!(truncate_locator("CHANNEL A DIMM 1"), "CHANNEL~");
    }

    #[test]
    fn topology_quantities_use_readable_grammar() {
        assert_eq!(format_quantity(1, "package", "packages"), "1 package");
        assert_eq!(format_quantity(2, "package", "packages"), "2 packages");
        assert_eq!(
            format_optional_quantity(None, "physical core", "physical cores"),
            "physical cores unknown"
        );
    }
}
