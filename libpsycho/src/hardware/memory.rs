//! System memory pressure and defensive SMBIOS Type 16/17 parsing.
//!
//! Win32 supplies current usable and available memory. SMBIOS is kept as an
//! explicit lazy query because it describes installed modules and firmware
//! topology, may be absent under Wine, and requires bounded binary parsing.

use std::sync::OnceLock;

use bitflags::bitflags;

use super::{DetectionIssue, HardwareComponent, HardwareError, HardwareResult};
use crate::os::windows::winapi::{self, NativeSystemLayout};

/// Point-in-time usable memory and address-space pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryStatus {
    /// Approximate percentage of physical memory currently in use.
    pub memory_load_percent: u32,
    /// Total usable physical memory in bytes.
    pub total_physical_bytes: u64,
    /// Available usable physical memory in bytes.
    pub available_physical_bytes: u64,
    /// Current system commit limit in bytes.
    pub total_page_file_bytes: u64,
    /// Current system commit headroom in bytes.
    pub available_page_file_bytes: u64,
    /// User-mode virtual-address-space size for this process in bytes.
    pub total_virtual_bytes: u64,
    /// User-mode virtual-address-space headroom for this process in bytes.
    pub available_virtual_bytes: u64,
}

/// Cached native memory layout and startup capacities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemMemoryInfo {
    /// Native operating-system page size in bytes.
    pub page_size: u32,
    /// Native virtual-allocation granularity in bytes.
    pub allocation_granularity: u32,
    /// Startup memory-pressure snapshot, when Win32 supplied it.
    pub startup_status: Option<MemoryStatus>,
    /// Firmware-derived installed capacity, including hardware-reserved RAM.
    pub installed_physical_bytes: Option<u64>,
}

/// SMBIOS version attached to the returned table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbiosVersion {
    /// SMBIOS major version.
    pub major: u8,
    /// SMBIOS minor version.
    pub minor: u8,
    /// DMI revision from `RawSMBIOSData`.
    pub dmi_revision: u8,
}

/// Physical memory-array location from SMBIOS Type 16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryArrayLocation {
    /// Location is not known.
    Unknown,
    /// Array is on the system or motherboard.
    SystemBoard,
    /// Array is on an ISA add-in card.
    IsaCard,
    /// Array is on an EISA add-in card.
    EisaCard,
    /// Array is on a PCI add-in card.
    PciCard,
    /// Array is on an MCA add-in card.
    McaCard,
    /// Array is on a PCMCIA add-in card.
    PcmciaCard,
    /// Array is on a proprietary add-in card.
    ProprietaryCard,
    /// Array is on a NuBus device.
    Nubus,
    /// Array is on a PC-98/C20 add-in card.
    Pc98C20,
    /// Array is on a PC-98/C24 add-in card.
    Pc98C24,
    /// Array is on a PC-98/E add-in card.
    Pc98E,
    /// Array is on a PC-98/local-bus add-in card.
    Pc98LocalBus,
    /// Newer or vendor-defined raw value.
    Other(u8),
}

/// Intended use of an SMBIOS physical memory array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryArrayUse {
    /// Use is not known.
    Unknown,
    /// General system memory.
    SystemMemory,
    /// Video memory.
    VideoMemory,
    /// Flash memory.
    FlashMemory,
    /// Non-volatile RAM.
    NonVolatileRam,
    /// Cache memory.
    CacheMemory,
    /// Newer or vendor-defined raw value.
    Other(u8),
}

/// Error-correction capability of an SMBIOS physical memory array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryErrorCorrection {
    /// Firmware reports another correction scheme.
    Other,
    /// Correction scheme is unknown.
    Unknown,
    /// No correction.
    None,
    /// Parity checking.
    Parity,
    /// Single-bit ECC.
    SingleBitEcc,
    /// Multi-bit ECC.
    MultiBitEcc,
    /// CRC-based correction.
    Crc,
    /// Newer or vendor-defined raw value.
    UnknownValue(u8),
}

/// One SMBIOS Type 16 physical memory array.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryArray {
    /// SMBIOS structure handle.
    pub handle: u16,
    /// Physical placement.
    pub location: MemoryArrayLocation,
    /// Intended use.
    pub use_kind: MemoryArrayUse,
    /// Array-level error correction.
    pub error_correction: MemoryErrorCorrection,
    /// Maximum supported capacity in bytes, when known.
    pub maximum_capacity_bytes: Option<u64>,
    /// Number of Type 17 slots associated with the array.
    pub device_slot_count: u16,
}

/// Physical memory-device form factor from SMBIOS Type 17.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryFormFactor {
    /// Firmware reports another form factor.
    Other,
    /// Form factor is unknown.
    Unknown,
    /// SIMM.
    Simm,
    /// SIP.
    Sip,
    /// Discrete chip.
    Chip,
    /// DIP.
    Dip,
    /// ZIP.
    Zip,
    /// Proprietary card.
    ProprietaryCard,
    /// DIMM.
    Dimm,
    /// TSOP.
    Tsop,
    /// Row of chips.
    RowOfChips,
    /// RIMM.
    Rimm,
    /// SO-DIMM.
    Sodimm,
    /// SRIMM.
    Srimm,
    /// FB-DIMM.
    FbDimm,
    /// Bare die.
    Die,
    /// Newer or vendor-defined raw value.
    UnknownValue(u8),
}

/// Memory technology/type from the legacy Type 17 field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryType {
    /// Firmware reports another type.
    Other,
    /// Type is unknown.
    Unknown,
    /// Generic DRAM.
    Dram,
    /// SDRAM.
    Sdram,
    /// RDRAM.
    Rdram,
    /// DDR SDRAM.
    Ddr,
    /// DDR2 SDRAM.
    Ddr2,
    /// DDR2 FB-DIMM.
    Ddr2FbDimm,
    /// DDR3 SDRAM.
    Ddr3,
    /// DDR4 SDRAM.
    Ddr4,
    /// Low-power DDR.
    Lpddr,
    /// Low-power DDR2.
    Lpddr2,
    /// Low-power DDR3.
    Lpddr3,
    /// Low-power DDR4.
    Lpddr4,
    /// Logical non-volatile device.
    LogicalNonVolatile,
    /// High Bandwidth Memory.
    Hbm,
    /// High Bandwidth Memory 2.
    Hbm2,
    /// DDR5 SDRAM.
    Ddr5,
    /// Low-power DDR5.
    Lpddr5,
    /// High Bandwidth Memory 3.
    Hbm3,
    /// Defined SMBIOS value not normalized above.
    UnknownValue(u8),
}

bitflags! {
    /// Electrical and packaging details from SMBIOS Type 17.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MemoryTypeDetail: u16 {
        /// Firmware classified the detail as other.
        const OTHER = 1 << 1;
        /// Firmware classified the detail as unknown.
        const UNKNOWN = 1 << 2;
        /// Fast-paged memory.
        const FAST_PAGED = 1 << 3;
        /// Static-column memory.
        const STATIC_COLUMN = 1 << 4;
        /// Pseudo-static memory.
        const PSEUDO_STATIC = 1 << 5;
        /// Rambus memory.
        const RAMBUS = 1 << 6;
        /// Synchronous memory.
        const SYNCHRONOUS = 1 << 7;
        /// CMOS memory.
        const CMOS = 1 << 8;
        /// Extended-data-out memory.
        const EDO = 1 << 9;
        /// Window DRAM.
        const WINDOW_DRAM = 1 << 10;
        /// Cache DRAM.
        const CACHE_DRAM = 1 << 11;
        /// Non-volatile memory.
        const NON_VOLATILE = 1 << 12;
        /// Registered/buffered module.
        const REGISTERED = 1 << 13;
        /// Unbuffered module.
        const UNBUFFERED = 1 << 14;
        /// Load-reduced module.
        const LRDIMM = 1 << 15;
    }
}

/// Technology from the extended SMBIOS Type 17 field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryTechnology {
    /// Firmware reports another technology.
    Other,
    /// Technology is unknown.
    Unknown,
    /// Volatile DRAM.
    Dram,
    /// NVDIMM-N.
    NvdimmN,
    /// NVDIMM-F.
    NvdimmF,
    /// NVDIMM-P.
    NvdimmP,
    /// Intel Optane persistent memory.
    IntelOptanePersistent,
    /// Multiplexed-rank DIMM.
    Mrdimm,
    /// Newer or vendor-defined raw value.
    UnknownValue(u8),
}

/// One SMBIOS Type 17 memory slot or populated module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryDevice {
    /// SMBIOS structure handle.
    pub handle: u16,
    /// Type 16 physical-array handle.
    pub array_handle: u16,
    /// Whether firmware says the slot is populated.
    pub populated: bool,
    /// Installed capacity in bytes, when known.
    pub size_bytes: Option<u64>,
    /// Total module width including ECC bits, when known.
    pub total_width_bits: Option<u16>,
    /// Data width excluding ECC bits, when known.
    pub data_width_bits: Option<u16>,
    /// Physical module form.
    pub form_factor: MemoryFormFactor,
    /// Device locator supplied by firmware.
    pub device_locator: Option<String>,
    /// Bank locator supplied by firmware.
    pub bank_locator: Option<String>,
    /// DDR/HBM generation or legacy memory type.
    pub memory_type: MemoryType,
    /// Electrical and packaging flags.
    pub type_detail: MemoryTypeDetail,
    /// Maximum rated transfer rate in MT/s, when known.
    pub speed_mts: Option<u32>,
    /// Configured transfer rate in MT/s, when known.
    pub configured_speed_mts: Option<u32>,
    /// Manufacturer string.
    pub manufacturer: Option<String>,
    /// Manufacturer part number.
    pub part_number: Option<String>,
    /// Rank count, when known.
    pub rank: Option<u8>,
    /// Minimum supported voltage in millivolts.
    pub minimum_voltage_mv: Option<u16>,
    /// Maximum supported voltage in millivolts.
    pub maximum_voltage_mv: Option<u16>,
    /// Configured voltage in millivolts.
    pub configured_voltage_mv: Option<u16>,
    /// Extended volatile/persistent memory technology.
    pub technology: Option<MemoryTechnology>,
    /// Volatile capacity for mixed persistent modules, when supplied.
    pub volatile_size_bytes: Option<u64>,
    /// Non-volatile capacity for mixed persistent modules, when supplied.
    pub non_volatile_size_bytes: Option<u64>,
}

/// Parsed SMBIOS physical memory arrays and devices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryDeviceProfile {
    /// Firmware SMBIOS/DMI version.
    pub version: SmbiosVersion,
    /// Physical memory-array records.
    pub arrays: Vec<MemoryArray>,
    /// Memory slot/module records.
    pub devices: Vec<MemoryDevice>,
}

static MEMORY_DEVICE_PROFILE: OnceLock<HardwareResult<MemoryDeviceProfile>> = OnceLock::new();

pub(super) fn detect_system_memory(
    layout: NativeSystemLayout,
    issues: &mut Vec<DetectionIssue>,
) -> SystemMemoryInfo {
    let startup_status = match memory_status() {
        Ok(status) => Some(status),
        Err(error) => {
            issues.push(DetectionIssue::new(HardwareComponent::Memory, error));
            None
        }
    };
    let installed_physical_bytes = match winapi::physically_installed_memory_bytes() {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            issues.push(DetectionIssue::new(HardwareComponent::Memory, error));
            None
        }
    };
    SystemMemoryInfo {
        page_size: layout.page_size,
        allocation_granularity: layout.allocation_granularity,
        startup_status,
        installed_physical_bytes,
    }
}

/// Query current physical, commit, and virtual-address-space pressure.
///
/// This function intentionally performs a fresh query on every call. Capacity
/// fields in [`crate::hardware::system_profile`] are cached, but allocator
/// policy must not use stale availability values.
pub fn memory_status() -> HardwareResult<MemoryStatus> {
    let status = winapi::system_memory_status()
        .map_err(|error| HardwareError::operation("GlobalMemoryStatusEx", error))?;
    Ok(MemoryStatus {
        memory_load_percent: status.memory_load_percent,
        total_physical_bytes: status.total_physical_bytes,
        available_physical_bytes: status.available_physical_bytes,
        total_page_file_bytes: status.total_page_file_bytes,
        available_page_file_bytes: status.available_page_file_bytes,
        total_virtual_bytes: status.total_virtual_bytes,
        available_virtual_bytes: status.available_virtual_bytes,
    })
}

/// Return the lazily cached SMBIOS physical-memory profile.
///
/// Firmware is parsed once. The error is cached as well so unavailable SMBIOS
/// under Wine or broken firmware does not cause repeated platform calls.
pub fn memory_device_profile() -> HardwareResult<&'static MemoryDeviceProfile> {
    match MEMORY_DEVICE_PROFILE.get_or_init(query_memory_device_profile) {
        Ok(profile) => Ok(profile),
        Err(error) => Err(error.clone()),
    }
}

fn query_memory_device_profile() -> HardwareResult<MemoryDeviceProfile> {
    let bytes = winapi::raw_smbios_table()
        .map_err(|error| HardwareError::operation("GetSystemFirmwareTable(RSMB)", error))?;
    parse_raw_smbios(&bytes)
}

fn parse_raw_smbios(raw: &[u8]) -> HardwareResult<MemoryDeviceProfile> {
    const HEADER_SIZE: usize = 8;
    if raw.len() < HEADER_SIZE {
        return Err(HardwareError::malformed(
            "RawSMBIOSData",
            "truncated table header",
        ));
    }
    let declared_length = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
    if declared_length > raw.len() - HEADER_SIZE {
        return Err(HardwareError::malformed(
            "RawSMBIOSData",
            "declared table length exceeds the returned buffer",
        ));
    }
    let version = SmbiosVersion {
        major: raw[1],
        minor: raw[2],
        dmi_revision: raw[3],
    };
    let table = &raw[HEADER_SIZE..HEADER_SIZE + declared_length];
    let mut arrays = Vec::new();
    let mut devices = Vec::new();
    let mut offset = 0usize;

    while offset < table.len() {
        let structure = parse_structure(table, offset)?;
        match structure.kind {
            16 => arrays.push(parse_memory_array(&structure)?),
            17 => devices.push(parse_memory_device(&structure)?),
            127 => break,
            _ => {}
        }
        offset = structure.next_offset;
    }

    Ok(MemoryDeviceProfile {
        version,
        arrays,
        devices,
    })
}

struct SmbiosStructure<'a> {
    kind: u8,
    handle: u16,
    formatted: &'a [u8],
    strings: &'a [u8],
    next_offset: usize,
}

fn parse_structure(table: &[u8], offset: usize) -> HardwareResult<SmbiosStructure<'_>> {
    if table.len().saturating_sub(offset) < 4 {
        return Err(HardwareError::malformed(
            "SMBIOS structure",
            "truncated formatted header",
        ));
    }
    let length = table[offset + 1] as usize;
    if length < 4 || length > table.len() - offset {
        return Err(HardwareError::malformed(
            "SMBIOS structure",
            "invalid formatted length",
        ));
    }
    let formatted_end = offset + length;
    let mut terminator = formatted_end;
    while terminator + 1 < table.len() && !(table[terminator] == 0 && table[terminator + 1] == 0) {
        terminator += 1;
    }
    if terminator + 1 >= table.len() {
        return Err(HardwareError::malformed(
            "SMBIOS structure",
            "missing double-NUL string terminator",
        ));
    }

    Ok(SmbiosStructure {
        kind: table[offset],
        handle: read_u16(table, offset + 2).unwrap(),
        formatted: &table[offset..formatted_end],
        strings: &table[formatted_end..terminator],
        next_offset: terminator + 2,
    })
}

fn parse_memory_array(structure: &SmbiosStructure<'_>) -> HardwareResult<MemoryArray> {
    let data = structure.formatted;
    if data.len() < 15 {
        return Err(HardwareError::malformed(
            "SMBIOS Type 16",
            "formatted area is shorter than the base structure",
        ));
    }
    let legacy_capacity = read_u32(data, 7).unwrap();
    let maximum_capacity_bytes = if legacy_capacity == 0x8000_0000 {
        read_u64(data, 15)
    } else {
        Some(u64::from(legacy_capacity) * 1024)
    };
    Ok(MemoryArray {
        handle: structure.handle,
        location: array_location(data[4]),
        use_kind: array_use(data[5]),
        error_correction: error_correction(data[6]),
        maximum_capacity_bytes,
        device_slot_count: read_u16(data, 13).unwrap(),
    })
}

fn parse_memory_device(structure: &SmbiosStructure<'_>) -> HardwareResult<MemoryDevice> {
    let data = structure.formatted;
    if data.len() < 21 {
        return Err(HardwareError::malformed(
            "SMBIOS Type 17",
            "formatted area is shorter than the base structure",
        ));
    }
    let encoded_size = read_u16(data, 12).unwrap();
    let (populated, size_bytes) = decode_device_size(encoded_size, read_u32(data, 28));
    Ok(MemoryDevice {
        handle: structure.handle,
        array_handle: read_u16(data, 4).unwrap(),
        populated,
        size_bytes,
        total_width_bits: known_u16(read_u16(data, 8)),
        data_width_bits: known_u16(read_u16(data, 10)),
        form_factor: form_factor(data[14]),
        device_locator: structure.string(data[16]),
        bank_locator: structure.string(data[17]),
        memory_type: memory_type(data[18]),
        type_detail: MemoryTypeDetail::from_bits_retain(read_u16(data, 19).unwrap()),
        speed_mts: decode_speed(read_u16(data, 21), read_u32(data, 84)),
        configured_speed_mts: decode_speed(read_u16(data, 32), read_u32(data, 88)),
        manufacturer: data.get(23).and_then(|index| structure.string(*index)),
        part_number: data.get(26).and_then(|index| structure.string(*index)),
        rank: data
            .get(27)
            .map(|attributes| attributes & 0x0f)
            .filter(|rank| *rank != 0),
        minimum_voltage_mv: known_nonzero_u16(read_u16(data, 34)),
        maximum_voltage_mv: known_nonzero_u16(read_u16(data, 36)),
        configured_voltage_mv: known_nonzero_u16(read_u16(data, 38)),
        technology: data.get(40).copied().map(memory_technology),
        non_volatile_size_bytes: known_capacity(read_u64(data, 52)),
        volatile_size_bytes: known_capacity(read_u64(data, 60)),
    })
}

impl SmbiosStructure<'_> {
    fn string(&self, index: u8) -> Option<String> {
        if index == 0 {
            return None;
        }
        let bytes = self
            .strings
            .split(|byte| *byte == 0)
            .nth(usize::from(index - 1))?;
        let text: String = String::from_utf8_lossy(bytes)
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect::<String>()
            .trim()
            .to_owned();
        (!text.is_empty()).then_some(text)
    }
}

fn decode_device_size(encoded: u16, extended: Option<u32>) -> (bool, Option<u64>) {
    match encoded {
        0 => (false, Some(0)),
        0xffff => (true, None),
        0x7fff => (
            true,
            extended.map(|value| u64::from(value & 0x7fff_ffff) * 1024 * 1024),
        ),
        value if value & 0x8000 != 0 => (true, Some(u64::from(value & 0x7fff) * 1024)),
        value => (true, Some(u64::from(value) * 1024 * 1024)),
    }
}

fn decode_speed(legacy: Option<u16>, extended: Option<u32>) -> Option<u32> {
    match legacy? {
        0 => None,
        0xffff => extended.filter(|value| *value != 0),
        value => Some(u32::from(value)),
    }
}

fn known_u16(value: Option<u16>) -> Option<u16> {
    value.filter(|value| !matches!(*value, 0 | 0xffff))
}

fn known_nonzero_u16(value: Option<u16>) -> Option<u16> {
    value.filter(|value| *value != 0)
}

fn known_capacity(value: Option<u64>) -> Option<u64> {
    value.filter(|value| !matches!(*value, 0 | u64::MAX))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn array_location(value: u8) -> MemoryArrayLocation {
    match value {
        0x02 => MemoryArrayLocation::Unknown,
        0x03 => MemoryArrayLocation::SystemBoard,
        0x04 => MemoryArrayLocation::IsaCard,
        0x05 => MemoryArrayLocation::EisaCard,
        0x06 => MemoryArrayLocation::PciCard,
        0x07 => MemoryArrayLocation::McaCard,
        0x08 => MemoryArrayLocation::PcmciaCard,
        0x09 => MemoryArrayLocation::ProprietaryCard,
        0x0a => MemoryArrayLocation::Nubus,
        0xa0 => MemoryArrayLocation::Pc98C20,
        0xa1 => MemoryArrayLocation::Pc98C24,
        0xa2 => MemoryArrayLocation::Pc98E,
        0xa3 => MemoryArrayLocation::Pc98LocalBus,
        other => MemoryArrayLocation::Other(other),
    }
}

fn array_use(value: u8) -> MemoryArrayUse {
    match value {
        0x02 => MemoryArrayUse::Unknown,
        0x03 => MemoryArrayUse::SystemMemory,
        0x04 => MemoryArrayUse::VideoMemory,
        0x05 => MemoryArrayUse::FlashMemory,
        0x06 => MemoryArrayUse::NonVolatileRam,
        0x07 => MemoryArrayUse::CacheMemory,
        other => MemoryArrayUse::Other(other),
    }
}

fn error_correction(value: u8) -> MemoryErrorCorrection {
    match value {
        0x01 => MemoryErrorCorrection::Other,
        0x02 => MemoryErrorCorrection::Unknown,
        0x03 => MemoryErrorCorrection::None,
        0x04 => MemoryErrorCorrection::Parity,
        0x05 => MemoryErrorCorrection::SingleBitEcc,
        0x06 => MemoryErrorCorrection::MultiBitEcc,
        0x07 => MemoryErrorCorrection::Crc,
        other => MemoryErrorCorrection::UnknownValue(other),
    }
}

fn form_factor(value: u8) -> MemoryFormFactor {
    match value {
        0x01 => MemoryFormFactor::Other,
        0x02 => MemoryFormFactor::Unknown,
        0x03 => MemoryFormFactor::Simm,
        0x04 => MemoryFormFactor::Sip,
        0x05 => MemoryFormFactor::Chip,
        0x06 => MemoryFormFactor::Dip,
        0x07 => MemoryFormFactor::Zip,
        0x08 => MemoryFormFactor::ProprietaryCard,
        0x09 => MemoryFormFactor::Dimm,
        0x0a => MemoryFormFactor::Tsop,
        0x0b => MemoryFormFactor::RowOfChips,
        0x0c => MemoryFormFactor::Rimm,
        0x0d => MemoryFormFactor::Sodimm,
        0x0e => MemoryFormFactor::Srimm,
        0x0f => MemoryFormFactor::FbDimm,
        0x10 => MemoryFormFactor::Die,
        other => MemoryFormFactor::UnknownValue(other),
    }
}

fn memory_type(value: u8) -> MemoryType {
    match value {
        0x01 => MemoryType::Other,
        0x02 => MemoryType::Unknown,
        0x03 => MemoryType::Dram,
        0x0f => MemoryType::Sdram,
        0x11 => MemoryType::Rdram,
        0x12 => MemoryType::Ddr,
        0x13 => MemoryType::Ddr2,
        0x14 => MemoryType::Ddr2FbDimm,
        0x18 => MemoryType::Ddr3,
        0x1a => MemoryType::Ddr4,
        0x1b => MemoryType::Lpddr,
        0x1c => MemoryType::Lpddr2,
        0x1d => MemoryType::Lpddr3,
        0x1e => MemoryType::Lpddr4,
        0x1f => MemoryType::LogicalNonVolatile,
        0x20 => MemoryType::Hbm,
        0x21 => MemoryType::Hbm2,
        0x22 => MemoryType::Ddr5,
        0x23 => MemoryType::Lpddr5,
        0x24 => MemoryType::Hbm3,
        other => MemoryType::UnknownValue(other),
    }
}

fn memory_technology(value: u8) -> MemoryTechnology {
    match value {
        0x01 => MemoryTechnology::Other,
        0x02 => MemoryTechnology::Unknown,
        0x03 => MemoryTechnology::Dram,
        0x04 => MemoryTechnology::NvdimmN,
        0x05 => MemoryTechnology::NvdimmF,
        0x06 => MemoryTechnology::NvdimmP,
        0x07 => MemoryTechnology::IntelOptanePersistent,
        0x08 => MemoryTechnology::Mrdimm,
        other => MemoryTechnology::UnknownValue(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_type_16_and_type_17_fixture() {
        let mut table = vec![
            16, 23, 0x00, 0x10, 0x03, 0x03, 0x05, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0x02, 0x00,
        ];
        table.extend_from_slice(&(64u64 * 1024 * 1024 * 1024).to_le_bytes());
        table.extend_from_slice(&[0, 0]);

        let mut device = vec![0u8; 40];
        device[0] = 17;
        device[1] = 40;
        device[2..4].copy_from_slice(&0x1100u16.to_le_bytes());
        device[4..6].copy_from_slice(&0x1000u16.to_le_bytes());
        device[8..10].copy_from_slice(&72u16.to_le_bytes());
        device[10..12].copy_from_slice(&64u16.to_le_bytes());
        device[12..14].copy_from_slice(&8192u16.to_le_bytes());
        device[14] = 0x09;
        device[16] = 1;
        device[17] = 2;
        device[18] = 0x1a;
        device[19..21].copy_from_slice(&MemoryTypeDetail::SYNCHRONOUS.bits().to_le_bytes());
        device[21..23].copy_from_slice(&3200u16.to_le_bytes());
        device[23] = 3;
        device[26] = 4;
        device[27] = 2;
        device[32..34].copy_from_slice(&2933u16.to_le_bytes());
        device[38..40].copy_from_slice(&1200u16.to_le_bytes());
        table.extend_from_slice(&device);
        table.extend_from_slice(b"DIMM 0\0BANK 0\0Example\0PART-1\0\0");
        table.extend_from_slice(&[127, 4, 0xff, 0xff, 0, 0]);

        let mut raw = vec![0, 3, 8, 0];
        raw.extend_from_slice(&(table.len() as u32).to_le_bytes());
        raw.extend_from_slice(&table);

        let profile = parse_raw_smbios(&raw).unwrap();
        assert_eq!(profile.version.major, 3);
        assert_eq!(profile.arrays[0].maximum_capacity_bytes, Some(64 << 30));
        assert_eq!(profile.devices[0].size_bytes, Some(8 << 30));
        assert_eq!(profile.devices[0].memory_type, MemoryType::Ddr4);
        assert_eq!(profile.devices[0].configured_speed_mts, Some(2933));
        assert_eq!(profile.devices[0].device_locator.as_deref(), Some("DIMM 0"));
    }

    #[test]
    fn rejects_structure_without_double_nul_terminator() {
        let table = [
            17, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut raw = vec![0, 3, 8, 0];
        raw.extend_from_slice(&(table.len() as u32).to_le_bytes());
        raw.extend_from_slice(&table);
        assert!(parse_raw_smbios(&raw).is_err());
    }

    #[test]
    fn decodes_kibibyte_and_extended_module_sizes() {
        assert_eq!(decode_device_size(0x8001, None), (true, Some(1024)));
        assert_eq!(
            decode_device_size(0x7fff, Some(32768)),
            (true, Some(32 << 30))
        );
    }
}
