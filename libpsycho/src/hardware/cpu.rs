//! CPUID identity, topology, cache, and OS-usable feature detection.
//!
//! CPUID leaves are queried directly and only within the maximum basic or
//! extended leaf reported by the processor. Windows remains authoritative for
//! topology because process-visible cores, packages, and NUMA nodes can differ
//! from raw package topology under affinity restrictions or virtualization.

#[cfg(target_arch = "x86")]
use core::arch::x86::{__cpuid_count, CpuidResult};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__cpuid_count, CpuidResult};

use bitflags::bitflags;

use super::{DetectionIssue, HardwareComponent};
use crate::os::windows::winapi::{self, NativeSystemLayout, ProcessorCacheType, ProcessorTopology};

bitflags! {
    /// CPU instruction features used for implementation dispatch.
    ///
    /// [`CpuInfo::advertised_features`] mirrors CPUID bits. Use
    /// [`CpuInfo::usable_features`] before executing instructions because that
    /// set also accounts for operating-system extended-state support.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct CpuFeatures: u64 {
        /// MMX integer SIMD.
        const MMX = 1 << 0;
        /// Streaming SIMD Extensions.
        const SSE = 1 << 1;
        /// Streaming SIMD Extensions 2.
        const SSE2 = 1 << 2;
        /// Streaming SIMD Extensions 3.
        const SSE3 = 1 << 3;
        /// Supplemental Streaming SIMD Extensions 3.
        const SSSE3 = 1 << 4;
        /// Streaming SIMD Extensions 4.1.
        const SSE4_1 = 1 << 5;
        /// Streaming SIMD Extensions 4.2.
        const SSE4_2 = 1 << 6;
        /// AMD Streaming SIMD Extensions 4a.
        const SSE4A = 1 << 7;
        /// Advanced Vector Extensions with OS-enabled YMM state.
        const AVX = 1 << 8;
        /// Advanced Vector Extensions 2.
        const AVX2 = 1 << 9;
        /// Half-precision conversion instructions.
        const F16C = 1 << 10;
        /// Fused multiply-add instructions.
        const FMA = 1 << 11;
        /// AVX-512 foundation.
        const AVX512F = 1 << 12;
        /// AVX-512 byte and word instructions.
        const AVX512BW = 1 << 13;
        /// AVX-512 doubleword and quadword instructions.
        const AVX512DQ = 1 << 14;
        /// AVX-512 conflict detection.
        const AVX512CD = 1 << 15;
        /// AVX-512 vector-length extensions.
        const AVX512VL = 1 << 16;
        /// AES round instructions.
        const AES = 1 << 17;
        /// Carry-less multiplication.
        const PCLMULQDQ = 1 << 18;
        /// SHA-1 and SHA-256 acceleration.
        const SHA = 1 << 19;
        /// Population count.
        const POPCNT = 1 << 20;
        /// Leading-zero count.
        const LZCNT = 1 << 21;
        /// Bit Manipulation Instructions 1.
        const BMI1 = 1 << 22;
        /// Bit Manipulation Instructions 2.
        const BMI2 = 1 << 23;
        /// Multi-precision add-carry instructions.
        const ADX = 1 << 24;
        /// Move with byte swap.
        const MOVBE = 1 << 25;
        /// Enhanced REP MOVSB/STOSB.
        const ERMS = 1 << 26;
        /// Read time-stamp counter and processor ID.
        const RDTSCP = 1 << 27;
        /// Hardware random-number instruction.
        const RDRAND = 1 << 28;
        /// Hardware seed-generation instruction.
        const RDSEED = 1 << 29;
        /// Cache-line flush optimized.
        const CLFLUSHOPT = 1 << 30;
        /// Cache-line write back.
        const CLWB = 1 << 31;
    }
}

/// Normalized CPU vendor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuVendor {
    /// GenuineIntel.
    Intel,
    /// AuthenticAMD or HygonGenuine.
    Amd,
    /// Vendor string not known to this libpsycho version.
    Unknown,
}

/// Normalized Windows processor-cache type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuCacheKind {
    /// Shared instruction and data cache.
    Unified,
    /// Instruction cache.
    Instruction,
    /// Data cache.
    Data,
    /// Trace cache.
    Trace,
    /// Unknown Windows cache-type value.
    Unknown(i32),
}

/// One cache record visible to Windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuCache {
    /// Cache hierarchy level.
    pub level: u8,
    /// Cache associativity, or `0xff` when fully associative.
    pub associativity: u8,
    /// Cache-line size in bytes.
    pub line_size: u16,
    /// Cache capacity in bytes.
    pub size_bytes: u32,
    /// Logical processors that share this cache.
    pub shared_logical_processor_count: u32,
    /// Instruction/data use classification.
    pub kind: CpuCacheKind,
}

/// Physical cores associated with one Windows efficiency class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuEfficiencyClass {
    /// Windows efficiency class. Higher values represent faster cores.
    pub class: u8,
    /// Physical cores in this class.
    pub core_count: u32,
}

/// Cached CPU identity, topology, and instruction features.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuInfo {
    /// Normalized processor vendor.
    pub vendor: CpuVendor,
    /// Exact 12-byte CPUID vendor string.
    pub vendor_id: String,
    /// Human-readable CPUID brand string, when provided.
    pub brand: Option<String>,
    /// Display family derived from CPUID leaf 1.
    pub family: u16,
    /// Display model derived from CPUID leaf 1.
    pub model: u16,
    /// Stepping identifier from CPUID leaf 1.
    pub stepping: u8,
    /// Highest supported standard CPUID leaf.
    pub max_basic_leaf: u32,
    /// Highest supported extended CPUID leaf.
    pub max_extended_leaf: u32,
    /// Whether CPUID reports a hypervisor.
    pub hypervisor_present: bool,
    /// Hypervisor vendor string, when a hypervisor leaf is available.
    pub hypervisor_vendor: Option<String>,
    /// Active logical processors visible to Windows.
    pub logical_processor_count: u32,
    /// Physical core records visible to Windows.
    pub physical_core_count: Option<u32>,
    /// Physical processor packages visible to Windows.
    pub package_count: Option<u32>,
    /// NUMA nodes visible to Windows.
    pub numa_node_count: Option<u32>,
    /// Logical concurrency currently available to this process.
    pub available_parallelism: u32,
    /// Cache records reported by Windows.
    pub caches: Vec<CpuCache>,
    /// Physical core counts grouped by Windows efficiency class.
    pub efficiency_classes: Vec<CpuEfficiencyClass>,
    /// Raw instruction features advertised by CPUID.
    pub advertised_features: CpuFeatures,
    /// Features safe for the current OS context to execute.
    pub usable_features: CpuFeatures,
}

pub(super) fn detect(layout: NativeSystemLayout, issues: &mut Vec<DetectionIssue>) -> CpuInfo {
    let basic = cpuid(0, 0);
    let max_basic_leaf = basic.eax;
    let vendor_id = cpuid_text([basic.ebx, basic.edx, basic.ecx]);
    let vendor = match vendor_id.as_str() {
        "GenuineIntel" => CpuVendor::Intel,
        "AuthenticAMD" | "HygonGenuine" => CpuVendor::Amd,
        _ => CpuVendor::Unknown,
    };

    let extended = cpuid(0x8000_0000, 0);
    let max_extended_leaf = extended.eax;
    let leaf1 = if max_basic_leaf >= 1 {
        cpuid(1, 0)
    } else {
        CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    };
    let (family, model, stepping) = decode_signature(leaf1.eax);
    let hypervisor_present = leaf1.ecx & (1 << 31) != 0;
    let hypervisor_vendor = hypervisor_present
        .then(|| {
            let leaf = cpuid(0x4000_0000, 0);
            cpuid_text([leaf.ebx, leaf.ecx, leaf.edx])
        })
        .filter(|vendor| !vendor.is_empty());

    let advertised_features = advertised_features(max_basic_leaf, max_extended_leaf, leaf1);
    let usable_features = usable_features(advertised_features);
    let brand = brand_string(max_extended_leaf);
    let topology = match winapi::processor_topology() {
        Ok(topology) => Some(topology),
        Err(error) => {
            issues.push(DetectionIssue::new(HardwareComponent::Cpu, error));
            None
        }
    };
    let available_parallelism = std::thread::available_parallelism()
        .map(|count| count.get() as u32)
        .unwrap_or_else(|_| layout.logical_processor_count.max(1));

    let (physical_core_count, package_count, numa_node_count, caches, efficiency_classes) =
        normalize_topology(topology);
    CpuInfo {
        vendor,
        vendor_id,
        brand,
        family,
        model,
        stepping,
        max_basic_leaf,
        max_extended_leaf,
        hypervisor_present,
        hypervisor_vendor,
        logical_processor_count: layout.logical_processor_count,
        physical_core_count,
        package_count,
        numa_node_count,
        available_parallelism,
        caches,
        efficiency_classes,
        advertised_features,
        usable_features,
    }
}

fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    // CPUID is available on every processor supported by the Windows targets
    // in this workspace. Leaf bounds are checked by the caller where the
    // architecture defines a maximum-leaf contract.
    __cpuid_count(leaf, subleaf)
}

fn decode_signature(eax: u32) -> (u16, u16, u8) {
    let base_family = ((eax >> 8) & 0x0f) as u16;
    let base_model = ((eax >> 4) & 0x0f) as u16;
    let extended_family = ((eax >> 20) & 0xff) as u16;
    let extended_model = ((eax >> 16) & 0x0f) as u16;
    let family = if base_family == 0x0f {
        base_family + extended_family
    } else {
        base_family
    };
    let model = if matches!(base_family, 0x06 | 0x0f) {
        (extended_model << 4) | base_model
    } else {
        base_model
    };
    (family, model, (eax & 0x0f) as u8)
}

fn advertised_features(
    max_basic_leaf: u32,
    max_extended_leaf: u32,
    leaf1: CpuidResult,
) -> CpuFeatures {
    let mut features = CpuFeatures::empty();
    set_bit(&mut features, leaf1.edx, 23, CpuFeatures::MMX);
    set_bit(&mut features, leaf1.edx, 25, CpuFeatures::SSE);
    set_bit(&mut features, leaf1.edx, 26, CpuFeatures::SSE2);
    set_bit(&mut features, leaf1.ecx, 0, CpuFeatures::SSE3);
    set_bit(&mut features, leaf1.ecx, 1, CpuFeatures::PCLMULQDQ);
    set_bit(&mut features, leaf1.ecx, 9, CpuFeatures::SSSE3);
    set_bit(&mut features, leaf1.ecx, 12, CpuFeatures::FMA);
    set_bit(&mut features, leaf1.ecx, 19, CpuFeatures::SSE4_1);
    set_bit(&mut features, leaf1.ecx, 20, CpuFeatures::SSE4_2);
    set_bit(&mut features, leaf1.ecx, 22, CpuFeatures::MOVBE);
    set_bit(&mut features, leaf1.ecx, 23, CpuFeatures::POPCNT);
    set_bit(&mut features, leaf1.ecx, 25, CpuFeatures::AES);
    set_bit(&mut features, leaf1.ecx, 28, CpuFeatures::AVX);
    set_bit(&mut features, leaf1.ecx, 29, CpuFeatures::F16C);
    set_bit(&mut features, leaf1.ecx, 30, CpuFeatures::RDRAND);

    if max_basic_leaf >= 7 {
        let leaf7 = cpuid(7, 0);
        set_bit(&mut features, leaf7.ebx, 3, CpuFeatures::BMI1);
        set_bit(&mut features, leaf7.ebx, 5, CpuFeatures::AVX2);
        set_bit(&mut features, leaf7.ebx, 8, CpuFeatures::BMI2);
        set_bit(&mut features, leaf7.ebx, 9, CpuFeatures::ERMS);
        set_bit(&mut features, leaf7.ebx, 16, CpuFeatures::AVX512F);
        set_bit(&mut features, leaf7.ebx, 17, CpuFeatures::AVX512DQ);
        set_bit(&mut features, leaf7.ebx, 18, CpuFeatures::RDSEED);
        set_bit(&mut features, leaf7.ebx, 19, CpuFeatures::ADX);
        set_bit(&mut features, leaf7.ebx, 23, CpuFeatures::CLFLUSHOPT);
        set_bit(&mut features, leaf7.ebx, 24, CpuFeatures::CLWB);
        set_bit(&mut features, leaf7.ebx, 28, CpuFeatures::AVX512CD);
        set_bit(&mut features, leaf7.ebx, 29, CpuFeatures::SHA);
        set_bit(&mut features, leaf7.ebx, 30, CpuFeatures::AVX512BW);
        set_bit(&mut features, leaf7.ebx, 31, CpuFeatures::AVX512VL);
    }

    if max_extended_leaf >= 0x8000_0001 {
        let leaf = cpuid(0x8000_0001, 0);
        set_bit(&mut features, leaf.ecx, 5, CpuFeatures::LZCNT);
        set_bit(&mut features, leaf.ecx, 6, CpuFeatures::SSE4A);
        set_bit(&mut features, leaf.edx, 27, CpuFeatures::RDTSCP);
    }
    features
}

fn set_bit(features: &mut CpuFeatures, register: u32, bit: u32, feature: CpuFeatures) {
    if register & (1 << bit) != 0 {
        features.insert(feature);
    }
}

fn usable_features(advertised: CpuFeatures) -> CpuFeatures {
    let mut usable = advertised;
    if !std::is_x86_feature_detected!("avx") {
        usable.remove(
            CpuFeatures::AVX
                | CpuFeatures::AVX2
                | CpuFeatures::F16C
                | CpuFeatures::FMA
                | avx512_features(),
        );
    } else if !std::is_x86_feature_detected!("avx512f") {
        usable.remove(avx512_features());
    }
    normalize_feature_dependencies(usable)
}

const fn avx512_features() -> CpuFeatures {
    CpuFeatures::from_bits_retain(
        CpuFeatures::AVX512F.bits()
            | CpuFeatures::AVX512BW.bits()
            | CpuFeatures::AVX512DQ.bits()
            | CpuFeatures::AVX512CD.bits()
            | CpuFeatures::AVX512VL.bits(),
    )
}

fn normalize_feature_dependencies(mut features: CpuFeatures) -> CpuFeatures {
    if !features.contains(CpuFeatures::AVX) {
        features
            .remove(CpuFeatures::AVX2 | CpuFeatures::F16C | CpuFeatures::FMA | avx512_features());
    }
    if !features.contains(CpuFeatures::AVX512F) {
        features.remove(
            CpuFeatures::AVX512BW
                | CpuFeatures::AVX512DQ
                | CpuFeatures::AVX512CD
                | CpuFeatures::AVX512VL,
        );
    }
    features
}

fn brand_string(max_extended_leaf: u32) -> Option<String> {
    if max_extended_leaf < 0x8000_0004 {
        return None;
    }
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002..=0x8000_0004 {
        let result = cpuid(leaf, 0);
        for register in [result.eax, result.ebx, result.ecx, result.edx] {
            bytes.extend_from_slice(&register.to_le_bytes());
        }
    }
    let brand = String::from_utf8_lossy(&bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_owned();
    (!brand.is_empty()).then_some(brand)
}

fn cpuid_text(registers: [u32; 3]) -> String {
    let mut bytes = [0u8; 12];
    for (chunk, register) in bytes.chunks_exact_mut(4).zip(registers) {
        chunk.copy_from_slice(&register.to_le_bytes());
    }
    String::from_utf8_lossy(&bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_owned()
}

fn normalize_topology(
    topology: Option<ProcessorTopology>,
) -> (
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Vec<CpuCache>,
    Vec<CpuEfficiencyClass>,
) {
    let Some(topology) = topology else {
        return (None, None, None, Vec::new(), Vec::new());
    };
    let caches = topology
        .caches
        .into_iter()
        .map(|cache| CpuCache {
            level: cache.level,
            associativity: cache.associativity,
            line_size: cache.line_size,
            size_bytes: cache.size,
            shared_logical_processor_count: cache.shared_logical_processor_count,
            kind: match cache.cache_type {
                ProcessorCacheType::Unified => CpuCacheKind::Unified,
                ProcessorCacheType::Instruction => CpuCacheKind::Instruction,
                ProcessorCacheType::Data => CpuCacheKind::Data,
                ProcessorCacheType::Trace => CpuCacheKind::Trace,
                ProcessorCacheType::Unknown(value) => CpuCacheKind::Unknown(value),
            },
        })
        .collect();
    let efficiency_classes = topology
        .efficiency_classes
        .into_iter()
        .map(|entry| CpuEfficiencyClass {
            class: entry.class,
            core_count: entry.core_count,
        })
        .collect();
    (
        (topology.physical_core_count != 0).then_some(topology.physical_core_count),
        (topology.package_count != 0).then_some(topology.package_count),
        (topology.numa_node_count != 0).then_some(topology.numa_node_count),
        caches,
        efficiency_classes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_uses_extended_family_and_model_rules() {
        // Base family 0xf, extended family 8, base model 1, extended model 2.
        let eax = (8 << 20) | (2 << 16) | (0xf << 8) | (1 << 4) | 3;
        assert_eq!(decode_signature(eax), (23, 33, 3));
    }

    #[test]
    fn usable_features_reject_orphaned_vector_extensions() {
        let features =
            CpuFeatures::AVX2 | CpuFeatures::FMA | CpuFeatures::AVX512F | CpuFeatures::AVX512BW;
        assert!(normalize_feature_dependencies(features).is_empty());

        let features = CpuFeatures::AVX | CpuFeatures::AVX512BW;
        assert_eq!(normalize_feature_dependencies(features), CpuFeatures::AVX);
    }
}
