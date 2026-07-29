//! Direct3D 9 adapter identity and effective feature detection.
//!
//! The active-device path starts from a borrowed `IDirect3DDevice9`, reads its
//! creation parameters, and asks the owning `IDirect3D9` about that exact
//! adapter ordinal and device type. This avoids the common but incorrect
//! assumption that adapter zero describes the GPU rendering the game.

use bitflags::bitflags;
use windows::Win32::Graphics::Direct3D9::{
    D3DDEVCAPS_HWTRANSFORMANDLIGHT, D3DDEVCAPS_PUREDEVICE, D3DPMISCCAPS_MRTINDEPENDENTBITDEPTHS,
    D3DPTEXTURECAPS_CUBEMAP, D3DPTEXTURECAPS_NONPOW2CONDITIONAL, D3DPTEXTURECAPS_POW2,
    D3DPTEXTURECAPS_VOLUMEMAP, D3DPTFILTERCAPS_MAGFANISOTROPIC, D3DPTFILTERCAPS_MINFANISOTROPIC,
    D3DUSAGE_DEPTHSTENCIL, D3DUSAGE_QUERY_POSTPIXELSHADER_BLENDING, D3DUSAGE_QUERY_SRGBREAD,
    D3DUSAGE_QUERY_SRGBWRITE, D3DUSAGE_RENDERTARGET,
};

use super::{HardwareError, HardwareResult};
use crate::os::windows::directx9::{
    AdapterIdentifier9, D3DCAPS9, D3DDEVTYPE, D3DDEVTYPE_HAL, D3DDEVTYPE_NULLREF, D3DDEVTYPE_REF,
    D3DDEVTYPE_SW, D3DFMT_A8R8G8B8, D3DFMT_A16B16G16R16F, D3DFMT_INTZ, D3DFMT_R32F, D3DFMT_RESZ,
    D3DRTYPE_SURFACE, D3DRTYPE_TEXTURE, Device9Ref, Direct3D9, create_direct3d9,
};

/// Stable D3D9 adapter identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpuIdentity {
    /// Human-readable adapter description.
    pub description: String,
    /// Driver module reported by D3D9.
    pub driver: String,
    /// Win32 display-device name.
    pub device_name: String,
    /// Packed native driver version.
    pub driver_version: i64,
    /// PCI or virtual-vendor identifier.
    pub vendor_id: u32,
    /// PCI or virtual-device identifier.
    pub device_id: u32,
    /// PCI subsystem identifier.
    pub subsystem_id: u32,
    /// PCI revision.
    pub revision: u32,
    /// D3D9 device GUID in canonical `u128` form.
    pub device_identifier: u128,
    /// WHQL level reported by D3D9.
    pub whql_level: u32,
}

/// D3D9 device implementation selected at creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum D3d9DeviceKind {
    /// Hardware abstraction layer.
    Hardware,
    /// Microsoft reference rasterizer.
    Reference,
    /// Registered software rasterizer.
    Software,
    /// Null reference rasterizer.
    NullReference,
    /// Newer or vendor-specific raw `D3DDEVTYPE`.
    Unknown(i32),
}

/// Parsed D3D shader version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShaderModel {
    /// Major shader-model version.
    pub major: u8,
    /// Minor shader-model version.
    pub minor: u8,
}

bitflags! {
    /// Normalized feature flags derived from `D3DCAPS9`.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct D3d9FeatureFlags: u32 {
        /// Hardware transform and lighting.
        const HARDWARE_TRANSFORM_AND_LIGHT = 1 << 0;
        /// Pure-device operation.
        const PURE_DEVICE = 1 << 1;
        /// Cube textures.
        const CUBE_TEXTURES = 1 << 2;
        /// Volume textures.
        const VOLUME_TEXTURES = 1 << 3;
        /// Power-of-two texture dimensions are generally required.
        const POW2_TEXTURES_REQUIRED = 1 << 4;
        /// Conditional non-power-of-two textures are supported.
        const CONDITIONAL_NPOT_TEXTURES = 1 << 5;
        /// Anisotropic minification filtering.
        const ANISOTROPIC_MIN_FILTER = 1 << 6;
        /// Anisotropic magnification filtering.
        const ANISOTROPIC_MAG_FILTER = 1 << 7;
        /// Simultaneous render targets may have independent bit depths.
        const INDEPENDENT_MRT_BIT_DEPTHS = 1 << 8;
        /// Vertex texture fetching exposes at least one supported filter mode.
        const VERTEX_TEXTURE_FETCH = 1 << 9;
    }
}

bitflags! {
    /// Effective resource formats proven through `CheckDeviceFormat`.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct D3d9FormatFeatures: u32 {
        /// Vendor RESZ depth resolve.
        const RESZ = 1 << 0;
        /// Shader-readable INTZ depth texture.
        const INTZ = 1 << 1;
        /// Four-channel FP16 render-target texture.
        const FP16_RENDER_TARGET = 1 << 2;
        /// Post-pixel-shader blending into a four-channel FP16 target.
        const FP16_BLENDABLE = 1 << 3;
        /// Single-channel FP32 render-target texture.
        const FP32_RENDER_TARGET = 1 << 4;
        /// Post-pixel-shader blending into a single-channel FP32 target.
        const FP32_BLENDABLE = 1 << 5;
        /// sRGB decoding when sampling an ARGB texture.
        const SRGB_TEXTURE_READ = 1 << 6;
        /// sRGB encoding when writing an ARGB render target.
        const SRGB_RENDER_TARGET_WRITE = 1 << 7;
    }
}

/// Normalized limits and features from `D3DCAPS9`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct D3d9Capabilities {
    /// Feature flags derived from capability bitfields.
    pub features: D3d9FeatureFlags,
    /// Maximum two-dimensional texture width.
    pub max_texture_width: u32,
    /// Maximum two-dimensional texture height.
    pub max_texture_height: u32,
    /// Maximum volume-texture extent.
    pub max_volume_extent: u32,
    /// Maximum anisotropy value.
    pub max_anisotropy: u32,
    /// Maximum simultaneous render targets.
    pub max_simultaneous_render_targets: u32,
    /// Maximum simultaneous texture bindings.
    pub max_simultaneous_textures: u32,
    /// Maximum fixed-function texture-blend stages.
    pub max_texture_blend_stages: u32,
    /// Maximum vertex streams.
    pub max_vertex_streams: u32,
    /// Maximum byte stride for one vertex stream.
    pub max_vertex_stream_stride: u32,
    /// Effective vertex shader model.
    pub vertex_shader_model: ShaderModel,
    /// Effective pixel shader model.
    pub pixel_shader_model: ShaderModel,
    /// Vertex shader float constant-register count.
    pub max_vertex_shader_constants: u32,
}

/// Profile of the D3D9 device that is actually rendering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct D3d9DeviceProfile {
    /// Adapter ordinal used to create the device.
    pub adapter_ordinal: u32,
    /// Device implementation type used at creation.
    pub device_kind: D3d9DeviceKind,
    /// D3D9 behavior flags used at creation.
    pub behavior_flags: u32,
    /// Adapter and driver identity.
    pub identity: GpuIdentity,
    /// Effective created-device limits and features.
    pub capabilities: D3d9Capabilities,
    /// Effective format support for the same adapter/device type.
    pub format_features: D3d9FormatFeatures,
    /// Driver estimate from `GetAvailableTextureMem`.
    ///
    /// This value is neither total dedicated VRAM nor a stable budget and may
    /// change between calls. It is retained only as the profile-time estimate.
    pub approximate_available_texture_memory_bytes: u32,
}

/// Profile of one adapter exposed by a newly created D3D9 interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct D3d9AdapterProfile {
    /// D3D9 adapter ordinal.
    pub adapter_ordinal: u32,
    /// Adapter and driver identity.
    pub identity: GpuIdentity,
    /// HAL capabilities available for device creation.
    pub capabilities: D3d9Capabilities,
    /// HAL format support.
    pub format_features: D3d9FormatFeatures,
}

/// Detect the GPU and features used by an existing D3D9 device.
///
/// Call this on a thread allowed to query the host renderer. The function does
/// not retain the borrowed device or cache a COM pointer. All identity and
/// capability data is copied into owned Rust values before returning.
pub fn d3d9_device_profile(device: &Device9Ref<'_>) -> HardwareResult<D3d9DeviceProfile> {
    let creation = device.creation_parameters().map_err(|error| {
        HardwareError::operation("IDirect3DDevice9::GetCreationParameters", error)
    })?;
    let d3d = device
        .direct3d()
        .map_err(|error| HardwareError::operation("IDirect3DDevice9::GetDirect3D", error))?;
    let identifier = d3d
        .adapter_identifier(creation.adapter_ordinal)
        .map_err(|error| HardwareError::operation("IDirect3D9::GetAdapterIdentifier", error))?;
    let caps = device
        .device_caps()
        .map_err(|error| HardwareError::operation("IDirect3DDevice9::GetDeviceCaps", error))?;
    let format_features =
        query_format_features(&d3d, creation.adapter_ordinal, creation.device_type)?;

    Ok(D3d9DeviceProfile {
        adapter_ordinal: creation.adapter_ordinal,
        device_kind: device_kind(creation.device_type),
        behavior_flags: creation.behavior_flags,
        identity: normalize_identity(identifier),
        capabilities: normalize_caps(&caps),
        format_features,
        approximate_available_texture_memory_bytes: device.available_texture_mem(),
    })
}

/// Enumerate all D3D9 adapters and their HAL creation capabilities.
///
/// This is independent inventory. It must not be used to infer which adapter a
/// host renderer selected; use [`d3d9_device_profile`] for that decision.
pub fn d3d9_adapter_profiles() -> HardwareResult<Vec<D3d9AdapterProfile>> {
    let d3d =
        create_direct3d9().map_err(|error| HardwareError::operation("Direct3DCreate9", error))?;
    let mut profiles = Vec::with_capacity(d3d.adapter_count() as usize);
    for adapter_ordinal in 0..d3d.adapter_count() {
        let identifier = d3d
            .adapter_identifier(adapter_ordinal)
            .map_err(|error| HardwareError::operation("IDirect3D9::GetAdapterIdentifier", error))?;
        let caps = d3d
            .device_caps(adapter_ordinal, D3DDEVTYPE_HAL)
            .map_err(|error| HardwareError::operation("IDirect3D9::GetDeviceCaps", error))?;
        profiles.push(D3d9AdapterProfile {
            adapter_ordinal,
            identity: normalize_identity(identifier),
            capabilities: normalize_caps(&caps),
            format_features: query_format_features(&d3d, adapter_ordinal, D3DDEVTYPE_HAL)?,
        });
    }
    Ok(profiles)
}

fn query_format_features(
    d3d: &Direct3D9,
    adapter: u32,
    device_type: D3DDEVTYPE,
) -> HardwareResult<D3d9FormatFeatures> {
    let mode = d3d
        .adapter_display_mode(adapter)
        .map_err(|error| HardwareError::operation("IDirect3D9::GetAdapterDisplayMode", error))?;
    let mut features = D3d9FormatFeatures::empty();
    probe_format(
        d3d,
        adapter,
        device_type,
        mode.Format,
        D3DUSAGE_RENDERTARGET as u32,
        D3DRTYPE_SURFACE,
        D3DFMT_RESZ,
        D3d9FormatFeatures::RESZ,
        &mut features,
    )?;
    probe_format(
        d3d,
        adapter,
        device_type,
        mode.Format,
        D3DUSAGE_DEPTHSTENCIL as u32,
        D3DRTYPE_TEXTURE,
        D3DFMT_INTZ,
        D3d9FormatFeatures::INTZ,
        &mut features,
    )?;
    probe_render_target(
        d3d,
        adapter,
        device_type,
        mode.Format,
        D3DFMT_A16B16G16R16F,
        D3d9FormatFeatures::FP16_RENDER_TARGET,
        D3d9FormatFeatures::FP16_BLENDABLE,
        &mut features,
    )?;
    probe_render_target(
        d3d,
        adapter,
        device_type,
        mode.Format,
        D3DFMT_R32F,
        D3d9FormatFeatures::FP32_RENDER_TARGET,
        D3d9FormatFeatures::FP32_BLENDABLE,
        &mut features,
    )?;
    probe_format(
        d3d,
        adapter,
        device_type,
        mode.Format,
        D3DUSAGE_QUERY_SRGBREAD as u32,
        D3DRTYPE_TEXTURE,
        D3DFMT_A8R8G8B8,
        D3d9FormatFeatures::SRGB_TEXTURE_READ,
        &mut features,
    )?;
    probe_format(
        d3d,
        adapter,
        device_type,
        mode.Format,
        (D3DUSAGE_RENDERTARGET | D3DUSAGE_QUERY_SRGBWRITE) as u32,
        D3DRTYPE_TEXTURE,
        D3DFMT_A8R8G8B8,
        D3d9FormatFeatures::SRGB_RENDER_TARGET_WRITE,
        &mut features,
    )?;
    Ok(features)
}

#[allow(clippy::too_many_arguments)]
fn probe_render_target(
    d3d: &Direct3D9,
    adapter: u32,
    device_type: D3DDEVTYPE,
    adapter_format: crate::os::windows::directx9::D3DFORMAT,
    format: crate::os::windows::directx9::D3DFORMAT,
    render_target_feature: D3d9FormatFeatures,
    blending_feature: D3d9FormatFeatures,
    features: &mut D3d9FormatFeatures,
) -> HardwareResult<()> {
    probe_format(
        d3d,
        adapter,
        device_type,
        adapter_format,
        D3DUSAGE_RENDERTARGET as u32,
        D3DRTYPE_TEXTURE,
        format,
        render_target_feature,
        features,
    )?;
    probe_format(
        d3d,
        adapter,
        device_type,
        adapter_format,
        (D3DUSAGE_RENDERTARGET | D3DUSAGE_QUERY_POSTPIXELSHADER_BLENDING) as u32,
        D3DRTYPE_TEXTURE,
        format,
        blending_feature,
        features,
    )
}

#[allow(clippy::too_many_arguments)]
fn probe_format(
    d3d: &Direct3D9,
    adapter: u32,
    device_type: D3DDEVTYPE,
    adapter_format: crate::os::windows::directx9::D3DFORMAT,
    usage: u32,
    resource_type: windows::Win32::Graphics::Direct3D9::D3DRESOURCETYPE,
    format: crate::os::windows::directx9::D3DFORMAT,
    feature: D3d9FormatFeatures,
    features: &mut D3d9FormatFeatures,
) -> HardwareResult<()> {
    let supported = d3d
        .supports_device_format(
            adapter,
            device_type,
            adapter_format,
            usage,
            resource_type,
            format,
        )
        .map_err(|error| HardwareError::operation("IDirect3D9::CheckDeviceFormat", error))?;
    if supported {
        features.insert(feature);
    }
    Ok(())
}

fn normalize_identity(identifier: AdapterIdentifier9) -> GpuIdentity {
    GpuIdentity {
        description: identifier.description,
        driver: identifier.driver,
        device_name: identifier.device_name,
        driver_version: identifier.driver_version,
        vendor_id: identifier.vendor_id,
        device_id: identifier.device_id,
        subsystem_id: identifier.subsystem_id,
        revision: identifier.revision,
        device_identifier: identifier.device_identifier,
        whql_level: identifier.whql_level,
    }
}

fn normalize_caps(caps: &D3DCAPS9) -> D3d9Capabilities {
    let mut features = D3d9FeatureFlags::empty();
    insert_cap(
        &mut features,
        caps.DevCaps,
        D3DDEVCAPS_HWTRANSFORMANDLIGHT,
        D3d9FeatureFlags::HARDWARE_TRANSFORM_AND_LIGHT,
    );
    insert_cap(
        &mut features,
        caps.DevCaps,
        D3DDEVCAPS_PUREDEVICE,
        D3d9FeatureFlags::PURE_DEVICE,
    );
    insert_cap(
        &mut features,
        caps.TextureCaps,
        D3DPTEXTURECAPS_CUBEMAP,
        D3d9FeatureFlags::CUBE_TEXTURES,
    );
    insert_cap(
        &mut features,
        caps.TextureCaps,
        D3DPTEXTURECAPS_VOLUMEMAP,
        D3d9FeatureFlags::VOLUME_TEXTURES,
    );
    insert_cap(
        &mut features,
        caps.TextureCaps,
        D3DPTEXTURECAPS_POW2,
        D3d9FeatureFlags::POW2_TEXTURES_REQUIRED,
    );
    insert_cap(
        &mut features,
        caps.TextureCaps,
        D3DPTEXTURECAPS_NONPOW2CONDITIONAL,
        D3d9FeatureFlags::CONDITIONAL_NPOT_TEXTURES,
    );
    insert_cap(
        &mut features,
        caps.TextureFilterCaps,
        D3DPTFILTERCAPS_MINFANISOTROPIC,
        D3d9FeatureFlags::ANISOTROPIC_MIN_FILTER,
    );
    insert_cap(
        &mut features,
        caps.TextureFilterCaps,
        D3DPTFILTERCAPS_MAGFANISOTROPIC,
        D3d9FeatureFlags::ANISOTROPIC_MAG_FILTER,
    );
    insert_cap(
        &mut features,
        caps.PrimitiveMiscCaps,
        D3DPMISCCAPS_MRTINDEPENDENTBITDEPTHS,
        D3d9FeatureFlags::INDEPENDENT_MRT_BIT_DEPTHS,
    );
    if caps.VertexTextureFilterCaps != 0 {
        features.insert(D3d9FeatureFlags::VERTEX_TEXTURE_FETCH);
    }
    D3d9Capabilities {
        features,
        max_texture_width: caps.MaxTextureWidth,
        max_texture_height: caps.MaxTextureHeight,
        max_volume_extent: caps.MaxVolumeExtent,
        max_anisotropy: caps.MaxAnisotropy,
        max_simultaneous_render_targets: caps.NumSimultaneousRTs,
        max_simultaneous_textures: caps.MaxSimultaneousTextures,
        max_texture_blend_stages: caps.MaxTextureBlendStages,
        max_vertex_streams: caps.MaxStreams,
        max_vertex_stream_stride: caps.MaxStreamStride,
        vertex_shader_model: shader_model(caps.VertexShaderVersion),
        pixel_shader_model: shader_model(caps.PixelShaderVersion),
        max_vertex_shader_constants: caps.MaxVertexShaderConst,
    }
}

fn insert_cap(features: &mut D3d9FeatureFlags, raw: u32, mask: i32, feature: D3d9FeatureFlags) {
    if raw & mask as u32 != 0 {
        features.insert(feature);
    }
}

fn shader_model(raw: u32) -> ShaderModel {
    ShaderModel {
        major: ((raw >> 8) & 0xff) as u8,
        minor: (raw & 0xff) as u8,
    }
}

fn device_kind(device_type: D3DDEVTYPE) -> D3d9DeviceKind {
    match device_type {
        kind if kind == D3DDEVTYPE_HAL => D3d9DeviceKind::Hardware,
        kind if kind == D3DDEVTYPE_REF => D3d9DeviceKind::Reference,
        kind if kind == D3DDEVTYPE_SW => D3d9DeviceKind::Software,
        kind if kind == D3DDEVTYPE_NULLREF => D3d9DeviceKind::NullReference,
        kind => D3d9DeviceKind::Unknown(kind.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_caps_and_shader_versions() {
        let caps = D3DCAPS9 {
            DevCaps: D3DDEVCAPS_HWTRANSFORMANDLIGHT as u32,
            TextureCaps: (D3DPTEXTURECAPS_CUBEMAP | D3DPTEXTURECAPS_VOLUMEMAP) as u32,
            TextureFilterCaps: D3DPTFILTERCAPS_MINFANISOTROPIC as u32,
            MaxTextureWidth: 8192,
            MaxTextureHeight: 4096,
            MaxAnisotropy: 16,
            VertexShaderVersion: 0x0300,
            PixelShaderVersion: 0x0300,
            NumSimultaneousRTs: 4,
            ..Default::default()
        };
        let normalized = normalize_caps(&caps);
        assert!(
            normalized
                .features
                .contains(D3d9FeatureFlags::HARDWARE_TRANSFORM_AND_LIGHT)
        );
        assert!(
            normalized
                .features
                .contains(D3d9FeatureFlags::CUBE_TEXTURES)
        );
        assert_eq!(
            normalized.vertex_shader_model,
            ShaderModel { major: 3, minor: 0 }
        );
        assert_eq!(normalized.max_simultaneous_render_targets, 4);
    }

    #[test]
    fn preserves_unknown_device_types() {
        assert_eq!(device_kind(D3DDEVTYPE(99)), D3d9DeviceKind::Unknown(99));
    }
}
