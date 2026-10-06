//! Official SMAA 1x source and immutable lookup textures.
//!
//! The existing AA worker concatenates source before compilation. Device-owned
//! lookup textures are uploaded once on demand, retained with the effect, and
//! released with it on reset. No file access or compilation occurs in a draw.
//! ARGB8 preserves the reference's DX9 area `.ra` and search `.r` channels
//! exactly while using the existing safe texture upload wrapper.

use libpsycho::os::windows::directx9::*;

const REFERENCE: &[u8] = include_bytes!("../../../shaders/embedded/smaa/SMAA.hlsl");
const AREA: &[u8] = include_bytes!("../../../shaders/embedded/smaa/area.bin");
const SEARCH: &[u8] = include_bytes!("../../../shaders/embedded/smaa/search.bin");

/// Concatenate the official HLSL3 implementation with one OMV entry point.
/// Called only by the established preparation worker or offline tests.
pub(super) fn source(entry: &[u8]) -> Vec<u8> {
    let mut source = b"float4 ScreenData : register(c0);\nfloat4 Options0 : register(c3);\nfloat4 Options1 : register(c4);\n#define SMAA_HLSL_3 1\n#define SMAA_RT_METRICS ScreenData.zwxy\n#define SMAA_THRESHOLD Options0.y\n#define SMAA_CORNER_ROUNDING Options1.x\n#define SMAA_MAX_SEARCH_STEPS 16\n#define SMAA_MAX_SEARCH_STEPS_DIAG 8\n".to_vec();
    source.extend_from_slice(REFERENCE);
    source.extend_from_slice(b"\n");
    source.extend_from_slice(entry);
    source
}

/// Device-owned immutable lookup bindings; neither aliases a writable target.
pub(super) struct LookupTextures {
    pub(super) area: Texture9,
    pub(super) search: Texture9,
}

impl LookupTextures {
    /// Upload the official 160x560 two-channel area and packed 64x16 search
    /// tables once. Partial failure drops all acquired COM resources.
    pub(super) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        let area_pixels: Vec<u32> = AREA
            .chunks_exact(2)
            .map(|v| ((v[1] as u32) << 24) | ((v[0] as u32) << 16))
            .collect();
        let search_pixels: Vec<u32> = SEARCH.iter().map(|v| (*v as u32) << 16).collect();
        let area = device.create_texture(160, 560, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)?;
        area.write_level0_argb(160, 560, &area_pixels)?;
        let search = device.create_texture(64, 16, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)?;
        search.write_level0_argb(64, 16, &search_pixels)?;
        Ok(Self { area, search })
    }
}
