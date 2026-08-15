// Adapted from New Vegas Reloaded's ShadowCubeMap.pso.hlsl (GPL-3.0-or-later).
float4 ShadowData : register(c0);
sampler2D DiffuseMap : register(s0);
samplerCUBE StaticDepthMap : register(s1);

struct PixelInput {
    float3 lightVector : TEXCOORD0;
    float2 uv : TEXCOORD1;
};

float4 Main(PixelInput input) : COLOR0 {
    if (ShadowData.y > 0.5f) {
        float4 diffuse = tex2D(DiffuseMap, input.uv);
        // NVR intentionally uses a softer 0.2 cutout for local-light cubes;
        // preserving thin foliage is more important than the directional
        // cascade's stricter silhouette threshold here.
        clip(diffuse.a - 0.2f);
    }
    float depth = saturate(length(input.lightVector) / max(ShadowData.z, 0.001f));
    if (ShadowData.w > 0.5f) {
        // The target already contains the immutable face. Merge the animated
        // fragment with the same D3D cube coordinates used by the receiver so
        // an actor behind a wall cannot replace that nearer wall depth.
        float3 cubeDirection = input.lightVector * float3(-1.0f, -1.0f, 1.0f);
        depth = min(depth, texCUBE(StaticDepthMap, cubeDirection).r);
    }
    // The cube target stores only red (R32F), but the legacy D3D compiler still
    // requires COLOR0 to be a complete four-component output.
    return float4(depth, depth, depth, 1.0f);
}
