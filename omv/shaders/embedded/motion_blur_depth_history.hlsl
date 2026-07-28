// Current world depth encoded into an ordinary A8R8G8B8 render target.
//
// D3D9 depth textures cannot be copied portably into a shader-readable history
// resource. Packing the resolved raw depth through a one-sample fullscreen pass
// keeps the history path vendor- and depth-format-independent.

sampler2D WorldDepth : register(s0);
float4 ScreenData : register(c0);

float2 DepthTexelCenter(float2 uv) {
    float2 pixel = clamp(floor(uv * ScreenData.xy), 0.0f, ScreenData.xy - 1.0f);
    return (pixel + 0.5f) * ScreenData.zw;
}

float3 PackDepth24(float depth) {
    float3 packed = frac(saturate(depth) * float3(1.0f, 255.0f, 65025.0f));
    packed -= packed.yzz * float3(1.0f / 255.0f, 1.0f / 255.0f, 0.0f);
    return packed;
}

float4 Main(float2 requestedUv : TEXCOORD0) : COLOR0 {
    float2 uv = DepthTexelCenter(requestedUv);
    float rawDepth = tex2Dlod(WorldDepth, float4(uv, 0.0f, 0.0f)).r;
    return float4(PackDepth24(rawDepth), 1.0f);
}
