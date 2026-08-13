// Adapted from New Vegas Reloaded's ShadowMap.pso.hlsl (GPL-3.0-or-later).
float4 ShadowData : register(c0);
sampler2D DiffuseMap : register(s0);

struct PixelInput {
    float4 shadowPosition : TEXCOORD0;
    float2 uv : TEXCOORD1;
};

float2 WarpDepth(float depth) {
    float normalized = depth * 2.0f - 1.0f;
    // FP16 EVSM must clamp its positive exponent to avoid overflow.
    return float2(exp(5.54f * normalized), -exp(-5.0f * normalized));
}

float4 Main(PixelInput input) : COLOR0 {
    if (ShadowData.y > 0.5f) {
        float4 diffuse = tex2D(DiffuseMap, input.uv);
        clip(diffuse.a - 0.5f);
    }
    float depth = saturate(input.shadowPosition.z / input.shadowPosition.w);
    if (ShadowData.w > 1.5f) {
        // Actor targets store linear depth plus coverage. With four-sample
        // rasterization each covered sample writes `(depth, 1)` and the black
        // clear supplies `(0, 0)`; resolve and bilinear filtering then retain
        // a valid coverage-weighted mean instead of corrupting EVSM moments.
        return float4(depth, 1.0f, 0.0f, 0.0f);
    }
    float2 warped = WarpDepth(depth);
    return float4(warped, warped * warped);
}
