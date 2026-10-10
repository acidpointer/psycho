sampler2D ShaftLight : register(s0);
sampler2D CoverageMask : register(s3);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 EnvironmentData : register(c6);
float4 OptionData3 : register(c7);
float4 SunData : register(c8);
float4 EffectData : register(c9);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float2 CoveredEndpoint(float2 uv) {
    float2 delta = SunData.xy - uv;
    float2 boundary = float2(delta.x >= 0.0f ? 1.0f : 0.0f, delta.y >= 0.0f ? 1.0f : 0.0f);
    float2 extent = abs(boundary - uv) / max(abs(delta), 0.000001f);
    return uv + delta * min(1.0f, min(extent.x, extent.y));
}

float4 Main(PixelInput input) : COLOR0 {
    // Reconstruct along and across the ray, rather than a small fixed X/Y
    // blur that leaves widely spaced blocker projections untouched. The
    // longitudinal kernel covers two radial segments on either side even
    // when the sample-count cap is reached at high resolution.
    float2 endpoint = CoveredEndpoint(input.uv);
    float2 radialPixels = (endpoint - input.uv) * ScreenData.xy;
    float rayLength = length(radialPixels);
    float sampleCount = clamp(ceil(rayLength * 0.5f), 32.0f, 256.0f);
    float2 d = EffectData.x != 0.0f
        ? (endpoint - input.uv) / sampleCount * 0.5f
        : float2(-radialPixels.y, radialPixels.x) / max(rayLength, 1.0f) * ScreenData.zw;
    if (EffectData.x == 0.0f) {
        // Three transverse taps smooth reconstruction without widening a
        // shadow by eight full-resolution pixels. Coverage guidance keeps
        // opaque walls from filling narrow open windows during filtering.
        float centerCoverage = tex2Dlod(CoverageMask, float4(input.uv, 0.0f, 0.0f)).g;
        float leftWeight = 0.25f * (1.0f - abs(centerCoverage - tex2Dlod(CoverageMask, float4(input.uv - d, 0.0f, 0.0f)).g));
        float rightWeight = 0.25f * (1.0f - abs(centerCoverage - tex2Dlod(CoverageMask, float4(input.uv + d, 0.0f, 0.0f)).g));
        float filtered = tex2Dlod(ShaftLight, float4(input.uv, 0.0f, 0.0f)).r * 0.5f;
        filtered += tex2Dlod(ShaftLight, float4(input.uv - d, 0.0f, 0.0f)).r * leftWeight;
        filtered += tex2Dlod(ShaftLight, float4(input.uv + d, 0.0f, 0.0f)).r * rightWeight;
        return float4(saturate(filtered / (0.5f + leftWeight + rightWeight)), 0.0f, 0.0f, 1.0f);
    }
    float value = 0.0f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d * 4.0f, 0.0f, 0.0f)).r * 0.035f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d * 3.0f, 0.0f, 0.0f)).r * 0.070f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d * 2.0f, 0.0f, 0.0f)).r * 0.120f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d, 0.0f, 0.0f)).r * 0.180f;
    value += tex2Dlod(ShaftLight, float4(input.uv, 0.0f, 0.0f)).r * 0.190f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d, 0.0f, 0.0f)).r * 0.180f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d * 2.0f, 0.0f, 0.0f)).r * 0.120f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d * 3.0f, 0.0f, 0.0f)).r * 0.070f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d * 4.0f, 0.0f, 0.0f)).r * 0.035f;
    return float4(saturate(value), 0.0f, 0.0f, 1.0f);
}
