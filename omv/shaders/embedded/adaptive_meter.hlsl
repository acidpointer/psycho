// Bounded spatial integration for display adaptation. The first pass covers
// a stratified 64x64 source grid, averaging 4x4 samples into each 16x16 tile.
// Log luminance is computed BEFORE averaging. The second pass reduces tiles
// once to 1x1; response generation never repeats nonlinear scene metering.
// RG = weighted log-luminance sum and weight (normalized together), B = peak.
// All resources are FP16, sampled at explicit LOD zero with clamp addressing.
#ifndef OMV_METER_REDUCE
#define OMV_METER_REDUCE 0
#endif
sampler2D SceneColor : register(s0);
sampler2D PreviousResponse : register(s1);
sampler2D BloomTexture : register(s4);
float4 AdaptData0 : register(c0);
float4 AdaptData1 : register(c1);
float4 AdaptData2 : register(c2);
float4 AdaptData3 : register(c3);
static const float3 LumaFactors = float3(0.2126f, 0.7152f, 0.0722f);
struct PixelInput { float2 uv : TEXCOORD0; };

float4 Main(PixelInput input) : COLOR0 {
    float2 sums = 0.0f;
    float peak = 0.0f;
#if OMV_METER_REDUCE
    [loop] for (int y = 0; y < 16; ++y) {
        [loop] for (int x = 0; x < 16; ++x) {
            float2 uv = (float2(x, y) + 0.5f) / 16.0f;
            float3 tile = tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f)).rgb;
            sums += tile.rg;
            peak = max(peak, tile.b);
        }
    }
    return float4(sums / 256.0f, peak, 0.0f);
#else
    float4 previous = tex2Dlod(PreviousResponse, float4(0.5f, 0.5f, 0.0f, 0.0f));
    bool validHistory = AdaptData0.w > 0.5f && previous.g <= 0.5f;
    float fine = tex2Dlod(PreviousResponse, float4(1.5f * AdaptData1.w, 0.5f, 0.0f, 0.0f)).g;
    previous.g += validHistory ? fine : 0.0f;
    float2 tile = floor(input.uv * 16.0f);
    [loop] for (int y = 0; y < 4; ++y) {
        [loop] for (int x = 0; x < 4; ++x) {
            float2 uv = (tile * 4.0f + float2(x, y) + 0.5f) / 64.0f;
            float3 scene = tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f)).rgb;
            // Reject invalid external color before logs or accumulation.
            bool finite = all(scene >= 0.0f) && all(scene < 65504.0f);
            scene = finite ? scene : 0.0f;
            float luminance = saturate(dot(scene, LumaFactors));
            float2 center = uv * 2.0f - 1.0f;
            float spatial = lerp(1.0f, 0.40f, saturate(dot(center, center) * 0.5f));
            float black = saturate((luminance - 1.0f / 255.0f) * 85.0f);
            float weight = black * black * (3.0f - 2.0f * black) * spatial;
            float logLuma = log2(max(luminance, 1.0f / 1024.0f));
            if (validHistory) {
                logLuma = clamp(logLuma, previous.g - 2.5f, previous.g + 2.5f);
            }
            sums += float2(logLuma * weight, weight);
            float3 combined = scene;
            if (AdaptData2.y > 0.5f) {
                float3 bloom = tex2Dlod(BloomTexture, float4(uv, 0.0f, 0.0f)).rgb;
                bloom = all(bloom >= 0.0f) && all(bloom < 65504.0f) ? bloom : 0.0f;
                bloom = lerp(dot(bloom, LumaFactors).xxx, bloom, AdaptData3.y);
                float3 tint = AdaptData3.z >= 0.0f
                    ? lerp(1.0f.xxx, float3(1.08f, 1.02f, 0.90f), AdaptData3.z)
                    : lerp(1.0f.xxx, float3(0.94f, 0.99f, 1.08f), -AdaptData3.z);
                bloom *= tint * exp2(AdaptData2.w) * AdaptData2.z * (1.0f + AdaptData3.w * 0.25f);
                float shoulder = AdaptData3.x;
                float3 additive = scene + bloom * (1.0f - scene * (0.25f + shoulder * 0.55f));
                float3 screen = 1.0f - (1.0f - saturate(scene)) * (1.0f - saturate(bloom));
                combined = lerp(additive, screen, shoulder * 0.70f);
            }
            peak = max(peak, max(combined.r, max(combined.g, combined.b)));
        }
    }
    return float4(sums / 16.0f, peak, 0.0f);
#endif
}
