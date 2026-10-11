// Final display noise, shared by compose and the optical output writer.
// Grain is monochrome and multiplicative; dither is zero-centered. The caller
// supplies the pre-grade deband flatness and binds wrapping linear grain s6.
// Apply exactly once, after any RGB channel displacement, preserving alpha.
sampler2D FilmGrainTexture : register(s6);
float4 FrameData : register(c1);
float4 OptionData2 : register(c5);
float4 GradeData0 : register(c10);
float4 GradeData2 : register(c12);
float4 GradeData4 : register(c14);
float4 GradeData5 : register(c15);
float4 GradeData6 : register(c16);

static const float3 LumaFactors = float3(0.2126f, 0.7152f, 0.0722f);
static const float DebandDitherNoiseScaleCodes = 4.0f;
static const float FilmGrainTextureSize = 512.0f;

float Luma(float3 color) { return dot(color, LumaFactors); }
float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}
float GoldenNoisePixel(float2 pixel, float frameIndex) {
    float seed = dot(pixel, float2(0.06711056f, 0.00583715f)) + frameIndex * 0.000731f;
    return frac(52.9829189f * frac(seed));
}
float GoldenNoise(float2 uv, float frameIndex) {
    return GoldenNoisePixel(uv * ScreenData.xy, frameIndex);
}
float FilmGrainNoise(float2 uv, float frameIndex) {
    float2 frameOffset = frac(frameIndex * float2(0.7548777f, 0.5698403f));
    float2 grainUv =
        uv * ScreenData.xy / (GradeData6.w * FilmGrainTextureSize) + frameOffset;
    return tex2Dlod(FilmGrainTexture, float4(grainUv, 0.0f, 0.0f)).r * 2.0f - 1.0f;
}
float3 ApplyOutputNoise(float3 color, float2 uv, float debandFlatWeight) {
    if (GradeData4.x > 0.5f && GradeData5.w > 0.5f) {
        float grainResponse = 1.0f - sqrt(saturate(Luma(color)));
        float grain = FilmGrainNoise(uv, FrameData.x)
            * GradeData2.w * GradeData0.x * grainResponse;
        color += color * grain;
    }
    float ditherStrength = max(
        GradeData4.y > 0.5f ? OptionData2.y : 0.0f,
        GradeData4.x > 0.5f && GradeData5.z > 0.5f
            ? GradeData2.z * GradeData0.x * debandFlatWeight * DebandDitherNoiseScaleCodes
            : 0.0f
    );
    float noise = (GoldenNoise(uv, FrameData.x) - 0.5f) * ditherStrength / 255.0f;
    return saturate(color + noise);
}
