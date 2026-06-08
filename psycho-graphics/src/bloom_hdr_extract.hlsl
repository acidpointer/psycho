sampler2D SceneColor : register(s0);
sampler2D FirstPersonDepth : register(s2);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 LumaFactors = float3(0.2126f, 0.7152f, 0.0722f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float3 SampleColor(float2 uv) {
    return tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f)).rgb;
}

float Luma(float3 color) {
    return dot(color, LumaFactors);
}

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

bool IsFirstPersonPixel(float2 uv) {
    if (FrameData.w < 0.5f) {
        return false;
    }

    float depth = tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

bool TouchesFirstPerson(float2 uv) {
    float2 texel = ScreenData.zw;
    return
        IsFirstPersonPixel(uv) ||
        IsFirstPersonPixel(uv + float2( texel.x * 1.5f, 0.0f)) ||
        IsFirstPersonPixel(uv + float2(-texel.x * 1.5f, 0.0f)) ||
        IsFirstPersonPixel(uv + float2(0.0f,  texel.y * 1.5f)) ||
        IsFirstPersonPixel(uv + float2(0.0f, -texel.y * 1.5f));
}

float3 BrightExtract(float3 color) {
    float luma = Luma(color);
    float threshold = saturate(OptionData0.y);
    float knee = max(OptionData0.w, 0.001f);
    float bright = Smooth01((luma - threshold + knee) / max(knee * 2.0f, 0.001f));
    float strength = saturate((luma - threshold + knee) / max(1.0f - threshold + knee, 0.001f));
    float3 chroma = lerp(float3(luma, luma, luma), color, 0.72f);
    return chroma * bright * strength;
}

float3 AtmosphereExtract(float3 color) {
    float atmosphere = saturate(OptionData2.w);
    float luma = Luma(color);
    float mid = Smooth01((luma - 0.18f) / 0.62f);
    float antiWhite = 1.0f - Smooth01((luma - 0.92f) / 0.18f);
    return color * mid * antiWhite * atmosphere * 0.18f;
}

float4 Main(PixelInput input) : COLOR0 {
    if (TouchesFirstPerson(input.uv)) {
        return float4(0.0f, 0.0f, 0.0f, 1.0f);
    }

    float2 texel = ScreenData.zw;
    float3 color = SampleColor(input.uv) * 0.36f;
    color += SampleColor(input.uv + float2( texel.x * 1.5f,  texel.y * 1.5f)) * 0.16f;
    color += SampleColor(input.uv + float2(-texel.x * 1.5f,  texel.y * 1.5f)) * 0.16f;
    color += SampleColor(input.uv + float2( texel.x * 1.5f, -texel.y * 1.5f)) * 0.16f;
    color += SampleColor(input.uv + float2(-texel.x * 1.5f, -texel.y * 1.5f)) * 0.16f;

    float3 extracted = BrightExtract(color) + AtmosphereExtract(color);
    return float4(saturate(extracted), 1.0f);
}
