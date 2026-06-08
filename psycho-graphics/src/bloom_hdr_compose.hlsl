sampler2D SceneColor : register(s0);
sampler2D FirstPersonDepth : register(s2);
sampler2D BloomTexture : register(s4);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 LumaFactors = float3(0.2126f, 0.7152f, 0.0722f);
static const float3 WarmTint = float3(1.08f, 1.02f, 0.90f);
static const float3 CoolTint = float3(0.94f, 0.99f, 1.08f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Luma(float3 color) {
    return dot(color, LumaFactors);
}

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float3 SampleColor(float2 uv) {
    return tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f)).rgb;
}

float3 SampleBloom(float2 uv) {
    return tex2Dlod(BloomTexture, float4(uv, 0.0f, 0.0f)).rgb;
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
        IsFirstPersonPixel(uv + float2( texel.x, 0.0f)) ||
        IsFirstPersonPixel(uv + float2(-texel.x, 0.0f)) ||
        IsFirstPersonPixel(uv + float2(0.0f,  texel.y)) ||
        IsFirstPersonPixel(uv + float2(0.0f, -texel.y));
}

float3 ApplySaturation(float3 color, float amount) {
    float luma = Luma(color);
    return lerp(float3(luma, luma, luma), color, max(amount, 0.0f));
}

float3 ApplyWarmth(float3 color) {
    float warmth = clamp(OptionData1.w, -1.0f, 1.0f);
    float3 tint = warmth >= 0.0f
        ? lerp(float3(1.0f, 1.0f, 1.0f), WarmTint, warmth)
        : lerp(float3(1.0f, 1.0f, 1.0f), CoolTint, -warmth);
    return color * tint;
}

float3 AcesApprox(float3 color) {
    color = max(color, 0.0f);
    return saturate((color * (2.51f * color + 0.03f)) / (color * (2.43f * color + 0.59f) + 0.14f));
}

float GoldenNoise(float2 uv, float frameIndex) {
    float2 pixel = uv * ScreenData.xy;
    float seed = dot(pixel, float2(0.06711056f, 0.00583715f)) + frameIndex * 0.000731f;
    return frac(52.9829189f * frac(seed));
}

float4 Main(PixelInput input) : COLOR0 {
    float3 base = SampleColor(input.uv);
    float3 bloom = ApplyWarmth(SampleBloom(input.uv));

    if (OptionData2.z > 0.5f) {
        return float4(saturate(bloom * 4.0f), 1.0f);
    }

    if (TouchesFirstPerson(input.uv)) {
        bloom *= 0.28f;
    }

    float exposure = exp2(clamp(OptionData1.x, -0.5f, 0.5f));
    float3 color = max(base * exposure, 0.0f);
    float luma = Luma(color);

    float shadowMask = 1.0f - Smooth01((luma - 0.05f) / 0.50f);
    float atmosphere = saturate(OptionData2.w);
    color += (1.0f - color) * shadowMask * saturate(OptionData2.x) * (0.075f + atmosphere * 0.045f);

    float3 bloomContribution = bloom * max(OptionData0.x, 0.0f);
    float shoulder = saturate(OptionData1.y);
    float3 additive = color + bloomContribution * (1.0f - color * (0.25f + shoulder * 0.55f));
    float3 screen = 1.0f - (1.0f - saturate(color)) * (1.0f - saturate(bloomContribution));
    color = lerp(additive, screen, shoulder * 0.70f);

    float3 toneMapped = AcesApprox(color * (1.0f + atmosphere * 0.08f));
    color = lerp(color, toneMapped, shoulder * 0.48f);
    color = ApplySaturation(color, OptionData1.z);
    color = ApplyWarmth(color);

    float noise = (GoldenNoise(input.uv, FrameData.x) - 0.5f) * saturate(OptionData2.y) / 255.0f;
    return float4(saturate(color + noise), 1.0f);
}
