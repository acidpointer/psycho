sampler2D SceneColor : register(s0);
sampler2D FirstPersonDepth : register(s2);
sampler2D BloomTexture : register(s4);
sampler2D ColorLut : register(s5);
sampler2D FilmGrainTexture : register(s6);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 GradeData0 : register(c10);
float4 GradeData1 : register(c11);
float4 GradeData2 : register(c12);
float4 GradeData3 : register(c13);
float4 GradeData4 : register(c14);
float4 GradeData5 : register(c15);
float4 GradeData6 : register(c16);
float4 LutDomainScale : register(c17);
float4 LutDomainBias : register(c18);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 LumaFactors = float3(0.2126f, 0.7152f, 0.0722f);
static const float3 WarmTint = float3(1.08f, 1.02f, 0.90f);
static const float3 CoolTint = float3(0.94f, 0.99f, 1.08f);
static const float DebandDitherNoiseScaleCodes = 4.0f;
static const float FilmGrainTextureSize = 512.0f;

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

float4 SampleScene(float2 uv) {
    return tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f));
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

float3 DebandScene(float2 uv, float3 center, out float flatWeight) {
    float2 texel = ScreenData.zw;
    float strength = GradeData2.z * GradeData0.x;
    float2 offset = texel * 6.0f;
    float3 left = SampleScene(uv - float2(offset.x, 0.0f)).rgb;
    float3 right = SampleScene(uv + float2(offset.x, 0.0f)).rgb;
    float3 up = SampleScene(uv - float2(0.0f, offset.y)).rgb;
    float3 down = SampleScene(uv + float2(0.0f, offset.y)).rgb;
    float3 average = (center + left + right + up + down) * 0.2f;
    float3 delta = max(max(abs(left - right), abs(up - down)), abs(center - average));
    float edge = max(delta.r, max(delta.g, delta.b));
    flatWeight = 1.0f - Smooth01(edge * 42.5f);
    return lerp(center, average, strength * flatWeight * 0.85f);
}

float3 SampleColorLut(float3 color) {
    float size = LutDomainScale.w;
    float3 domainColor = saturate(color * LutDomainScale.xyz + LutDomainBias.xyz);
    float3 position = domainColor * (size - 1.0f);
    float blue0 = floor(position.b);
    float blue1 = min(blue0 + 1.0f, size - 1.0f);
    float2 dimensions = float2(size * size, size);
    float2 uv0 = float2(blue0 * size + position.r + 0.5f, position.g + 0.5f) / dimensions;
    float2 uv1 = float2(blue1 * size + position.r + 0.5f, position.g + 0.5f) / dimensions;
    float3 low = tex2Dlod(ColorLut, float4(uv0, 0.0f, 0.0f)).rgb;
    float3 high = tex2Dlod(ColorLut, float4(uv1, 0.0f, 0.0f)).rgb;
    return lerp(low, high, position.b - blue0);
}

float3 ApplyAnalyticGrade(float3 inputColor) {
    float master = GradeData0.x;
    float3 color = inputColor * exp2(GradeData0.y);

    float temperature = GradeData1.y;
    float tint = GradeData1.z;
    float3 whiteBalance = float3(
        1.0f + temperature * 0.10f + tint * 0.025f,
        1.0f - tint * 0.055f,
        1.0f - temperature * 0.10f + tint * 0.025f
    );
    color *= whiteBalance;

    color = 0.5f.xxx + (color - 0.5f.xxx) * (1.0f + GradeData0.z);
    float luma = Luma(color);
    float chromaRange = max(color.r, max(color.g, color.b)) - min(color.r, min(color.g, color.b));
    float adaptiveVibrance = 1.0f + GradeData1.x * (1.0f - saturate(chromaRange));
    float saturation = GradeData0.w * adaptiveVibrance;
    color = luma.xxx + (color - luma.xxx) * saturation;

    float blackFade = GradeData1.w * 0.06f;
    color = blackFade.xxx + color * (1.0f - blackFade);
    float shoulder = GradeData2.x * 0.65f;
    color = saturate(color);
    color = color * (1.0f + shoulder) / (1.0f + shoulder * color);

    return lerp(inputColor, color, master);
}

float3 ApplyFinishing(float3 inputColor, float3 halationBlur, float2 uv) {
    float master = GradeData0.x;
    float3 color = inputColor;
    if (GradeData5.x > 0.5f) {
        color = ApplyAnalyticGrade(color);
    }
    if (GradeData5.y > 0.5f) {
        float3 lutColor = SampleColorLut(color);
        color = lerp(color, lutColor, GradeData2.y * master);
    }
    if (GradeData6.y > 0.5f) {
        color += halationBlur * float3(1.0f, 0.28f, 0.10f)
            * GradeData3.y * master * 0.85f;
    }

    if (GradeData6.x > 0.5f) {
        float2 centered = uv * 2.0f - 1.0f;
        centered.x *= ScreenData.x / max(ScreenData.y, 1.0f);
        float vignette = Smooth01(dot(centered, centered) * 0.42f);
        color *= 1.0f - vignette * GradeData3.x * master * 0.32f;
    }
    return color;
}

float3 ComposeBloom(float3 base, float3 bloomContribution, float shoulder) {
    float3 additive = base + bloomContribution * (1.0f - base * (0.25f + shoulder * 0.55f));
    float3 screen = 1.0f - (1.0f - saturate(base)) * (1.0f - saturate(bloomContribution));
    return lerp(additive, screen, shoulder * 0.70f);
}

float4 Main(PixelInput input) : COLOR0 {
    float4 baseSample = SampleScene(input.uv);
    float3 base = baseSample.rgb;
    float debandFlatWeight = 0.0f;
    if (GradeData4.x > 0.5f && GradeData5.z > 0.5f && GradeData2.z > 0.00001f) {
        base = DebandScene(input.uv, base, debandFlatWeight);
    }

    float3 highlightBlur = 0.0f;
    if (max(GradeData4.y, GradeData6.y) > 0.5f) {
        float exposure = exp2(clamp(OptionData1.x, -0.5f, 0.5f));
        highlightBlur = ApplySaturation(SampleBloom(input.uv), OptionData1.z);
        highlightBlur = ApplyWarmth(highlightBlur) * exposure;
        if (TouchesFirstPerson(input.uv)) {
            highlightBlur *= 0.28f;
        }
    }

    float3 bloom = 0.0f;
    if (GradeData4.y > 0.5f) {
        bloom = highlightBlur;
        if (OptionData2.z > 0.5f) {
            return float4(saturate(bloom * 4.0f), baseSample.a);
        }
    }

    float bloomLift = 1.0f + OptionData2.x * 0.25f;
    float3 bloomContribution = bloom * max(OptionData0.x, 0.0f) * bloomLift;
    float shoulder = OptionData1.y;
    float3 ungraded = ComposeBloom(base, bloomContribution, shoulder);
    float3 color = ungraded;

    if (GradeData4.x > 0.5f) {
        color = ApplyFinishing(color, highlightBlur, input.uv);
        if (GradeData5.w > 0.5f) {
            float grainResponse = 1.0f - sqrt(saturate(Luma(color)));
            float grain = FilmGrainNoise(input.uv, FrameData.x)
                * GradeData2.w * GradeData0.x * grainResponse;
            color += color * grain;
        }
        if (GradeData3.z > 0.5f) {
            color = input.uv.x < 0.5f ? ungraded : color;
        }
    }

    float ditherStrength = max(
        GradeData4.y > 0.5f ? OptionData2.y : 0.0f,
        GradeData4.x > 0.5f && GradeData5.z > 0.5f
            ? GradeData2.z * GradeData0.x * debandFlatWeight * DebandDitherNoiseScaleCodes
            : 0.0f
    );
    float noise = (GoldenNoise(input.uv, FrameData.x) - 0.5f) * ditherStrength / 255.0f;
    return float4(saturate(color + noise), baseSample.a);
}
