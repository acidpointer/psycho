sampler2D FirstPersonDepth : register(s2);
sampler2D BloomTexture : register(s4);
sampler2D ColorLut : register(s5);
#ifndef OMV_TONE_VARIANT
#define OMV_TONE_VARIANT 0
#endif
#if OMV_TONE_VARIANT == 2
sampler2D AdaptiveToneResponse : register(s7);
#endif

// Compose's existing c9 slot carries the declared LUT upper domain. Extraction
// and blur retain their own c9 payloads; constants are bound per pass.
float4 LutDomainMax : register(c9);
// x defers display noise to optics; y admits masked first-person spatial AA.
float4 ComposePassData : register(c20);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 GradeData1 : register(c11);
float4 GradeData3 : register(c13);
float4 LutDomainScale : register(c17);
float4 LutDomainBias : register(c18);
// Fixed: x = contrast amount, y = shoulder reserve, w = toe curvature.
// Adaptive: x/y = response UV scale/bias. z = inverse response width.
float4 AdaptiveToneData : register(c19);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 WarmTint = float3(1.08f, 1.02f, 0.90f);
static const float3 CoolTint = float3(0.94f, 0.99f, 1.08f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

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

float3 DebandScene(float2 uv, float3 center, float3 originalCenter, out float flatWeight) {
    float2 texel = ScreenData.zw;
    float strength = GradeData2.z * GradeData0.x;
    float2 offset = texel * 6.0f;
    float3 left = SampleScene(uv - float2(offset.x, 0.0f)).rgb;
    float3 right = SampleScene(uv + float2(offset.x, 0.0f)).rgb;
    float3 up = SampleScene(uv - float2(0.0f, offset.y)).rgb;
    float3 down = SampleScene(uv + float2(0.0f, offset.y)).rgb;
    // Classify the original input so deferred dither uses the same flatness
    // gate after channel displacement. First-person AA changes only the value
    // being filtered, not the classifier or the source alpha.
    float3 average = (originalCenter + left + right + up + down) * 0.2f;
    float3 delta = max(max(abs(left - right), abs(up - down)), abs(originalCenter - average));
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
    float3 mapped = lerp(low, high, position.b - blue0);
#if OMV_TONE_VARIANT != 0
    // A display-domain LUT cannot classify over-white radiance. Preserve that
    // excess as a unit-slope residual instead of flattening it at the boundary.
    // In-domain samples and external LUT domains retain their existing meaning.
    mapped += max(color - LutDomainMax.xyz, 0.0f);
#endif
    return mapped;
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

    // Positive contrast must not create a negative intercept which later
    // clamps multiple shadow texels to black. Fade its affine displacement
    // toward zero at black; midpoint/highlight response and saved negative
    // contrast keep their existing equations. Black fade remains explicit.
    float3 contrastWeight = GradeData0.z > 0.0f ? saturate(color * 2.0f) : 1.0f;
    color += (color - 0.5f.xxx) * GradeData0.z * contrastWeight;
    float luma = Luma(color);
    float chromaRange = max(color.r, max(color.g, color.b)) - min(color.r, min(color.g, color.b));
    float adaptiveVibrance = 1.0f + GradeData1.x * (1.0f - saturate(chromaRange));
    float saturation = GradeData0.w * adaptiveVibrance;
    color = luma.xxx + (color - luma.xxx) * saturation;

    float blackFade = GradeData1.w * 0.06f;
    color = blackFade.xxx + color * (1.0f - blackFade);
    float shoulder = GradeData2.x * 0.65f;
#if OMV_TONE_VARIANT == 0
    color = saturate(color);
#else
    // The final display shoulder owns positive headroom. Only negative values
    // generated by creative contrast/saturation are outside its input domain.
    color = max(color, 0.0f);
#endif
    color = color * (1.0f + shoulder) / (1.0f + shoulder * color);

    return lerp(inputColor, color, master);
}

#if OMV_TONE_VARIANT == 1
float3 ApplyAdaptiveDisplayMapping(float3 inputColor) {
    float peak = max(inputColor.r, max(inputColor.g, inputColor.b));
    // Mapping the brightest channel bounds every channel smoothly with one
    // shared scale. Luminance mapping followed by a hard peak cap collapsed
    // different bright blue/sunset levels to the same RGB triplet.
    float responseScale = DisplayToneScale(peak, AdaptiveToneData.x, AdaptiveToneData.y, AdaptiveToneData.w);
    return inputColor * responseScale;
}
#elif OMV_TONE_VARIANT == 2
float3 ApplyAdaptiveDisplayMapping(float3 inputColor) {
    float peak = max(inputColor.r, max(inputColor.g, inputColor.b));
    // Compact the entire positive input domain; texel centers include black
    // and the white asymptote. No hard table endpoint or per-pixel tail pass.
    float responseUv = rcp(1.0f + peak) * AdaptiveToneData.x + AdaptiveToneData.y;
    // The response has one row and clamp addressing on both axes. Reusing U
    // for V samples that same row without constructing another coordinate.
    float headroom = tex2D(AdaptiveToneResponse, responseUv.xx).r;
    float mappedPeak = 1.0f - headroom;
    return inputColor * (mappedPeak / max(peak, 0.00001f));
}
#endif

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
    // Both silhouette sides need filtering. Reuse bloom's existing one-pixel
    // coverage footprint instead of adding a mask pass or more depth samples.
    // Pixels beyond that footprint retain world TAA; missing coverage is inert.
    bool touchesFirstPerson = false;
    if (ComposePassData.y > 0.5f || max(GradeData4.y, GradeData6.y) > 0.5f) {
        touchesFirstPerson = TouchesFirstPerson(input.uv);
    }
    if (ComposePassData.y > 0.5f && touchesFirstPerson) {
        base = ResolveFxaa(input.uv, base, float4(0.08f, 0.25f, 3.0f, 0.75f));
    }
    float debandFlatWeight = 0.0f;
    if (GradeData4.x > 0.5f && GradeData5.z > 0.5f && GradeData2.z > 0.00001f) {
        base = DebandScene(input.uv, base, baseSample.rgb, debandFlatWeight);
    }

    float3 highlightBlur = 0.0f;
    if (max(GradeData4.y, GradeData6.y) > 0.5f) {
        float exposure = exp2(clamp(OptionData1.x, -0.5f, 0.5f));
        highlightBlur = ApplySaturation(SampleBloom(input.uv), OptionData1.z);
        highlightBlur = ApplyWarmth(highlightBlur) * exposure;
        if (touchesFirstPerson) {
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
        if (GradeData3.z > 0.5f) {
            color = input.uv.x < 0.5f ? ungraded : color;
        }
    }

#if OMV_TONE_VARIANT != 0
    // Tone mapping is the final deterministic display transform. Running it
    // before grading, LUT, halation, or vignette allowed those operations to
    // recreate values above white which the output clamp then erased. Grain
    // and dither remain later because they are display noise, not scene color.
    color = ApplyAdaptiveDisplayMapping(color);
#endif

    // The optical writer emits noise when compose feeds channel displacement.
    if (ComposePassData.x < 0.5f) {
        color = ApplyOutputNoise(color, input.uv, debandFlatWeight);
    }
    return float4(saturate(color), baseSample.a);
}
