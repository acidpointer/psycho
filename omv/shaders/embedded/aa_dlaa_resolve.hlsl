// Directionally Localized Anti-Aliasing adapted from GShade DLAA.fx.
// Source is licensed under CC BY 3.0. See THIRD_PARTY_NOTICES.md.

sampler2D Prefilter : register(s0);
float4 ScreenData : register(c0);
float4 Options : register(c3);

float Luma(float3 color) {
    return dot(color.ggg, float3(0.333333, 0.333333, 0.333333));
}

float SafeDenominator(float value) {
    return abs(value) >= 0.0001 ? value : (value < 0.0 ? -0.0001 : 0.0001);
}

float4 SampleOffset(float2 uv, float x, float y) {
    return tex2D(Prefilter, uv + float2(x, y) * ScreenData.zw);
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float4 center = SampleOffset(uv, 0.0, 0.0);
    float4 left = SampleOffset(uv, -1.0, 0.0);
    float4 right = SampleOffset(uv, 1.0, 0.0);
    float4 up = SampleOffset(uv, 0.0, -1.0);
    float4 down = SampleOffset(uv, 0.0, 1.0);

    float4 combinedHorizontal = 2.0 * (left + right);
    float4 combinedVertical = 2.0 * (up + down);
    float4 centerDifferenceHorizontal = abs(combinedHorizontal - 4.0 * center) * 0.25;
    float4 centerDifferenceVertical = abs(combinedVertical - 4.0 * center) * 0.25;
    float4 blurredHorizontal = (combinedHorizontal + 2.0 * center) / 6.0;
    float4 blurredVertical = (combinedVertical + 2.0 * center) / 6.0;
    float lumaHorizontal = Luma(centerDifferenceHorizontal.rgb);
    float lumaVertical = Luma(centerDifferenceVertical.rgb);
    float shortHorizontal = saturate((3.0 * lumaHorizontal - 0.1) / max(Luma(blurredVertical.rgb), 0.0001));
    float shortVertical = saturate((3.0 * lumaVertical - 0.1) / max(Luma(blurredHorizontal.rgb), 0.0001));
    float4 result = lerp(center, blurredHorizontal, shortVertical);
    result = lerp(result, blurredVertical, shortHorizontal * 0.5);

    float4 averageHorizontal = (
        left + SampleOffset(uv, -3.5, 0.0) + SampleOffset(uv, -5.5, 0.0) + SampleOffset(uv, -7.5, 0.0) +
        right + SampleOffset(uv, 3.5, 0.0) + SampleOffset(uv, 5.5, 0.0) + SampleOffset(uv, 7.5, 0.0)
    ) * 0.125;
    float4 averageVertical = (
        up + SampleOffset(uv, 0.0, -3.5) + SampleOffset(uv, 0.0, -5.5) + SampleOffset(uv, 0.0, -7.5) +
        down + SampleOffset(uv, 0.0, 3.5) + SampleOffset(uv, 0.0, 5.5) + SampleOffset(uv, 0.0, 7.5)
    ) * 0.125;
    float edgeHorizontal = saturate(averageHorizontal.a * 2.0 - 1.0);
    float edgeVertical = saturate(averageVertical.a * 2.0 - 1.0);
    float mask = abs(edgeHorizontal - edgeVertical) + abs(lumaHorizontal + lumaVertical) > 0.2 ? 1.0 : 0.0;

    if (mask > 0.5) {
        float centerLuma = Luma(center.rgb);
        float blurUp = saturate((Luma(averageHorizontal.rgb) - Luma(up.rgb)) /
                                SafeDenominator(centerLuma - Luma(up.rgb)));
        float blurLeft = saturate((Luma(averageVertical.rgb) - Luma(left.rgb)) /
                                  SafeDenominator(centerLuma - Luma(left.rgb)));
        float blurDown = saturate(1.0 + (Luma(averageHorizontal.rgb) - centerLuma) /
                                  SafeDenominator(centerLuma - Luma(down.rgb)));
        float blurRight = saturate(1.0 + (Luma(averageVertical.rgb) - centerLuma) /
                                   SafeDenominator(centerLuma - Luma(right.rgb)));
        float4 vertical = lerp(left, center, blurLeft);
        vertical = lerp(right, vertical, blurRight);
        float4 horizontal = lerp(up, center, blurUp);
        horizontal = lerp(down, horizontal, blurDown);
        result = lerp(result, vertical, edgeVertical);
        result = lerp(result, horizontal, edgeHorizontal);
    }

    if (Options.x > 1.5) {
        return lerp(result, float4(1.0, 1.0, 0.0, 1.0), saturate(mask * 2.0));
    }
    if (Options.x > 0.5) {
        return (mask * 2.0).xxxx;
    }
    return float4(result.rgb, 1.0);
}
