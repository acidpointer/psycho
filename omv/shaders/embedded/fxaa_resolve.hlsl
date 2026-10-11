// Shared Fast FXAA equation. Native display color owns edge detection; callers
// decide coverage and preserve source alpha. No history or depth is consumed.
float FxaaLuma(float3 color) {
    return dot(color, float3(0.299, 0.587, 0.114));
}

float3 ResolveFxaa(float2 uv, float3 center, float4 options) {
    float2 texel = ScreenData.zw;
    float3 nw = SampleScene(uv + texel * float2(-1.0, -1.0)).rgb;
    float3 ne = SampleScene(uv + texel * float2(1.0, -1.0)).rgb;
    float3 sw = SampleScene(uv + texel * float2(-1.0, 1.0)).rgb;
    float3 se = SampleScene(uv + texel).rgb;
    float lc = FxaaLuma(center);
    float lnw = FxaaLuma(nw);
    float lne = FxaaLuma(ne);
    float lsw = FxaaLuma(sw);
    float lse = FxaaLuma(se);
    float low = min(lc, min(min(lnw, lne), min(lsw, lse)));
    float high = max(lc, max(max(lnw, lne), max(lsw, lse)));
    if (high - low < max(options.x, 0.001)) {
        return center;
    }
    float2 direction = float2(-((lnw + lne) - (lsw + lse)),
                              (lnw + lsw) - (lne + lse));
    float reduce = max((lnw + lne + lsw + lse) * 0.25 * options.y, 0.0001);
    direction = clamp(direction / (min(abs(direction.x), abs(direction.y)) + reduce),
                      -options.z, options.z) * texel;
    float3 a = 0.5 * (SampleScene(uv + direction * (-1.0 / 6.0)).rgb +
                     SampleScene(uv + direction * (1.0 / 6.0)).rgb);
    float3 b = a * 0.5 + 0.25 * (SampleScene(uv - direction * 0.5).rgb +
                                 SampleScene(uv + direction * 0.5).rgb);
    float lb = FxaaLuma(b);
    return (lb < low || lb > high) ? a : lerp(center, b, options.w);
}
