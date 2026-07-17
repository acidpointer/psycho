// OMV Fast FXAA. Embedded version of the former loose OMV runtime effect.

sampler2D SceneColor : register(s0);
float4 ScreenData : register(c0);
float4 Options : register(c3);

float Luma(float3 color) {
    return dot(color, float3(0.299, 0.587, 0.114));
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float2 texel = ScreenData.zw;
    float3 center = tex2D(SceneColor, uv).rgb;
    float3 nw = tex2D(SceneColor, uv + texel * float2(-1.0, -1.0)).rgb;
    float3 ne = tex2D(SceneColor, uv + texel * float2(1.0, -1.0)).rgb;
    float3 sw = tex2D(SceneColor, uv + texel * float2(-1.0, 1.0)).rgb;
    float3 se = tex2D(SceneColor, uv + texel).rgb;
    float lc = Luma(center);
    float lnw = Luma(nw);
    float lne = Luma(ne);
    float lsw = Luma(sw);
    float lse = Luma(se);
    float low = min(lc, min(min(lnw, lne), min(lsw, lse)));
    float high = max(lc, max(max(lnw, lne), max(lsw, lse)));
    if (high - low < max(Options.x, 0.001)) {
        return float4(center, 1.0);
    }

    float2 direction = float2(-((lnw + lne) - (lsw + lse)),
                              (lnw + lsw) - (lne + lse));
    float reduce = max((lnw + lne + lsw + lse) * 0.25 * Options.y, 0.0001);
    direction = clamp(direction / (min(abs(direction.x), abs(direction.y)) + reduce),
                      -Options.z, Options.z) * texel;
    float3 a = 0.5 * (tex2D(SceneColor, uv + direction * (-1.0 / 6.0)).rgb +
                      tex2D(SceneColor, uv + direction * (1.0 / 6.0)).rgb);
    float3 b = a * 0.5 + 0.25 * (tex2D(SceneColor, uv - direction * 0.5).rgb +
                                 tex2D(SceneColor, uv + direction * 0.5).rgb);
    float lb = Luma(b);
    float3 resolved = (lb < low || lb > high) ? a : lerp(center, b, Options.w);
    return float4(resolved, 1.0);
}
