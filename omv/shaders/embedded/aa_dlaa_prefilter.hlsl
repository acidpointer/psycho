// Directionally Localized Anti-Aliasing adapted from GShade DLAA.fx.
// Source is licensed under CC BY 3.0. See THIRD_PARTY_NOTICES.md.

sampler2D SceneColor : register(s0);
float4 ScreenData : register(c0);

float Luma(float3 color) {
    return dot(color, float3(0.2126, 0.7152, 0.0722));
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float2 t = ScreenData.zw;
    float4 center = tex2D(SceneColor, uv);
    float4 left = tex2D(SceneColor, uv + float2(-t.x, 0.0));
    float4 right = tex2D(SceneColor, uv + float2(t.x, 0.0));
    float4 top = tex2D(SceneColor, uv + float2(0.0, -t.y));
    float4 bottom = tex2D(SceneColor, uv + float2(0.0, t.y));
    float4 edges = 4.0 * abs((left + right + top + bottom) - 4.0 * center);
    return float4(center.rgb, Luma(edges.rgb));
}
