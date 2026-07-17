// Normal Filter Anti-Aliasing adapted for OMV from GShade NFAA.fx.
// Source is licensed under CC BY 3.0. See THIRD_PARTY_NOTICES.md.

sampler2D SceneColor : register(s0);
float4 ScreenData : register(c0);
float4 Options : register(c3);

float Luma(float3 color) {
    return dot(color, float3(0.333333, 0.333333, 0.333333));
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float2 texel = ScreenData.zw;
    float top = Luma(tex2D(SceneColor, uv + float2(0.0, -texel.y)).rgb);
    float bottom = Luma(tex2D(SceneColor, uv + float2(0.0, texel.y)).rgb);
    float left = Luma(tex2D(SceneColor, uv + float2(-texel.x, 0.0)).rgb);
    float right = Luma(tex2D(SceneColor, uv + float2(texel.x, 0.0)).rgb);
    float2 normal = float2(top - bottom, -(right - left));
    float normalLength = length(normal);

    if (Options.z > 1.5) {
        return float4(-float2(-(right - left), -(top - bottom)) * 0.5 + 0.5, 1.0, 1.0);
    }
    float mask = normalLength * (2.5 * max(Options.y, 0.0));
    mask = mask > 0.025 ? 1.0 - mask : 1.0;
    mask = saturate(lerp(mask, 1.0, -1.0));
    if (Options.z > 0.5) {
        return float4(mask.xxx, 1.0);
    }

    float4 original = tex2D(SceneColor, uv);
    float threshold = rcp(max(Options.x, 1.0));
    if (normalLength < threshold) {
        return original;
    }

    normal *= texel / max(normalLength * 0.5, 0.0001);
    float4 filtered = original;
    filtered += tex2D(SceneColor, uv + float2(normal.x, -normal.y) * 0.5) * 0.9;
    filtered += tex2D(SceneColor, uv - float2(normal.x, -normal.y) * 0.5) * 0.9;
    filtered += tex2D(SceneColor, uv + normal * 0.9) * 0.75;
    filtered += tex2D(SceneColor, uv - normal * 0.9) * 0.75;
    filtered /= 4.3;
    return lerp(filtered, original, mask);
}
