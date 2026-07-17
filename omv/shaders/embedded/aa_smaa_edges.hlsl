// SMAA 1x edge pass adapted from the MIT-licensed SMAA reference implementation.
// See THIRD_PARTY_NOTICES.md.

sampler2D SceneColor : register(s0);
float4 ScreenData : register(c0);
float4 Options0 : register(c3);

float Luma(float3 color) {
    return dot(color, float3(0.299, 0.587, 0.114));
}

float Delta(float3 a, float3 b) {
    return Options0.x < 0.5 ? abs(Luma(a) - Luma(b)) : max(max(abs(a.r - b.r), abs(a.g - b.g)), abs(a.b - b.b));
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float2 t = ScreenData.zw;
    float3 c = tex2D(SceneColor, uv).rgb;
    float3 left = tex2D(SceneColor, uv + float2(-t.x, 0.0)).rgb;
    float3 top = tex2D(SceneColor, uv + float2(0.0, -t.y)).rgb;
    float2 edges = step(Options0.y, float2(Delta(c, left), Delta(c, top)));
    if (dot(edges, float2(1.0, 1.0)) == 0.0) {
        return 0.0;
    }
    float3 right2 = tex2D(SceneColor, uv + float2(2.0 * t.x, 0.0)).rgb;
    float3 bottom2 = tex2D(SceneColor, uv + float2(0.0, 2.0 * t.y)).rgb;
    float localContrast = max(max(Delta(c, left), Delta(c, top)), max(Delta(c, right2), Delta(c, bottom2)));
    edges *= step(localContrast * 0.5, float2(Delta(c, left), Delta(c, top)));
    return float4(edges, 0.0, 1.0);
}
