// SMAA 1x neighborhood blend pass adapted from the MIT-licensed SMAA reference implementation.

sampler2D SceneColor : register(s0);
sampler2D Weights : register(s1);
sampler2D Edges : register(s2);
float4 ScreenData : register(c0);
float4 Options1 : register(c4);

float3 SampleColor(float2 uv) {
    return tex2Dlod(SceneColor, float4(uv, 0.0, 0.0)).rgb;
}

float4 SampleWeights(float2 uv) {
    return tex2Dlod(Weights, float4(uv, 0.0, 0.0));
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float2 t = ScreenData.zw;
    float4 weights = SampleWeights(uv);
    if (Options1.y > 1.5) {
        return float4(weights.rgb, 1.0);
    }
    if (Options1.y > 0.5) {
        return float4(tex2Dlod(Edges, float4(uv, 0.0, 0.0)).rg, 0.0, 1.0);
    }

    float left = weights.r + weights.g;
    float top = weights.b + weights.a;
    float right = dot(SampleWeights(uv + float2(t.x, 0.0)).rg, 1.0);
    float bottom = dot(SampleWeights(uv + float2(0.0, t.y)).ba, 1.0);
    float total = left + right + top + bottom;
    float3 center = SampleColor(uv);
    if (total < 0.0001) {
        return float4(center, 1.0);
    }

    float3 neighborhood = center;
    neighborhood += SampleColor(uv + float2(-t.x, 0.0)) * left;
    neighborhood += SampleColor(uv + float2(t.x, 0.0)) * right;
    neighborhood += SampleColor(uv + float2(0.0, -t.y)) * top;
    neighborhood += SampleColor(uv + float2(0.0, t.y)) * bottom;
    neighborhood /= 1.0 + total;
    return float4(lerp(center, neighborhood, saturate(total * 0.5)), 1.0);
}
