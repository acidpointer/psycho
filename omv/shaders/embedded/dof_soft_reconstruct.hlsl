sampler2D BaseTexture : register(s0);
sampler2D QuarterTexture : register(s1);
sampler2D EighthTexture : register(s2);

float4 PyramidData : register(c9);
float4 SoftData : register(c10);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float4 SampleQuarter(float2 uv) {
    float2 texel = PyramidData.xy;
    float4 value = tex2D(QuarterTexture, uv) * 4.0f;
    value += tex2D(QuarterTexture, uv + float2( texel.x, 0.0f));
    value += tex2D(QuarterTexture, uv + float2(-texel.x, 0.0f));
    value += tex2D(QuarterTexture, uv + float2(0.0f,  texel.y));
    value += tex2D(QuarterTexture, uv + float2(0.0f, -texel.y));
#if DOF_ULTRA
    value += tex2D(QuarterTexture, uv + float2( texel.x,  texel.y)) * 0.7f;
    value += tex2D(QuarterTexture, uv + float2(-texel.x,  texel.y)) * 0.7f;
    value += tex2D(QuarterTexture, uv + float2( texel.x, -texel.y)) * 0.7f;
    value += tex2D(QuarterTexture, uv + float2(-texel.x, -texel.y)) * 0.7f;
    return value / 10.8f;
#else
    return value * 0.125f;
#endif
}

float4 SampleEighth(float2 uv) {
    float2 texel = PyramidData.zw;
    float4 value = tex2D(EighthTexture, uv) * 4.0f;
    value += tex2D(EighthTexture, uv + float2( texel.x, 0.0f));
    value += tex2D(EighthTexture, uv + float2(-texel.x, 0.0f));
    value += tex2D(EighthTexture, uv + float2(0.0f,  texel.y));
    value += tex2D(EighthTexture, uv + float2(0.0f, -texel.y));
#if DOF_ULTRA
    value += tex2D(EighthTexture, uv + float2( texel.x,  texel.y)) * 0.7f;
    value += tex2D(EighthTexture, uv + float2(-texel.x,  texel.y)) * 0.7f;
    value += tex2D(EighthTexture, uv + float2( texel.x, -texel.y)) * 0.7f;
    value += tex2D(EighthTexture, uv + float2(-texel.x, -texel.y)) * 0.7f;
    return value / 10.8f;
#else
    return value * 0.125f;
#endif
}

float4 Main(PixelInput input) : COLOR0 {
    float softness = saturate(SoftData.z);
    float quarterWeight = 0.35f + smoothstep(0.0f, 1.0f, softness) * 0.47f;
    float4 value = lerp(tex2D(BaseTexture, input.uv), SampleQuarter(input.uv), quarterWeight);
#if DOF_USE_EIGHTH
    float eighthWeight = smoothstep(0.30f, 1.00f, softness) * 0.78f;
    return lerp(value, SampleEighth(input.uv), eighthWeight);
#else
    return value;
#endif
}
