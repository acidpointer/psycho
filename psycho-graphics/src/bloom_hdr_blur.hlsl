sampler2D BloomInput : register(s0);

float4 ScreenData : register(c0);
float4 OptionData0 : register(c3);
float4 EffectData : register(c9);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float3 SampleBloom(float2 uv) {
    return tex2Dlod(BloomInput, float4(uv, 0.0f, 0.0f)).rgb;
}

float4 Main(PixelInput input) : COLOR0 {
    float radius = clamp(OptionData0.z, 0.5f, 7.0f);
    float2 d = EffectData.xy * radius;

    float3 color = SampleBloom(input.uv) * 0.188f;
    color += SampleBloom(input.uv + d * 1.0f) * 0.168f;
    color += SampleBloom(input.uv - d * 1.0f) * 0.168f;
    color += SampleBloom(input.uv + d * 2.0f) * 0.122f;
    color += SampleBloom(input.uv - d * 2.0f) * 0.122f;
    color += SampleBloom(input.uv + d * 3.0f) * 0.074f;
    color += SampleBloom(input.uv - d * 3.0f) * 0.074f;
    color += SampleBloom(input.uv + d * 4.0f) * 0.042f;
    color += SampleBloom(input.uv - d * 4.0f) * 0.042f;
    return float4(saturate(color), 1.0f);
}
