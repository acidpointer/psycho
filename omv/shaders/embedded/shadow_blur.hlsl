// OMV separable EVSM4 prefilter. The renderer enforces distinct source/target identities.
float2 BlurDirection : register(c0);
float2 InverseResolution : register(c1);
float4 SourceScaleBias : register(c2);
sampler2D SourceMap : register(s0);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float4 Main(PixelInput input) : COLOR0 {
    float2 sourceUv = input.uv * SourceScaleBias.xy + SourceScaleBias.zw;
    float2 direction = BlurDirection * InverseResolution;
    float4 color = tex2Dlod(SourceMap, float4(sourceUv, 0.0f, 0.0f)) * 0.2270270270f;
    color += tex2Dlod(SourceMap, float4(sourceUv + direction * 1.3846153846f, 0.0f, 0.0f)) * 0.3162162162f;
    color += tex2Dlod(SourceMap, float4(sourceUv - direction * 1.3846153846f, 0.0f, 0.0f)) * 0.3162162162f;
    color += tex2Dlod(SourceMap, float4(sourceUv + direction * 3.2307692308f, 0.0f, 0.0f)) * 0.0702702703f;
    color += tex2Dlod(SourceMap, float4(sourceUv - direction * 3.2307692308f, 0.0f, 0.0f)) * 0.0702702703f;
    return color;
}
