sampler2D ShaftLight : register(s0);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 EnvironmentData : register(c6);
float4 OptionData3 : register(c7);
float4 SunData : register(c8);
float4 EffectData : register(c9);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float4 Main(PixelInput input) : COLOR0 {
    float2 d = EffectData.xy;
    float value = 0.0f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d * 4.0f, 0.0f, 0.0f)).r * 0.035f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d * 3.0f, 0.0f, 0.0f)).r * 0.070f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d * 2.0f, 0.0f, 0.0f)).r * 0.120f;
    value += tex2Dlod(ShaftLight, float4(input.uv - d, 0.0f, 0.0f)).r * 0.180f;
    value += tex2Dlod(ShaftLight, float4(input.uv, 0.0f, 0.0f)).r * 0.190f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d, 0.0f, 0.0f)).r * 0.180f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d * 2.0f, 0.0f, 0.0f)).r * 0.120f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d * 3.0f, 0.0f, 0.0f)).r * 0.070f;
    value += tex2Dlod(ShaftLight, float4(input.uv + d * 4.0f, 0.0f, 0.0f)).r * 0.035f;
    return float4(saturate(value), 0.0f, 0.0f, 1.0f);
}
