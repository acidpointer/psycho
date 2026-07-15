sampler2D CocTexture : register(s0);

float4 EffectData : register(c9);
float4 FilterData : register(c10);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float NearCoc(float2 uv) {
    float value = tex2Dlod(CocTexture, float4(saturate(uv), 0.0f, 0.0f)).r;
    return EffectData.z < 0.5f ? saturate(-value) : saturate(value);
}

void Gather(float2 uv, float attenuation, inout float nearCoc) {
    nearCoc = max(nearCoc, NearCoc(uv) * attenuation);
}

float4 Main(PixelInput input) : COLOR0 {
    float2 direction = EffectData.xy;
    float2 perpendicular = FilterData.xy;
    float nearCoc = NearCoc(input.uv);
    Gather(input.uv + perpendicular * 0.5f, 0.99f, nearCoc);
    Gather(input.uv - perpendicular * 0.5f, 0.99f, nearCoc);
    Gather(input.uv + direction * 0.20f, 0.99f, nearCoc);
    Gather(input.uv - direction * 0.20f, 0.99f, nearCoc);
    Gather(input.uv + direction * 0.40f, 0.96f, nearCoc);
    Gather(input.uv - direction * 0.40f, 0.96f, nearCoc);
    Gather(input.uv + direction * 0.60f, 0.91f, nearCoc);
    Gather(input.uv - direction * 0.60f, 0.91f, nearCoc);
    Gather(input.uv + direction * 0.80f, 0.84f, nearCoc);
    Gather(input.uv - direction * 0.80f, 0.84f, nearCoc);
    Gather(input.uv + direction, 0.75f, nearCoc);
    Gather(input.uv - direction, 0.75f, nearCoc);
    return float4(nearCoc, 0.0f, 0.0f, 1.0f);
}
