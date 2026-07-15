sampler2D SourceTexture : register(s0);

float4 EffectData : register(c9);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float4 Main(PixelInput input) : COLOR0 {
    float2 texel = EffectData.xy;
    float4 color = tex2D(SourceTexture, input.uv + float2( texel.x,  texel.y));
    color += tex2D(SourceTexture, input.uv + float2(-texel.x,  texel.y));
    color += tex2D(SourceTexture, input.uv + float2( texel.x, -texel.y));
    color += tex2D(SourceTexture, input.uv + float2(-texel.x, -texel.y));
    return color * 0.25f;
}
