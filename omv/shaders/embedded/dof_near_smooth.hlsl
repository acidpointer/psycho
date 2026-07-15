sampler2D FullCoc : register(s0);
sampler2D ExpandedTileMask : register(s1);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float NearCoc(float2 uv) {
    return saturate(-tex2Dlod(FullCoc, float4(saturate(uv), 0.0f, 0.0f)).r);
}

float4 Main(PixelInput input) : COLOR0 {
    float nearCoc = NearCoc(input.uv);
    float expanded = tex2D(ExpandedTileMask, input.uv).r;
    return float4(max(nearCoc, expanded), 0.0f, 0.0f, 1.0f);
}
