// Preserve raw native depth. Point sampling and texel centers are set by the
// D3D9 snapshot owner; R32F stores the original depth convention unchanged.
sampler2D SourceDepth : register(s0);

float4 Main(float2 uv : TEXCOORD0) : COLOR0
{
    return tex2D(SourceDepth, uv).rrrr;
}
