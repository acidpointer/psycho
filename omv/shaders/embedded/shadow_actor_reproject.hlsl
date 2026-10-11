// Convert the shared resolved distribution into each parent depth domain.
// The same affine operation applies to depth*coverage, so MSAA coverage and
// subsequent bilinear filtering keep the original actor comparison contract.
sampler2D SharedActorMoments : register(s0);
float4 DepthConversion : register(c0);
struct PixelInput { float2 uv : TEXCOORD0; };
float4 Main(PixelInput input) : COLOR0 {
    float2 moments = tex2Dlod(SharedActorMoments, float4(input.uv, 0.0f, 0.0f)).rg;
    return float4(moments.x * DepthConversion.x + moments.y * DepthConversion.y, moments.y, 0.0f, 0.0f);
}
