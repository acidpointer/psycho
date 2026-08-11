// Fill an EVSM render target with the exact moments for fully lit far depth.
float4 FarMoments : register(c0);

float4 Main() : COLOR0 {
    return FarMoments;
}
