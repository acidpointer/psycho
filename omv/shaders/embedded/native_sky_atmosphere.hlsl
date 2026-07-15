float4 SkyUpper : register(c21);
float4 SkyLower : register(c22);
float4 HorizonColor : register(c23);
float4 SunDirection : register(c25);
float4 SkyData : register(c26);
float4 SunData : register(c28);
float4 SkyMultiplier : register(c29);
float4 SunDiskColor : register(c30);

struct PixelInput {
    float4 color : COLOR0;
    float2 screen : VPOS;
    float3 eye : TEXCOORD0_centroid;
};

float3 Delinearize(float3 color) {
    float3 low = color * 12.92;
    float3 high = pow(abs(color), 1.0 / 2.4) * 1.055 - 0.055;
    return (color <= 0.0031308) ? low : high;
}

float Pow3(float value) {
    return value * value * value;
}

float Pow8(float value) {
    float value2 = value * value;
    float value4 = value2 * value2;
    return value4 * value4;
}

float InterleavedGradientNoise(float2 screen) {
    return frac(52.9829189 * frac(dot(screen, float2(0.06711056, 0.00583715))));
}

float4 Main(PixelInput input) : COLOR0 {
    const float3 up = float3(0.0, 0.0, 1.0);
    float3 eyeDirection = normalize(input.eye);
    float verticality = Pow3(dot(eyeDirection, up) * 0.5 + 0.5);
    float atmosphere = Pow8(1.0 - verticality) * SkyData.x;
    float sunFacing = saturate(dot(eyeDirection, SunDirection.xyz) * 0.5 + 0.5);
    float sunInfluence = pow(sunFacing, SunDirection.w);
    float sunHeight = SunData.w;
    float3 sunColor = SunDiskColor.rgb;

    float3 color = lerp(SkyLower.rgb, SkyUpper.rgb, verticality);
    color = lerp(color, HorizonColor.rgb, saturate(atmosphere * (0.5 + 0.5 * sunInfluence)));
    color += sunColor * sunInfluence * (1.0 - sunHeight) * atmosphere * SkyData.z * smoothstep(0.0, 0.5, SunData.x);
    color *= SkyMultiplier.w;

    float dither = InterleavedGradientNoise(input.screen);
    return float4(Delinearize(color) + dither / 255.0, 1.0);
}
