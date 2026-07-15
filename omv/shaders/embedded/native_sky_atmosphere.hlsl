float4 SkyUpper : register(c21);
float4 SkyLower : register(c22);
float4 HorizonColor : register(c23);
float4 SunLightColor : register(c24);
float4 SunDirection : register(c25);
float4 SkyData : register(c26);
float4 SunData : register(c28);
float4 SunsetColor : register(c29);
float4 SunDiskColor : register(c30);

static const float4x4 DitherMatrix = {
    { 0.0588, 0.5294, 0.1765, 0.6471 },
    { 0.7647, 0.2941, 0.8824, 0.4118 },
    { 0.2353, 0.7059, 0.1176, 0.5882 },
    { 0.9412, 0.4706, 0.8235, 0.3259 }
};

struct PixelInput {
    float4 color : COLOR0;
    float2 screen : VPOS;
    float3 eye : TEXCOORD0_centroid;
};

float3 Linearize(float3 color) {
    float3 low = color / 12.92;
    float3 high = pow((color + 0.055) / 1.055, 2.4);
    return (color <= 0.04045) ? low : high;
}

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

float3 EvaluateSun(float sunHeight) {
    float3 sun = Linearize(SunDiskColor.rgb);
    float3 sunset = Linearize(SunsetColor.rgb);
    float sunsetWeight = saturate(Pow8(1.0 - sunHeight)) * SunData.x;
    return (1.0 + sunHeight) * sun + sunset * sunsetWeight * SkyData.x;
}

float4 Main(PixelInput input) : COLOR0 {
    const float3 up = float3(0.0, 0.0, 1.0);
    float3 eyeDirection = normalize(input.eye);
    float verticality = Pow3(dot(eyeDirection, up) * 0.5 + 0.5);
    float atmosphere = Pow8(1.0 - verticality) * SkyData.x;
    float sunFacing = saturate(dot(eyeDirection, SunDirection.xyz) * 0.5 + 0.5);
    float sunInfluence = pow(sunFacing, rcp(max(SkyData.y, 0.05)));
    float sunHeight = max(dot(SunDirection.xyz, up), 0.0);
    float3 sunColor = EvaluateSun(sunHeight);

    float3 color = lerp(Linearize(SkyLower.rgb), Linearize(SkyUpper.rgb), verticality);
    color = lerp(color, Linearize(HorizonColor.rgb), saturate(atmosphere * (0.5 + 0.5 * sunInfluence)));
    color += sunColor * sunInfluence * (1.0 - sunHeight) * atmosphere * SkyData.z * smoothstep(0.0, 0.5, SunData.x);
    color *= SunsetColor.w;

    float dither = DitherMatrix[(int)input.screen.x % 4][(int)input.screen.y % 4];
    return float4(Delinearize(color) + dither / 255.0, 1.0);
}
