sampler2D StarTexture : register(s0);

float4 SkyData : register(c26);
float4 CloudData : register(c27);
float4 SunData : register(c28);

struct PixelInput {
    float2 uv : TEXCOORD0;
    float2 screen : VPOS;
    float horizonFade : TEXCOORD2;
    float3 location : TEXCOORD1;
    float4 color : COLOR0;
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

float Hash11(float value) {
    value = frac(value * 0.1031);
    value *= value + 33.33;
    value *= value + value;
    return frac(value);
}

float ValueNoise(float3 value) {
    float3 cell = floor(value);
    float3 weight = frac(value);
    weight = weight * weight * (3.0 - 2.0 * weight);
    float index = cell.x + cell.y * 57.0 + cell.z * 113.0;

    return lerp(
        lerp(
            lerp(Hash11(index), Hash11(index + 1.0), weight.x),
            lerp(Hash11(index + 57.0), Hash11(index + 58.0), weight.x),
            weight.y
        ),
        lerp(
            lerp(Hash11(index + 113.0), Hash11(index + 114.0), weight.x),
            lerp(Hash11(index + 170.0), Hash11(index + 171.0), weight.x),
            weight.y
        ),
        weight.z
    );
}

float4 Main(PixelInput input) : COLOR0 {
    float4 stars = tex2D(StarTexture, input.uv);
    float3 starLinear = Linearize(stars.rgb);
    float3 tint = Linearize(input.color.rgb);
    float luminance = dot(starLinear, float3(0.2126, 0.7152, 0.0722));
    float brightStar = smoothstep(0.0, 1.0, luminance);
    float3 direction = normalize(input.location);
    float noiseScale = 4.0;
    float twinkleSpeed = 0.1 * CloudData.y;
    float twinkle = ValueNoise((SunData.z * twinkleSpeed).xxx + noiseScale * direction);
    twinkle *= twinkle * 1.5;
    float brightness = 1.0 + twinkle * 100.0 * brightStar;
    float alpha = stars.a * input.color.a * input.horizonFade * SkyData.w;
    return float4(Delinearize(starLinear * tint * brightness), alpha);
}
