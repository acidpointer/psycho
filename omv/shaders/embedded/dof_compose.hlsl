sampler2D SceneColor : register(s0);
sampler2D FarTexture : register(s1);
sampler2D NearTexture : register(s2);
sampler2D FullCoc : register(s3);
sampler2D NearMask : register(s4);

float4 FrameData : register(c1);
float4 StrengthData : register(c5);
float4 RadiusData : register(c6);
float4 EffectData : register(c9);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float3 ToLinear(float3 color) {
    return color * (color * (color * 0.305306011f + 0.682171111f) + 0.012522878f);
}

float3 ToSrgb(float3 color) {
    color = max(color, 0.0f);
    float3 s1 = sqrt(color);
    float3 s2 = sqrt(s1);
    float3 s3 = sqrt(s2);
    return saturate(
        0.662002687f * s1 + 0.684122060f * s2 - 0.323583601f * s3 - 0.022541147f * color
    );
}

void AccumulateFar(
    float2 uv,
    float targetCoc,
    float bilinearWeight,
    inout float4 valueSum,
    inout float weightSum
) {
    float4 sampleValue = tex2Dlod(FarTexture, float4(uv, 0.0f, 0.0f));
    float compatibility = saturate(1.0f - abs(sampleValue.a - targetCoc) * 3.0f);
    compatibility *= compatibility;
    float weight = bilinearWeight * compatibility;
    valueSum += sampleValue * weight;
    weightSum += weight;
}

float4 UpsampleFar(float2 uv, float targetCoc) {
    float2 texel = EffectData.xy;
    float2 pixel = uv / texel - 0.5f;
    float2 basePixel = floor(pixel);
    float2 blend = saturate(pixel - basePixel);
    float2 uv00 = (basePixel + float2(0.5f, 0.5f)) * texel;
    float2 uv10 = (basePixel + float2(1.5f, 0.5f)) * texel;
    float2 uv01 = (basePixel + float2(0.5f, 1.5f)) * texel;
    float2 uv11 = (basePixel + float2(1.5f, 1.5f)) * texel;
    float4 valueSum = 0.0f;
    float weightSum = 0.0f;
    AccumulateFar(uv00, targetCoc, (1.0f - blend.x) * (1.0f - blend.y), valueSum, weightSum);
    AccumulateFar(uv10, targetCoc, blend.x * (1.0f - blend.y), valueSum, weightSum);
    AccumulateFar(uv01, targetCoc, (1.0f - blend.x) * blend.y, valueSum, weightSum);
    AccumulateFar(uv11, targetCoc, blend.x * blend.y, valueSum, weightSum);
    if (weightSum <= 0.0001f) {
        return tex2D(FarTexture, uv);
    }
    return valueSum / weightSum;
}

float4 UpsampleNear(float2 uv) {
    float2 texel = EffectData.xy;
    float2 pixel = uv / texel - 0.5f;
    float2 basePixel = floor(pixel);
    float2 blend = saturate(pixel - basePixel);
    float2 uv00 = (basePixel + float2(0.5f, 0.5f)) * texel;
    float2 uv10 = (basePixel + float2(1.5f, 0.5f)) * texel;
    float2 uv01 = (basePixel + float2(0.5f, 1.5f)) * texel;
    float2 uv11 = (basePixel + float2(1.5f, 1.5f)) * texel;
    float4 value = tex2Dlod(NearTexture, float4(uv00, 0.0f, 0.0f))
        * (1.0f - blend.x) * (1.0f - blend.y);
    value += tex2Dlod(NearTexture, float4(uv10, 0.0f, 0.0f))
        * blend.x * (1.0f - blend.y);
    value += tex2Dlod(NearTexture, float4(uv01, 0.0f, 0.0f))
        * (1.0f - blend.x) * blend.y;
    value += tex2Dlod(NearTexture, float4(uv11, 0.0f, 0.0f))
        * blend.x * blend.y;
    return value;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 scene = tex2Dlod(SceneColor, float4(input.uv, 0.0f, 0.0f));
    float coc = tex2Dlod(FullCoc, float4(input.uv, 0.0f, 0.0f)).r;
    float farCoc = saturate(coc);
    float farMix = farCoc * FrameData.z;
    float3 color = 0.0f;
    bool blurApplied = false;
    if (farMix > 0.001f && RadiusData.y > 0.001f) {
        color = lerp(ToLinear(scene.rgb), UpsampleFar(input.uv, farCoc).rgb, farMix);
        blurApplied = true;
    }

    if (RadiusData.x > 0.001f && StrengthData.x > 0.001f) {
        float originalNear = saturate(-coc);
        float expandedNear = tex2Dlod(NearMask, float4(input.uv, 0.0f, 0.0f)).r;
        float nearAuthority = saturate(max(originalNear, expandedNear));
        float nearMix = nearAuthority * FrameData.z;
        if (nearMix > 0.001f) {
            float4 nearValue = UpsampleNear(input.uv);
            if (!blurApplied) {
                color = ToLinear(scene.rgb);
            }
            float nearCoverage = saturate(nearValue.a * nearMix);
            float3 nearPremultiplied = nearValue.rgb * nearMix;
            color = nearPremultiplied + color * (1.0f - nearCoverage);
            blurApplied = true;
        }
    }
    return blurApplied ? float4(ToSrgb(color), scene.a) : scene;
}
