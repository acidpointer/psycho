sampler2D SceneColor : register(s0);

float4 ScreenData : register(c0);
float4 OptionData0 : register(c3);

static const float3 LuminanceFactors = float3(0.299f, 0.587f, 0.114f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Luma(float3 color) {
    return dot(color, LuminanceFactors);
}

float4 Main(PixelInput input) : COLOR0 {
    float2 texel = ScreenData.zw;

    float3 rgbM = tex2D(SceneColor, input.uv).rgb;
    float3 rgbNW = tex2D(SceneColor, input.uv + texel * float2(-1.0f, -1.0f)).rgb;
    float3 rgbNE = tex2D(SceneColor, input.uv + texel * float2( 1.0f, -1.0f)).rgb;
    float3 rgbSW = tex2D(SceneColor, input.uv + texel * float2(-1.0f,  1.0f)).rgb;
    float3 rgbSE = tex2D(SceneColor, input.uv + texel * float2( 1.0f,  1.0f)).rgb;

    float lumaM = Luma(rgbM);
    float lumaNW = Luma(rgbNW);
    float lumaNE = Luma(rgbNE);
    float lumaSW = Luma(rgbSW);
    float lumaSE = Luma(rgbSE);

    float lumaMin = min(lumaM, min(min(lumaNW, lumaNE), min(lumaSW, lumaSE)));
    float lumaMax = max(lumaM, max(max(lumaNW, lumaNE), max(lumaSW, lumaSE)));
    float contrast = lumaMax - lumaMin;
    if (contrast < max(OptionData0.x, 0.001f)) {
        return float4(rgbM, 1.0f);
    }

    float2 direction;
    direction.x = -((lumaNW + lumaNE) - (lumaSW + lumaSE));
    direction.y =  ((lumaNW + lumaSW) - (lumaNE + lumaSE));

    float directionReduce = max((lumaNW + lumaNE + lumaSW + lumaSE) * 0.25f * OptionData0.y, 0.0001f);
    float reciprocalMin = 1.0f / (min(abs(direction.x), abs(direction.y)) + directionReduce);
    direction = clamp(direction * reciprocalMin, -OptionData0.z, OptionData0.z) * texel;

    float3 rgbA = 0.5f * (
        tex2D(SceneColor, input.uv + direction * (1.0f / 3.0f - 0.5f)).rgb +
        tex2D(SceneColor, input.uv + direction * (2.0f / 3.0f - 0.5f)).rgb);
    float3 rgbB = rgbA * 0.5f + 0.25f * (
        tex2D(SceneColor, input.uv + direction * -0.5f).rgb +
        tex2D(SceneColor, input.uv + direction *  0.5f).rgb);

    float lumaB = Luma(rgbB);
    float3 resolved = (lumaB < lumaMin || lumaB > lumaMax) ? rgbA : lerp(rgbM, rgbB, OptionData0.w);
    return float4(resolved, 1.0f);
}
