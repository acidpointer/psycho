sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);

static const float DepthEndpointEpsilon = 0.000001f;
static const float MinBias = 0.01f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float HardwareDepth(float2 uv) {
    return tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
}

float FirstPersonHardwareDepth(float2 uv) {
    return tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
}

bool UseReversedDepth() {
    return OptionData1.y > 0.5f;
}

bool IsValidDepth(float depth) {
    if (UseReversedDepth()) {
        return depth >= 0.0f && depth <= 1.0f;
    }

    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float LinearDepth(float depth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    if (UseReversedDepth()) {
        return (nearZ * farZ) / max(depth * (farZ - nearZ) + nearZ, 0.001f);
    }

    return (nearZ * farZ) / max(farZ - depth * (farZ - nearZ), 0.001f);
}

bool IsSkyDepth(float rawDepth, float linearDepth) {
    float farZ = max(CameraData.y, 2.0f);
    if (UseReversedDepth()) {
        return rawDepth <= DepthEndpointEpsilon || linearDepth >= farZ * 0.995f;
    }

    return rawDepth >= (1.0f - DepthEndpointEpsilon) || linearDepth >= farZ * 0.995f;
}

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float Stability() {
    if (OptionData1.w > 0.0f) {
        return saturate(OptionData1.w);
    }

    return 0.75f;
}

bool FirstPersonMaskEnabled() {
    return OptionData2.x > 0.5f;
}

bool IsFirstPersonPixel(float2 uv) {
    if (!FirstPersonMaskEnabled()) {
        return false;
    }

    float depth = FirstPersonHardwareDepth(uv);
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float SoftRangeWeight(float delta, float range) {
    float softBand = lerp(0.25f, 0.75f, Stability());
    float start = range * (1.0f - softBand);
    return 1.0f - Smooth01((delta - start) / max(range - start, 0.001f));
}

float ContactSample(float centerDepth, float2 uv, float2 direction, float radiusPixels, float range, float bias) {
    float2 sampleUv = uv + direction * radiusPixels * ScreenData.zw;
    float rawSampleDepth = HardwareDepth(sampleUv);
    if (!IsValidDepth(rawSampleDepth)) {
        return 0.0f;
    }

    float sampleDepth = LinearDepth(rawSampleDepth);
    if (IsSkyDepth(rawSampleDepth, sampleDepth)) {
        return 0.0f;
    }

    if (IsFirstPersonPixel(sampleUv)) {
        return 0.0f;
    }

    float delta = centerDepth - sampleDepth;
    if (delta <= 0.0f) {
        return 0.0f;
    }

    float rangeWeight = SoftRangeWeight(delta, range);
    float contact = Smooth01((delta - bias) / max(range * 0.6f - bias, 0.001f));
    return contact * rangeWeight;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 color = tex2D(SceneColor, input.uv);

    if (FrameData.w < 0.5f) {
        return color;
    }

    float rawDepth = HardwareDepth(input.uv);
    if (!IsValidDepth(rawDepth)) {
        return color;
    }

    float centerDepth = LinearDepth(rawDepth);
    if (IsSkyDepth(rawDepth, centerDepth)) {
        return color;
    }

    if (IsFirstPersonPixel(input.uv)) {
        return color;
    }

    float radiusPixels = max(OptionData0.y, 0.5f);
    float range = max(centerDepth * OptionData0.z, 0.08f);
    float bias = max(centerDepth * OptionData0.w, MinBias);

    float occlusion = 0.0f;
    occlusion += ContactSample(centerDepth, input.uv, float2( 1.0000f,  0.0000f), radiusPixels, range, bias);
    occlusion += ContactSample(centerDepth, input.uv, float2(-1.0000f,  0.0000f), radiusPixels, range, bias);
    occlusion += ContactSample(centerDepth, input.uv, float2( 0.0000f,  1.0000f), radiusPixels, range, bias);
    occlusion += ContactSample(centerDepth, input.uv, float2( 0.0000f, -1.0000f), radiusPixels, range, bias);
    occlusion += ContactSample(centerDepth, input.uv, float2( 0.7071f,  0.7071f), radiusPixels * 1.35f, range, bias);
    occlusion += ContactSample(centerDepth, input.uv, float2(-0.7071f,  0.7071f), radiusPixels * 1.35f, range, bias);
    occlusion += ContactSample(centerDepth, input.uv, float2( 0.7071f, -0.7071f), radiusPixels * 1.35f, range, bias);
    occlusion += ContactSample(centerDepth, input.uv, float2(-0.7071f, -0.7071f), radiusPixels * 1.35f, range, bias);

    float amount = saturate(occlusion * 0.125f) * OptionData0.x;
    float ao = max(1.0f - amount, OptionData1.z);
    color.rgb *= ao;
    return color;
}
