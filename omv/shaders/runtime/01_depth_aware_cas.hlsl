sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 DepthData : register(c11);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 LuminanceFactors = float3(0.2126f, 0.7152f, 0.0722f);

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
	return DepthData.x >= 0.0f ? DepthData.x > 0.5f : OptionData1.y > 0.5f;
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

float DepthWeight(float centerDepth, float rawDepth, float2 uv, float range) {
    if (IsFirstPersonPixel(uv)) {
        return 0.0f;
    }

    if (!IsValidDepth(rawDepth)) {
        return 0.0f;
    }

    float linearDepth = LinearDepth(rawDepth);
    if (IsSkyDepth(rawDepth, linearDepth)) {
        return 0.0f;
    }

    return saturate(1.0f - abs(centerDepth - linearDepth) / max(range, 0.001f));
}

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float3 ClampByLocalRange(float3 value, float3 center, float3 north, float3 south, float3 east, float3 west, float limit) {
    float3 localMin = min(center, min(min(north, south), min(east, west)));
    float3 localMax = max(center, max(max(north, south), max(east, west)));
    return clamp(value, localMin - limit, localMax + limit);
}

float4 Main(PixelInput input) : COLOR0 {
    float4 centerColor = tex2D(SceneColor, input.uv);

    if (FrameData.w < 0.5f) {
        return centerColor;
    }

    float rawCenterDepth = HardwareDepth(input.uv);
    if (!IsValidDepth(rawCenterDepth)) {
        return centerColor;
    }

    float centerDepth = LinearDepth(rawCenterDepth);
    if (IsSkyDepth(rawCenterDepth, centerDepth)) {
        return centerColor;
    }
    if (IsFirstPersonPixel(input.uv)) {
        return centerColor;
    }

    float2 texel = ScreenData.zw;
    float2 uvN = input.uv + float2(0.0f, -texel.y);
    float2 uvS = input.uv + float2(0.0f,  texel.y);
    float2 uvE = input.uv + float2( texel.x, 0.0f);
    float2 uvW = input.uv + float2(-texel.x, 0.0f);

    float3 north = tex2D(SceneColor, uvN).rgb;
    float3 south = tex2D(SceneColor, uvS).rgb;
    float3 east = tex2D(SceneColor, uvE).rgb;
    float3 west = tex2D(SceneColor, uvW).rgb;

    float depthRange = max(centerDepth * OptionData0.y, 0.15f);
    float wN = DepthWeight(centerDepth, HardwareDepth(uvN), uvN, depthRange);
    float wS = DepthWeight(centerDepth, HardwareDepth(uvS), uvS, depthRange);
    float wE = DepthWeight(centerDepth, HardwareDepth(uvE), uvE, depthRange);
    float wW = DepthWeight(centerDepth, HardwareDepth(uvW), uvW, depthRange);

    float weightSum = wN + wS + wE + wW;
    if (weightSum < 0.001f) {
        return centerColor;
    }

    float3 blur = (north * wN + south * wS + east * wE + west * wW) / weightSum;
    float3 detail = centerColor.rgb - blur;

    float contrast = abs(dot(detail, LuminanceFactors));
    float contrastGate = Smooth01(contrast / max(OptionData0.w, 0.001f));
    float edgeGate = saturate(weightSum * 0.25f);
    float strength = OptionData0.x * contrastGate * edgeGate;

    float3 sharpened = centerColor.rgb + detail * strength;
    sharpened = ClampByLocalRange(sharpened, centerColor.rgb, north, south, east, west, OptionData0.z);

    return float4(saturate(sharpened), centerColor.a);
}
