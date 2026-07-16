sampler2D CurrentAO : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);
sampler2D HistoryAO : register(s4);

float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 FastOption1 : register(c4);
float4 FastOption2 : register(c5);
float4 ContactOption1 : register(c8);
float4 ContactOption2 : register(c9);
float4 DepthData : register(c11);
float4 CameraFrustum : register(c12);
float4 TemporalRow0 : register(c13);
float4 TemporalRow1 : register(c14);
float4 TemporalRow2 : register(c15);
float4 PreviousFrustum : register(c16);
float4 HistoryData : register(c17);
float4 TemporalData : register(c18);

static const float DepthEndpointEpsilon = 0.000001f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

bool IsInsideScreen(float2 uv) {
    return uv.x >= 0.0f && uv.y >= 0.0f && uv.x <= 1.0f && uv.y <= 1.0f;
}

bool UseReversedDepth() {
    if (DepthData.x >= 0.0f) {
        return DepthData.x > 0.5f;
    }

    return FastOption1.y > 0.5f || ContactOption1.y > 0.5f;
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
    return FrameData.z > 0.5f && (FastOption2.y > 0.5f || ContactOption2.x > 0.5f);
}

bool IsFirstPersonPixel(float2 uv) {
    if (!FirstPersonMaskEnabled()) {
        return false;
    }

    float depth = tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float3 ReconstructViewPosition(float2 uv, float linearDepth) {
    float viewX = lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * linearDepth;
    float viewY = lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * linearDepth;
    return float3(viewX, viewY, linearDepth);
}

float2 ProjectPreviousViewPosition(float3 position) {
    float invDepth = rcp(max(position.z, 0.001f));
    float viewX = position.x * invDepth;
    float viewY = position.y * invDepth;
    float u = (viewX - PreviousFrustum.x)
        / max(PreviousFrustum.y - PreviousFrustum.x, 0.001f);
    float v = (PreviousFrustum.w - viewY)
        / max(PreviousFrustum.w - PreviousFrustum.z, 0.001f);
    return float2(u, v);
}

float PreviousDepthKey(float linearDepth) {
    float farZ = max(HistoryData.w, 2.0f);
    return saturate(log2(linearDepth + 1.0f) / max(log2(farZ + 1.0f), 0.001f));
}

float2 CurrentRange(float2 uv, float center) {
    float minimum = center;
    float maximum = center;
    float2 texel = TemporalData.xy;
    float sampleValue = tex2Dlod(CurrentAO, float4(uv + float2(texel.x, 0.0f), 0.0f, 0.0f)).r;
    minimum = min(minimum, sampleValue);
    maximum = max(maximum, sampleValue);
    sampleValue = tex2Dlod(CurrentAO, float4(uv - float2(texel.x, 0.0f), 0.0f, 0.0f)).r;
    minimum = min(minimum, sampleValue);
    maximum = max(maximum, sampleValue);
    sampleValue = tex2Dlod(CurrentAO, float4(uv + float2(0.0f, texel.y), 0.0f, 0.0f)).r;
    minimum = min(minimum, sampleValue);
    maximum = max(maximum, sampleValue);
    sampleValue = tex2Dlod(CurrentAO, float4(uv - float2(0.0f, texel.y), 0.0f, 0.0f)).r;
    return float2(min(minimum, sampleValue), max(maximum, sampleValue));
}

float4 Main(PixelInput input) : COLOR0 {
    float4 current = tex2Dlod(CurrentAO, float4(input.uv, 0.0f, 0.0f));
    if (HistoryData.x < 0.5f || HistoryData.y <= 0.0f || IsFirstPersonPixel(input.uv)) {
        return current;
    }

    float rawDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
    if (!IsValidDepth(rawDepth)) {
        return current;
    }

    float linearDepth = LinearDepth(rawDepth);
    if (IsSkyDepth(rawDepth, linearDepth)) {
        return current;
    }

    float3 currentPosition = ReconstructViewPosition(input.uv, linearDepth);
    float3 previousPosition = float3(
        dot(TemporalRow0.xyz, currentPosition) + TemporalRow0.w,
        dot(TemporalRow1.xyz, currentPosition) + TemporalRow1.w,
        dot(TemporalRow2.xyz, currentPosition) + TemporalRow2.w
    );
    if (previousPosition.z <= max(HistoryData.z, 0.001f)) {
        return current;
    }

    float2 previousUv = ProjectPreviousViewPosition(previousPosition);
    if (!IsInsideScreen(previousUv)) {
        return current;
    }

    float4 history = tex2Dlod(HistoryAO, float4(previousUv, 0.0f, 0.0f));
    float expectedDepthKey = PreviousDepthKey(previousPosition.z);
    float depthWeight = saturate(1.0f - abs(history.g - expectedDepthKey) * TemporalData.z);
    depthWeight *= depthWeight;

    float2 currentRange = CurrentRange(input.uv, current.r);
    float historyAmount = clamp(history.r, currentRange.x, currentRange.y);
    float historyWeight = saturate(HistoryData.y * depthWeight);
    float amount = lerp(current.r, historyAmount, historyWeight);
    return float4(amount, current.g, 0.0f, 1.0f);
}
