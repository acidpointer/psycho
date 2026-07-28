// OMV world-only temporal AA. Projection jitter and resolve ownership are engine-side.

sampler2D CurrentColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D HistoryColor : register(s2);
sampler2D HistoryDepthKey : register(s3);

float4 ScreenData : register(c0);
float4 CurrentFrustum : register(c1);
float4 CameraData : register(c2);
float4 Options0 : register(c3);
float4 TemporalRow0 : register(c5);
float4 TemporalRow1 : register(c6);
float4 TemporalRow2 : register(c7);
float4 PreviousFrustum : register(c8);
float4 PreviousDepth : register(c9);

bool Inside(float2 uv) {
    return all(uv >= 0.0) && all(uv <= 1.0);
}

bool ReversedDepth() {
    return CameraData.z > 0.5;
}

bool ValidDepth(float depth) {
    return ReversedDepth() ? depth > 0.000001 && depth <= 1.0 : depth > 0.000001 && depth < 0.999999;
}

bool SkyDepth(float depth) {
    return ReversedDepth()
        ? depth >= 0.0 && depth <= 0.000001
        : depth >= 0.999999 && depth <= 1.0;
}

float LinearDepth(float depth) {
    float nearZ = max(CameraData.x, 0.01);
    float farZ = max(CameraData.y, nearZ + 1.0);
    if (ReversedDepth()) {
        return nearZ * farZ / max(depth * (farZ - nearZ) + nearZ, 0.001);
    }
    return nearZ * farZ / max(farZ - depth * (farZ - nearZ), 0.001);
}

float3 ReconstructCurrent(float2 uv, float depth) {
    float x = lerp(CurrentFrustum.x, CurrentFrustum.y, uv.x) * depth;
    float y = lerp(CurrentFrustum.w, CurrentFrustum.z, uv.y) * depth;
    return float3(x, y, depth);
}

float2 ProjectPrevious(float3 position) {
    float2 view = position.xy / max(position.z, 0.001);
    return float2(
        (view.x - PreviousFrustum.x) / max(PreviousFrustum.y - PreviousFrustum.x, 0.001),
        (PreviousFrustum.w - view.y) / max(PreviousFrustum.w - PreviousFrustum.z, 0.001)
    );
}

float DepthKey(float depth) {
    return saturate(log2(depth + 1.0) / max(log2(PreviousDepth.y + 1.0), 0.001));
}

float HistoryAgreement(float3 current, float3 history, float skyMask) {
    float3 magnitude = max(max(abs(current), abs(history)), 0.02);
    float3 relative = abs(history - current) / magnitude;
    float difference = max(relative.x, max(relative.y, relative.z));
    float rejectionStart = lerp(0.20, 0.05, skyMask);
    float rejectionEnd = lerp(1.00, 0.50, skyMask);
    return 1.0 - smoothstep(rejectionStart, rejectionEnd, difference);
}

void Neighborhood(float2 uv, float3 center, out float3 low, out float3 high, out float3 average) {
    float2 t = ScreenData.zw;
    low = center;
    high = center;
    average = center;
    float3 sampleColor = tex2Dlod(CurrentColor, float4(uv + float2(t.x, 0.0), 0.0, 0.0)).rgb;
    low = min(low, sampleColor); high = max(high, sampleColor); average += sampleColor;
    sampleColor = tex2Dlod(CurrentColor, float4(uv - float2(t.x, 0.0), 0.0, 0.0)).rgb;
    low = min(low, sampleColor); high = max(high, sampleColor); average += sampleColor;
    sampleColor = tex2Dlod(CurrentColor, float4(uv + float2(0.0, t.y), 0.0, 0.0)).rgb;
    low = min(low, sampleColor); high = max(high, sampleColor); average += sampleColor;
    sampleColor = tex2Dlod(CurrentColor, float4(uv - float2(0.0, t.y), 0.0, 0.0)).rgb;
    low = min(low, sampleColor); high = max(high, sampleColor); average += sampleColor;
    average *= 0.2;
    float3 extent = (high - low) * max(Options0.y, 0.25);
    float3 midpoint = (low + high) * 0.5;
    low = midpoint - extent * 0.5;
    high = midpoint + extent * 0.5;
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float4 current = tex2Dlod(CurrentColor, float4(uv, 0.0, 0.0));
    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0, 0.0)).r;
    bool geometry = ValidDepth(rawDepth);
    bool sky = SkyDepth(rawDepth);
    if (CameraData.w < 0.5 || (!geometry && !sky)) {
        return current;
    }

    float skyMask = sky ? 1.0 : 0.0;
    float linearDepth = geometry ? LinearDepth(rawDepth) : 1.0;
    float3 position = ReconstructCurrent(uv, linearDepth);
    float3 previousPosition = float3(
        dot(TemporalRow0.xyz, position) + TemporalRow0.w * (1.0 - skyMask),
        dot(TemporalRow1.xyz, position) + TemporalRow1.w * (1.0 - skyMask),
        dot(TemporalRow2.xyz, position) + TemporalRow2.w * (1.0 - skyMask)
    );
    float2 historyUv = ProjectPrevious(previousPosition);
    float minimumPreviousZ = sky ? 0.001 : max(PreviousDepth.x, 0.001);
    if (previousPosition.z <= minimumPreviousZ || !Inside(historyUv)) {
        return current;
    }

    float4 history = tex2Dlod(HistoryColor, float4(historyUv, 0.0, 0.0));
    float historyKey = tex2Dlod(HistoryDepthKey, float4(historyUv, 0.0, 0.0)).r;
    float expectedKey = sky ? -1.0 : DepthKey(previousPosition.z);
    float depthWeight = saturate(1.0 - abs(historyKey - expectedKey) * PreviousDepth.z);
    depthWeight *= depthWeight;
    float3 low;
    float3 high;
    float3 average;
    Neighborhood(uv, current.rgb, low, high, average);
    float3 clampedHistory = clamp(history.rgb, low, high);
    float agreement = HistoryAgreement(current.rgb, clampedHistory, skyMask);
    float historyWeight = saturate(Options0.x * depthWeight * agreement);
    float3 sharpened = max(current.rgb + (current.rgb - average) * Options0.z, 0.0);
    float3 resolved = lerp(sharpened, clampedHistory, historyWeight);

    return float4(resolved, current.a);
}
