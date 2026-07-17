// OMV world-only temporal AA. Projection jitter and resolve ownership are engine-side.

sampler2D CurrentColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D HistoryColor : register(s2);

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
    float3 current = tex2Dlod(CurrentColor, float4(uv, 0.0, 0.0)).rgb;
    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0, 0.0)).r;
    float linearDepth = ValidDepth(rawDepth) ? LinearDepth(rawDepth) : CameraData.y;
    float currentKey = saturate(log2(linearDepth + 1.0) / max(log2(CameraData.y + 1.0), 0.001));
    if (CameraData.w < 0.5 || !ValidDepth(rawDepth)) {
        return float4(current, currentKey);
    }

    float3 position = ReconstructCurrent(uv, linearDepth);
    float3 previousPosition = float3(
        dot(TemporalRow0.xyz, position) + TemporalRow0.w,
        dot(TemporalRow1.xyz, position) + TemporalRow1.w,
        dot(TemporalRow2.xyz, position) + TemporalRow2.w
    );
    float2 historyUv = ProjectPrevious(previousPosition);
    if (previousPosition.z <= max(PreviousDepth.x, 0.001) || !Inside(historyUv)) {
        return float4(current, currentKey);
    }

    float4 history = tex2Dlod(HistoryColor, float4(historyUv, 0.0, 0.0));
    float expectedKey = DepthKey(previousPosition.z);
    float depthWeight = saturate(1.0 - abs(history.a - expectedKey) * PreviousDepth.z);
    depthWeight *= depthWeight;
    float3 low;
    float3 high;
    float3 average;
    Neighborhood(uv, current, low, high, average);
    float3 clampedHistory = clamp(history.rgb, low, high);
    float historyWeight = saturate(Options0.x * depthWeight);
    float3 sharpened = max(current + (current - average) * Options0.z, 0.0);
    float3 resolved = lerp(sharpened, clampedHistory, historyWeight);

    return float4(resolved, currentKey);
}
