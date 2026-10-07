// OMV world-only temporal AA. Projection jitter and resolve ownership are engine-side.

sampler2D CurrentColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D HistoryColor : register(s2);
sampler2D HistoryDepthKey : register(s3);

float4 ScreenData : register(c0);
float4 CurrentFrustum : register(c1);
float4 CameraData : register(c2);
float4 Options0 : register(c3);
float4 RasterJitter : register(c4);
float4 TemporalRow0 : register(c5);
float4 TemporalRow1 : register(c6);
float4 TemporalRow2 : register(c7);
float4 PreviousFrustum : register(c8);
float4 PreviousDepth : register(c9);
float4 OutputFrustum : register(c10);

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

float2 ProjectCurrentOutput(float3 position) {
    float2 view = position.xy / max(position.z, 0.001);
    return float2(
        (view.x - OutputFrustum.x) / (OutputFrustum.y - OutputFrustum.x),
        (OutputFrustum.w - view.y) / (OutputFrustum.w - OutputFrustum.z)
    );
}

float DepthKey(float depth) {
    return saturate(log2(depth + 1.0) / max(log2(PreviousDepth.y + 1.0), 0.001));
}

float CurrentDepthKey(float rawDepth, bool geometry, bool sky) {
    if (sky) {
        return -1.0;
    }
    if (!geometry) {
        return 2.0;
    }
    float linearDepth = LinearDepth(rawDepth);
    return saturate(log2(linearDepth + 1.0) / max(log2(CameraData.y + 1.0), 0.001));
}

float HistoryAgreement(float3 current, float3 history, float skyMask) {
    float3 magnitude = max(max(abs(current), abs(history)), 0.02);
    float3 relative = abs(history - current) / magnitude;
    float difference = max(relative.x, max(relative.y, relative.z));
    float rejectionStart = lerp(0.20, 0.05, skyMask);
    float rejectionEnd = lerp(1.00, 0.50, skyMask);
    return 1.0 - smoothstep(rejectionStart, rejectionEnd, difference);
}

float HistoryDepthAgreement(float2 uv, float expectedKey) {
    // Color uses bilinear history filtering. A point key at its requested UV
    // cannot certify the other contributing texels, especially at sky edges.
    float2 pixel = uv * ScreenData.xy - 0.5;
    float2 fraction = frac(pixel);
    float2 base = (floor(pixel) + 0.5) * ScreenData.zw;
    float4 keys = float4(
        tex2Dlod(HistoryDepthKey, float4(base, 0.0, 0.0)).r,
        tex2Dlod(HistoryDepthKey, float4(base + float2(ScreenData.z, 0.0), 0.0, 0.0)).r,
        tex2Dlod(HistoryDepthKey, float4(base + float2(0.0, ScreenData.w), 0.0, 0.0)).r,
        tex2Dlod(HistoryDepthKey, float4(base + ScreenData.zw, 0.0, 0.0)).r);
    float2 contributes = float2(fraction.x > 0.0, fraction.y > 0.0);
    float4 errors = abs(keys - expectedKey) * float4(1.0, contributes, contributes.x * contributes.y);
    float error = max(max(errors.x, errors.y), max(errors.z, errors.w));
    float weight = saturate(1.0 - error * PreviousDepth.z);
    return weight * weight;
}

void Neighborhood(float2 uv, float3 center, out float3 low, out float3 high, out float3 average, out float3 radianceHigh) {
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
    radianceHigh = high;
    float3 extent = (high - low) * max(Options0.y, 0.25);
    float3 midpoint = (low + high) * 0.5;
    // A user's tighter history box must never exclude the valid current sample.
    low = min(midpoint - extent * 0.5, center);
    high = max(midpoint + extent * 0.5, center);
}

#if OMV_TAA_MRT
struct TemporalOutput {
    float4 color : COLOR0;
    float4 depthKey : COLOR1;
};

TemporalOutput MakeOutput(float4 color, float depthKey) {
    TemporalOutput output;
    output.color = color;
    output.depthKey = float4(depthKey, 0.0, 0.0, 1.0);
    return output;
}

TemporalOutput Main(float2 uv : TEXCOORD0) {
#else
float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
#endif
    // Reconstruct radiance onto the fixed output grid. Alpha remains the
    // exact engine-owned raster pixel, not filtered temporal metadata.
    float alpha = tex2Dlod(CurrentColor, float4(uv, 0.0, 0.0)).a;
    float2 rasterUv = uv - RasterJitter.xy;
    float4 current = float4(tex2Dlod(CurrentColor, float4(rasterUv, 0.0, 0.0)).rgb, alpha);
    float2 depthUv = (clamp(floor(rasterUv * ScreenData.xy), 0.0, ScreenData.xy - 1.0) + 0.5) * ScreenData.zw;
    float rawDepth = tex2Dlod(SceneDepth, float4(depthUv, 0.0, 0.0)).r;
    bool geometry = ValidDepth(rawDepth);
    bool sky = SkyDepth(rawDepth);
    float currentDepthKey = CurrentDepthKey(rawDepth, geometry, sky);
    if (CameraData.w < 0.5 || (!geometry && !sky)) {
#if OMV_TAA_MRT
        return MakeOutput(current, currentDepthKey);
#else
        return current;
#endif
    }

    float skyMask = sky ? 1.0 : 0.0;
    float linearDepth = geometry ? LinearDepth(rawDepth) : 1.0;
    float3 position = ReconstructCurrent(depthUv, linearDepth);
    float3 previousPosition = float3(
        dot(TemporalRow0.xyz, position) + TemporalRow0.w * (1.0 - skyMask),
        dot(TemporalRow1.xyz, position) + TemporalRow1.w * (1.0 - skyMask),
        dot(TemporalRow2.xyz, position) + TemporalRow2.w * (1.0 - skyMask)
    );
    // Motion is computed for one actual raster/depth point with jitter
    // cancelled at both projections, then applied on the output pixel grid.
    float2 motionUv = ProjectPrevious(previousPosition) - ProjectCurrentOutput(position);
    float2 historyUv = uv + motionUv;
    float minimumPreviousZ = sky ? 0.001 : max(PreviousDepth.x, 0.001);
    if (previousPosition.z <= minimumPreviousZ || !Inside(historyUv)) {
#if OMV_TAA_MRT
        return MakeOutput(current, currentDepthKey);
#else
        return current;
#endif
    }

    float4 history = tex2Dlod(HistoryColor, float4(historyUv, 0.0, 0.0));
    float expectedKey = sky ? -1.0 : DepthKey(previousPosition.z);
    float depthWeight = HistoryDepthAgreement(historyUv, expectedKey);
    float3 low;
    float3 high;
    float3 average;
    float3 radianceHigh;
    Neighborhood(rasterUv, current.rgb, low, high, average, radianceHigh);
    float3 clampedHistory = clamp(history.rgb, low, high);
    float agreement = HistoryAgreement(current.rgb, clampedHistory, skyMask);
    float historyWeight = saturate(Options0.x * depthWeight * agreement);
    float3 sharpened = clamp(current.rgb + (current.rgb - average) * Options0.z, max(low, 0.0), radianceHigh);
    float3 resolved = lerp(sharpened, clampedHistory, historyWeight);

    float4 outputColor = float4(resolved, current.a);
#if OMV_TAA_MRT
    return MakeOutput(outputColor, currentDepthKey);
#else
    return outputColor;
#endif
}
