// Camera-reprojected contact history with receiver-depth disocclusion rejection.
float4 ScreenData : register(c0);
float4 CurrentFrustum : register(c1);
float4 CurrentToPrevious0 : register(c3);
float4 CurrentToPrevious1 : register(c4);
float4 CurrentToPrevious2 : register(c5);
float4 PreviousFrustum : register(c6);
float4 HistoryControl : register(c7); // x valid, y history weight, z relative depth tolerance, w floor

sampler2D CurrentContact : register(s0);
sampler2D HistoryContact : register(s1);

struct PixelInput { float2 uv : TEXCOORD0; };

float3 CurrentViewPosition(float2 uv, float depth) {
    return float3(
        lerp(CurrentFrustum.x, CurrentFrustum.y, uv.x) * depth,
        lerp(CurrentFrustum.w, CurrentFrustum.z, uv.y) * depth,
        depth);
}

float2 ProjectPrevious(float3 position) {
    float2 projected = position.xy / max(position.z, 0.001f);
    return float2(
        (projected.x - PreviousFrustum.x) /
            max(PreviousFrustum.y - PreviousFrustum.x, 0.001f),
        (PreviousFrustum.w - projected.y) /
            max(PreviousFrustum.w - PreviousFrustum.z, 0.001f));
}

float2 HistoryTap(float2 uv, float predictedDepth, float weight) {
    float2 history = tex2Dlod(HistoryContact, float4(uv, 0.0f, 0.0f)).rg;
    float tolerance = max(HistoryControl.w, predictedDepth * HistoryControl.z);
    float accepted = history.g > 0.0f && abs(history.g - predictedDepth) <= tolerance;
    return float2(history.r * weight * accepted, weight * accepted);
}

float4 Main(PixelInput input) : COLOR0 {
    float2 current = tex2Dlod(CurrentContact, float4(input.uv, 0.0f, 0.0f)).rg;
    if (HistoryControl.x < 0.5f || current.g <= 0.0f)
        return float4(current, 0.0f, 1.0f);

    float3 currentView = CurrentViewPosition(input.uv, current.g);
    float4 homogeneous = float4(currentView, 1.0f);
    float3 previousView = float3(
        dot(CurrentToPrevious0, homogeneous),
        dot(CurrentToPrevious1, homogeneous),
        dot(CurrentToPrevious2, homogeneous));
    if (previousView.z <= 0.0f)
        return float4(current, 0.0f, 1.0f);
    float2 historyUv = ProjectPrevious(previousView);
    if (min(historyUv.x, historyUv.y) < 0.0f || max(historyUv.x, historyUv.y) > 1.0f)
        return float4(current, 0.0f, 1.0f);

    // Depth-aware manual bilinear filtering stabilizes sub-texel camera
    // motion while rejecting each foreign surface before interpolation.
    float2 texelPosition = historyUv / ScreenData.zw - 0.5f;
    float2 base = floor(texelPosition);
    float2 fraction = frac(texelPosition);
    float2 uv00 = (base + 0.5f) * ScreenData.zw;
    float4 weights = float4(
        (1.0f - fraction.x) * (1.0f - fraction.y),
        fraction.x * (1.0f - fraction.y),
        (1.0f - fraction.x) * fraction.y,
        fraction.x * fraction.y);
    float2 history = 0.0f;
    history += HistoryTap(uv00, previousView.z, weights.x);
    history += HistoryTap(uv00 + float2(ScreenData.z, 0.0f), previousView.z, weights.y);
    history += HistoryTap(uv00 + float2(0.0f, ScreenData.w), previousView.z, weights.z);
    history += HistoryTap(uv00 + ScreenData.zw, previousView.z, weights.w);
    if (history.y <= 0.0001f)
        return float4(current, 0.0f, 1.0f);

    float visibility = lerp(
        current.r, saturate(history.x / history.y), saturate(HistoryControl.y));
    return float4(visibility, current.g, 0.0f, 1.0f);
}
