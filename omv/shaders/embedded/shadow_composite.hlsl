// Source-owned OMV shadow composition. Fog, alpha, and first person draw later.
#ifndef OMV_POINT_LIGHTS
#define OMV_POINT_LIGHTS 1
#endif
#ifndef OMV_INTERIOR
#define OMV_INTERIOR 0
#endif

float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 ShadowControl : register(c23); // x reversed, y directional enabled, z darkness
float4 DepthControl : register(c26); // x endpoint epsilon
float4 ContactControl : register(c31); // x contact texture enabled
float4 PointControl : register(c32); // x point buffer enabled, y darkness

static const float ShadowDepthKeyRange = 250000.0f;

sampler2D SourceColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D DirectionalVisibilityMap : register(s2);
sampler2D PointShadowBuffer : register(s3);
sampler2D ContactVisibility : register(s4);
sampler2D PointLightTotal : register(s6);

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (ShadowControl.x > 0.5f)
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

bool HasGeometryDepth(float rawDepth) {
    return rawDepth > DepthControl.x && rawDepth < 1.0f - DepthControl.x;
}

float ExactVisibility(sampler2D visibilityMap, float2 uv, float receiverDepth) {
    float2 sampleValue = tex2Dlod(visibilityMap, float4(uv, 0.0f, 0.0f)).rg;
    float sampleDepth = sampleValue.g * ShadowDepthKeyRange;
    float tolerance = max(2.0f, receiverDepth * 0.0025f);
    float accepted = sampleValue.g > 0.0f && abs(sampleDepth - receiverDepth) <= tolerance;
    return accepted > 0.0f ? sampleValue.r : 1.0f;
}

float2 ContactTap(float2 uv, float centerDepth, float weight) {
    float2 sampleValue = tex2Dlod(ContactVisibility, float4(uv, 0.0f, 0.0f)).rg;
    float sampleDepth = sampleValue.g * ShadowDepthKeyRange;
    float accepted = sampleValue.g > 0.0f &&
        abs(sampleDepth - centerDepth) <= max(2.0f, centerDepth * 0.0025f);
    return float2(sampleValue.r * weight * accepted, weight * accepted);
}

float ExactContactVisibility(float2 uv, float receiverDepth) {
    float2 center = tex2Dlod(ContactVisibility, float4(uv, 0.0f, 0.0f)).rg;
    float centerDepth = center.g * ShadowDepthKeyRange;
    float tolerance = max(2.0f, receiverDepth * 0.0025f);
    if (center.g <= 0.0f || abs(centerDepth - receiverDepth) > tolerance)
        return 1.0f;
    float2 sum = float2(center.r * 0.40f, 0.40f);
    sum += ContactTap(uv + float2(ScreenData.z, 0.0f), centerDepth, 0.15f);
    sum += ContactTap(uv - float2(ScreenData.z, 0.0f), centerDepth, 0.15f);
    sum += ContactTap(uv + float2(0.0f, ScreenData.w), centerDepth, 0.15f);
    sum += ContactTap(uv - float2(0.0f, ScreenData.w), centerDepth, 0.15f);
    return sum.x / max(sum.y, 0.0001f);
}

struct PointEnergy {
    float3 deficit;
    float3 total;
};

PointEnergy ExactPointValues(float2 uv, float receiverDepth) {
    float4 deficitValue = tex2Dlod(PointShadowBuffer, float4(uv, 0.0f, 0.0f));
    float4 totalValue = tex2Dlod(PointLightTotal, float4(uv, 0.0f, 0.0f));
    float sampleDepth = deficitValue.a / max(totalValue.a, 1.0f) * ShadowDepthKeyRange;
    float tolerance = max(2.0f, receiverDepth * 0.0025f);
    float accepted = totalValue.a > 0.0f && abs(sampleDepth - receiverDepth) <= tolerance;
    PointEnergy result;
    result.deficit = accepted > 0.0f ? deficitValue.rgb : 0.0f;
    result.total = accepted > 0.0f ? totalValue.rgb : 0.0f;
    return result;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 source = tex2Dlod(SourceColor, float4(input.uv, 0.0f, 0.0f));
    float rawDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
    if (!HasGeometryDepth(rawDepth)) return source;

    float viewDepth = LinearDepth(rawDepth);
    if (viewDepth <= 0.0f || viewDepth >= DepthLinearizeData.w * 0.985f) return source;

    float directional = 1.0f;
    if (ShadowControl.y > 0.5f) {
        directional = ExactVisibility(DirectionalVisibilityMap, input.uv, viewDepth);
        if (ContactControl.x > 0.5f)
            directional = min(
                directional,
                ExactContactVisibility(input.uv, viewDepth));
        directional = 1.0f - saturate(ShadowControl.z) * (1.0f - directional);
    }

#if OMV_POINT_LIGHTS
    PointEnergy pointEnergy = ExactPointValues(input.uv, viewDepth);
    float3 pointDeficit = max(pointEnergy.deficit, 0.0f);
    float3 pointTotal = max(pointEnergy.total, 0.0f);
    float3 linearSource = pow(max(source.rgb, 0.0f), 2.2f);
    float emitter = smoothstep(1.0f, 1.15f, max(linearSource.r, max(linearSource.g, linearSource.b)));
#if OMV_INTERIOR
    // Total and deficit share one analytic attenuation scale. Only their
    // cube-proven occluded fraction is portable to Fallout's already-lit
    // framebuffer; subtracting the absolute estimate dims every selected
    // interior light and makes the darkness slider intensity-dependent.
    float3 validTotal = step(0.00001f, pointTotal);
    float3 occludedFraction = saturate(pointDeficit / max(pointTotal, 0.00001f)) * validTotal;
    float3 attenuation = max(1.0f - saturate(PointControl.y) * occludedFraction, 0.25f);
    float3 shadowed = linearSource * attenuation;
#else
    float3 ownedLocal = min(pointTotal, linearSource);
    pointDeficit = min(pointDeficit, ownedLocal) * saturate(PointControl.y);
    float3 shadowed = max(
        linearSource * directional + ownedLocal * (1.0f - directional) - pointDeficit,
        linearSource * directional);
#endif
    float3 finalLinear = lerp(shadowed, linearSource, emitter);
    return float4(pow(max(finalLinear, 0.0f), 1.0f / 2.2f), source.a);
#else
    float maximumSource = max(source.r, max(source.g, source.b));
    float emitter = smoothstep(1.0f, 1.15f, pow(max(maximumSource, 0.0f), 2.2f));
    float attenuation = lerp(directional, 1.0f, emitter);
    return float4(source.rgb * pow(attenuation, 1.0f / 2.2f), source.a);
#endif
}
