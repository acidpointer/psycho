// Source-owned OMV shadow composition. Fog, alpha, and first person draw later.
#ifndef OMV_POINT_LIGHTS
#define OMV_POINT_LIGHTS 1
#endif

float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 ShadowControl : register(c23); // x reversed, y directional enabled, z darkness
float4 DepthControl : register(c26); // x endpoint epsilon
float4 ContactControl : register(c31); // x contact texture enabled
float4 PointControl : register(c32); // x point buffer enabled, y darkness
float4 DeferredTexel : register(c36); // xy inverse half-resolution mask size

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

float2 VisibilityTap(
    sampler2D visibilityMap,
    float2 uv,
    float receiverDepth,
    float weight)
{
    float2 sampleValue = tex2Dlod(visibilityMap, float4(uv, 0.0f, 0.0f)).rg;
    float sampleDepth = sampleValue.g * ShadowDepthKeyRange;
    float tolerance = max(2.0f, receiverDepth * 0.0025f);
    float accepted = sampleValue.g > 0.0f && abs(sampleDepth - receiverDepth) <= tolerance;
    return float2(sampleValue.r * weight * accepted, weight * accepted);
}

float DeferredVisibility(sampler2D visibilityMap, float2 uv, float receiverDepth) {
    // Reconstruct bilinear weights explicitly so every contributing mask texel
    // can first prove that it belongs to this receiver. Hardware bilinear would
    // mix a foreground shadow into a background wall during camera movement.
    float2 texel = DeferredTexel.xy;
    float2 coordinate = uv / texel - 0.5f;
    float2 base = floor(coordinate);
    float2 fraction = coordinate - base;
    float2 uv00 = (base + 0.5f) * texel;
    float2 sum = 0.0f;
    sum += VisibilityTap(visibilityMap, uv00, receiverDepth, (1.0f - fraction.x) * (1.0f - fraction.y));
    sum += VisibilityTap(visibilityMap, uv00 + float2(texel.x, 0.0f), receiverDepth, fraction.x * (1.0f - fraction.y));
    sum += VisibilityTap(visibilityMap, uv00 + float2(0.0f, texel.y), receiverDepth, (1.0f - fraction.x) * fraction.y);
    sum += VisibilityTap(visibilityMap, uv00 + texel, receiverDepth, fraction.x * fraction.y);
    return sum.y > 0.0001f ? sum.x / sum.y : 1.0f;
}

struct PointEnergy {
    float3 deficit;
    float3 total;
};

void PointTap(
    float2 uv,
    float receiverDepth,
    float weight,
    out float4 deficit,
    out float4 total)
{
    float4 deficitValue = tex2Dlod(PointShadowBuffer, float4(uv, 0.0f, 0.0f));
    float4 totalValue = tex2Dlod(PointLightTotal, float4(uv, 0.0f, 0.0f));
    float sampleDepth = deficitValue.a / max(totalValue.a, 1.0f) * ShadowDepthKeyRange;
    float tolerance = max(2.0f, receiverDepth * 0.0025f);
    float accepted = totalValue.a > 0.0f && abs(sampleDepth - receiverDepth) <= tolerance;
    deficit = float4(deficitValue.rgb * weight * accepted, weight * accepted);
    total = float4(totalValue.rgb * weight * accepted, weight * accepted);
}

PointEnergy DeferredPointValues(float2 uv, float receiverDepth) {
    float2 texel = DeferredTexel.xy;
    float2 coordinate = uv / texel - 0.5f;
    float2 base = floor(coordinate);
    float2 fraction = coordinate - base;
    float2 uv00 = (base + 0.5f) * texel;
    float4 deficitSum = 0.0f;
    float4 totalSum = 0.0f;
    float4 deficitTap;
    float4 totalTap;
    PointTap(uv00, receiverDepth, (1.0f - fraction.x) * (1.0f - fraction.y), deficitTap, totalTap);
    deficitSum += deficitTap;
    totalSum += totalTap;
    PointTap(uv00 + float2(texel.x, 0.0f), receiverDepth, fraction.x * (1.0f - fraction.y), deficitTap, totalTap);
    deficitSum += deficitTap;
    totalSum += totalTap;
    PointTap(uv00 + float2(0.0f, texel.y), receiverDepth, (1.0f - fraction.x) * fraction.y, deficitTap, totalTap);
    deficitSum += deficitTap;
    totalSum += totalTap;
    PointTap(uv00 + texel, receiverDepth, fraction.x * fraction.y, deficitTap, totalTap);
    deficitSum += deficitTap;
    totalSum += totalTap;
    PointEnergy result;
    result.deficit = deficitSum.a > 0.0001f ? deficitSum.rgb / deficitSum.a : 0.0f;
    result.total = totalSum.a > 0.0001f ? totalSum.rgb / totalSum.a : 0.0f;
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
        directional = DeferredVisibility(DirectionalVisibilityMap, input.uv, viewDepth);
        if (ContactControl.x > 0.5f)
            directional = min(
                directional,
                DeferredVisibility(ContactVisibility, input.uv, viewDepth));
        directional = 1.0f - saturate(ShadowControl.z) * (1.0f - directional);
    }

#if OMV_POINT_LIGHTS
    PointEnergy pointEnergy = DeferredPointValues(input.uv, viewDepth);
    float3 pointDeficit = max(pointEnergy.deficit, 0.0f);
    float3 pointTotal = max(pointEnergy.total, 0.0f);
    float3 linearSource = pow(max(source.rgb, 0.0f), 2.2f);
    float emitter = smoothstep(1.0f, 1.15f, max(linearSource.r, max(linearSource.g, linearSource.b)));
    float3 ownedLocal = min(pointTotal, linearSource);
    pointDeficit = min(pointDeficit, ownedLocal) * saturate(PointControl.y);
    float3 shadowed = max(
        linearSource * directional + ownedLocal * (1.0f - directional) - pointDeficit,
        0.0f);
    if (ShadowControl.y > 0.5f)
        shadowed = max(shadowed, linearSource * directional);
    float3 finalLinear = lerp(shadowed, linearSource, emitter);
    return float4(pow(max(finalLinear, 0.0f), 1.0f / 2.2f), source.a);
#else
    float maximumSource = max(source.r, max(source.g, source.b));
    float emitter = smoothstep(1.0f, 1.15f, pow(max(maximumSource, 0.0f), 2.2f));
    float attenuation = lerp(directional, 1.0f, emitter);
    return float4(source.rgb * pow(attenuation, 1.0f / 2.2f), source.a);
#endif
}
