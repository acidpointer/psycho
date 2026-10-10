sampler2D ReducedDepth : register(s0);
sampler2D DensityNoise : register(s1);
sampler2D ShaftVisibility : register(s2);
sampler2D NativeSunTexture : register(s3);
// Exact static EVSM/actor atlas publication, independent of sun screen position.
#ifdef OMV_WORLD_FIELD
sampler2D ShadowAtlas : register(s4);
#endif
#ifndef OMV_WORLD_FIELD
sampler2D CompletedNearAtmosphere : register(s4);
#endif
sampler2D ActorNearMiddleMoments : register(s5);
sampler2D ActorFarMoments : register(s6);
row_major float4x4 CascadeMatrices[4] : register(c18);
float4 CascadeSplits : register(c34);
float4 CascadeTexel : register(c35);
float4 ActorControl : register(c36);
float4 ActorCrops[3] : register(c37);
float4 ActorTexel : register(c40);
float4 CascadeBlendWidth : register(c41);
float4 WorldShadowControl : register(c42); // active, shaft strength, world samples
float4 WorldFieldTarget : register(c43);
float4 SunTextureU : register(c15);
float4 SunTextureV : register(c16);
float4 SunTextureDenominator : register(c17);

// Match the native-sky replacement's exact texture transfer. The transfer is
// monotone, so decoding the peak channel equals the peak of decoded RGB.
float SolarTextureResponse(float3 color) {
    float peak = max(color.r, max(color.g, color.b));
    return peak <= 0.04045f ? peak / 12.92f : pow((peak + 0.055f) / 1.055f, 2.4f);
}

float AuthoredSunCoverage(float2 uv) {
	float3 screen = float3(uv, 1.0f);
	float denominator = dot(SunTextureDenominator.xyz, screen);
	if (denominator <= 0.0f || SunTextureDenominator.w <= 0.0f) { return 0.0f; }
	float2 solarUv = float2(dot(SunTextureU.xyz, screen), dot(SunTextureV.xyz, screen)) / denominator;
	if (any(solarUv < 0.0f) || any(solarUv > 1.0f)) { return 0.0f; }
	float4 authored = tex2Dlod(NativeSunTexture, float4(solarUv, 0.0f, 0.0f));
	return SolarTextureResponse(authored.rgb) * authored.a * SunTextureDenominator.w;
}

#ifndef ATMOSPHERE_SAMPLE_COUNT
#define ATMOSPHERE_SAMPLE_COUNT 12
#endif

float4 ReducedTarget : register(c0);
float4 DepthData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
float4 MediumData0 : register(c6);
float4 MediumData1 : register(c7);
float4 MediumColor : register(c8);
float4 GateData : register(c9);
float4 LightingData : register(c10);
float4 SunDirection : register(c11);
float4 SunColor : register(c12);
float4 SunDiskDelta : register(c13);
float4 LightingMediumData : register(c14);

static const float MaximumOpticalDepth = 40.0f;
static const float MaximumExponent = 20.0f;
static const float InverseFourPi = 0.0795774715f;
static const float FourPi = 12.5663706144f;

struct PixelInput {
	float2 uv : TEXCOORD0;
};

bool IsFiniteScalar(float value) {
	return value == value && abs(value) < 3.0e38f;
}

bool IsFiniteVector(float3 value) {
	return IsFiniteScalar(value.x) && IsFiniteScalar(value.y) && IsFiniteScalar(value.z);
}

float4 IdentityMedium() {
	return float4(0.0f, 0.0f, 0.0f, 1.0f);
}

float DecodeDistance(float encoded) {
	float bound = max(DepthData.w, 1.0f);
	return exp2(saturate(encoded) * log2(1.0f + bound)) - 1.0f;
}

float SafeHeightDensity(float worldHeight) {
	float exponent = -MediumData0.z * (worldHeight - MediumData0.w);
	return MediumData0.y * exp(clamp(exponent, -MaximumExponent, MaximumExponent));
}

float AnalyticHeightOpticalDepth(float distance, float worldOriginZ, float worldDirectionZ) {
	float densityAtOrigin = SafeHeightDensity(worldOriginZ);
	float slope = MediumData0.z * worldDirectionZ;
	float span = slope * distance;
	if (abs(span) < 0.001f) {
		return densityAtOrigin * distance;
	}
	float exponent = exp(clamp(-span, -MaximumExponent, MaximumExponent));
	return densityAtOrigin * (1.0f - exponent) / slope;
}

float DensityVariation(float3 worldPosition) {
	float scale = MediumData1.w;
	float2 uv = worldPosition.xy * scale;
	uv += worldPosition.z * scale * float2(0.754877666f, 0.569840296f);
	float3 noise = tex2Dlod(DensityNoise, float4(uv, 0.0f, 0.0f)).rgb;
	return dot(noise, float3(0.333333333f, 0.333333333f, 0.333333333f)) * 2.0f - 1.0f;
}

float HeterogeneousCorrection(float distance, float3 worldOrigin, float3 worldDirection) {
	if (MediumData1.z <= 0.0f || distance <= 0.0f) {
		return 0.0f;
	}
	float stepLength = distance / ATMOSPHERE_SAMPLE_COUNT;
	float correction = 0.0f;
	[unroll]
	for (int index = 0; index < ATMOSPHERE_SAMPLE_COUNT; ++index) {
		float sampleDistance = (index + 0.5f) * stepLength;
		float3 worldPosition = worldOrigin + worldDirection * sampleDistance;
		float localDensity = MediumData0.x + SafeHeightDensity(worldPosition.z);
		float variation = DensityVariation(worldPosition) * MediumData1.z;
		correction += max(localDensity, 0.0f) * variation * stepLength;
	}
	return correction;
}

float HenyeyGreenstein(float mu, float anisotropy) {
	float g = clamp(anisotropy, -0.8f, 0.9f);
	float denominator = max(1.0f + g * g - 2.0f * g * clamp(mu, -1.0f, 1.0f), 0.000001f);
	return (1.0f - g * g) * InverseFourPi / pow(denominator, 1.5f);
}

// A normalized isotropic/HG mixture preserves total angular energy while
// limiting peak directional response to two isotropic units. The native sky
// owns compact solar haze; a second unbounded forward lobe over it washed out
// sky and hid shadow contrast at other angles. Local lights retain their
// independent HG response in atmosphere_local_light.hlsl.
float DirectionalPhase(float mu, float anisotropy) {
    float g = clamp(anisotropy, -0.8f, 0.9f);
    float hg = HenyeyGreenstein(mu, g) * FourPi;
    return lerp(1.0f, hg, LightingMediumData.z);
}

#ifdef OMV_WORLD_FIELD
// Same EVSM4 and actor coverage contract as shadow_directional_mask.
float ReduceLightBleeding(float probability, float amount) {
    // All four production bleed values are in [0.1, 0.8], so the
    // denominator is already at least 0.2. Preserve division/rounding.
    return saturate((probability - amount) / (1.0f - amount));
}

float Chebyshev(float2 moments, float receiver, float minimumVariance, float bleedReduction) {
    if (receiver <= moments.x) return 1.0f;
    float variance = max(moments.y - moments.x * moments.x, minimumVariance);
    float difference = receiver - moments.x;
    return ReduceLightBleeding(variance / (variance + difference * difference), bleedReduction);
}

float Evsm4(float4 moments, float depth, float bleedReduction) {
    float normalized = depth * 2.0f - 1.0f;
    // Evaluate positive/negative moments sequentially inside the volume loop.
    float receiver = exp(5.54f * normalized);
    float scale = 0.01f * 5.54f * receiver;
    float visibility = Chebyshev(moments.xz, receiver, scale * scale, bleedReduction);
    receiver = -exp(-5.0f * normalized);
    scale = 0.01f * 5.0f * receiver;
    return min(visibility, Chebyshev(moments.yw, receiver, scale * scale, bleedReduction));
}

float2 AtlasUv(float2 localUv, int cascadeIndex) {
    float2 quadrant = cascadeIndex == 0 ? float2(0.0f, 0.0f)
        : (cascadeIndex == 1 ? float2(0.5f, 0.0f)
        : (cascadeIndex == 2 ? float2(0.0f, 0.5f) : float2(0.5f, 0.5f)));
    localUv = clamp(localUv, CascadeTexel.xx, CascadeTexel.yy);
    return localUv * 0.5f + quadrant;
}

float2 SampleActorDepthCoverage(float2 uv, int cascadeIndex) {
    if (cascadeIndex < 2) {
        float2 packedUv = float2(uv.x * 0.5f + 0.5f * cascadeIndex, uv.y);
        return tex2Dlod(ActorNearMiddleMoments, float4(packedUv, 0.0f, 0.0f)).rg;
    }
    return tex2Dlod(ActorFarMoments, float4(uv, 0.0f, 0.0f)).rg;
}

float ActorVisibility(float2 depthCoverage, float receiverDepth) {
    float coverage = saturate(depthCoverage.y);
    if (coverage <= 0.0001f) return 1.0f;
    float actorDepth = depthCoverage.x / max(coverage, 0.0001f);
    return receiverDepth <= actorDepth + 0.0005f ? 1.0f : 1.0f - coverage;
}

float2 CascadeVisibility(int cascadeIndex, float3 ndc) {
    float2 localUv = float2(ndc.x * 0.5f + 0.5f, 0.5f - ndc.y * 0.5f);
    float border = min(min(localUv.x, 1.0f - localUv.x), min(localUv.y, 1.0f - localUv.y));
    border = min(border, min(ndc.z, 1.0f - ndc.z));
    // The same border rejects outside and zero-weight boundary samples
    // before fetching moments; no separate UV/depth admission is needed.
    float contribution = smoothstep(0.0f, 0.05f, border);
    if (contribution == 0.0f) return float2(1.0f, 0.0f);

    float bleed = cascadeIndex == 0 ? 0.1f
        : (cascadeIndex == 1 ? 0.2f : (cascadeIndex == 2 ? 0.6f : 0.8f));
    float4 staticCenter = tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv, cascadeIndex), 0.0f, 0.0f));
    float actorVisibility = 1.0f;
    if (cascadeIndex < 3 && ActorControl[cascadeIndex] > 0.5f) {
        float4 crop = cascadeIndex == 0 ? ActorCrops[0] : (cascadeIndex == 1 ? ActorCrops[1] : ActorCrops[2]);
        float2 actorUv = localUv * crop.xy + crop.zw;
        if (min(actorUv.x, actorUv.y) >= 0.0f && max(actorUv.x, actorUv.y) <= 1.0f) {
            actorVisibility = ActorVisibility(
                SampleActorDepthCoverage(clamp(actorUv, ActorTexel.xx, ActorTexel.yy), cascadeIndex),
                saturate(ndc.z));
        }
    }
    float visibility = min(Evsm4(staticCenter, saturate(ndc.z), bleed), actorVisibility);
    // The multisample-resolved atlas is bilinearly filtered at each volume
    // sample. Keep the surface receiver's extra three-tap edge refinement out
    // of this repeated volume lookup to bound register pressure and GPU work.

    return float2(visibility, contribution);
}

float DirectionalVisibility(float distance, float3 ray0, float3 ray1, float3 ray2, float3 ray3) {
    float blocked = 0.0f;
    float remaining = 1.0f;
    [loop]
    for (int cascade = 0; cascade < 4; ++cascade) {
        float3 projected;
        if (cascade == 0) projected = CascadeMatrices[0][3].xyz + ray0 * distance;
        else if (cascade == 1) projected = CascadeMatrices[1][3].xyz + ray1 * distance;
        else if (cascade == 2) projected = CascadeMatrices[2][3].xyz + ray2 * distance;
        else projected = CascadeMatrices[3][3].xyz + ray3 * distance;
        float2 sample = CascadeVisibility(cascade, projected);
        float weight = remaining * sample.y;
        blocked += weight * (1.0f - sample.x);
        remaining -= weight;
        if (remaining <= 0.0001f) break;
    }
    return 1.0f - blocked;
}

// Orthographic atlas transforms preserve w=1. Clip the world ray against the
// actual outer-map box, including depth, rather than view-depth/cosine range.
float WorldShadowExit(float3 direction) {
    float3 origin = mul(float4(0.0f, 0.0f, 0.0f, 1.0f), CascadeMatrices[3]).xyz;
    float3 ray = mul(float4(direction, 0.0f), CascadeMatrices[3]).xyz;
    float exitDistance = MediumData1.x;
    [unroll]
    for (int axis = 0; axis < 3; ++axis) {
        float minimum = axis == 2 ? 0.0f : -1.0f;
        if (abs(ray[axis]) > 0.0000001f) {
            float endpoint = ray[axis] > 0.0f ? 1.0f : minimum;
            exitDistance = min(exitDistance, (endpoint - origin[axis]) / ray[axis]);
        } else if (origin[axis] < minimum || origin[axis] > 1.0f) {
            return 0.0f;
        }
    }
    return max(exitDistance, 0.0f);
}

float IntegratedWorldBlockage(float3 origin, float3 direction, float distance, float shadowExit) {
    float shadowDistance = min(distance, shadowExit);
    // Empty covered intervals have exactly zero extinction and blockage.
    if (shadowDistance <= 0.0f) return 0.0f;
    float stepLength = shadowDistance / WorldShadowControl.z;
    float blockedAmount = 0.0f;
    float transmittance = 1.0f;
    // The height exponent is affine along this fixed world ray.
    // Clamp each sample's exponent exactly as the original density path did.
    float heightOrigin = -MediumData0.z * (origin.z - MediumData0.w);
    float heightSlope = -MediumData0.z * direction.z;
    // Orthographic projection is affine along the ray. Each constant-index
    // direction transform is shared by every midpoint in this march.
    float3 ray0 = mul(float4(direction, 0.0f), CascadeMatrices[0]).xyz;
    float3 ray1 = mul(float4(direction, 0.0f), CascadeMatrices[1]).xyz;
    float3 ray2 = mul(float4(direction, 0.0f), CascadeMatrices[2]).xyz;
    float3 ray3 = mul(float4(direction, 0.0f), CascadeMatrices[3]).xyz;
    [loop]
    for (int index = 0; index < (int)WorldShadowControl.z; ++index) {
        float sampleDistance = (index + 0.5f) * stepLength;
        float3 position = origin + direction * sampleDistance;
        // Both density coefficients are nonnegative production constants.
        float density = MediumData0.x + MediumData0.y * exp(clamp(
            heightOrigin + heightSlope * sampleDistance, -MaximumExponent, MaximumExponent));
        if (MediumData1.z > 0.0f) {
            density *= max(1.0f + DensityVariation(position) * MediumData1.z, 0.0f);
        }
        // Nonnegative density and step make the lower clamp redundant.
        float segmentT = exp(-min(density * stepLength, MaximumOpticalDepth));
        float visibility = DirectionalVisibility(sampleDistance, ray0, ray1, ray2, ray3);
        blockedAmount += transmittance * (1.0f - segmentT) * (1.0f - visibility);
        transmittance *= segmentT;
    }
    return saturate(blockedAmount);
}
#endif

#ifndef OMV_WORLD_FIELD
float WorldBlockage(float2 uv, float encodedDistance) {
    float2 pixel = uv * WorldFieldTarget.xy - 0.5f;
    float2 base = floor(pixel);
    float2 fraction = frac(pixel);
    float blocked = 0.0f;
    float totalWeight = 0.0f;
    [unroll]
    for (int tap = 0; tap < 4; ++tap) {
        float2 offset = float2(tap == 1 || tap == 3 ? 1.0f : 0.0f, tap >= 2 ? 1.0f : 0.0f);
        float2 sampleUv = (base + offset + 0.5f) * WorldFieldTarget.zw;
        float4 field = tex2Dlod(ShaftVisibility, float4(sampleUv, 0.0f, 0.0f));
        float span = max(field.w - field.z, 0.0f);
        float blend = span > 0.0001f ? saturate((encodedDistance - field.z) / span) : 0.0f;
        float matched = clamp(encodedDistance, field.z, field.w);
        // Keys use the same log-depth encoding as production reduced depth.
        float distance = DecodeDistance(encodedDistance);
        float tolerance = max(256.0f, distance * 0.02f);
        float depthWeight = saturate(1.0f - abs(distance - DecodeDistance(matched)) / tolerance);
        float2 spatial = lerp(1.0f - fraction, fraction, offset);
        float weight = spatial.x * spatial.y * depthWeight * depthWeight;
        blocked += lerp(field.x, field.y, blend) * weight;
        totalWeight += weight;
    }
    return totalWeight > 0.0001f ? blocked / totalWeight : 0.0f;
}
#endif

#ifdef OMV_WORLD_FIELD
float4 WorldFieldMain(PixelInput input)
#else
float4 Main(PixelInput input)
#endif
: COLOR0 {
	if (GateData.x < 0.5f || GateData.y < 0.5f || GateData.z > 0.5f) {
		return IdentityMedium();
	}

	float2 encodedDepth = tex2Dlod(ReducedDepth, float4(input.uv, 0.0f, 0.0f)).rg;
#ifndef OMV_WORLD_FIELD
    // Both layers use this exact depth packet and ray. Equal endpoints must
    // produce identical scattering/transmittance, including density noise.
    // Reuse the completed near layer before any ray, phase or noise work.
    if (GateData.w > 0.5f && encodedDepth.x == encodedDepth.y) {
        return tex2Dlod(CompletedNearAtmosphere, float4(input.uv, 0.0f, 0.0f));
    }
#endif
	float encodedDistance = lerp(encodedDepth.x, encodedDepth.y, saturate(GateData.w));
	float distance = min(DecodeDistance(encodedDistance), min(MediumData1.x, DepthData.w));
	distance = max(distance, 0.0f);

	float viewX = lerp(CameraFrustum.x, CameraFrustum.y, input.uv.x);
	float viewY = lerp(CameraFrustum.w, CameraFrustum.z, input.uv.y);
	float3 viewDirection = normalize(float3(viewX, viewY, 1.0f));
	float3 worldRay = float3(
		dot(ViewToWorld0.xyz, viewDirection),
		dot(ViewToWorld1.xyz, viewDirection),
		dot(ViewToWorld2.xyz, viewDirection)
	);
	float worldRayLength = length(worldRay);
	if (!IsFiniteVector(worldRay) || !IsFiniteScalar(worldRayLength) || worldRayLength <= 0.000001f) {
		return IdentityMedium();
	}
	float3 worldDirection = worldRay / worldRayLength;
	float3 worldOrigin = float3(ViewToWorld0.w, ViewToWorld1.w, ViewToWorld2.w);

#ifdef OMV_WORLD_FIELD
    float shadowExit = WorldShadowExit(worldDirection);
    float nearDistance = max(min(DecodeDistance(encodedDepth.x), min(MediumData1.x, DepthData.w)), 0.0f);
    float farDistance = max(min(DecodeDistance(encodedDepth.y), min(MediumData1.x, DepthData.w)), 0.0f);
    float nearBlocked = IntegratedWorldBlockage(worldOrigin, worldDirection, nearDistance, shadowExit);
    float farBlocked = nearBlocked;
    if (min(farDistance, shadowExit) > min(nearDistance, shadowExit)) {
        farBlocked = IntegratedWorldBlockage(worldOrigin, worldDirection, farDistance, shadowExit);
    }
    return float4(nearBlocked, farBlocked, encodedDepth);
#else

	float opticalDepth = MediumData0.x * distance;
	opticalDepth += max(AnalyticHeightOpticalDepth(distance, worldOrigin.z, worldDirection.z), 0.0f);
	opticalDepth += HeterogeneousCorrection(distance, worldOrigin, worldDirection);
	if (!IsFiniteScalar(opticalDepth)) {
		return IdentityMedium();
	}
	opticalDepth = clamp(opticalDepth, 0.0f, MaximumOpticalDepth);

	float transmittance = exp(-opticalDepth);
	float scatterAmount = (1.0f - transmittance) * saturate(MediumData1.y);
	float3 scattering = max(MediumColor.rgb, 0.0f) * scatterAmount * saturate(MediumColor.w);
	if (LightingData.w > 0.5f) {
		// The same particles must scatter and extinguish light. Lighting-only
		// operation already supplies its density through MediumData0.x; an
		// independent lower bound here emits sunlight in otherwise empty air.
		float directionalScatterAmount = scatterAmount;
		float shaft = 1.0f;
		if (WorldShadowControl.x > 0.5f) {
            float blockedAmount = WorldBlockage(input.uv, encodedDistance);
            shaft = 1.0f - saturate(WorldShadowControl.y) * saturate(blockedAmount / max(1.0f - transmittance, 0.000001f));
		} else if (SunDirection.w > 0.5f) {
			shaft = saturate(tex2Dlod(ShaftVisibility, float4(input.uv, 0.0f, 0.0f)).r);
		}
		float mu = dot(worldDirection, SunDirection.xyz);
		// FNV supplies irradiance-scale direct light, not radiance per steradian.
		float phase = DirectionalPhase(mu, LightingData.y);
		float diskLobe = AuthoredSunCoverage(input.uv);
		float3 radiance = max(SunColor.rgb, 0.0f)
			+ max(SunDiskDelta.rgb, 0.0f) * max(LightingData.z, 0.0f) * diskLobe;

		scattering += radiance
			* max(LightingData.x, 0.0f)
			* saturate(SunColor.w)
			* phase
			* directionalScatterAmount
			* shaft;
	}
	if (!IsFiniteScalar(transmittance) || !IsFiniteVector(scattering)) {
		return IdentityMedium();
	}
	return float4(scattering, saturate(transmittance));
#endif
}
