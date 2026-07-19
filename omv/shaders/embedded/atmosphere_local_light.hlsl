sampler2D ReducedDepth : register(s0);
sampler2D DensityNoise : register(s1);
#if LOCAL_LIGHT_USE_NATIVE_SHADOW
sampler2D NativeShadow : register(s2);
#endif

#ifndef LOCAL_LIGHT_SAMPLE_COUNT
#define LOCAL_LIGHT_SAMPLE_COUNT 6
#endif

#ifndef LOCAL_LIGHT_BATCH_SIZE
#define LOCAL_LIGHT_BATCH_SIZE 1
#endif

#ifndef LOCAL_LIGHT_USE_NOISE
#define LOCAL_LIGHT_USE_NOISE 1
#endif

#ifndef LOCAL_LIGHT_USE_NATIVE_SHADOW
#define LOCAL_LIGHT_USE_NATIVE_SHADOW 0
#endif

float4 ReducedTarget : register(c0);
float4 DepthData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
float4 MediumData0 : register(c6);
float4 MediumData1 : register(c7);
float4 LocalPositionRadius0 : register(c8);
float4 LocalPositionRadius1 : register(c9);
float4 LocalPositionRadius2 : register(c10);
float4 LocalPositionRadius3 : register(c11);
float4 LocalColorIntensity0 : register(c12);
float4 LocalColorIntensity1 : register(c13);
float4 LocalColorIntensity2 : register(c14);
float4 LocalColorIntensity3 : register(c15);
float4 LocalControl : register(c16);
#if LOCAL_LIGHT_USE_NATIVE_SHADOW
float4 ShadowMatrix0 : register(c17);
float4 ShadowMatrix1 : register(c18);
float4 ShadowMatrix2 : register(c19);
float4 ShadowMatrix3 : register(c20);
#endif

static const float MaximumOpticalDepth = 40.0f;
static const float MaximumExponent = 20.0f;
static const float IntervalEpsilon = 0.0001f;
static const float ProjectionEpsilon = 0.000001f;
static const float MaximumLocalContribution = 8192.0f;

struct PixelInput {
	float2 uv : TEXCOORD0;
};

bool IsFiniteScalar(float value) {
	return value == value && abs(value) < 3.0e38f;
}

bool IsFiniteVector(float3 value) {
	return IsFiniteScalar(value.x) && IsFiniteScalar(value.y) && IsFiniteScalar(value.z);
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
#if LOCAL_LIGHT_USE_NOISE
	if (MediumData1.z <= 0.0f) {
		return 1.0f;
	}
	float scale = MediumData1.w;
	float2 uv = worldPosition.xy * scale;
	uv += worldPosition.z * scale * float2(0.754877666f, 0.569840296f);
	float3 noise = tex2Dlod(DensityNoise, float4(uv, 0.0f, 0.0f)).rgb;
	float centered = dot(noise, float3(0.333333333f, 0.333333333f, 0.333333333f)) * 2.0f - 1.0f;
	return max(1.0f + centered * MediumData1.z, 0.0f);
#else
	return 1.0f;
#endif
}

float HenyeyGreenstein(float mu, float anisotropy) {
	float g = clamp(anisotropy, -0.8f, 0.9f);
	float denominator = max(1.0f + g * g - 2.0f * g * clamp(mu, -1.0f, 1.0f), 0.000001f);
	return (1.0f - g * g) / (denominator * sqrt(denominator));
}

float ShadowVisibility(float3 worldPosition) {
#if LOCAL_LIGHT_USE_NATIVE_SHADOW
	float4 homogeneous = float4(worldPosition, 1.0f);
	float4 shadowPosition = float4(
		dot(ShadowMatrix0, homogeneous),
		dot(ShadowMatrix1, homogeneous),
		dot(ShadowMatrix2, homogeneous),
		dot(ShadowMatrix3, homogeneous)
	);
	if (!IsFiniteScalar(shadowPosition.w) || shadowPosition.w <= ProjectionEpsilon) {
		return 1.0f;
	}
	float2 shadowUv = float2(
		0.5f * shadowPosition.x / shadowPosition.w + 0.5f,
		0.5f - 0.5f * shadowPosition.y / shadowPosition.w
	);
	if (!IsFiniteScalar(shadowUv.x) || !IsFiniteScalar(shadowUv.y)
		|| shadowUv.x < 0.0f || shadowUv.x > 1.0f
		|| shadowUv.y < 0.0f || shadowUv.y > 1.0f
		|| !IsFiniteScalar(shadowPosition.z)) {
		return 1.0f;
	}
	float shadowDepth = tex2Dlod(NativeShadow, float4(shadowUv, 0.0f, 0.0f)).r;
	return shadowPosition.z < shadowDepth + LocalControl.x ? 1.0f : 0.0f;
#else
	return 1.0f;
#endif
}

float3 IntegrateLocalLight(
	float3 worldOrigin,
	float3 worldDirection,
	float depthDistance,
	float4 positionRadius,
	float4 colorIntensity
) {
	float3 toCenter = positionRadius.xyz - worldOrigin;
	float projectedCenter = dot(toCenter, worldDirection);
	float radius = positionRadius.w;
	float discriminant = projectedCenter * projectedCenter - (dot(toCenter, toCenter) - radius * radius);
	if (!IsFiniteScalar(discriminant) || discriminant <= 0.0f) {
		return 0.0f;
	}
	float root = sqrt(discriminant);
	float entry = max(projectedCenter - root, 0.0f);
	float exitDistance = min(projectedCenter + root, depthDistance);
	if (exitDistance - entry <= IntervalEpsilon) {
		return 0.0f;
	}

	float stepLength = (exitDistance - entry) / LOCAL_LIGHT_SAMPLE_COUNT;
	float entryOpticalDepth = MediumData0.x * entry
		+ max(AnalyticHeightOpticalDepth(entry, worldOrigin.z, worldDirection.z), 0.0f);
	float cameraTransmittance = exp(-clamp(entryOpticalDepth, 0.0f, MaximumOpticalDepth));
	float3 scattering = 0.0f;
	float visibilitySum = 0.0f;
	[loop]
	for (int sampleIndex = 0; sampleIndex < LOCAL_LIGHT_SAMPLE_COUNT; ++sampleIndex) {
		float sampleDistance = entry + (sampleIndex + 0.5f) * stepLength;
		float3 worldPosition = worldOrigin + worldDirection * sampleDistance;
		float density = max(MediumData0.x + SafeHeightDensity(worldPosition.z), 0.0f);
		density *= DensityVariation(worldPosition);
		float stepOpticalDepth = clamp(density * stepLength, 0.0f, MaximumOpticalDepth);
		float stepTransmittance = exp(-stepOpticalDepth);
		float midpointTransmittance = cameraTransmittance * sqrt(stepTransmittance);
		float3 lightVector = positionRadius.xyz - worldPosition;
		float distanceSquared = dot(lightVector, lightVector);
		float attenuation = saturate(1.0f - distanceSquared / max(radius * radius, ProjectionEpsilon));
		float inverseLightDistance = rsqrt(max(distanceSquared, ProjectionEpsilon));
		float3 directionToLight = lightVector * inverseLightDistance;
		float phase = HenyeyGreenstein(dot(worldDirection, directionToLight), LocalControl.z);
		float visibility = ShadowVisibility(worldPosition);
		visibilitySum += visibility;
		float scatterAmount = (1.0f - stepTransmittance) * saturate(MediumData1.y);
		scattering += colorIntensity.rgb
			* max(colorIntensity.w, 0.0f)
			* attenuation
			* phase
			* visibility
			* midpointTransmittance
			* scatterAmount;
		cameraTransmittance *= stepTransmittance;
	}

	if (LocalControl.w > 0.5f && LocalControl.w < 1.5f) {
		return float3(0.10f, 0.55f, 1.0f);
	}
	if (LocalControl.w >= 1.5f && LocalControl.w < 2.5f) {
		float visibility = visibilitySum / LOCAL_LIGHT_SAMPLE_COUNT;
		float3 shadowed = float3(0.65f, 0.02f, 0.02f);
		float3 visible = float3(0.02f, 0.65f, 0.12f);
		return lerp(shadowed, visible, visibility);
	}
	if (!IsFiniteVector(scattering)) {
		return 0.0f;
	}
	if (LocalControl.w >= 2.5f) {
		return saturate(scattering / (scattering + 0.01f)) * 0.65f;
	}
	return min(max(scattering, 0.0f), MaximumLocalContribution);
}

float4 Main(PixelInput input) : COLOR0 {
	float2 encodedDepth = tex2Dlod(ReducedDepth, float4(input.uv, 0.0f, 0.0f)).rg;
	float encodedDistance = lerp(encodedDepth.x, encodedDepth.y, saturate(LocalControl.y));
	float depthDistance = min(DecodeDistance(encodedDistance), min(MediumData1.x, DepthData.w));
	if (depthDistance <= IntervalEpsilon) {
		return 0.0f;
	}

	float viewX = lerp(CameraFrustum.x, CameraFrustum.y, input.uv.x);
	float viewY = lerp(CameraFrustum.w, CameraFrustum.z, input.uv.y);
	float3 viewDirection = normalize(float3(viewX, viewY, 1.0f));
	float3 worldRay = float3(
		dot(ViewToWorld0.xyz, viewDirection),
		dot(ViewToWorld1.xyz, viewDirection),
		dot(ViewToWorld2.xyz, viewDirection)
	);
	float rayLength = length(worldRay);
	if (!IsFiniteVector(worldRay) || !IsFiniteScalar(rayLength) || rayLength <= ProjectionEpsilon) {
		return 0.0f;
	}
	float3 worldDirection = worldRay / rayLength;
	float3 worldOrigin = float3(ViewToWorld0.w, ViewToWorld1.w, ViewToWorld2.w);
	float3 result = IntegrateLocalLight(
		worldOrigin,
		worldDirection,
		depthDistance,
		LocalPositionRadius0,
		LocalColorIntensity0
	);
#if LOCAL_LIGHT_BATCH_SIZE >= 2
	result += IntegrateLocalLight(
		worldOrigin,
		worldDirection,
		depthDistance,
		LocalPositionRadius1,
		LocalColorIntensity1
	);
#endif
#if LOCAL_LIGHT_BATCH_SIZE >= 3
	result += IntegrateLocalLight(
		worldOrigin,
		worldDirection,
		depthDistance,
		LocalPositionRadius2,
		LocalColorIntensity2
	);
#endif
#if LOCAL_LIGHT_BATCH_SIZE >= 4
	result += IntegrateLocalLight(
		worldOrigin,
		worldDirection,
		depthDistance,
		LocalPositionRadius3,
		LocalColorIntensity3
	);
#endif
	return float4(result, 0.0f);
}
