// Frozen production shader from 94e5cad, before radial segment coverage.
// Retains the original point-sampled visibility for GPU regression tests.
sampler2D ReducedDepth : register(s0);
sampler2D DensityNoise : register(s1);
#if LOCAL_LIGHT_SHADOW_MODE == 1
sampler2D NativeShadow : register(s2);
#elif LOCAL_LIGHT_SHADOW_MODE == 2
samplerCUBE OmvShadowCube0 : register(s2);
#if LOCAL_LIGHT_BATCH_SIZE >= 2
samplerCUBE OmvShadowCube1 : register(s3);
#endif
#if LOCAL_LIGHT_BATCH_SIZE >= 3
samplerCUBE OmvShadowCube2 : register(s4);
#endif
#if LOCAL_LIGHT_BATCH_SIZE >= 4
samplerCUBE OmvShadowCube3 : register(s5);
#endif
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

#ifndef LOCAL_LIGHT_SHADOW_MODE
#define LOCAL_LIGHT_SHADOW_MODE 0
#endif

#ifndef LOCAL_LIGHT_SKIP_SHARED_FAR
#define LOCAL_LIGHT_SKIP_SHARED_FAR 1
#endif

#ifndef LOCAL_LIGHT_UNIFORM_MEDIUM
#define LOCAL_LIGHT_UNIFORM_MEDIUM 1
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
float4 LocalPhaseControl : register(c21); // mixture, 1-g*g, 1+g*g, -2*g
#if LOCAL_LIGHT_SHADOW_MODE == 1
float4 ShadowMatrix0 : register(c17);
float4 ShadowMatrix1 : register(c18);
float4 ShadowMatrix2 : register(c19);
float4 ShadowMatrix3 : register(c20);
#elif LOCAL_LIGHT_SHADOW_MODE == 2
float4 ShadowCubeData : register(c17); // xyzw cube radii
float4 ShadowCubeWeight : register(c18); // xyzw occlusion-only fades
#endif

static const float MaximumOpticalDepth = 40.0f;
static const float MaximumExponent = 20.0f;
static const float IntervalEpsilon = 0.0001f;
static const float ProjectionEpsilon = 0.000001f;
static const float MaximumLocalContribution = 8192.0f;
// FNV exposes local-light diffuse/dimmer values, not photometric radiance.
// Calibrate that engine-space scalar so the shipped lighting-only medium has
// a useful 0..4 menu range without increasing directional extinction.
static const float NativeLightRadianceScale = 8.0f;

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

// Use the same energy-normalized isotropic/HG mixture as sunlight. Native
// diffuse/dimmer calibration must not acquire a second, unbounded angular
// gain as the camera crosses a lamp. The mixture retains anisotropy and has a
// peak of at most two isotropic units for every supported g.
float LocalPhase(float mu) {
	// Batch-invariant HG coefficients are uploaded once, rather than rebuilt
	// for every ray segment in every light.
	float denominator = max(LocalPhaseControl.z + LocalPhaseControl.w * clamp(mu, -1.0f, 1.0f), 0.000001f);
	float inverse = rsqrt(denominator);
	float hg = LocalPhaseControl.y * inverse * inverse * inverse;
	return lerp(1.0f, hg, LocalPhaseControl.x);
}

float ShadowVisibility(
	float3 worldPosition,
	float4 positionRadius
#if LOCAL_LIGHT_SHADOW_MODE == 2
	, float casterDepth,
	float cubeRadius,
	float shadowWeight
#endif
) {
#if LOCAL_LIGHT_SHADOW_MODE == 1
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
#elif LOCAL_LIGHT_SHADOW_MODE == 2
	if (shadowWeight <= 0.0f) return 1.0f;
	float3 toLight = positionRadius.xyz - worldPosition;
	// Neutral/invalid texels have no occluder. Reject them before distance and
	// soft comparison work; per-segment visibility otherwise repeats that work
	// even for an entirely clear cube.
	if (!(casterDepth > 0.0f && casterDepth < 1.0f)) return 1.0f;
	float distance = length(toLight);
	float normalizedDistance = distance / max(cubeRadius, ProjectionEpsilon);
	float comparisonBias = LocalControl.x * max(normalizedDistance, 0.25f);
	float comparisonWidth = max(comparisonBias, 0.02f);
	float visibility = 1.0f - smoothstep(
		casterDepth + comparisonBias - comparisonWidth,
		casterDepth + comparisonBias + comparisonWidth,
		normalizedDistance
	);
	// Single scattering is blocked at the sampled world point. A radius-based
	// release or brightness floor invents illuminated shells behind occluders.
	// Neutral/invalid cube texels remain the existing unshadowed fallback.
	return lerp(1.0f, visibility, shadowWeight);
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
#if LOCAL_LIGHT_SHADOW_MODE == 2
	, samplerCUBE shadowCube,
	float cubeRadius,
	float shadowWeight
#endif
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
	float entryOpticalDepth = MediumData0.x * entry;
	if (MediumData0.y > 0.0f) {
		entryOpticalDepth += max(AnalyticHeightOpticalDepth(entry, worldOrigin.z, worldDirection.z), 0.0f);
	}
	float cameraTransmittance = exp(-clamp(entryOpticalDepth, 0.0f, MaximumOpticalDepth));
	float3 nativeRadiance = colorIntensity.rgb * max(colorIntensity.w, 0.0f) * NativeLightRadianceScale;
	float3 scattering = 0.0f;
	float visibilitySum = 0.0f;
#if LOCAL_LIGHT_UNIFORM_MEDIUM
	bool variableDensity = MediumData0.y > 0.0f;
#if LOCAL_LIGHT_USE_NOISE
	variableDensity = variableDensity || MediumData1.z > 0.0f;
#endif
	float uniformStepTransmittance = 1.0f;
	if (!variableDensity) {
		uniformStepTransmittance = exp(-clamp(MediumData0.x * stepLength, 0.0f, MaximumOpticalDepth));
	}
#endif
	// Visibility belongs inside the integral: one closest-approach comparison
	// cannot classify the entire ray as its occluders and camera direction vary.
	[loop]
	for (int sampleIndex = 0; sampleIndex < LOCAL_LIGHT_SAMPLE_COUNT; ++sampleIndex) {
		float sampleDistance = entry + (sampleIndex + 0.5f) * stepLength;
		float3 worldPosition = worldOrigin + worldDirection * sampleDistance;
#if LOCAL_LIGHT_SHADOW_MODE == 2
		// Start the cube read before independent medium/noise arithmetic. The
		// compare still uses this exact segment, and zero fade performs no read.
		float casterDepth = 1.0f;
		if (shadowWeight > 0.0f) {
			float3 cubeDirection = (positionRadius.xyz - worldPosition) * float3(-1.0f, -1.0f, 1.0f);
			casterDepth = texCUBElod(shadowCube, float4(cubeDirection, 0.0f)).r;
		}
#endif
#if LOCAL_LIGHT_UNIFORM_MEDIUM
		float stepTransmittance = uniformStepTransmittance;
		if (variableDensity) {
#endif
			float density = MediumData0.x;
			if (MediumData0.y > 0.0f) density += SafeHeightDensity(worldPosition.z);
			density *= DensityVariation(worldPosition);
			float stepOpticalDepth = clamp(density * stepLength, 0.0f, MaximumOpticalDepth);
			float varyingTransmittance = exp(-stepOpticalDepth);
#if LOCAL_LIGHT_UNIFORM_MEDIUM
			stepTransmittance = varyingTransmittance;
		}
#else
		float stepTransmittance = varyingTransmittance;
#endif
		float visibility = ShadowVisibility(
			worldPosition,
			positionRadius
#if LOCAL_LIGHT_SHADOW_MODE == 2
			, casterDepth,
			cubeRadius,
			shadowWeight
#endif
		);
		visibilitySum += visibility;
		// A fully occluded sample has exactly zero single-scattering radiance.
		// Avoid its phase/attenuation work, but always advance transmittance:
		// later visible samples still look through this segment's medium.
		if (visibility > 0.0f) {
			float midpointTransmittance = cameraTransmittance * sqrt(stepTransmittance);
			float3 lightVector = positionRadius.xyz - worldPosition;
			float distanceSquared = dot(lightVector, lightVector);
			float attenuation = saturate(1.0f - distanceSquared / max(radius * radius, ProjectionEpsilon));
			float inverseLightDistance = rsqrt(max(distanceSquared, ProjectionEpsilon));
			float3 directionToLight = lightVector * inverseLightDistance;
			float phase = LocalPhase(dot(worldDirection, directionToLight));
			float scatterAmount = (1.0f - stepTransmittance) * saturate(MediumData1.y);
			scattering += nativeRadiance
				* attenuation
				* phase
				* visibility
				* midpointTransmittance
				* scatterAmount;
		}
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
#if LOCAL_LIGHT_SKIP_SHARED_FAR
	// Composition chooses the near layer independently at every gather tap
	// when its encoded endpoints match (span=0, layerBlend=0). The far local
	// contribution is then unused: skip its complete march and cube samples.
	// Mixed cells retain both integrations and their original composition.
	if (LocalControl.y > 0.5f && encodedDepth.x == encodedDepth.y) {
		return 0.0f;
	}
#endif
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
#if LOCAL_LIGHT_SHADOW_MODE == 2
		, OmvShadowCube0,
		ShadowCubeData.x,
		ShadowCubeWeight.x
#endif
	);
#if LOCAL_LIGHT_BATCH_SIZE >= 2
	result += IntegrateLocalLight(
		worldOrigin,
		worldDirection,
		depthDistance,
		LocalPositionRadius1,
		LocalColorIntensity1
#if LOCAL_LIGHT_SHADOW_MODE == 2
		, OmvShadowCube1,
		ShadowCubeData.y,
		ShadowCubeWeight.y
#endif
	);
#endif
#if LOCAL_LIGHT_BATCH_SIZE >= 3
	result += IntegrateLocalLight(
		worldOrigin,
		worldDirection,
		depthDistance,
		LocalPositionRadius2,
		LocalColorIntensity2
#if LOCAL_LIGHT_SHADOW_MODE == 2
		, OmvShadowCube2,
		ShadowCubeData.z,
		ShadowCubeWeight.z
#endif
	);
#endif
#if LOCAL_LIGHT_BATCH_SIZE >= 4
	result += IntegrateLocalLight(
		worldOrigin,
		worldDirection,
		depthDistance,
		LocalPositionRadius3,
		LocalColorIntensity3
#if LOCAL_LIGHT_SHADOW_MODE == 2
		, OmvShadowCube3,
		ShadowCubeData.w,
		ShadowCubeWeight.w
#endif
	);
#endif
	return float4(result, 0.0f);
}
