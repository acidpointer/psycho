sampler2D ReducedDepth : register(s0);
sampler2D DensityNoise : register(s1);
sampler2D ShaftVisibility : register(s2);

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

float4 Main(PixelInput input) : COLOR0 {
	if (GateData.x < 0.5f || GateData.y < 0.5f || GateData.z > 0.5f) {
		return IdentityMedium();
	}

	float2 encodedDepth = tex2Dlod(ReducedDepth, float4(input.uv, 0.0f, 0.0f)).rg;
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
		float mu = dot(worldDirection, SunDirection.xyz);
		// FNV supplies irradiance-scale direct light, not radiance per steradian.
		float phase = HenyeyGreenstein(mu, LightingData.y) * FourPi;
		float diskLobe = smoothstep(0.995f, 0.9999f, mu);
		float3 radiance = max(SunColor.rgb, 0.0f)
			+ max(SunDiskDelta.rgb, 0.0f) * max(LightingData.z, 0.0f) * diskLobe;
		float shaft = 1.0f;
		if (SunDirection.w > 0.5f) {
			shaft = saturate(tex2Dlod(ShaftVisibility, float4(input.uv, 0.0f, 0.0f)).r);
		}
		scattering += radiance
			* max(LightingData.x, 0.0f)
			* saturate(SunColor.w)
			* phase
			* scatterAmount
			* shaft;
	}
	if (!IsFiniteScalar(transmittance) || !IsFiniteVector(scattering)) {
		return IdentityMedium();
	}
	return float4(scattering, saturate(transmittance));
}
