sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);

#ifndef AO_FAMILY_MODE
#define AO_FAMILY_MODE 3
#endif

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 FastOption0 : register(c3);
float4 FastOption1 : register(c4);
float4 FastOption2 : register(c5);
float4 ContactOption0 : register(c7);
float4 ContactOption1 : register(c8);
float4 ContactOption2 : register(c9);
float4 DepthData : register(c11);
float4 CameraFrustum : register(c12);
float4 DepthPrecisionData : register(c19);
float4 DepthLinearizeData : register(c20);

static const float DepthEndpointEpsilon = 0.000001f;
static const float MinFastRadiusPixels = 1.0f;
static const float MinFastRange = 0.35f;
static const float MinFastBias = 0.015f;
static const float FastDepthBiasScale = 0.000035f;
static const float MinContactRange = 0.08f;
static const float MinContactBias = 0.01f;
static const float KernelTurn = 0.70710678f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

bool IsInsideScreen(float2 uv) {
    return uv.x >= 0.0f && uv.y >= 0.0f && uv.x <= 1.0f && uv.y <= 1.0f;
}

bool UseReversedDepth() {
	if (DepthData.x >= 0.0f) {
		return DepthData.x > 0.5f;
	}

	return FastOption1.y > 0.5f || ContactOption1.y > 0.5f;
}

float HardwareDepth(float2 uv) {
    return tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
}

float FirstPersonHardwareDepth(float2 uv) {
    return tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
}

bool IsValidDepth(float depth, bool reversedDepth) {
    if (reversedDepth) {
        return depth >= 0.0f && depth <= 1.0f;
    }

    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float LinearDepth(float depth, bool reversedDepth) {
    if (reversedDepth) {
        return DepthLinearizeData.x
            / max(depth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }

    return DepthLinearizeData.x
        / max(DepthLinearizeData.w - depth * DepthLinearizeData.y, 0.001f);
}

bool IsSkyDepth(float rawDepth, float linearDepth, bool reversedDepth) {
    float farZ = DepthLinearizeData.w;
    if (reversedDepth) {
        return rawDepth <= DepthEndpointEpsilon || linearDepth >= farZ * 0.995f;
    }

    return rawDepth >= (1.0f - DepthEndpointEpsilon) || linearDepth >= farZ * 0.995f;
}

bool FirstPersonMaskEnabled() {
    return FrameData.z > 0.5f && (FastOption2.y > 0.5f || ContactOption2.x > 0.5f);
}

bool IsFirstPersonPixel(float2 uv) {
    if (!IsInsideScreen(uv) || !FirstPersonMaskEnabled()) {
        return false;
    }

    float depth = FirstPersonHardwareDepth(uv);
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float DepthKey(float linearDepth) {
    float farZ = DepthLinearizeData.w;
    return saturate(log2(linearDepth + 1.0f) / max(log2(farZ + 1.0f), 0.001f));
}

float DepthPrecisionBias(float linearDepth) {
	return linearDepth * linearDepth * max(DepthPrecisionData.x, 0.0f);
}

float FastRadiusPixels(float linearDepth) {
	float maxRadius = max(FastOption0.z, MinFastRadiusPixels);
	float range = max(linearDepth * FastOption0.w, MinFastRange);
	float frustumWidth = max(CameraFrustum.y - CameraFrustum.x, 0.001f);
	float projectedRadius = range * ScreenData.x / max(linearDepth * frustumWidth, 0.001f);
	float radiusScale = max(FastOption0.y, 1.0f) / 75.5f;
	return clamp(projectedRadius * radiusScale, MinFastRadiusPixels, maxRadius);
}

float3 ReconstructViewPosition(float2 uv, float linearDepth) {
	float viewX = lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * linearDepth;
	float viewY = lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * linearDepth;
	return float3(viewX, viewY, linearDepth);
}

float2 DepthTexelCenter(float2 uv) {
	float2 pixel = min(floor(uv * ScreenData.xy), ScreenData.xy - 1.0f);
	return (pixel + 0.5f) * ScreenData.zw;
}

bool LoadViewPosition(float2 uv, bool reversedDepth, out float3 position) {
	position = 0.0f;
	if (!IsInsideScreen(uv)) {
		return false;
	}

	float2 sampleUv = DepthTexelCenter(uv);
	float rawSampleDepth = HardwareDepth(sampleUv);
	if (!IsValidDepth(rawSampleDepth, reversedDepth)) {
		return false;
	}

	float sampleDepth = LinearDepth(rawSampleDepth, reversedDepth);
	if (IsSkyDepth(rawSampleDepth, sampleDepth, reversedDepth)) {
		return false;
	}
	position = ReconstructViewPosition(sampleUv, sampleDepth);
	return true;
}

float3 ReconstructNormal(float2 uv, bool reversedDepth, float3 centerPosition) {
	float3 left;
	float3 right;
	float3 up;
	float3 down;
	bool leftValid = LoadViewPosition(
		uv - float2(ScreenData.z, 0.0f), reversedDepth, left
	);
	bool rightValid = LoadViewPosition(
		uv + float2(ScreenData.z, 0.0f), reversedDepth, right
	);
	bool upValid = LoadViewPosition(
		uv - float2(0.0f, ScreenData.w), reversedDepth, up
	);
	bool downValid = LoadViewPosition(
		uv + float2(0.0f, ScreenData.w), reversedDepth, down
	);

	float3 dx = !leftValid
		? (rightValid ? right - centerPosition : 0.0f)
		: (!rightValid || abs(left.z - centerPosition.z) < abs(right.z - centerPosition.z)
			? centerPosition - left
			: right - centerPosition);
	float3 dy = !upValid
		? (downValid ? down - centerPosition : 0.0f)
		: (!downValid || abs(up.z - centerPosition.z) < abs(down.z - centerPosition.z)
			? centerPosition - up
			: down - centerPosition);
	float3 normal = cross(dx, dy);
	float lengthSquared = dot(normal, normal);
	return lengthSquared > 0.0000001f
		? normal * rsqrt(lengthSquared)
		: float3(0.0f, 0.0f, -1.0f);
}

float2 ProjectViewPosition(float3 position) {
	float invDepth = rcp(max(position.z, 0.001f));
	float viewX = position.x * invDepth;
	float viewY = position.y * invDepth;
	float u = (viewX - CameraFrustum.x) / max(CameraFrustum.y - CameraFrustum.x, 0.001f);
	float v = (CameraFrustum.w - viewY) / max(CameraFrustum.w - CameraFrustum.z, 0.001f);
	return float2(u, v);
}

float StableRotation(float2 uv) {
	float2 pixel = floor(uv * ScreenData.xy * 0.5f);
	return frac(52.9829189f * frac(dot(pixel, float2(0.06711056f, 0.00583715f)))) * 6.2831853f;
}

float ViewRadiusFromPixels(float radiusPixels, float linearDepth) {
	float frustumWidth = max(CameraFrustum.y - CameraFrustum.x, 0.001f);
	return max(radiusPixels, 0.5f) * linearDepth * frustumWidth / max(ScreenData.x, 1.0f);
}

float SampleProjectedOcclusion(
	float3 centerPosition,
	float3 normal,
	float3 tangent,
	float3 bitangent,
	float2 direction,
	float sampleScale,
	float radius,
	float bias,
	bool reversedDepth,
	bool rejectCoplanar
) {
	float3 hemisphereDirection = normalize(
		tangent * direction.x + bitangent * direction.y + normal * 0.55f
	);
	float3 expectedPosition = centerPosition + hemisphereDirection * radius * sampleScale;
	float2 sampleUv = ProjectViewPosition(expectedPosition);
	float3 actualPosition;
	if (!LoadViewPosition(sampleUv, reversedDepth, actualPosition)) {
		return 0.0f;
	}

	float depthDelta = centerPosition.z - actualPosition.z;
	if (abs(depthDelta) >= radius || actualPosition.z >= expectedPosition.z - bias) {
		return 0.0f;
	}

	if (rejectCoplanar && dot(actualPosition - centerPosition, normal) <= bias) {
		return 0.0f;
	}

	float falloff = 1.0f - Smooth01(abs(depthDelta) / max(radius, 0.001f));
	return falloff * falloff;
}

float KernelOcclusion(
	float3 centerPosition,
	float3 normal,
	float2 uv,
	float radiusPixels,
	float range,
	float bias,
	bool reversedDepth,
	bool rejectCoplanar
) {
	float3 axis = abs(normal.z) < 0.99f
		? float3(0.0f, 0.0f, 1.0f)
		: float3(0.0f, 1.0f, 0.0f);
	float3 tangent = normalize(cross(axis, normal));
	float3 bitangent = cross(normal, tangent);
	float angle = StableRotation(uv);
	float cosine = cos(angle);
	float sine = sin(angle);
	float2x2 rotation = float2x2(cosine, -sine, sine, cosine);
	float radius = min(
		max(range, 0.001f),
		ViewRadiusFromPixels(radiusPixels, centerPosition.z)
	);

	float occlusion = 0.0f;
	float2 direction = mul(float2(1.0f, 0.0f), rotation);
	[loop]
	for (int sampleIndex = 0; sampleIndex < 8; ++sampleIndex) {
		float sampleScale = sampleIndex < 4
			? 0.28f + 0.12f * sampleIndex
			: 0.73f + 0.09f * (sampleIndex - 4);
		occlusion += SampleProjectedOcclusion(
			centerPosition, normal, tangent, bitangent, direction,
			sampleScale, radius, bias, reversedDepth, rejectCoplanar
		);
		direction = float2(
			(direction.x - direction.y) * KernelTurn,
			(direction.x + direction.y) * KernelTurn
		);
	}
	return occlusion * 0.125f;
}

float4 NoOcclusion() {
    return float4(0.0f, 1.0f, 0.0f, 1.0f);
}

float4 Main(PixelInput input) : COLOR0 {
    if (FrameData.w < 0.5f) {
        return NoOcclusion();
    }

    if (IsFirstPersonPixel(input.uv)) {
        return NoOcclusion();
    }

    bool reversedDepth = UseReversedDepth();
	float2 centerUv = DepthTexelCenter(input.uv);
	float rawDepth = HardwareDepth(centerUv);
    if (!IsValidDepth(rawDepth, reversedDepth)) {
        return NoOcclusion();
    }

	float centerDepth = LinearDepth(rawDepth, reversedDepth);
    if (IsSkyDepth(rawDepth, centerDepth, reversedDepth)) {
        return NoOcclusion();
    }

    float fastStrength = max(FastOption0.x, 0.0f);
    float contactStrength = max(ContactOption0.x, 0.0f);
    if (fastStrength <= 0.0f && contactStrength <= 0.0f) {
        return float4(0.0f, DepthKey(centerDepth), 0.0f, 1.0f);
    }

	if (DepthData.z < 0.5f) {
		return NoOcclusion();
	}

	float3 centerPosition = ReconstructViewPosition(centerUv, centerDepth);
	float3 normal = ReconstructNormal(centerUv, reversedDepth, centerPosition);
	float fastRadius = FastRadiusPixels(centerDepth);
	float fastRange = max(centerDepth * FastOption0.w, MinFastRange);
	float fastBias = max(centerDepth * FastDepthBiasScale, MinFastBias);
	float contactRadius = max(ContactOption0.y, 0.5f);
	float contactRange = max(centerDepth * ContactOption0.z, MinContactRange);
	float contactBias = max(
		max(centerDepth * ContactOption0.w, MinContactBias),
		DepthPrecisionBias(centerDepth)
	);

	float amount = 0.0f;
#if AO_FAMILY_MODE != 2
	float fastOcclusion = KernelOcclusion(
		centerPosition, normal, input.uv,
		fastRadius, fastRange, fastBias, reversedDepth, false
	);
	amount += saturate(fastOcclusion) * fastStrength;
#endif
#if AO_FAMILY_MODE != 1
	float contactOcclusion = KernelOcclusion(
		centerPosition, normal, input.uv,
		contactRadius, contactRange, contactBias, reversedDepth, true
	);
	amount += saturate(contactOcclusion) * contactStrength;
#endif

    return float4(saturate(amount), DepthKey(centerDepth), 0.0f, 1.0f);
}
