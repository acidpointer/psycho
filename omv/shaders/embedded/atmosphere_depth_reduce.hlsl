sampler2D SceneDepth : register(s0);

#ifndef ATMOSPHERE_REDUCTION_SCALE
#define ATMOSPHERE_REDUCTION_SCALE 2
#endif

float4 FullTarget : register(c0);
float4 ReducedTarget : register(c1);
float4 DepthData : register(c2);
float4 CameraFrustum : register(c3);

static const float DepthEpsilon = 0.000001f;

struct PixelInput {
	float2 uv : TEXCOORD0;
};

float LinearizeDepth(float rawDepth) {
	float nearZ = max(DepthData.x, 0.01f);
	float farZ = max(DepthData.y, nearZ + 1.0f);
	if (DepthData.z > 0.5f) {
		return (nearZ * farZ) / max(rawDepth * (farZ - nearZ) + nearZ, 0.001f);
	}
	return (nearZ * farZ) / max(farZ - rawDepth * (farZ - nearZ), 0.001f);
}

bool IsSky(float rawDepth) {
	return DepthData.z > 0.5f
		? rawDepth <= DepthEpsilon
		: rawDepth >= 1.0f - DepthEpsilon;
}

float RayDistance(float2 uv, float rawDepth) {
	if (IsSky(rawDepth)) {
		return DepthData.w;
	}
	float viewDepth = LinearizeDepth(rawDepth);
	float viewX = lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * viewDepth;
	float viewY = lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * viewDepth;
	return min(length(float3(viewX, viewY, viewDepth)), DepthData.w);
}

float SampleDistance(float2 pixel) {
	pixel = min(pixel, FullTarget.xy - 1.0f);
	float2 uv = (pixel + 0.5f) * FullTarget.zw;
	float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
	return RayDistance(uv, rawDepth);
}

float EncodeDistance(float distance) {
	return log2(1.0f + clamp(distance, 0.0f, DepthData.w))
		/ max(log2(1.0f + DepthData.w), 0.001f);
}

float4 Main(PixelInput input) : COLOR0 {
	float2 reducedPixel = floor(input.uv * ReducedTarget.xy);
	float2 basePixel = reducedPixel * ATMOSPHERE_REDUCTION_SCALE;
	float nearest = DepthData.w;
	float farthest = 0.0f;
	[unroll]
	for (int y = 0; y < ATMOSPHERE_REDUCTION_SCALE; ++y) {
		[unroll]
		for (int x = 0; x < ATMOSPHERE_REDUCTION_SCALE; ++x) {
			float distance = SampleDistance(basePixel + float2(x, y));
			nearest = min(nearest, distance);
			farthest = max(farthest, distance);
		}
	}
	return float4(EncodeDistance(nearest), EncodeDistance(farthest), 0.0f, 1.0f);
}
