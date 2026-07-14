sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);
sampler2D WorldColor : register(s3);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 DepthData : register(c11);
float4 FirstPersonCameraData : register(c13);

static const float DepthEndpointEpsilon = 0.000001f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float HardwareDepth(float2 uv) {
    return tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
}

float FirstPersonHardwareDepth(float2 uv) {
    return tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
}

bool UseWorldReversedDepth() {
	return DepthData.x >= 0.0f ? DepthData.x > 0.5f : OptionData0.x > 0.5f;
}

float ClipBias() {
    return max(OptionData0.y, 0.0f);
}

float ClipFeather() {
    return max(OptionData0.z, 0.000001f);
}

bool IsEndpointDepth(float depth) {
    return depth <= DepthEndpointEpsilon || depth >= (1.0f - DepthEndpointEpsilon);
}

bool UseFirstPersonReversedDepth() {
	return DepthData.y >= 0.0f ? DepthData.y > 0.5f : OptionData0.x > 0.5f;
}

float LinearDepth(float depth, float2 nearFar, bool reversedDepth) {
	float nearZ = max(nearFar.x, 0.01f);
	float farZ = max(nearFar.y, nearZ + 1.0f);
	if (reversedDepth) {
		return (nearZ * farZ) / max(depth * (farZ - nearZ) + nearZ, 0.001f);
	}

	return (nearZ * farZ) / max(farZ - depth * (farZ - nearZ), 0.001f);
}

float OcclusionAmount(float worldDepth, float firstPersonDepth) {
	float worldViewZ = LinearDepth(worldDepth, CameraData.xy, UseWorldReversedDepth());
	float firstPersonViewZ = LinearDepth(
		firstPersonDepth,
		FirstPersonCameraData.xy,
		UseFirstPersonReversedDepth()
	);
	float referenceDepth = max(min(worldViewZ, firstPersonViewZ), 1.0f);
	float delta = firstPersonViewZ - worldViewZ;
	float bias = ClipBias() * referenceDepth;
	float feather = ClipFeather() * referenceDepth;

	float amount = saturate((delta - bias) / feather);
    return amount >= 0.5f ? 1.0f : 0.0f;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 color = tex2D(SceneColor, input.uv);

	if (FrameData.w < 0.5f || DepthData.z < 0.5f || DepthData.w < 0.5f) {
        return color;
    }

    float firstPersonDepth = FirstPersonHardwareDepth(input.uv);
    if (IsEndpointDepth(firstPersonDepth)) {
        return color;
    }

    float worldDepth = HardwareDepth(input.uv);
    if (IsEndpointDepth(worldDepth)) {
        return color;
    }

    float clip = OcclusionAmount(worldDepth, firstPersonDepth);
    if (clip <= 0.0f) {
        return color;
    }

    float4 worldColor = tex2D(WorldColor, input.uv);
    return lerp(color, worldColor, clip);
}
