sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 EnvironmentData : register(c6);
float4 OptionData3 : register(c7);
float4 SunData : register(c8);
float4 DepthData : register(c11);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 LuminanceFactors = float3(0.2126f, 0.7152f, 0.0722f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

bool UseReversedDepth() {
	return DepthData.x >= 0.0f ? DepthData.x > 0.5f : OptionData2.z > 0.5f;
}

bool IsInsideScreen(float2 uv) {
    return uv.x >= 0.0f && uv.y >= 0.0f && uv.x <= 1.0f && uv.y <= 1.0f;
}

float HardwareDepth(float2 uv) {
    return tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
}

float FirstPersonHardwareDepth(float2 uv) {
    return tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
}

float3 SceneSample(float2 uv) {
    return tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f)).rgb;
}

float ScreenDistance(float2 a, float2 b) {
    float aspect = max(CameraData.z, 0.1f);
    return length((a - b) * float2(aspect, 1.0f));
}

float LinearDepth(float depth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    if (UseReversedDepth()) {
        return (nearZ * farZ) / max(depth * (farZ - nearZ) + nearZ, 0.001f);
    }

    return (nearZ * farZ) / max(farZ - depth * (farZ - nearZ), 0.001f);
}

float SkyMask(float2 uv) {
    if (!IsInsideScreen(uv) || FrameData.w < 0.5f) {
        return 0.0f;
    }

    float rawDepth = HardwareDepth(uv);
    float linearDepth = LinearDepth(rawDepth);
    float farZ = max(CameraData.y, 2.0f);

    if (UseReversedDepth()) {
        float endpointSky = 1.0f - Smooth01(rawDepth / 0.000080f);
        float farSky = Smooth01((linearDepth - farZ * 0.985f) / max(farZ * 0.015f, 1.0f));
        return saturate(max(endpointSky, farSky));
    }

    float endpointSky = Smooth01((rawDepth - 0.999920f) / 0.000080f);
    float farSky = Smooth01((linearDepth - farZ * 0.985f) / max(farZ * 0.015f, 1.0f));
    return saturate(max(endpointSky, farSky));
}

float FirstPersonMask(float2 uv) {
    if (!IsInsideScreen(uv) || FrameData.w < 0.5f) {
        return 0.0f;
    }

    float depth = FirstPersonHardwareDepth(uv);
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon) ? 1.0f : 0.0f;
}

float FirstPersonBlock(float2 uv) {
    float2 texel = ScreenData.zw;
    float mask = FirstPersonMask(uv);
    mask = max(mask, FirstPersonMask(uv + float2( texel.x * 1.5f, 0.0f)));
    mask = max(mask, FirstPersonMask(uv + float2(-texel.x * 1.5f, 0.0f)));
    mask = max(mask, FirstPersonMask(uv + float2(0.0f,  texel.y * 1.5f)));
    mask = max(mask, FirstPersonMask(uv + float2(0.0f, -texel.y * 1.5f)));
    return mask * saturate(OptionData2.x);
}

float RawBrightness(float3 color) {
    float luminance = dot(color, LuminanceFactors);
    float peak = max(color.r, max(color.g, color.b));
    return max(luminance, peak * 0.72f);
}

float ShaftSourceMask(float3 color) {
    float threshold = saturate(OptionData1.z) * 0.58f;
    float brightness = RawBrightness(color);
    float broad = Smooth01((brightness - threshold) / max(1.0f - threshold, 0.001f));
    return saturate(broad);
}

float SunScreenFade(float2 sunUv) {
    float margin = 0.32f;
    float xEdge = min(sunUv.x, 1.0f - sunUv.x);
    float yEdge = min(sunUv.y, 1.0f - sunUv.y);
    float fadeX = Smooth01((xEdge + margin) / margin);
    float fadeY = Smooth01((yEdge + margin) / margin);
    return saturate(fadeX * fadeY * max(SunData.w, 0.0f));
}

float SceneSunSource(float2 uv, float pathOpen) {
	float visibility = SunScreenFade(SunData.xy);
	if (visibility <= 0.0f || pathOpen <= 0.0f) {
		return 0.0f;
	}

	float distanceToSun = ScreenDistance(uv, SunData.xy);
	float fieldRadius = max(OptionData2.y, 0.08f);
	float field = 1.0f - Smooth01(distanceToSun / fieldRadius);
	float sceneSource = ShaftSourceMask(SceneSample(uv));
	return visibility * pathOpen * field * sceneSource;
}

float4 Main(PixelInput input) : COLOR0 {
	float sky = SkyMask(input.uv);
	float firstPerson = FirstPersonBlock(input.uv);
	float pathOpen = sky * (1.0f - firstPerson);
	float source = SceneSunSource(input.uv, pathOpen);

    return float4(source, pathOpen, firstPerson, 1.0f);
}
