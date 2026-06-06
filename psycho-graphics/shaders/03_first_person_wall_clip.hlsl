sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);
sampler2D WorldColor : register(s3);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);

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

bool UseReversedDepth() {
    return OptionData0.x > 0.5f;
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

float OcclusionAmount(float worldDepth, float firstPersonDepth) {
    float delta = UseReversedDepth()
        ? worldDepth - firstPersonDepth
        : firstPersonDepth - worldDepth;

    float amount = saturate((delta - ClipBias()) / ClipFeather());
    return amount >= 0.5f ? 1.0f : 0.0f;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 color = tex2D(SceneColor, input.uv);

    if (FrameData.w < 0.5f) {
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
