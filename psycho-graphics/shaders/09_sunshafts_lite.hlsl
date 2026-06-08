/*
    Psycho Graphics sunshafts lite.

    Single-pass screen-space shafts for FNV. c8.xy is CPU-projected sun UV.
    The mask is depth-driven: world and first-person geometry block the ray taps.
*/

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

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 LuminanceFactors = float3(0.2126f, 0.7152f, 0.0722f);
static const float3 WarmTint = float3(1.0f, 0.80f, 0.46f);
static const float3 DayTint = float3(1.0f, 0.94f, 0.80f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

bool UseReversedDepth() {
    return OptionData2.z > 0.5f;
}

bool DebugMask() {
    return OptionData2.w > 0.5f;
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

float FirstPersonPathBlock(float2 uv) {
    return FirstPersonMask(uv) * saturate(OptionData2.x);
}

float RawBrightness(float3 color) {
    float luminance = dot(color, LuminanceFactors);
    float peak = max(color.r, max(color.g, color.b));
    return max(luminance, peak * 0.72f);
}

float BrightMask(float3 color) {
    float threshold = saturate(OptionData1.z);
    float brightness = RawBrightness(color);
    return Smooth01((brightness - threshold) / max(1.0f - threshold, 0.001f));
}

float FogAlpha(float linearDepth) {
    if (EnvironmentData.w < 0.5f) {
        return 0.0f;
    }

    float fogStart = EnvironmentData.x;
    float fogEnd = EnvironmentData.y;
    if (fogEnd <= fogStart || fogEnd <= 0.0f) {
        return 0.0f;
    }

    float fogPower = max(EnvironmentData.z, 0.001f);
    float fogT = saturate((linearDepth - fogStart) / max(fogEnd - fogStart, 0.001f));
    return max(pow(fogT, fogPower), Smooth01(fogT));
}

float OpenSkyMask(float2 uv) {
    return SkyMask(uv) * (1.0f - FirstPersonPathBlock(uv));
}

float ReceiverMask(float2 uv) {
    if (FirstPersonBlock(uv) > 0.0f) {
        return 0.0f;
    }

    float sky = SkyMask(uv);
    if (sky > 0.0f) {
        return sky;
    }

    float rawDepth = HardwareDepth(uv);
    float linearDepth = LinearDepth(rawDepth);
    float fogReceiver = FogAlpha(linearDepth) * 0.18f;
    return saturate(fogReceiver);
}

float OffscreenFade(float2 uv) {
    float2 outside = max(abs(uv - 0.5f) - 0.5f, float2(0.0f, 0.0f));
    return 1.0f - Smooth01(length(outside) / 0.28f);
}

float SunVisibility(float2 sunUv) {
    if (!IsInsideScreen(sunUv)) {
        return 0.0f;
    }

    float radiusPixels = max(OptionData3.x, 2.0f);
    float2 stepUv = ScreenData.zw * radiusPixels;
    float visibility = 0.0f;
    visibility += OpenSkyMask(sunUv) * 0.50f;
    visibility += OpenSkyMask(sunUv + float2( stepUv.x, 0.0f)) * 0.125f;
    visibility += OpenSkyMask(sunUv + float2(-stepUv.x, 0.0f)) * 0.125f;
    visibility += OpenSkyMask(sunUv + float2(0.0f,  stepUv.y)) * 0.125f;
    visibility += OpenSkyMask(sunUv + float2(0.0f, -stepUv.y)) * 0.125f;
    return saturate(visibility);
}

float SunEmitter(float2 sampleUv, float2 sunUv, float open) {
    if (open <= 0.0f) {
        return 0.0f;
    }

    float distanceToSun = ScreenDistance(sampleUv, sunUv);
    float coreRadius = max(OptionData3.y, 0.012f);
    float haloRadius = max(OptionData2.y, coreRadius * 2.0f);
    float core = 1.0f - Smooth01(distanceToSun / coreRadius);
    float halo = 1.0f - Smooth01(distanceToSun / haloRadius);
    float source = BrightMask(SceneSample(sampleUv));
    return open * source * (core * 0.78f + halo * 0.22f);
}

float ShaftTap(float2 sampleUv, float2 sunUv, float open, float transmittance, float weight) {
    float source = SunEmitter(sampleUv, sunUv, open);
    return source * transmittance * weight;
}

float RadialShaft(float2 uv, float2 sunUv) {
    float density = max(OptionData0.w, 0.10f);
    float decay = saturate(OptionData0.z);
    float blockedDecay = lerp(0.10f, 0.38f, saturate(OptionData3.w));
    float2 ray = (sunUv - uv) * density;
    float light = 0.0f;
    float totalWeight = 0.0f;
    float transmittance = 1.0f;
    float2 sampleUv = uv;
    float open = 0.0f;

    sampleUv = uv + ray * 0.070f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.030f);
    totalWeight += 0.030f;

    sampleUv = uv + ray * 0.140f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.040f);
    totalWeight += 0.040f;

    sampleUv = uv + ray * 0.220f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.052f);
    totalWeight += 0.052f;

    sampleUv = uv + ray * 0.310f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.066f);
    totalWeight += 0.066f;

    sampleUv = uv + ray * 0.410f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.080f);
    totalWeight += 0.080f;

    sampleUv = uv + ray * 0.520f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.094f);
    totalWeight += 0.094f;

    sampleUv = uv + ray * 0.640f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.108f);
    totalWeight += 0.108f;

    sampleUv = uv + ray * 0.760f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.122f);
    totalWeight += 0.122f;

    sampleUv = uv + ray * 0.875f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.136f);
    totalWeight += 0.136f;

    sampleUv = uv + ray * 0.965f;
    open = OpenSkyMask(sampleUv);
    transmittance *= lerp(blockedDecay, decay, open);
    light += ShaftTap(sampleUv, sunUv, open, transmittance, 0.150f);
    totalWeight += 0.150f;

    return saturate(light / max(totalWeight, 0.001f));
}

float DistanceShape(float screenDistance) {
    float range = max(OptionData2.y, 0.08f);
    float nearFade = Smooth01(screenDistance / max(OptionData3.y * 1.5f, 0.018f));
    float farFade = 1.0f - Smooth01(screenDistance / range);
    return nearFade * farFade;
}

float Corona(float screenDistance) {
    float radius = max(OptionData3.y, 0.012f);
    float corona = 1.0f - Smooth01(screenDistance / radius);
    return corona * corona;
}

float ExposureCurve(float amount) {
    amount = max(amount, 0.0f);
    return amount / (1.0f + amount * 2.8f);
}

float ShaderForce() {
    return clamp(OptionData1.x, 0.0f, 4.0f);
}

float4 Main(PixelInput input) : COLOR0 {
    float4 color = tex2D(SceneColor, input.uv);
    float force = ShaderForce();
    if (FrameData.w < 0.5f || SunData.z <= 0.5f || force <= 0.0f || OptionData0.x <= 0.0f || OptionData0.y <= 0.0f) {
        return color;
    }

    float2 sunUv = SunData.xy;
    float screenFade = OffscreenFade(sunUv);
    float visibility = SunVisibility(sunUv) * screenFade;
    float receiver = ReceiverMask(input.uv);
    float screenDistance = ScreenDistance(input.uv, sunUv);
    float distanceShape = DistanceShape(screenDistance);
    float radialLight = RadialShaft(input.uv, sunUv);

    if (DebugMask()) {
        return float4(visibility, receiver, radialLight, 1.0f);
    }

    if (visibility <= 0.001f || receiver <= 0.001f || distanceShape <= 0.001f || radialLight <= 0.001f) {
        return color;
    }

    float rawAmount = radialLight * visibility * distanceShape * receiver;
    rawAmount *= max(OptionData0.x, 0.0f) * max(OptionData0.y, 0.0f) * force * 1.85f;
    float shaftAmount = min(ExposureCurve(rawAmount), 0.24f);

    float sunCore = BrightMask(SceneSample(saturate(sunUv))) * visibility;
    float coronaAmount = Corona(screenDistance) * sunCore * receiver;
    coronaAmount = min(coronaAmount * max(OptionData0.x, 0.0f) * force * 0.055f, 0.045f);

    float warmth = saturate(OptionData1.w);
    float3 tint = lerp(DayTint, WarmTint, warmth);
    float3 rays = tint * (shaftAmount + coronaAmount);
    float3 composed = color.rgb + rays * (1.0f - color.rgb * 0.55f);

    return float4(saturate(composed), color.a);
}
