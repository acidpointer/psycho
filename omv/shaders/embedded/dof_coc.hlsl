sampler2D SceneDepth : register(s0);
sampler2D FirstPersonDepth : register(s1);
sampler2D FocusTexture : register(s2);

float4 CameraData : register(c2);
float4 FocusTiming : register(c4);
float4 StrengthData : register(c5);
float4 RadiusData : register(c6);
float4 DistantData : register(c7);
float4 DepthData : register(c11);
float4 FirstPersonCamera : register(c13);

static const float DepthEpsilon = 0.000001f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float LinearizeDepth(float rawDepth, float nearZ, float farZ, bool reversedDepth) {
    nearZ = max(nearZ, 0.01f);
    farZ = max(farZ, nearZ + 1.0f);
    if (reversedDepth) {
        return (nearZ * farZ) / max(rawDepth * (farZ - nearZ) + nearZ, 0.001f);
    }
    return (nearZ * farZ) / max(farZ - rawDepth * (farZ - nearZ), 0.001f);
}

bool LoadFirstPersonDepth(float2 uv, out float linearDepth) {
    if (FirstPersonCamera.w < 0.5f || DepthData.w < 0.5f) {
        linearDepth = 0.0f;
        return false;
    }
    float rawDepth = tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
    bool reversedDepth = DepthData.y > 0.5f;
    bool empty = reversedDepth
        ? rawDepth <= DepthEpsilon
        : rawDepth >= 1.0f - DepthEpsilon;
    if (empty) {
        linearDepth = 0.0f;
        return false;
    }
    linearDepth = LinearizeDepth(
        rawDepth,
        FirstPersonCamera.x,
        CameraData.y,
        reversedDepth
    );
    return linearDepth > 0.0f;
}

void LoadDepth(float2 uv, out float linearDepth, out bool firstPerson, out bool sky) {
    firstPerson = LoadFirstPersonDepth(uv, linearDepth);
    if (firstPerson) {
        sky = false;
        return;
    }

    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
    bool reversedDepth = DepthData.x > 0.5f;
    sky = reversedDepth
        ? rawDepth <= DepthEpsilon
        : rawDepth >= 1.0f - DepthEpsilon;
    linearDepth = sky
        ? CameraData.y
        : LinearizeDepth(rawDepth, CameraData.x, CameraData.y, reversedDepth);
    sky = sky || linearDepth >= CameraData.y * 0.995f;
}

float DecodeFocus(float encoded) {
    float farZ = max(CameraData.y, 2.0f);
    return max(exp2(saturate(encoded) * log2(farZ + 1.0f)) - 1.0f, 0.01f);
}

float OpticalFalloff(float inverseDistanceDelta, float inverseFocus, float focusWidth) {
    float normalizedDelta = inverseDistanceDelta
        / max(inverseFocus * focusWidth, 0.0000001f);
    float squaredDelta = min(normalizedDelta * normalizedDelta, 32.0f);
    return 1.0f - exp2(-squaredDelta);
}

float SignedCoc(float linearDepth, float focusDistance, bool firstPerson, bool sky) {
    bool nearEnabled = RadiusData.x > 0.001f && StrengthData.x > 0.001f;
    bool farEnabled = RadiusData.y > 0.001f;
    if (sky) {
        return farEnabled ? saturate(RadiusData.w) : 0.0f;
    }

    float inverseFocus = rcp(max(focusDistance, 0.01f));
    float inverseDepth = rcp(max(linearDepth, 0.01f));
    float nearCoc = nearEnabled
        ? OpticalFalloff(
            max(inverseDepth - inverseFocus, 0.0f),
            inverseFocus,
            max(FocusTiming.z, 0.001f)
        ) * StrengthData.x
        : 0.0f;
    float farCoc = farEnabled
        ? OpticalFalloff(
            max(inverseFocus - inverseDepth, 0.0f),
            inverseFocus,
            max(DistantData.w, 0.001f)
        ) * StrengthData.y
        : 0.0f;

    if (firstPerson) {
        return clamp((farCoc - nearCoc) * StrengthData.z, -1.0f, 1.0f);
    }

    float distantCoc = farEnabled
        ? smoothstep(DistantData.x, DistantData.y, linearDepth) * StrengthData.w
        : 0.0f;
    return nearCoc > 0.0f
        ? -saturate(nearCoc)
        : saturate(max(farCoc, distantCoc));
}

float4 Main(PixelInput input) : COLOR0 {
    float focusDistance = DecodeFocus(tex2Dlod(FocusTexture, float4(0.5f, 0.5f, 0.0f, 0.0f)).r);
    float linearDepth;
    bool firstPerson;
    bool sky;
    LoadDepth(input.uv, linearDepth, firstPerson, sky);
    float coc = SignedCoc(linearDepth, focusDistance, firstPerson, sky);
    return float4(coc, 0.0f, 0.0f, 1.0f);
}
