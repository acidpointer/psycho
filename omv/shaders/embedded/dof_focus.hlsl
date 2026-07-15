sampler2D PreviousFocus : register(s0);
sampler2D SceneDepth : register(s1);

float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 FocusData : register(c3);
float4 FocusTiming : register(c4);
float4 DepthData : register(c11);

static const float DepthEpsilon = 0.000001f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float LinearizeDepth(float rawDepth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    if (DepthData.x > 0.5f) {
        return (nearZ * farZ) / max(rawDepth * (farZ - nearZ) + nearZ, 0.001f);
    }
    return (nearZ * farZ) / max(farZ - rawDepth * (farZ - nearZ), 0.001f);
}

bool LoadWorldDepth(float2 uv, out float linearDepth) {
    float rawDepth = tex2Dlod(SceneDepth, float4(saturate(uv), 0.0f, 0.0f)).r;
    bool reversedDepth = DepthData.x > 0.5f;
    bool empty = reversedDepth
        ? rawDepth <= DepthEpsilon
        : rawDepth >= 1.0f - DepthEpsilon;
    if (empty) {
        linearDepth = 0.0f;
        return false;
    }
    linearDepth = LinearizeDepth(rawDepth);
    return linearDepth > CameraData.x && linearDepth < CameraData.y * 0.995f;
}

float EncodeFocus(float distance) {
    float farZ = max(CameraData.y, 2.0f);
    return saturate(log2(max(distance, 0.0f) + 1.0f) / log2(farZ + 1.0f));
}

float DecodeFocus(float encoded) {
    float farZ = max(CameraData.y, 2.0f);
    return max(exp2(saturate(encoded) * log2(farZ + 1.0f)) - 1.0f, 0.01f);
}

void AddGlobal(
    float2 uv,
    float weight,
    inout float logSum,
    inout float inverseSum,
    inout float weightSum
) {
    float depth;
    if (!LoadWorldDepth(uv, depth)) {
        return;
    }
    logSum += log2(max(depth, 0.01f)) * weight;
    inverseSum += weight / max(depth, 0.01f);
    weightSum += weight;
}

void AddClusters(
    float2 uv,
    float weight,
    float globalSeed,
    float previousSeed,
    float tolerance,
    inout float globalInverse,
    inout float globalWeight,
    inout float previousInverse,
    inout float previousWeight
) {
    float depth;
    if (!LoadWorldDepth(uv, depth)) {
        return;
    }
    float logDepth = log2(max(depth, 0.01f));
    if (abs(logDepth - globalSeed) <= tolerance) {
        globalInverse += weight / depth;
        globalWeight += weight;
    }
    if (abs(logDepth - previousSeed) <= tolerance) {
        previousInverse += weight / depth;
        previousWeight += weight;
    }
}

#define GLOBAL_SAMPLE(x, y, weight) AddGlobal(float2(0.5f, 0.5f) + float2(x, y) * radius, weight, logSum, inverseSum, weightSum)
#define CLUSTER_SAMPLE(x, y, weight) AddClusters(float2(0.5f, 0.5f) + float2(x, y) * radius, weight, globalSeed, previousSeed, tolerance, globalInverse, globalWeight, previousInverse, previousWeight)

float4 Main(PixelInput input) : COLOR0 {
    float fallbackFocus = clamp(FocusData.x, max(CameraData.x, 0.01f), max(CameraData.y, 1.0f));
    if (FocusTiming.w > 0.5f) {
        return float4(EncodeFocus(fallbackFocus), 0.0f, 0.0f, 1.0f);
    }

    float previousFocus = FrameData.w > 0.5f
        ? DecodeFocus(tex2Dlod(PreviousFocus, float4(0.5f, 0.5f, 0.0f, 0.0f)).r)
        : fallbackFocus;
    float radius = FocusData.y;
    float centerDepth;
    bool centerValid = LoadWorldDepth(float2(0.5f, 0.5f), centerDepth);
    float logSum = 0.0f;
    float inverseSum = 0.0f;
    float weightSum = 0.0f;
    GLOBAL_SAMPLE( 0.00f,  0.00f, 1.20f);
    GLOBAL_SAMPLE( 0.45f,  0.00f, 1.00f);
    GLOBAL_SAMPLE(-0.45f,  0.00f, 1.00f);
    GLOBAL_SAMPLE( 0.00f,  0.45f, 1.00f);
    GLOBAL_SAMPLE( 0.00f, -0.45f, 1.00f);
    GLOBAL_SAMPLE( 0.34f,  0.34f, 0.85f);
    GLOBAL_SAMPLE(-0.34f,  0.34f, 0.85f);
    GLOBAL_SAMPLE( 0.34f, -0.34f, 0.85f);
    GLOBAL_SAMPLE(-0.34f, -0.34f, 0.85f);
    GLOBAL_SAMPLE( 0.92f,  0.18f, 0.55f);
    GLOBAL_SAMPLE(-0.18f,  0.92f, 0.55f);
    GLOBAL_SAMPLE(-0.92f, -0.18f, 0.55f);
    GLOBAL_SAMPLE( 0.18f, -0.92f, 0.55f);

    if (weightSum < 2.0f) {
        return float4(EncodeFocus(previousFocus), 0.0f, 0.0f, 1.0f);
    }

    float globalSeed = centerValid ? log2(centerDepth) : logSum / weightSum;
    float previousSeed = log2(max(previousFocus, 0.01f));
    float tolerance = max(log2(1.0f + FocusData.z), 0.025f);
    float globalInverse = 0.0f;
    float globalWeight = 0.0f;
    float previousInverse = 0.0f;
    float previousWeight = 0.0f;
    CLUSTER_SAMPLE( 0.00f,  0.00f, 1.20f);
    CLUSTER_SAMPLE( 0.45f,  0.00f, 1.00f);
    CLUSTER_SAMPLE(-0.45f,  0.00f, 1.00f);
    CLUSTER_SAMPLE( 0.00f,  0.45f, 1.00f);
    CLUSTER_SAMPLE( 0.00f, -0.45f, 1.00f);
    CLUSTER_SAMPLE( 0.34f,  0.34f, 0.85f);
    CLUSTER_SAMPLE(-0.34f,  0.34f, 0.85f);
    CLUSTER_SAMPLE( 0.34f, -0.34f, 0.85f);
    CLUSTER_SAMPLE(-0.34f, -0.34f, 0.85f);
    CLUSTER_SAMPLE( 0.92f,  0.18f, 0.55f);
    CLUSTER_SAMPLE(-0.18f,  0.92f, 0.55f);
    CLUSTER_SAMPLE(-0.92f, -0.18f, 0.55f);
    CLUSTER_SAMPLE( 0.18f, -0.92f, 0.55f);

    float untrimmedTarget = weightSum / max(inverseSum, 0.000001f);
    float globalTarget = globalWeight / max(globalInverse, 0.000001f);
    float previousTarget = previousWeight / max(previousInverse, 0.000001f);
    bool globalClusterValid = globalWeight >= weightSum * (centerValid ? 0.18f : 0.20f);
    bool previousClusterValid = FrameData.w > 0.5f && previousWeight >= weightSum * 0.25f;
    float targetFocus = globalClusterValid
        ? globalTarget
        : previousClusterValid ? previousTarget : untrimmedTarget;

    float relativeChange = abs(targetFocus - previousFocus) / max(previousFocus, 1.0f);
    if (FrameData.w > 0.5f && relativeChange <= FocusData.w) {
        targetFocus = previousFocus;
    }

    float seconds = targetFocus < previousFocus ? FocusTiming.x : FocusTiming.y;
    float response = FrameData.w > 0.5f
        ? 1.0f - exp(-FrameData.y / max(seconds, 0.001f))
        : 1.0f;
    float previousPower = rcp(max(previousFocus, 0.01f));
    float targetPower = rcp(max(targetFocus, 0.01f));
    float focusDistance = rcp(max(lerp(previousPower, targetPower, response), 0.000001f));
    return float4(EncodeFocus(focusDistance), 0.0f, 0.0f, 1.0f);
}
