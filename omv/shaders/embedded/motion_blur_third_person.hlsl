// OMV third-person camera motion blur.
//
// Unlike the first-person shader, this path validates each current world
// surface against packed depth from the preceding frame. Camera reprojection
// is accepted only when the same surface existed at the reprojected position,
// keeping the independently moving player and disocclusions sharp.

#ifndef MOTION_BLUR_SAMPLES
#define MOTION_BLUR_SAMPLES 7
#endif

sampler2D SceneColor : register(s0);
sampler2D WorldDepth : register(s1);
sampler2D PreviousWorldDepthHistory : register(s3);

float4 ScreenData : register(c0);
float4 MotionOptions : register(c1);
float4 LayerFlags : register(c2);
float4 CurrentWorldFrustum : register(c3);
float4 CurrentWorldDepth : register(c4);
float4 WorldRow0 : register(c5);
float4 WorldRow1 : register(c6);
float4 WorldRow2 : register(c7);
float4 PreviousWorldFrustum : register(c8);
float4 PreviousWorldDepth : register(c9);
float4 HistoryFlags : register(c17);

static const float DepthEndpointEpsilon = 0.000001f;

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float2 DepthTexelCenter(float2 uv) {
    float2 pixel = clamp(floor(uv * ScreenData.xy), 0.0f, ScreenData.xy - 1.0f);
    return (pixel + 0.5f) * ScreenData.zw;
}

bool GeometryDepth(float rawDepth) {
    return rawDepth > DepthEndpointEpsilon
        && rawDepth < (1.0f - DepthEndpointEpsilon);
}

bool SkyDepth(float rawDepth) {
    return LayerFlags.x > 0.5f
        ? rawDepth <= DepthEndpointEpsilon
        : rawDepth >= (1.0f - DepthEndpointEpsilon);
}

float LinearDepth(float rawDepth, float2 nearFar, bool reversedDepth) {
    float nearZ = max(nearFar.x, 0.01f);
    float farZ = max(nearFar.y, nearZ + 1.0f);
    return reversedDepth
        ? nearZ * farZ / max(rawDepth * (farZ - nearZ) + nearZ, 0.001f)
        : nearZ * farZ / max(farZ - rawDepth * (farZ - nearZ), 0.001f);
}

float3 ViewRay(float2 uv, float4 frustum) {
    return float3(
        lerp(frustum.x, frustum.y, uv.x),
        lerp(frustum.w, frustum.z, uv.y),
        1.0f
    );
}

float2 ProjectPrevious(float3 position, float4 frustum) {
    float2 view = position.xy / max(position.z, 0.001f);
    return float2(
        (view.x - frustum.x) / max(frustum.y - frustum.x, 0.001f),
        (frustum.w - view.y) / max(frustum.w - frustum.z, 0.001f)
    );
}

float3 TransformPrevious(float3 position) {
    return float3(
        dot(WorldRow0.xyz, position) + WorldRow0.w,
        dot(WorldRow1.xyz, position) + WorldRow1.w,
        dot(WorldRow2.xyz, position) + WorldRow2.w
    );
}

float3 RotatePrevious(float3 direction) {
    return float3(
        dot(WorldRow0.xyz, direction),
        dot(WorldRow1.xyz, direction),
        dot(WorldRow2.xyz, direction)
    );
}

float2 ClipMotionToViewport(float2 uv, float2 motion) {
    float2 low = 0.5f * ScreenData.zw;
    float2 high = 1.0f - low;
    float scale = 1.0f;
    if (motion.x > 0.0f) {
        scale = min(scale, (high.x - uv.x) / motion.x);
    } else if (motion.x < 0.0f) {
        scale = min(scale, (low.x - uv.x) / motion.x);
    }
    if (motion.y > 0.0f) {
        scale = min(scale, (high.y - uv.y) / motion.y);
    } else if (motion.y < 0.0f) {
        scale = min(scale, (low.y - uv.y) / motion.y);
    }
    return motion * saturate(scale);
}

float2 BoundedMotion(float2 uv, float2 previousUv) {
    float2 motion = (previousUv - uv) * MotionOptions.x;
    float speedPixels = length(motion * ScreenData.xy);
    float maxPixels = max(MotionOptions.y, 0.0f);
    if (speedPixels > maxPixels && speedPixels > 0.0001f) {
        motion *= maxPixels / speedPixels;
        speedPixels = maxPixels;
    }
    float threshold = max(MotionOptions.z, 0.0f);
    float activation = Smooth01(
        (speedPixels - threshold) / max(0.5f, threshold * 0.5f)
    );
    return ClipMotionToViewport(uv, motion * activation);
}

float UnpackDepth24(float3 packedDepth) {
    return dot(packedDepth, float3(1.0f, 1.0f / 255.0f, 1.0f / 65025.0f));
}

bool PreviousWorldSurfaceMatches(
    float2 previousUv,
    float predictedPreviousDepth,
    float motionPixels
) {
    if (HistoryFlags.x < 0.5f) {
        return false;
    }
    float previousRaw = UnpackDepth24(
        tex2Dlod(
            PreviousWorldDepthHistory,
            float4(DepthTexelCenter(previousUv), 0.0f, 0.0f)
        ).rgb
    );
    if (!GeometryDepth(previousRaw)) {
        return false;
    }
    float previousDepth = LinearDepth(
        previousRaw,
        PreviousWorldDepth.xy,
        HistoryFlags.z > 0.5f
    );
    float relativeDifference = abs(previousDepth - predictedPreviousDepth)
        / max(min(previousDepth, predictedPreviousDepth), 0.01f);
    float tolerance = 0.03f + min(motionPixels * 0.003f, 0.07f);
    return relativeDifference <= tolerance;
}

float DepthAcceptance(
    float2 sampleUv,
    bool centerSky,
    float centerDepth,
    float motionPixels
) {
    float sampleRaw = tex2Dlod(
        WorldDepth,
        float4(DepthTexelCenter(sampleUv), 0.0f, 0.0f)
    ).r;
    bool sampleSky = SkyDepth(sampleRaw);
    if (sampleSky != centerSky || (!sampleSky && !GeometryDepth(sampleRaw))) {
        return 0.0f;
    }
    if (centerSky) {
        return 1.0f;
    }
    float sampleDepth = LinearDepth(
        sampleRaw,
        CurrentWorldDepth.xy,
        LayerFlags.x > 0.5f
    );
    float relativeDifference = abs(sampleDepth - centerDepth)
        / max(min(sampleDepth, centerDepth), 0.01f);
    float tolerance = 0.025f + min(motionPixels * 0.002f, 0.075f);
    return 1.0f - Smooth01(
        (relativeDifference - tolerance) / max(tolerance, 0.0001f)
    );
}

float4 Main(float2 requestedUv : TEXCOORD0) : COLOR0 {
    float2 uv = DepthTexelCenter(requestedUv);
    float4 current = tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f));
    float worldRaw = tex2Dlod(WorldDepth, float4(uv, 0.0f, 0.0f)).r;
    bool centerSky = SkyDepth(worldRaw);
    if (!centerSky && !GeometryDepth(worldRaw)) {
        return current;
    }

    float centerDepth = 0.0f;
    float3 previousPosition;
    if (centerSky) {
        previousPosition = RotatePrevious(ViewRay(uv, CurrentWorldFrustum));
    } else {
        centerDepth = LinearDepth(
            worldRaw,
            CurrentWorldDepth.xy,
            LayerFlags.x > 0.5f
        );
        previousPosition = TransformPrevious(
            ViewRay(uv, CurrentWorldFrustum) * centerDepth
        );
    }
    if (previousPosition.z <= max(PreviousWorldDepth.x, 0.001f)) {
        return current;
    }

    float2 previousUv = clamp(
        ProjectPrevious(previousPosition, PreviousWorldFrustum),
        0.5f * ScreenData.zw,
        1.0f - 0.5f * ScreenData.zw
    );
    float2 motion = BoundedMotion(uv, previousUv);
    float motionPixels = length(motion * ScreenData.xy);
    if (motionPixels <= 0.0001f) {
        return current;
    }
    if (
        !centerSky
        && !PreviousWorldSurfaceMatches(previousUv, previousPosition.z, motionPixels)
    ) {
        return current;
    }

    float3 sum = current.rgb * 0.5f;
    float weightSum = 0.5f;
    [loop]
    for (int sampleIndex = 1; sampleIndex < MOTION_BLUR_SAMPLES; ++sampleIndex) {
        float t = (float)sampleIndex / (float)(MOTION_BLUR_SAMPLES - 1);
        float2 sampleUv = uv + motion * t;
        float endpointWeight =
            sampleIndex == (MOTION_BLUR_SAMPLES - 1) ? 0.5f : 1.0f;
        float weight = endpointWeight * DepthAcceptance(
            sampleUv,
            centerSky,
            centerDepth,
            motionPixels
        );
        float3 sampleColor =
            tex2Dlod(SceneColor, float4(sampleUv, 0.0f, 0.0f)).rgb;
        sum += sampleColor * weight;
        weightSum += weight;
    }
    return float4(sum / max(weightSum, 0.0001f), current.a);
}
