// Adaptive approximate anti-aliasing adapted from Depth3D AXAA.fxh.
// NVIDIA BSD-3-Clause terms are preserved in THIRD_PARTY_NOTICES.md.

sampler2D SceneColor : register(s0);
float4 ScreenData : register(c0);

float Luma(float3 color) {
    return max(color.r, max(color.g, color.b));
}

float3 SampleColor(float2 uv, float x, float y) {
    return tex2Dlod(SceneColor, float4(uv + float2(x, y) * ScreenData.zw, 0.0, 0.0)).rgb;
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float3 rgbNorth = SampleColor(uv, 0.0, -1.0);
    float3 rgbWest = SampleColor(uv, -1.0, 0.0);
    float3 rgbCenter = SampleColor(uv, 0.0, 0.0);
    float3 rgbEast = SampleColor(uv, 1.0, 0.0);
    float3 rgbSouth = SampleColor(uv, 0.0, 1.0);
    float lumaNorth = Luma(rgbNorth);
    float lumaWest = Luma(rgbWest);
    float lumaCenter = Luma(rgbCenter);
    float lumaEast = Luma(rgbEast);
    float lumaSouth = Luma(rgbSouth);
    float rangeMinimum = min(lumaCenter, min(min(lumaNorth, lumaWest), min(lumaSouth, lumaEast)));
    float rangeMaximum = max(lumaCenter, max(max(lumaNorth, lumaWest), max(lumaSouth, lumaEast)));
    float range = rangeMaximum - rangeMinimum;
    float rangeMiddle = 0.5 * (rangeMinimum + rangeMaximum);
    if (abs(lumaCenter - rangeMiddle) <= 0.1 * range) {
        return float4(rgbCenter, 1.0);
    }

    float3 lowPass = rgbNorth + rgbWest + rgbCenter + rgbEast + rgbSouth;
    float lumaLowPass = (lumaNorth + lumaWest + lumaEast + lumaSouth) * 0.25;
    float rangeLowPass = abs(lumaLowPass - lumaCenter);
    float safeRange = max(range, 0.001);
    float ratio = saturate(rangeLowPass / safeRange);
    float blendLowPass = max(0.0, ratio / safeRange - 0.25) * (1.0 / 0.75);
    blendLowPass = min(0.75, blendLowPass);

    float3 rgbNorthWest = SampleColor(uv, -1.0, -1.0);
    float3 rgbNorthEast = SampleColor(uv, 1.0, -1.0);
    float3 rgbSouthWest = SampleColor(uv, -1.0, 1.0);
    float3 rgbSouthEast = SampleColor(uv, 1.0, 1.0);
    lowPass = (lowPass + rgbNorthWest + rgbNorthEast + rgbSouthWest + rgbSouthEast) / 9.0;
    float lumaNorthWest = Luma(rgbNorthWest);
    float lumaNorthEast = Luma(rgbNorthEast);
    float lumaSouthWest = Luma(rgbSouthWest);
    float lumaSouthEast = Luma(rgbSouthEast);
    float verticalEdge =
        abs(0.25 * lumaNorthWest - 0.5 * lumaNorth + 0.25 * lumaNorthEast) +
        abs(0.50 * lumaWest - lumaCenter + 0.50 * lumaEast) +
        abs(0.25 * lumaSouthWest - 0.5 * lumaSouth + 0.25 * lumaSouthEast);
    float horizontalEdge =
        abs(0.25 * lumaNorthWest - 0.5 * lumaWest + 0.25 * lumaSouthWest) +
        abs(0.50 * lumaNorth - lumaCenter + 0.50 * lumaSouth) +
        abs(0.25 * lumaNorthEast - 0.5 * lumaEast + 0.25 * lumaSouthEast);
    bool horizontalSpan = horizontalEdge >= verticalEdge;
    float lengthSign = horizontalSpan ? -ScreenData.w : -ScreenData.z;
    if (!horizontalSpan) {
        lumaNorth = lumaWest;
        lumaSouth = lumaEast;
    }

    float gradientNorth = abs(lumaNorth - lumaCenter);
    float gradientSouth = abs(lumaSouth - lumaCenter);
    lumaNorth = 0.5 * (lumaNorth + lumaCenter);
    lumaSouth = 0.5 * (lumaSouth + lumaCenter);
    float minimumDistance = abs(lumaCenter - min(min(lumaNorth, lumaSouth), min(lumaWest, lumaEast)));
    float maximumDistance = abs(lumaCenter - max(max(lumaNorth, lumaSouth), max(lumaWest, lumaEast)));
    int searchIterations = 3;
    if (max(minimumDistance, maximumDistance) <= 0.1) {
        searchIterations = 1;
    } else if (min(minimumDistance, maximumDistance) <= 0.3) {
        searchIterations = 2;
    }
    if (gradientNorth > 0.3 && gradientSouth > 0.3) {
        lengthSign = 0.0;
    }

    if (gradientSouth > gradientNorth) {
        lumaNorth = lumaSouth;
        gradientNorth = gradientSouth;
        lengthSign *= -1.0;
    }
    float2 negativePosition = uv + (horizontalSpan ? float2(0.0, lengthSign * 0.5)
                                                   : float2(lengthSign * 0.5, 0.0));
    float2 positivePosition = negativePosition;
    float2 searchOffset = horizontalSpan ? float2(ScreenData.z, 0.0)
                                         : float2(0.0, ScreenData.w);
    gradientNorth *= 0.25;
    negativePosition -= searchOffset;
    positivePosition += searchOffset;
    float negativeLuma = lumaNorth;
    float positiveLuma = lumaNorth;
    bool negativeDone = false;
    bool positiveDone = false;
    [loop] for (int i = 0; i < 3; ++i) {
        if (i >= searchIterations) break;
        if (!negativeDone) negativeLuma = Luma(tex2Dlod(SceneColor, float4(negativePosition, 0.0, 0.0)).rgb);
        if (!positiveDone) positiveLuma = Luma(tex2Dlod(SceneColor, float4(positivePosition, 0.0, 0.0)).rgb);
        negativeDone = negativeDone || abs(negativeLuma - lumaNorth) >= gradientNorth;
        positiveDone = positiveDone || abs(positiveLuma - lumaNorth) >= gradientNorth;
        if (negativeDone && positiveDone) break;
        if (!negativeDone) negativePosition -= searchOffset;
        if (!positiveDone) positivePosition += searchOffset;
    }

    float negativeDistance = horizontalSpan ? uv.x - negativePosition.x : uv.y - negativePosition.y;
    float positiveDistance = horizontalSpan ? positivePosition.x - uv.x : positivePosition.y - uv.y;
    bool useNegative = negativeDistance < positiveDistance;
    float endLuma = useNegative ? negativeLuma : positiveLuma;
    if (((lumaCenter - lumaNorth) < 0.0) == ((endLuma - lumaNorth) < 0.0)) {
        lengthSign = 0.0;
    }
    float spanLength = max(negativeDistance + positiveDistance, 0.0001);
    float closestDistance = useNegative ? negativeDistance : positiveDistance;
    float subpixelOffset = (0.5 - closestDistance / spanLength) * lengthSign;
    float2 filteredUv = uv + (horizontalSpan ? float2(0.0, subpixelOffset)
                                             : float2(subpixelOffset, 0.0));
    float3 filtered = tex2Dlod(SceneColor, float4(filteredUv, 0.0, 0.0)).rgb;
    return float4(lerp(lowPass, filtered, blendLowPass), 1.0);
}
