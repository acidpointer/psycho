sampler2D ShaftMask : register(s0);

#ifndef ATMOSPHERE_SHAFT_SAMPLE_COUNT
#define ATMOSPHERE_SHAFT_SAMPLE_COUNT 40
#endif

float4 ShaftTarget : register(c0);
float4 SunProjection : register(c1);

struct PixelInput {
	float2 uv : TEXCOORD0;
};

float StableOffset(float2 uv) {
	float2 pixel = floor(uv * ShaftTarget.xy);
	return frac(52.9829189f * frac(dot(pixel, float2(0.06711056f, 0.00583715f))));
}

float4 Main(PixelInput input) : COLOR0 {
	float influence = saturate(SunProjection.z * SunProjection.w);
	if (influence <= 0.0f) {
		return float4(1.0f, 1.0f, 0.0f, 1.0f);
	}

	float2 stepUv = (SunProjection.xy - input.uv) / ATMOSPHERE_SHAFT_SAMPLE_COUNT;
	float2 sampleUv = input.uv + stepUv * StableOffset(input.uv);
	float blockage = 0.0f;
	float confidence = 0.0f;
	float weight = 1.0f;
	float weightSum = 0.0f;
	[loop]
	for (int index = 0; index < ATMOSPHERE_SHAFT_SAMPLE_COUNT; ++index) {
		sampleUv += stepUv;
		float2 insideMin = step(0.0f, sampleUv);
		float2 insideMax = step(sampleUv, 1.0f);
		float inside = insideMin.x * insideMin.y * insideMax.x * insideMax.y;
		float2 mask = tex2Dlod(ShaftMask, float4(saturate(sampleUv), 0.0f, 0.0f)).rg;
		float pathOpen = lerp(mask.x, mask.y, 0.18f) * inside;
		blockage += (1.0f - pathOpen) * inside * weight;
		confidence += mask.y * inside * weight;
		weightSum += inside * weight;
		weight *= 0.985f;
	}
	float inverseWeight = 1.0f / max(weightSum, 0.0001f);
	float blockedFraction = saturate(blockage * inverseWeight);
	float field = exp(-12.0f * blockedFraction);
	float fieldConfidence = saturate(confidence * inverseWeight);
	field = lerp(1.0f, field, influence);
	return float4(field, fieldConfidence, 0.0f, 1.0f);
}
