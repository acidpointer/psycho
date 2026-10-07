#ifndef OMV_WORLD_FIELD
sampler2D ReducedDepth : register(s0);

float4 ShaftTarget : register(c0);
float4 ReducedTarget : register(c1);
float4 DepthData : register(c2);

struct PixelInput {
	float2 uv : TEXCOORD0;
};

float DecodeDistance(float encoded) {
	float bound = max(DepthData.x, 1.0f);
	return exp2(saturate(encoded) * log2(1.0f + bound)) - 1.0f;
}

#endif

float Smooth01(float value) {
	value = saturate(value);
	return value * value * (3.0f - 2.0f * value);
}

float2 Openness(float2 uv) {
	float2 encoded = tex2Dlod(ReducedDepth, float4(uv, 0.0f, 0.0f)).rg;
	float nearest = DecodeDistance(encoded.x);
	float farthest = DecodeDistance(encoded.y);
	#ifdef OMV_WORLD_FIELD
    float bound = max(DepthData.w, 1.0f);
#else
    float bound = max(DepthData.x, 1.0f);
#endif
	float start = bound * 0.965f;
	float width = max(bound * 0.030f, 1.0f);
	return float2(
		Smooth01((nearest - start) / width),
		Smooth01((farthest - start) / width)
	);
}

#ifdef OMV_WORLD_FIELD
float4 ProjectedMaskMain(PixelInput input)
#else
float4 Main(PixelInput input)
#endif
: COLOR0 {
	float2 offset = ReducedTarget.zw * 0.45f;
	float2 a = Openness(input.uv + float2(-offset.x, -offset.y));
	float2 b = Openness(input.uv + float2( offset.x, -offset.y));
	float2 c = Openness(input.uv + float2(-offset.x,  offset.y));
	float2 d = Openness(input.uv + float2( offset.x,  offset.y));
	float conservative = min(min(a.x, b.x), min(c.x, d.x));
	float confidence = (a.y + b.y + c.y + d.y) * 0.25f;
	return float4(conservative, confidence, 0.0f, 1.0f);
}

#ifdef OMV_WORLD_FIELD
float4 Main(PixelInput input) : COLOR0 {
    if (WorldShadowControl.x > 0.5f) return WorldFieldMain(input);
    return ProjectedMaskMain(input);
}
#endif
