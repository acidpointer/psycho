sampler2D WorldColor : register(s0);
sampler2D ReducedDepth : register(s1);

float4 FullTarget : register(c0);
float4 ReducedTarget : register(c1);
float4 DebugData : register(c2);

struct PixelInput {
	float2 uv : TEXCOORD0;
};

float DecodeDistance(float encoded) {
	return exp2(saturate(encoded) * log2(1.0f + DebugData.x)) - 1.0f;
}

float4 Main(PixelInput input) : COLOR0 {
	float4 source = tex2Dlod(WorldColor, float4(input.uv, 0.0f, 0.0f));
	float2 reducedPixel = floor(input.uv * ReducedTarget.xy);
	float2 reducedUv = (reducedPixel + 0.5f) * ReducedTarget.zw;
	float2 encodedDepth = tex2Dlod(ReducedDepth, float4(reducedUv, 0.0f, 0.0f)).rg;
	if (DebugData.y < 1.5f) {
		return float4(encodedDepth.xxx, source.a);
	}

	float nearest = DecodeDistance(encodedDepth.x);
	float farthest = DecodeDistance(encodedDepth.y);
	float span = saturate((farthest - nearest) / max(DebugData.x, 1.0f) * 32.0f);
	return float4(span, span * 0.35f, 0.0f, source.a);
}
