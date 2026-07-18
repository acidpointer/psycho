sampler2D WorldColor : register(s0);
sampler2D ReducedDepth : register(s1);
sampler2D IntegratedAtmosphere : register(s2);

float4 FullTarget : register(c0);
float4 ReducedTarget : register(c1);
float4 DebugData : register(c2);
float4 CameraFrustum : register(c3);
float4 ViewToWorld0 : register(c4);
float4 ViewToWorld1 : register(c5);
float4 ViewToWorld2 : register(c6);

struct PixelInput {
	float2 uv : TEXCOORD0;
};

float DecodeDistance(float encoded) {
	return exp2(saturate(encoded) * log2(1.0f + DebugData.x)) - 1.0f;
}

float4 Main(PixelInput input) : COLOR0 {
	float4 source = tex2Dlod(WorldColor, float4(input.uv, 0.0f, 0.0f));
	if (DebugData.y > 3.5f && DebugData.y < 4.5f) {
		return float4(saturate(source.aaa), source.a);
	}
	if (DebugData.y > 4.5f && DebugData.y < 5.5f) {
		float3 negative = max(-source.rgb, 0.0f);
		float3 overbright = max(source.rgb - 1.0f, 0.0f);
		float negativeSignal = saturate(max(negative.r, max(negative.g, negative.b)));
		float overbrightSignal = saturate(max(overbright.r, max(overbright.g, overbright.b)));
		float nominal = saturate(dot(max(source.rgb, 0.0f), float3(0.2126f, 0.7152f, 0.0722f))) * 0.2f;
		return float4(overbrightSignal, nominal, negativeSignal, source.a);
	}
	if (DebugData.y > 5.5f) {
		if (DebugData.w < 0.5f) {
			return source;
		}
		float2 reducedPixel = floor(input.uv * ReducedTarget.xy);
		float2 reducedUv = (reducedPixel + 0.5f) * ReducedTarget.zw;
		float4 integrated = tex2Dlod(IntegratedAtmosphere, float4(reducedUv, 0.0f, 0.0f));
		if (DebugData.y < 6.5f) {
			float transmittance = saturate(integrated.a);
			float opticalDepth = min(-log(max(transmittance, 0.000001f)), 8.0f) / 8.0f;
			return float4(opticalDepth, transmittance, 1.0f - transmittance, source.a);
		}
		float3 preview = max(integrated.rgb, 0.0f);
		preview = preview / (1.0f + preview);
		return float4(preview, source.a);
	}

	float2 reducedPixel = floor(input.uv * ReducedTarget.xy);
	float2 reducedUv = (reducedPixel + 0.5f) * ReducedTarget.zw;
	float2 encodedDepth = tex2Dlod(ReducedDepth, float4(reducedUv, 0.0f, 0.0f)).rg;
	if (DebugData.y < 1.5f) {
		return float4(encodedDepth.xxx, source.a);
	}

	float nearest = DecodeDistance(encodedDepth.x);
	float farthest = DecodeDistance(encodedDepth.y);
	if (DebugData.y > 2.5f) {
		if (DebugData.z < 0.5f) {
			return float4(1.0f, 0.0f, 1.0f, source.a);
		}
		float viewX = lerp(CameraFrustum.x, CameraFrustum.y, input.uv.x);
		float viewY = lerp(CameraFrustum.w, CameraFrustum.z, input.uv.y);
		float3 viewPosition = normalize(float3(viewX, viewY, 1.0f)) * nearest;
		float3 worldPosition = float3(
			dot(ViewToWorld0.xyz, viewPosition) + ViewToWorld0.w,
			dot(ViewToWorld1.xyz, viewPosition) + ViewToWorld1.w,
			dot(ViewToWorld2.xyz, viewPosition) + ViewToWorld2.w
		);
		float band = frac(worldPosition.z / 512.0f);
		float bandLine = 1.0f - smoothstep(0.04f, 0.12f, min(band, 1.0f - band));
		float3 bandColor = 0.35f + 0.35f * cos(worldPosition.z / 1024.0f + float3(0.0f, 2.094f, 4.189f));
		return float4(lerp(bandColor, 1.0f, bandLine), source.a);
	}

	float span = saturate((farthest - nearest) / max(DebugData.x, 1.0f) * 32.0f);
	return float4(span, span * 0.35f, 0.0f, source.a);
}
