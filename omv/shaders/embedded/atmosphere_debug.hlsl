sampler2D WorldColor : register(s0);
sampler2D ReducedDepth : register(s1);
sampler2D IntegratedAtmosphere : register(s2);
sampler2D ShaftMask : register(s3);
sampler2D ShaftVisibility : register(s4);

float4 FullTarget : register(c0);
float4 ReducedTarget : register(c1);
float4 DebugData : register(c2);
float4 CameraFrustum : register(c3);
float4 ViewToWorld0 : register(c4);
float4 ViewToWorld1 : register(c5);
float4 ViewToWorld2 : register(c6);
float4 LightingDebugData : register(c7);
float4 SunDirection : register(c8);
float4 SunColor : register(c9);
float4 SunDiskDelta : register(c10);
float4 LightingMediumData : register(c11);

static const float InverseFourPi = 0.0795774715f;
static const float FourPi = 12.5663706144f;

struct PixelInput {
	float2 uv : TEXCOORD0;
};

float DecodeDistance(float encoded) {
	return exp2(saturate(encoded) * log2(1.0f + DebugData.x)) - 1.0f;
}

float HenyeyGreenstein(float mu, float anisotropy) {
	float g = clamp(anisotropy, -0.8f, 0.9f);
	float denominator = max(1.0f + g * g - 2.0f * g * clamp(mu, -1.0f, 1.0f), 0.000001f);
	return (1.0f - g * g) * InverseFourPi / pow(denominator, 1.5f);
}

float3 WorldRay(float2 uv) {
	float viewX = lerp(CameraFrustum.x, CameraFrustum.y, uv.x);
	float viewY = lerp(CameraFrustum.w, CameraFrustum.z, uv.y);
	float3 viewDirection = normalize(float3(viewX, viewY, 1.0f));
	return normalize(float3(
		dot(ViewToWorld0.xyz, viewDirection),
		dot(ViewToWorld1.xyz, viewDirection),
		dot(ViewToWorld2.xyz, viewDirection)
	));
}

float4 Main(PixelInput input) : COLOR0 {
	float4 source = tex2Dlod(WorldColor, float4(input.uv, 0.0f, 0.0f));
	if (DebugData.y > 8.5f) {
		float lightingView = DebugData.y - 8.0f;
		if (LightingDebugData.w < 0.5f) {
			return float4(1.0f, 0.0f, 1.0f, source.a);
		}
		float2 mask = tex2Dlod(ShaftMask, float4(input.uv, 0.0f, 0.0f)).rg;
		float2 shaft = tex2Dlod(ShaftVisibility, float4(input.uv, 0.0f, 0.0f)).rg;
		if (lightingView < 1.5f) {
			if (SunDirection.w < 0.5f) {
				return float4(1.0f, 0.0f, 1.0f, source.a);
			}
			return float4(mask.x, mask.y, 0.0f, source.a);
		}
		if (lightingView < 2.5f) {
			if (SunDirection.w < 0.5f) {
				return float4(1.0f, 0.0f, 1.0f, source.a);
			}
			return float4(shaft.x, shaft.y, 1.0f - shaft.x, source.a);
		}
		float mu = dot(WorldRay(input.uv), SunDirection.xyz);
		// Match the production conversion from FNV direct light to phase response.
		float phase = HenyeyGreenstein(mu, LightingDebugData.x) * FourPi;
		if (lightingView < 3.5f) {
			float preview = phase / (1.0f + phase);
			return float4(preview, saturate(mu * 0.5f + 0.5f), 1.0f - preview, source.a);
		}
		float2 reducedPixel = floor(input.uv * ReducedTarget.xy);
		float2 reducedUv = (reducedPixel + 0.5f) * ReducedTarget.zw;
		float4 integrated = tex2Dlod(IntegratedAtmosphere, float4(reducedUv, 0.0f, 0.0f));
		if (lightingView < 4.5f) {
			float diskLobe = smoothstep(0.995f, 0.9999f, mu);
			float3 radiance = max(SunColor.rgb, 0.0f)
				+ max(SunDiskDelta.rgb, 0.0f) * max(LightingDebugData.z, 0.0f) * diskLobe;
			float visibility = lerp(1.0f, shaft.x, saturate(SunDirection.w));
			float distance = DecodeDistance(tex2Dlod(ReducedDepth, float4(reducedUv, 0.0f, 0.0f)).y);
			float lightingAmount = 1.0f - exp(-max(LightingMediumData.x, 0.0f) * distance);
			float directionalAmount = max(1.0f - saturate(integrated.a), lightingAmount);
			float3 preview = radiance * SunColor.w * LightingDebugData.y * phase
				* directionalAmount * visibility;
			preview = preview / (1.0f + preview);
			return float4(preview, source.a);
		}
		float3 combined = max(integrated.rgb, 0.0f);
		combined = combined / (1.0f + combined);
		return float4(combined, source.a);
	}
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
