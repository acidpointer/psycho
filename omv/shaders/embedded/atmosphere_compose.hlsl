sampler2D WorldColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D ReducedDepth : register(s2);
sampler2D NearAtmosphere : register(s3);
sampler2D FarAtmosphere : register(s4);

float4 FullTarget : register(c0);
float4 ReducedTarget : register(c1);
float4 DepthData : register(c2);
float4 CameraFrustum : register(c3);
float4 ComposeData : register(c4);

static const float DepthEpsilon = 0.000001f;
static const float WeightEpsilon = 0.0001f;

struct PixelInput {
	float2 uv : TEXCOORD0;
};

struct GatheredAtmosphere {
	float3 scattering;
	float transmittance;
	float weight;
	float mixed;
};

bool IsFiniteScalar(float value) {
	return value == value && abs(value) < 3.0e38f;
}

bool IsFiniteVector(float3 value) {
	return IsFiniteScalar(value.x) && IsFiniteScalar(value.y) && IsFiniteScalar(value.z);
}

float LinearizeDepth(float rawDepth) {
	float nearZ = max(DepthData.x, 0.01f);
	float farZ = max(DepthData.y, nearZ + 1.0f);
	if (DepthData.z > 0.5f) {
		return (nearZ * farZ) / max(rawDepth * (farZ - nearZ) + nearZ, 0.001f);
	}
	return (nearZ * farZ) / max(farZ - rawDepth * (farZ - nearZ), 0.001f);
}

bool IsSky(float rawDepth) {
	return DepthData.z > 0.5f
		? rawDepth <= DepthEpsilon
		: rawDepth >= 1.0f - DepthEpsilon;
}

float RayDistance(float2 uv, float rawDepth) {
	if (IsSky(rawDepth)) {
		return DepthData.w;
	}
	float viewDepth = LinearizeDepth(rawDepth);
	float viewX = lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * viewDepth;
	float viewY = lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * viewDepth;
	return min(length(float3(viewX, viewY, viewDepth)), DepthData.w);
}

float DecodeDistance(float encoded) {
	float bound = max(DepthData.w, 1.0f);
	return exp2(saturate(encoded) * log2(1.0f + bound)) - 1.0f;
}

float3 DecodeExtendedSrgb(float3 color) {
	float3 low = color / 12.92f;
	float3 high = pow((max(color, 0.0f) + 0.055f) / 1.055f, 2.4f);
	return (color <= 0.04045f) ? low : high;
}

float3 EncodeExtendedSrgb(float3 color) {
	float3 low = color * 12.92f;
	float3 high = pow(abs(color), 1.0f / 2.4f) * 1.055f - 0.055f;
	return (color <= 0.0031308f) ? low : high;
}

void AccumulateTap(
	inout GatheredAtmosphere gathered,
	float2 reducedPixel,
	float spatialWeight,
	float fullDistance,
	float baseTolerance
) {
	reducedPixel = clamp(reducedPixel, 0.0f, ReducedTarget.xy - 1.0f);
	float2 reducedUv = (reducedPixel + 0.5f) * ReducedTarget.zw;
	float2 encodedDepth = tex2Dlod(ReducedDepth, float4(reducedUv, 0.0f, 0.0f)).rg;
	float nearest = DecodeDistance(encodedDepth.x);
	float farthest = max(DecodeDistance(encodedDepth.y), nearest);
	float span = farthest - nearest;
	float mixed = saturate(span / max(baseTolerance * 4.0f, 1.0f));
	float matchedDistance = clamp(fullDistance, nearest, farthest);
	float depthWeight = saturate(1.0f - abs(fullDistance - matchedDistance) / max(baseTolerance, 1.0f));
	depthWeight *= depthWeight;
	float weight = spatialWeight * depthWeight;
	if (weight <= 0.0f) {
		return;
	}

	float layerBlend = span > 0.0001f
		? saturate((matchedDistance - nearest) / span)
		: 0.0f;
	float4 nearAtmosphere = tex2Dlod(NearAtmosphere, float4(reducedUv, 0.0f, 0.0f));
	float4 farAtmosphere = tex2Dlod(FarAtmosphere, float4(reducedUv, 0.0f, 0.0f));
	float4 atmosphere = lerp(nearAtmosphere, farAtmosphere, layerBlend);
	if (!IsFiniteVector(atmosphere.rgb) || !IsFiniteScalar(atmosphere.a)) {
		return;
	}
	gathered.scattering += max(atmosphere.rgb, 0.0f) * weight;
	gathered.transmittance += saturate(atmosphere.a) * weight;
	gathered.weight += weight;
	gathered.mixed = max(gathered.mixed, mixed);
}

GatheredAtmosphere GatherAtmosphere(float2 uv, float fullDistance) {
	float2 reducedPosition = uv * ReducedTarget.xy - 0.5f;
	float2 basePixel = floor(reducedPosition);
	float2 fraction = saturate(reducedPosition - basePixel);
	float baseTolerance = max(
		ComposeData.y * max(ComposeData.x, 1.0f),
		fullDistance * ComposeData.z
	);

	GatheredAtmosphere gathered;
	gathered.scattering = 0.0f;
	gathered.transmittance = 0.0f;
	gathered.weight = 0.0f;
	gathered.mixed = 0.0f;
	AccumulateTap(
		gathered,
		basePixel,
		(1.0f - fraction.x) * (1.0f - fraction.y),
		fullDistance,
		baseTolerance
	);
	AccumulateTap(
		gathered,
		basePixel + float2(1.0f, 0.0f),
		fraction.x * (1.0f - fraction.y),
		fullDistance,
		baseTolerance
	);
	AccumulateTap(
		gathered,
		basePixel + float2(0.0f, 1.0f),
		(1.0f - fraction.x) * fraction.y,
		fullDistance,
		baseTolerance
	);
	AccumulateTap(
		gathered,
		basePixel + 1.0f,
		fraction.x * fraction.y,
		fullDistance,
		baseTolerance
	);
	return gathered;
}

float4 Main(PixelInput input) : COLOR0 {
	float4 source = tex2Dlod(WorldColor, float4(input.uv, 0.0f, 0.0f));
	float rawDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
	float fullDistance = RayDistance(input.uv, rawDepth);
	if (!IsFiniteScalar(fullDistance)) {
		return source;
	}

	GatheredAtmosphere gathered = GatherAtmosphere(input.uv, fullDistance);
	bool accepted = gathered.weight > WeightEpsilon;
	if (ComposeData.w > 0.5f) {
		if (!accepted) {
			return float4(1.0f, 0.0f, 0.0f, source.a);
		}
		if (IsSky(rawDepth)) {
			return float4(0.0f, 0.35f, 1.0f, source.a);
		}
		float confidence = saturate(gathered.weight);
		float3 acceptedColor = lerp(
			float3(1.0f, 0.55f, 0.0f),
			float3(0.0f, 1.0f, 0.15f),
			confidence * (1.0f - gathered.mixed)
		);
		return float4(acceptedColor, source.a);
	}
	if (!accepted || !IsFiniteVector(source.rgb) || !IsFiniteScalar(source.a)) {
		return source;
	}

	float reciprocalWeight = 1.0f / gathered.weight;
	float3 scattering = gathered.scattering * reciprocalWeight;
	float transmittance = saturate(gathered.transmittance * reciprocalWeight);
	float3 linearSource = DecodeExtendedSrgb(source.rgb);
	float3 linearOutput = linearSource * transmittance + scattering;
	float3 encodedOutput = EncodeExtendedSrgb(linearOutput);
	if (!IsFiniteVector(linearSource) || !IsFiniteVector(linearOutput)
		|| !IsFiniteVector(encodedOutput) || !IsFiniteScalar(transmittance)) {
		return source;
	}
	return float4(encodedOutput, source.a);
}
