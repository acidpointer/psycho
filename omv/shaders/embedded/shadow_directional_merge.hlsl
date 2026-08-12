// Merge a cached static near cascade with the current actor-only EVSM map.
sampler2D StaticMoments : register(s0);
sampler2D ActorMoments : register(s1);

struct PixelInput { float2 uv : TEXCOORD0; };

float4 Main(PixelInput input) : COLOR0 {
    float4 staticMoments = tex2Dlod(StaticMoments, float4(input.uv, 0.0f, 0.0f));
    float4 actorMoments = tex2Dlod(ActorMoments, float4(input.uv, 0.0f, 0.0f));
    // Positive exponential moment one is monotonic in light-space depth.
    // Select the complete nearer distribution: minimizing channels
    // independently would combine incompatible positive/negative variances.
    return actorMoments.x < staticMoments.x ? actorMoments : staticMoments;
}
