row_major float4x4 ModelViewProjection : register(c0);
float4 BlendColor[3] : register(c4);
float3 EyePosition : register(c7);
row_major float4x4 Model : register(c8);

struct VertexInput {
    float4 position : POSITION;
    float4 uv : TEXCOORD0;
    float4 color : COLOR0;
};

struct VertexOutput {
    float4 position : POSITION;
    float3 location : TEXCOORD1;
    float2 uv : TEXCOORD0;
    float horizonFade : TEXCOORD2;
    float4 color : COLOR0;
};

VertexOutput Main(VertexInput input) {
    VertexOutput output;
    output.color.rgb = input.color.r * BlendColor[0].rgb + input.color.g * BlendColor[1].rgb + input.color.b * BlendColor[2].rgb;
    output.color.a = BlendColor[0].a * input.color.a;
    output.position = mul(ModelViewProjection, input.position).xyww;
#if OMV_REVERSED_DEPTH
    output.position.z = 0.0;
#endif
    output.location = input.position.xyz;
    output.uv = input.uv.xy;
    output.horizonFade = saturate((dot(Model[2], input.position) - EyePosition.z) / 17.0);
    return output;
}
