row_major float4x4 ModelViewProjection : register(c0);
float4 BlendColor[3] : register(c4);

struct VertexInput {
    float4 position : POSITION;
    float4 color : COLOR0;
};

struct VertexOutput {
    float4 position : POSITION;
    float3 eye : TEXCOORD0_centroid;
    float4 color : COLOR0;
};

VertexOutput Main(VertexInput input) {
    VertexOutput output;
    output.color.rgb = input.color.r * BlendColor[0].rgb + input.color.g * BlendColor[1].rgb + input.color.b * BlendColor[2].rgb;
    output.color.a = BlendColor[0].a * input.color.a;
    output.position = mul(ModelViewProjection, input.position).xyww;
#if OMV_REVERSED_DEPTH
    output.position.z *= 0.000100017;
#else
    output.position.z *= 0.999899983;
#endif
    output.eye = input.position.xyz;
    return output;
}
