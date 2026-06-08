sampler2D SceneColor : register(s0);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float4 Main(PixelInput input) : COLOR0 {
    return tex2D(SceneColor, input.uv);
}
