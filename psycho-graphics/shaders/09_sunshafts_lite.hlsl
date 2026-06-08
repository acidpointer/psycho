/*
    Psycho Graphics sunshafts config anchor.

    The effect is implemented by the engine-side sunshafts pipeline, which owns
    the mask, radial accumulation, blur, and compose buffers. This file exists
    only so the live shader menu can expose the effect configuration.
*/

sampler2D SceneColor : register(s0);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float4 Main(PixelInput input) : COLOR0 {
    return tex2D(SceneColor, input.uv);
}
