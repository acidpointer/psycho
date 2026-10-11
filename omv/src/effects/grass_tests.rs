//! Controlled native-bytecode coverage cases, not a reproduction of an
//! unrecorded game frame. The pixel programs are the shipped SDP records;
//! the vertex adapter publishes their audited interpolation ABI directly.

use super::grass::{self, CoverageScope, PreparedShader};
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

const ADAPTER: &[u8] = br#"
struct V { float4 p:POSITION; float4 t0:TEXCOORD0; float4 t1:TEXCOORD1;
float4 t2:TEXCOORD2; float4 t3:TEXCOORD3; float4 t4:TEXCOORD4;
float4 t5:TEXCOORD5; float4 c:COLOR0; };
float4 Fixture:register(c0);
V Main(float4 p:POSITION) {
V o; o.p=p; o.t0=float4(.5,.5,0,1); o.t1=float4(.5,.5,.25,1);
o.t2=o.t1; o.t3=o.t1; o.t4=float4(.25,.25,.25,1);
o.t5=float4(.5,.5,.5,Fixture.x); o.c=float4(.75,.5,.25,0); return o;
}
"#;

#[test]
fn single_sample_grass_matches_native_cutout_color_and_depth() {
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 8, 8, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device
        .create_render_target_texture(8, 8, D3DFMT_A8R8G8B8)
        .unwrap();
    let surface = target.surface_level(0).unwrap();
    let staging = device
        .create_system_memory_surface(8, 8, D3DFMT_A8R8G8B8)
        .unwrap();
    let depth = device
        .create_depth_stencil_surface(8, 8, D3DFMT_D24S8, D3DMULTISAMPLE_NONE, 0, false)
        .unwrap();
    device.set_render_target(0, &surface).unwrap();
    device.set_depth_stencil_surface(Some(&depth)).unwrap();
    for slot in 1..device.device_caps().unwrap().NumSimultaneousRTs.min(4) {
        device.clear_render_target(slot).unwrap();
    }
    device
        .set_viewport(&D3DVIEWPORT9 {
            Width: 8,
            Height: 8,
            MaxZ: 1.0,
            ..Default::default()
        })
        .unwrap();
    let vs = device
        .create_vertex_shader(
            &crate::shaders::compile_hlsl_source_target("grass_abi_adapter", ADAPTER, "vs_3_0")
                .unwrap(),
        )
        .unwrap();
    let decl = device
        .create_vertex_declaration(&[
            D3DVERTEXELEMENT9 {
                Stream: 0,
                Offset: 0,
                Type: D3DDECLTYPE_FLOAT4.0 as u8,
                Method: 0,
                Usage: D3DDECLUSAGE_POSITION.0 as u8,
                UsageIndex: 0,
            },
            D3DVERTEXELEMENT9 {
                Stream: 0xFF,
                Type: D3DDECLTYPE_UNUSED.0 as u8,
                ..Default::default()
            },
        ])
        .unwrap();
    device.set_vertex_declaration(&decl).unwrap();
    device.set_vertex_shader(&vs).unwrap();
    let albedo = device
        .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
        .unwrap();
    let auxiliary = device
        .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
        .unwrap();
    auxiliary.write_level0_argb_pixel(0xFF808080).unwrap();
    for sampler in 0..4 {
        device
            .set_texture(sampler, if sampler == 0 { &albedo } else { &auxiliary })
            .unwrap();
        for (state, value) in [
            (D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0),
            (D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0),
            (D3DSAMP_MINFILTER, D3DTEXF_POINT.0),
            (D3DSAMP_MAGFILTER, D3DTEXF_POINT.0),
            (D3DSAMP_MIPFILTER, D3DTEXF_NONE.0),
            (D3DSAMP_SRGBTEXTURE, 0),
        ] {
            device
                .set_sampler_state(sampler, state, value as u32)
                .unwrap();
        }
    }
    for (state, value) in [
        (D3DRS_ZENABLE, 1),
        (D3DRS_ZWRITEENABLE, 1),
        (D3DRS_ZFUNC, D3DCMP_LESSEQUAL.0 as u32),
        (D3DRS_STENCILENABLE, 0),
        (D3DRS_SCISSORTESTENABLE, 0),
        (D3DRS_CULLMODE, D3DCULL_NONE.0 as u32),
        (D3DRS_SRGBWRITEENABLE, 0),
        (D3DRS_COLORWRITEENABLE, 15),
        (D3DRS_MULTISAMPLEMASK, u32::MAX),
        (D3DRS_CLIPPLANEENABLE, 0),
        (D3DRS_ALPHATESTENABLE, 1),
        (D3DRS_ALPHAFUNC, D3DCMP_GREATER.0 as u32),
        (D3DRS_ALPHAREF, 10),
        (D3DRS_BLENDOP, D3DBLENDOP_ADD.0 as u32),
    ] {
        device.set_render_state(state, value).unwrap();
    }
    let mut constants = [[0.25; 4]; 16];
    let behind = device
        .create_pixel_shader(
            &crate::shaders::compile_hlsl_source_target(
                "grass_depth_probe",
                b"float4 Main():COLOR0{return float4(0,1,0,1);}",
                "ps_3_0",
            )
            .unwrap(),
        )
        .unwrap();
    let tri = |z: f32| {
        [
            [-1.0, -1.0, z, 1.0],
            [3.0, -1.0, z, 1.0],
            [-1.0, 3.0, z, 1.0],
        ]
    };
    let pairs = grass::native_pairs().unwrap();
    let mut native_differences = 0;
    for (pair, programs) in pairs.iter().enumerate() {
        let variant = programs.variant;
        let native = device.create_pixel_shader(&programs.tms).unwrap();
        // Exercise the production COM retention boundary; the native wrapper's
        // reference can disappear while OMV's pinned resource remains live.
        let pinned = unsafe { PixelShader9::retain_raw(native.as_raw()) }.unwrap();
        drop(native);
        let prepared = PreparedShader::prepare(&device, pinned, &pairs).unwrap();
        let tms = &prepared.source;
        let replacement = prepared.replacement.as_ref().unwrap();
        let single = device.create_pixel_shader(&programs.single).unwrap();
        assert_eq!(tms.function().unwrap(), programs.tms);
        assert_eq!(replacement.function().unwrap(), programs.single);
        for cutoff in [0u8, 10, 64, 128, 254, 255] {
            constants[3] = [f32::from(cutoff) / 255.0, 0.0, 0.0, 0.0];
            device.set_pixel_shader_constant_f(0, &constants).unwrap();
            for hdr in [false, true] {
                for fade in [0.0, 0.02, 0.5, 1.0] {
                    device
                        .set_vertex_shader_constant_f(0, &[[fade, 0.0, 0.0, 0.0]])
                        .unwrap();
                    for alpha in [0u32, 8, 32, 127, 128, 129, 192, 255] {
                        albedo
                            .write_level0_argb_pixel((alpha << 24) | 0x00804020)
                            .unwrap();
                        let mut oracle = None;
                        for phase in 0..3 {
                            device
                                .clear_attachments(
                                    (D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER) as u32,
                                    0xFF202040,
                                    1.0,
                                    0,
                                )
                                .unwrap();
                            device.set_render_state(D3DRS_ALPHABLENDENABLE, 0).unwrap();
                            device
                                .set_render_state(D3DRS_SRCBLEND, D3DBLEND_ONE.0 as u32)
                                .unwrap();
                            device
                                .set_render_state(D3DRS_DESTBLEND, D3DBLEND_ZERO.0 as u32)
                                .unwrap();
                            device
                                .set_pixel_shader(if phase == 0 { &single } else { tms })
                                .unwrap();
                            let ordinary = variant < 4;
                            let blend = ordinary && hdr;
                            device
                                .set_render_state(D3DRS_ZWRITEENABLE, u32::from(ordinary))
                                .unwrap();
                            if !ordinary {
                                device.set_render_state(D3DRS_ALPHABLENDENABLE, 1).unwrap();
                                device
                                    .set_render_state(D3DRS_SRCBLEND, D3DBLEND_DESTCOLOR.0 as u32)
                                    .unwrap();
                                device
                                    .set_render_state(D3DRS_DESTBLEND, D3DBLEND_ZERO.0 as u32)
                                    .unwrap();
                            }
                            if phase == 0 && blend {
                                device.set_render_state(D3DRS_ALPHABLENDENABLE, 1).unwrap();
                                device
                                    .set_render_state(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA.0 as u32)
                                    .unwrap();
                                device
                                    .set_render_state(
                                        D3DRS_DESTBLEND,
                                        D3DBLEND_INVSRCALPHA.0 as u32,
                                    )
                                    .unwrap();
                            }
                            let before_states = [
                                D3DRS_ALPHABLENDENABLE,
                                D3DRS_SRCBLEND,
                                D3DRS_DESTBLEND,
                                D3DRS_ZWRITEENABLE,
                            ]
                            .map(|state| device.render_state(state).unwrap());
                            device.begin_scene().unwrap();
                            let mut scope = if phase == 1 {
                                CoverageScope::begin(
                                    &device,
                                    tms.as_raw(),
                                    replacement,
                                    if blend { 7 } else { 0 },
                                    0,
                                )
                                .ok()
                                .unwrap()
                            } else {
                                None
                            };
                            unsafe { device.draw_primitive_up(D3DPT_TRIANGLELIST, 1, &tri(0.25)) }
                                .unwrap();
                            if let Some(ref mut scope) = scope {
                                assert!(scope.restore(&device));
                            }
                            device.end_scene().unwrap();
                            device.copy_render_target_data(&surface, &staging).unwrap();
                            let color = staging.read_rgba8().unwrap();
                            assert!(color.iter().flatten().all(|value| value.is_finite()));
                            if phase == 1 {
                                assert_eq!(
                                    device.current_pixel_shader_raw().unwrap(),
                                    tms.as_raw()
                                );
                                assert_eq!(
                                    [
                                        D3DRS_ALPHABLENDENABLE,
                                        D3DRS_SRCBLEND,
                                        D3DRS_DESTBLEND,
                                        D3DRS_ZWRITEENABLE
                                    ]
                                    .map(|state| device.render_state(state).unwrap()),
                                    before_states
                                );
                            }
                            // A behind draw is an observable depth rejection boundary.
                            device.begin_scene().unwrap();
                            device.set_render_state(D3DRS_ALPHATESTENABLE, 0).unwrap();
                            device.set_render_state(D3DRS_ALPHABLENDENABLE, 0).unwrap();
                            device.set_pixel_shader(&behind).unwrap();
                            unsafe { device.draw_primitive_up(D3DPT_TRIANGLELIST, 1, &tri(0.75)) }
                                .unwrap();
                            device.end_scene().unwrap();
                            device.set_render_state(D3DRS_ALPHATESTENABLE, 1).unwrap();
                            device.copy_render_target_data(&surface, &staging).unwrap();
                            let pixels = staging.read_rgba8().unwrap();
                            if phase == 0 {
                                oracle = Some((color, pixels));
                            } else if phase == 1 {
                                let expected = oracle.as_ref().unwrap();
                                assert!(
                                    color == expected.0 && pixels == expected.1,
                                    "native pair {pair}, variant {variant}, texture alpha {alpha}, fade {fade}, cutoff {cutoff}, HDR {hdr}"
                                );
                            } else if (color, pixels) != *oracle.as_ref().unwrap() {
                                native_differences += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        native_differences > 0,
        "the unchanged native TMS path must fail the same color/depth oracle"
    );

    let prepared = PreparedShader::prepare(
        &device,
        device.create_pixel_shader(&pairs[0].tms).unwrap(),
        &pairs,
    )
    .unwrap();
    let tms = &prepared.source;
    let replacement = prepared.replacement.as_ref().unwrap();
    // The lock mask is native integration input. Execute its production
    // device transaction directly rather than reconstructing engine counters.
    let states = [
        D3DRS_ALPHABLENDENABLE,
        D3DRS_SRCBLEND,
        D3DRS_DESTBLEND,
        D3DRS_ADAPTIVETESS_Y,
        D3DRS_POINTSIZE,
    ];
    let prior = [
        0,
        D3DBLEND_ONE.0 as u32,
        D3DBLEND_ZERO.0 as u32,
        u32::from_le_bytes(*b"ATOC"),
        u32::from_le_bytes(*b"A2M1"),
    ];
    for mask in [0, 1, 6, 7] {
        for vendor in [0, 1, 2] {
            for (state, value) in states.into_iter().zip(prior) {
                device.set_render_state(state, value).unwrap();
            }
            device.set_pixel_shader(tms).unwrap();
            let mut scope = CoverageScope::begin(&device, tms.as_raw(), replacement, mask, vendor)
                .ok()
                .unwrap()
                .unwrap();
            assert_eq!(
                device.current_pixel_shader_raw().unwrap(),
                replacement.as_raw()
            );
            let mut expected = prior;
            for (bit, value) in [1, D3DBLEND_SRCALPHA.0 as u32, D3DBLEND_INVSRCALPHA.0 as u32]
                .into_iter()
                .enumerate()
            {
                if mask & (1 << bit) != 0 {
                    expected[bit] = value;
                }
            }
            if vendor == 1 {
                expected[3] = 0;
            }
            if vendor == 2 {
                expected[4] = u32::from_le_bytes(*b"A2M0");
            }
            assert_eq!(
                states.map(|state| device.render_state(state).unwrap()),
                expected
            );
            assert!(scope.restore(&device));
            assert_eq!(
                states.map(|state| device.render_state(state).unwrap()),
                prior
            );
            assert_eq!(device.current_pixel_shader_raw().unwrap(), tms.as_raw());
        }
    }
    // A provider that changed the active pixel program keeps its exact binding
    // and state. Preparation also rejects executable programs outside the bank.
    assert!(PreparedShader::prepare(&device, behind.clone(), &pairs).is_err());
    device.set_pixel_shader(&behind).unwrap();
    assert!(
        CoverageScope::begin(&device, tms.as_raw(), replacement, 7, 1)
            .ok()
            .unwrap()
            .is_none()
    );
    assert_eq!(device.current_pixel_shader_raw().unwrap(), behind.as_raw());
    assert_eq!(
        states.map(|state| device.render_state(state).unwrap()),
        prior
    );

    let native_single = device.create_pixel_shader(&pairs[0].single).unwrap();
    let already_single = PreparedShader::prepare(&device, native_single.clone(), &pairs).unwrap();
    assert_eq!(
        already_single.replacement.as_ref().unwrap().as_raw(),
        native_single.as_raw()
    );

    // Observe the real multisample attachment at the production admission
    // boundary. The presentation/global flags do not choose this behavior.
    device.set_depth_stencil_surface(None).unwrap();
    let msaa = device
        .create_render_target_surface(8, 8, D3DFMT_A8R8G8B8, D3DMULTISAMPLE_4_SAMPLES, 0, false)
        .unwrap();
    assert_eq!(
        msaa.desc().unwrap().MultiSampleType,
        D3DMULTISAMPLE_4_SAMPLES
    );
    device.set_render_target(0, &msaa).unwrap();
    device.set_pixel_shader(tms).unwrap();
    for vendor in [0, 1, 2] {
        assert!(
            CoverageScope::begin(&device, tms.as_raw(), replacement, 7, vendor)
                .ok()
                .unwrap()
                .is_none()
        );
        assert_eq!(device.current_pixel_shader_raw().unwrap(), tms.as_raw());
        assert_eq!(
            states.map(|state| device.render_state(state).unwrap()),
            prior
        );
    }
}

#[test]
fn native_grass_programs_preserve_texture_work_and_meet_bytecode_budgets() {
    let pairs = grass::native_pairs().unwrap();
    for pair in &pairs {
        let (instructions, fetches, bytes) = match pair.variant {
            0 => (18, 1, 484),
            1 => (29, 3, 708),
            2 => (27, 3, 684),
            3 => (38, 5, 908),
            4..=6 => (124, 10, 2396),
            _ => unreachable!("native record decoder validates the bank index"),
        };
        let mut counts = [0; 2];
        for (index, code) in [&pair.tms, &pair.single].into_iter().enumerate() {
            assert!(matches!(code[0], 0xFFFF_0201 | 0xFFFF_0300));
            let mut offset = 1;
            let mut texture_count = 0;
            let mut samplers = 0u32;
            while offset < code.len() && code[offset] as u16 != 0xffff {
                let token = code[offset];
                let opcode = token as u16;
                if opcode == 0xfffe {
                    offset += 1 + ((token >> 16) & 0x7fff) as usize;
                    continue;
                }
                let end = offset + 1 + ((token >> 24) & 0x0f) as usize;
                assert!(end <= code.len());
                counts[index] += 1;
                texture_count += usize::from(matches!(opcode, 66 | 93 | 95));
                assert!(
                    !matches!(opcode, 91..=93 | 95),
                    "unexpected derivative/gradient/LOD op"
                );
                for &parameter in &code[offset + 1..end] {
                    let register_type = ((parameter >> 28) & 7) | ((parameter >> 8) & 0x18);
                    if register_type == 10 {
                        let sampler = parameter & 0x7ff;
                        assert!(sampler < 4);
                        samplers |= 1 << sampler;
                    }
                }
                offset = end;
            }
            assert_eq!(code.get(offset), Some(&0xffff), "native program terminator");
            assert!(counts[index] <= instructions);
            assert_eq!(texture_count, fetches);
            assert!(samplers != 0);
            assert!(code.len() * 4 <= bytes);
        }
        assert!(
            counts[1] <= counts[0] + 1,
            "single-sample instruction growth"
        );
    }
}
