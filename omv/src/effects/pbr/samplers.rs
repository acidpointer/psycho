//! Sampler and texture binding policy.
//!
//! This phase validates object samplers declared by the NVR object template.
//! It does not resolve material arrays or invent fallback textures. D3D sampler
//! state is global, so selector stamps from the SetTexture mirror are
//! diagnostic only and must not block replacement.

use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::os::windows::directx9::Device9Ref;

use super::shader_registry::{self, ShaderStage, ShaderTemplate};

const OBJECT_SAMPLER_LAYOUT_NONE: u32 = 0;
const OBJECT_SAMPLER_LAYOUT_BASE_NORMAL: u32 = 1;
const OBJECT_SAMPLER_LAYOUT_NORMAL_ONLY: u32 = 2;
const OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW3: u32 = 3;
const OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW4: u32 = 4;
const OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_SHADOW56: u32 = 5;
const OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_SHADOW67: u32 = 6;
const OBJECT_SAMPLER_LAYOUT_NORMAL_ONLY_SHADOW45: u32 = 7;
const OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW3_SHADOW56: u32 = 8;
const OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW4_SHADOW67: u32 = 9;

const OBJECT_SAMPLER_FALLBACK_NONE: u32 = 0;
const OBJECT_SAMPLER_FALLBACK_NOT_PIXEL: u32 = 1;
const OBJECT_SAMPLER_FALLBACK_MISSING_BASE: u32 = 2;
const OBJECT_SAMPLER_FALLBACK_MISSING_NORMAL: u32 = 3;
const OBJECT_SAMPLER_FALLBACK_MISSING_GLOW: u32 = 4;
const OBJECT_SAMPLER_FALLBACK_MISSING_SHADOW: u32 = 5;
const OBJECT_SAMPLER_FALLBACK_MISSING_SHADOW_MASK: u32 = 6;
const TEXTURE_STAGE_COUNT: usize = 16;

static TEXTURE_TRACKING_READY: AtomicBool = AtomicBool::new(false);
static TEXTURE_SLOTS: LazyLock<[TextureStageSlot; TEXTURE_STAGE_COUNT]> =
    LazyLock::new(|| std::array::from_fn(|_| TextureStageSlot::new()));
static TEXTURE_BINDS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static TEXTURE_BINDS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_SAMPLER_CHECKS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_SAMPLER_FALLBACKS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_SAMPLER_SELECTOR_MISMATCHES_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_SAMPLER_CHECKS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_SAMPLER_FALLBACKS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_SAMPLER_SELECTOR_MISMATCHES_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_SAMPLER_LAYOUT: AtomicU32 = AtomicU32::new(OBJECT_SAMPLER_LAYOUT_NONE);
static OBJECT_LAST_SAMPLER_FALLBACK: AtomicU32 = AtomicU32::new(OBJECT_SAMPLER_FALLBACK_NONE);
static OBJECT_LAST_SAMPLER_SELECTOR: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_SAMPLER_EXPECTED_MASK: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_SAMPLER_OBSERVED_MASK: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_SAMPLER_FAILED_STAGE: AtomicU32 = AtomicU32::new(u32::MAX);

struct TextureStageSlot {
    texture: AtomicUsize,
    selector: AtomicUsize,
}

impl TextureStageSlot {
    fn new() -> Self {
        Self {
            texture: AtomicUsize::new(0),
            selector: AtomicUsize::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ObjectSamplerLayout {
    code: u32,
    base: Option<u32>,
    normal: u32,
    glow: Option<u32>,
    shadow: Option<(u32, u32)>,
}

pub(super) fn set_texture_tracking_ready(ready: bool) {
    TEXTURE_TRACKING_READY.store(ready, Ordering::Release);
}

pub(super) fn record_texture_binding(stage: u32, texture: *mut std::ffi::c_void, selector: usize) {
    let Ok(index) = usize::try_from(stage) else {
        return;
    };
    let Some(slot) = TEXTURE_SLOTS.get(index) else {
        return;
    };

    slot.texture.store(texture as usize, Ordering::Release);
    slot.selector.store(selector, Ordering::Release);
    TEXTURE_BINDS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn validate_object_layout(
    device: &Device9Ref<'_>,
    template_id: u16,
    selector: usize,
) -> Result<(), ()> {
    OBJECT_SAMPLER_CHECKS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);

    let Some(template) = shader_registry::object_template_at(template_id) else {
        record_fallback(
            OBJECT_SAMPLER_LAYOUT_NONE,
            OBJECT_SAMPLER_FALLBACK_NOT_PIXEL,
        );
        return Err(());
    };
    if template.stage != ShaderStage::Pixel {
        record_fallback(
            OBJECT_SAMPLER_LAYOUT_NONE,
            OBJECT_SAMPLER_FALLBACK_NOT_PIXEL,
        );
        return Err(());
    }

    let layout = object_sampler_layout(template);
    OBJECT_LAST_SAMPLER_LAYOUT.store(layout.code, Ordering::Release);
    OBJECT_LAST_SAMPLER_SELECTOR.store(selector, Ordering::Release);
    OBJECT_LAST_SAMPLER_EXPECTED_MASK.store(layout.expected_mask(), Ordering::Release);
    OBJECT_LAST_SAMPLER_OBSERVED_MASK.store(observed_device_mask(device), Ordering::Release);
    OBJECT_LAST_SAMPLER_FAILED_STAGE.store(u32::MAX, Ordering::Release);

    if let Some(stage) = layout.base
        && !texture_stage_valid(
            device,
            stage,
            selector,
            OBJECT_SAMPLER_FALLBACK_MISSING_BASE,
        )
    {
        return Err(());
    }
    if !texture_stage_valid(
        device,
        layout.normal,
        selector,
        OBJECT_SAMPLER_FALLBACK_MISSING_NORMAL,
    ) {
        return Err(());
    }
    if let Some(stage) = layout.glow
        && !texture_stage_valid(
            device,
            stage,
            selector,
            OBJECT_SAMPLER_FALLBACK_MISSING_GLOW,
        )
    {
        return Err(());
    }
    if let Some((shadow, mask)) = layout.shadow {
        if !texture_stage_valid(
            device,
            shadow,
            selector,
            OBJECT_SAMPLER_FALLBACK_MISSING_SHADOW,
        ) {
            return Err(());
        }
        if !texture_stage_valid(
            device,
            mask,
            selector,
            OBJECT_SAMPLER_FALLBACK_MISSING_SHADOW_MASK,
        ) {
            return Err(());
        }
    }

    OBJECT_LAST_SAMPLER_FALLBACK.store(OBJECT_SAMPLER_FALLBACK_NONE, Ordering::Release);
    Ok(())
}

pub(super) fn service_frame() {
    TEXTURE_BINDS_LAST_FRAME.store(
        TEXTURE_BINDS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_SAMPLER_CHECKS_LAST_FRAME.store(
        OBJECT_SAMPLER_CHECKS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_SAMPLER_FALLBACKS_LAST_FRAME.store(
        OBJECT_SAMPLER_FALLBACKS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_SAMPLER_SELECTOR_MISMATCHES_LAST_FRAME.store(
        OBJECT_SAMPLER_SELECTOR_MISMATCHES_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
}

pub(super) fn object_sampler_checks_last_frame() -> u32 {
    OBJECT_SAMPLER_CHECKS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_sampler_fallbacks_last_frame() -> u32 {
    OBJECT_SAMPLER_FALLBACKS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_sampler_selector_mismatches_last_frame() -> u32 {
    OBJECT_SAMPLER_SELECTOR_MISMATCHES_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn texture_tracking_ready() -> bool {
    TEXTURE_TRACKING_READY.load(Ordering::Acquire)
}

pub(super) fn texture_binds_last_frame() -> u32 {
    TEXTURE_BINDS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_last_sampler_layout_label() -> &'static str {
    sampler_layout_label(OBJECT_LAST_SAMPLER_LAYOUT.load(Ordering::Acquire))
}

pub(super) fn object_last_sampler_fallback_label() -> &'static str {
    sampler_fallback_label(OBJECT_LAST_SAMPLER_FALLBACK.load(Ordering::Acquire))
}

pub(super) fn object_last_sampler_selector() -> usize {
    OBJECT_LAST_SAMPLER_SELECTOR.load(Ordering::Acquire)
}

pub(super) fn object_last_sampler_expected_mask() -> u32 {
    OBJECT_LAST_SAMPLER_EXPECTED_MASK.load(Ordering::Acquire)
}

pub(super) fn object_last_sampler_observed_mask() -> u32 {
    OBJECT_LAST_SAMPLER_OBSERVED_MASK.load(Ordering::Acquire)
}

pub(super) fn object_last_sampler_failed_stage() -> u32 {
    OBJECT_LAST_SAMPLER_FAILED_STAGE.load(Ordering::Acquire)
}

pub(super) fn reset() {
    OBJECT_SAMPLER_CHECKS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_SAMPLER_FALLBACKS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_SAMPLER_SELECTOR_MISMATCHES_THIS_FRAME.store(0, Ordering::Release);
    TEXTURE_BINDS_THIS_FRAME.store(0, Ordering::Release);
    TEXTURE_BINDS_LAST_FRAME.store(0, Ordering::Release);
    TEXTURE_TRACKING_READY.store(false, Ordering::Release);
    for slot in TEXTURE_SLOTS.iter() {
        slot.texture.store(0, Ordering::Release);
        slot.selector.store(0, Ordering::Release);
    }
    OBJECT_SAMPLER_CHECKS_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_SAMPLER_FALLBACKS_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_SAMPLER_SELECTOR_MISMATCHES_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_LAST_SAMPLER_LAYOUT.store(OBJECT_SAMPLER_LAYOUT_NONE, Ordering::Release);
    OBJECT_LAST_SAMPLER_FALLBACK.store(OBJECT_SAMPLER_FALLBACK_NONE, Ordering::Release);
    OBJECT_LAST_SAMPLER_SELECTOR.store(0, Ordering::Release);
    OBJECT_LAST_SAMPLER_EXPECTED_MASK.store(0, Ordering::Release);
    OBJECT_LAST_SAMPLER_OBSERVED_MASK.store(0, Ordering::Release);
    OBJECT_LAST_SAMPLER_FAILED_STAGE.store(u32::MAX, Ordering::Release);
}

impl ObjectSamplerLayout {
    fn expected_mask(self) -> u32 {
        let mut mask = stage_mask(self.normal);
        if let Some(stage) = self.base {
            mask |= stage_mask(stage);
        }
        if let Some(stage) = self.glow {
            mask |= stage_mask(stage);
        }
        if let Some((shadow, shadow_mask)) = self.shadow {
            mask |= stage_mask(shadow) | stage_mask(shadow_mask);
        }
        mask
    }
}

fn texture_stage_valid(
    device: &Device9Ref<'_>,
    stage: u32,
    selector: usize,
    missing_reason: u32,
) -> bool {
    if device.texture_bound(stage) {
        record_selector_drift(stage, selector);
        return true;
    }
    record_fallback_for_stage(missing_reason, stage);
    false
}

fn stage_mask(stage: u32) -> u32 {
    if stage < TEXTURE_STAGE_COUNT as u32 {
        1u32 << stage
    } else {
        0
    }
}

fn object_sampler_layout(template: &ShaderTemplate) -> ObjectSamplerLayout {
    let diffuse = has_define(template.defines, "PBR_OBJECT_DIFFUSE");
    let only_specular = has_define(template.defines, "PBR_OBJECT_ONLY_SPECULAR");
    let only_light = has_define(template.defines, "PBR_OBJECT_ONLY_LIGHT");
    let si = has_define(template.defines, "PBR_OBJECT_SI");
    let hair = has_define(template.defines, "PBR_OBJECT_HAIR");
    let shadow = has_define(template.defines, "PBR_OBJECT_SHADOW");
    let high_lights = has_define(template.defines, "PBR_OBJECT_HIGH");

    if high_lights {
        return ObjectSamplerLayout {
            code: OBJECT_SAMPLER_LAYOUT_BASE_NORMAL,
            base: Some(0),
            normal: 1,
            glow: None,
            shadow: None,
        };
    }

    let (base, normal) = if diffuse || only_specular {
        (None, 0)
    } else {
        (Some(0), 1)
    };
    let glow = if (si || hair) && !only_specular {
        Some(if only_light { 3 } else { 4 })
    } else {
        None
    };
    let shadow = if shadow {
        Some(if only_specular {
            (4, 5)
        } else if only_light {
            (5, 6)
        } else {
            (6, 7)
        })
    } else {
        None
    };

    ObjectSamplerLayout {
        code: object_sampler_layout_code(base, glow, shadow),
        base,
        normal,
        glow,
        shadow,
    }
}

fn object_sampler_layout_code(
    base: Option<u32>,
    glow: Option<u32>,
    shadow: Option<(u32, u32)>,
) -> u32 {
    match (base, glow, shadow) {
        (None, None, None) => OBJECT_SAMPLER_LAYOUT_NORMAL_ONLY,
        (None, None, Some((4, 5))) => OBJECT_SAMPLER_LAYOUT_NORMAL_ONLY_SHADOW45,
        (Some(0), None, None) => OBJECT_SAMPLER_LAYOUT_BASE_NORMAL,
        (Some(0), Some(3), None) => OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW3,
        (Some(0), Some(4), None) => OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW4,
        (Some(0), None, Some((5, 6))) => OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_SHADOW56,
        (Some(0), None, Some((6, 7))) => OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_SHADOW67,
        (Some(0), Some(3), Some((5, 6))) => OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW3_SHADOW56,
        (Some(0), Some(4), Some((6, 7))) => OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW4_SHADOW67,
        _ => OBJECT_SAMPLER_LAYOUT_NONE,
    }
}

fn record_fallback(layout: u32, reason: u32) {
    OBJECT_LAST_SAMPLER_LAYOUT.store(layout, Ordering::Release);
    OBJECT_LAST_SAMPLER_FALLBACK.store(reason, Ordering::Release);
    OBJECT_SAMPLER_FALLBACKS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
}

fn record_fallback_for_stage(reason: u32, stage: u32) {
    OBJECT_LAST_SAMPLER_FALLBACK.store(reason, Ordering::Release);
    OBJECT_LAST_SAMPLER_FAILED_STAGE.store(stage, Ordering::Release);
    OBJECT_SAMPLER_FALLBACKS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
}

fn has_define(defines: &str, name: &str) -> bool {
    defines.lines().any(|line| {
        let mut parts = line.split_whitespace();
        parts.next() == Some("#define") && parts.next() == Some(name)
    })
}

fn sampler_layout_label(layout: u32) -> &'static str {
    match layout {
        OBJECT_SAMPLER_LAYOUT_BASE_NORMAL => "BaseMap s0, NormalMap s1",
        OBJECT_SAMPLER_LAYOUT_NORMAL_ONLY => "NormalMap s0",
        OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW3 => "Base s0, Normal s1, Glow s3",
        OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW4 => "Base s0, Normal s1, Glow s4",
        OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_SHADOW56 => "Base s0, Normal s1, Shadow s5/s6",
        OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_SHADOW67 => "Base s0, Normal s1, Shadow s6/s7",
        OBJECT_SAMPLER_LAYOUT_NORMAL_ONLY_SHADOW45 => "Normal s0, Shadow s4/s5",
        OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW3_SHADOW56 => {
            "Base s0, Normal s1, Glow s3, Shadow s5/s6"
        }
        OBJECT_SAMPLER_LAYOUT_BASE_NORMAL_GLOW4_SHADOW67 => {
            "Base s0, Normal s1, Glow s4, Shadow s6/s7"
        }
        _ => "none",
    }
}

fn sampler_fallback_label(reason: u32) -> &'static str {
    match reason {
        OBJECT_SAMPLER_FALLBACK_NOT_PIXEL => "not a pixel object template",
        OBJECT_SAMPLER_FALLBACK_MISSING_BASE => "missing BaseMap sampler",
        OBJECT_SAMPLER_FALLBACK_MISSING_NORMAL => "missing NormalMap sampler",
        OBJECT_SAMPLER_FALLBACK_MISSING_GLOW => "missing GlowMap sampler",
        OBJECT_SAMPLER_FALLBACK_MISSING_SHADOW => "missing ShadowMap sampler",
        OBJECT_SAMPLER_FALLBACK_MISSING_SHADOW_MASK => "missing ShadowMaskMap sampler",
        _ => "none",
    }
}

fn observed_device_mask(device: &Device9Ref<'_>) -> u32 {
    let mut mask = 0;
    for stage in 0..TEXTURE_STAGE_COUNT as u32 {
        if device.texture_bound(stage) {
            mask |= stage_mask(stage);
        }
    }
    mask
}

fn record_selector_drift(stage: u32, selector: usize) {
    if selector == 0 || !TEXTURE_TRACKING_READY.load(Ordering::Acquire) {
        return;
    }
    let Ok(index) = usize::try_from(stage) else {
        return;
    };
    let Some(slot) = TEXTURE_SLOTS.get(index) else {
        return;
    };
    if slot.texture.load(Ordering::Acquire) != 0
        && slot.selector.load(Ordering::Acquire) != selector
    {
        OBJECT_SAMPLER_SELECTOR_MISMATCHES_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
    }
}
