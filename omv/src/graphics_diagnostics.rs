//! Compile-time-present, runtime-gated attribution for OMV's serialized
//! graphics callbacks.
//!
//! This instrumentation is temporary evidence collection for the NVIDIA
//! laptop performance investigation and will be removed once the evidence is
//! gathered. It is compiled into every build and always active: sampled
//! summaries emit one line per window and the A/B schedule skips one effect
//! family at a time. Disarmed paths do not exist; callback writers pay one
//! relaxed atomic load per counter or span and the present boundary pays a
//! few atomic operations per frame.
//!
//! Callback writers touch fixed atomic storage only. They never allocate,
//! format text, take a lock, submit a GPU query, or write a log. The xNVSE
//! `OnFramePresent` callback seals the sampled frame. Instead of one raw line
//! per sampled frame, sealed samples accumulate into a window and the boundary
//! emits one aggregated `[GRAPHICS PERF SUMMARY]` line per window with
//! per-frame means, so evidence stays readable without per-frame spam.
//!
//! Timings are CPU wall-clock intervals. A long interval around D3D work can
//! indicate a driver wait, but is not proof that the GPU spent the same
//! duration executing that work; D3D9 exposes no reliable per-pass GPU
//! timestamp query.
//!
//! The separately armed performance profile measures real per-effect GPU cost
//! by skipping one embedded effect family at a time in fixed windows and
//! reporting median/p90 present-boundary frame intervals per window as
//! `[GRAPHICS PERF A/B]` lines. Menu and loading-screen frames are excluded,
//! each window discards a settling prefix after a family switch, and window
//! zero is an unmodified baseline. The delta against the nearest baseline
//! windows attributes frame time to the skipped family. A skipped family must
//! behave exactly like an effect with no work, so pass-graph invariants stay
//! intact; profile builds visibly omit one effect at a time by design.

/// Cross-subsystem events that can multiply work within one presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Counter {
    /// Calls through the common native shadow transaction.
    NativeShadowEntry,
    /// Native shadow calls made by dispatcher variant A.
    NativeShadowVariantA,
    /// Native shadow calls made by dispatcher variant B.
    NativeShadowVariantB,
    /// Native shadow calls made by dispatcher variant C.
    NativeShadowVariantC,
    /// Native shadow calls owned by the main gameplay renderer.
    NativeShadowMain,
    /// Native shadow calls owned by a special render transaction.
    NativeShadowSpecial,
    /// Native shadow calls owned by screenshot rendering.
    NativeShadowScreenshot,
    /// Native shadow calls whose caller frame was not recognized.
    NativeShadowUnknownContext,
    /// Authoritative scalar-light manager traversals.
    SceneLightTraversal,
    /// Repeated light-publication attempts rejected in one render epoch.
    RepeatedLightPublication,
    /// Completed native shadow-slot callbacks.
    NativeShadowSlot,
    /// Completed native shadow resources retained successfully.
    RetainedNativeShadow,
    /// Native `BSShader::SetShaders` calls observed by PBR.
    SetShaders,
    /// Native `NiDX9RenderState::SetTexture` calls observed by PBR.
    SetTexture,
    /// Actual `NiTriShape` renderer submissions.
    TriShapeSubmission,
    /// Actual `NiTriStrips` renderer submissions.
    TriStripsSubmission,
    /// PBR geometry admissions.
    PbrAdmission,
    /// PBR geometry fallbacks to the native pair.
    PbrFallback,
    /// Native-sky geometry admissions.
    SkyAdmission,
    /// Native-sky geometry fallbacks.
    SkyFallback,
    /// Physical color copies issued by OMV.
    ColorCopy,
    /// Physical depth copies issued by OMV.
    DepthCopy,
    /// Broad D3D state-block captures.
    StateCapture,
    /// Broad D3D state-block applications.
    StateApply,
    /// Native shader-package transitions.
    ShaderPackageTransition,
    /// Native-PBR readiness queries made from selector or geometry callbacks.
    PbrReadinessQuery,
    /// Logical compiler-state entries inspected by a readiness query.
    PbrReadinessEntry,
    /// Geometry callbacks rejected before broader PBR readiness work.
    PbrPendingNone,
    /// Positive shader-table lookup-cache hits.
    ShaderTablePositiveHit,
    /// Shader-table lookup-cache misses.
    ShaderTableMiss,
    /// Shader-table slots inspected after a cache miss.
    ShaderTableEntry,
    /// Checked memory-range validations performed by object-PBR admission.
    ObjectMemoryValidation,
    /// Checked memory-range validations performed by native-sky admission.
    SkyMemoryValidation,
    /// Close-terrain light-cache hits.
    TerrainLightCacheHit,
    /// Close-terrain light-cache misses.
    TerrainLightCacheMiss,
    /// Native render-pass light entries inspected for close terrain.
    TerrainNativeLightEntry,
    /// Property-local light entries inspected for close terrain.
    TerrainPropertyLightEntry,
    /// Manager-published light entries inspected for close terrain.
    TerrainManagerLightEntry,
    /// Exact supplemental-light payload cache hits.
    SupplementalPayloadHit,
    /// Supplemental-light texture payload uploads.
    SupplementalPayloadUpload,
    /// Dynamic supplemental-light texture discard locks.
    SupplementalDiscardLock,
    /// Supplemental sampler-state getter calls.
    SupplementalSamplerGet,
    /// Supplemental sampler-state setter calls, including restoration.
    SupplementalSamplerSet,
    /// Close-terrain draws with no supplemental lights.
    SupplementalLightCountZero,
    /// Close-terrain draws with one through six supplemental lights.
    SupplementalLightCountOneToSix,
    /// Close-terrain draws with seven through twelve supplemental lights.
    SupplementalLightCountSevenToTwelve,
    /// Close-terrain draws with thirteen through twenty-four supplemental lights.
    SupplementalLightCountThirteenToTwentyFour,
    /// Raw native-sky shader transitions, including restoration.
    SkyRawShaderTransition,
    /// Sampled frames whose presentation serviced an open menu.
    MenuFrame,
    /// Depth resolution calls that returned a usable depth frame.
    DepthResolveResolved,
    /// Depth resolution calls rejected because another owner held the resolver.
    DepthResolveBusy,
    /// Depth resolution calls rejected by route, stage, or D3D errors.
    DepthResolveRejected,
    /// Sampler unbinds issued by OMV's clear helper.
    TargetClear,
    /// Static sun cascades actually rendered by shadow production.
    ShadowCascade,
    /// Cube faces rebuilt from immutable or published geometry.
    ShadowFaceStatic,
    /// Cube faces merged with current animated casters.
    ShadowFaceDynamic,
    /// Spatial AA draws identified as the Fast FXAA variant.
    AaFastFxaa,
    /// Spatial AA draws identified as the NFAA variant.
    AaNfaa,
    /// Spatial AA draws identified as the AXAA variant.
    AaAxaa,
    /// Spatial AA draws identified as the DLAA variant.
    AaDlaa,
    /// Spatial AA draws identified as the SMAA variant.
    AaSmaa,
    /// Phase-graph fallback commits (full-resolution safety copies).
    PhaseFallbackCommit,
    /// Frames whose native image-space viewport was letterboxed or cropped.
    ImageRectCropped,
    /// Cropped frames whose image rectangle differed from the previous one.
    ImageRectChanged,
}

impl Counter {
    #[allow(dead_code)] // Storage arrays are read only by the implementation and tests.
    const COUNT: usize = Self::ImageRectChanged as usize + 1;
}

/// Named CPU intervals used to locate a possible driver-facing stall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Interval {
    /// OMV gates and bounded setup before the native shadow transaction.
    NativeShadowPreWork,
    /// Complete native shadow prefix, including the predecessor trampoline.
    NativeShadowPrefix,
    /// OMV work after the native shadow prefix.
    NativeShadowPostWork,
    /// Scene-light manager traversal and scalar copy.
    SceneLightTraversal,
    /// Completed native-shadow resource retention.
    NativeShadowRetention,
    /// PBR admission and constant publication before geometry submission.
    PbrAdmission,
    /// Native-sky admission and constant publication.
    SkyAdmission,
    /// Actual `NiTriShape` renderer submission.
    TriShapeSubmission,
    /// Actual `NiTriStrips` renderer submission.
    TriStripsSubmission,
    /// D3D state-block capture.
    StateCapture,
    /// D3D state-block application.
    StateApply,
    /// One semantic color-copy call.
    ColorCopy,
    /// One semantic depth-copy call.
    #[allow(dead_code)] // Reserved for a scoped provider-side D3D copy interval.
    DepthCopy,
    /// Complete native-PBR selector classification and publication.
    PbrSelectorSetup,
    /// Object-PBR contract and replacement preparation.
    PbrObjectPreparation,
    /// Close-terrain light-cache lookup or reconstruction.
    PbrTerrainLights,
    /// Supplemental-light payload lookup, upload, and bind.
    PbrSupplementalUpload,
    /// Supplemental sampler-state mutation and restoration.
    PbrSupplementalSampler,
    /// Native-sky UpdateConstants classification and publication.
    SkyUpdateConstants,
    /// Complete OMV presentation servicing, including menu draws.
    PresentFrameTotal,
    /// Scene-pre image-space phase transaction.
    ScenePrePhase,
    /// Scene-post image-space phase transaction.
    ScenePostPhase,
    /// Final image-space phase transaction.
    FinalPhase,
    /// World-only AO application at the post-world boundary.
    WorldAoAfterWorld,
    /// First-person motion blur application at the post-world boundary.
    FirstPersonMotionBlur,
    /// Embedded AO pipeline drawing (fast and contact variants).
    AoPipeline,
    /// Embedded spatial anti-aliasing pipeline drawing.
    AaPipeline,
    /// Embedded bloom and color-grade final-color pipeline drawing.
    FinalColorPipeline,
    /// Embedded sunshaft pipeline drawing.
    SunshaftsPipeline,
    /// Embedded depth-of-field pipeline drawing.
    DepthOfFieldPipeline,
    /// Embedded image-space motion-blur pipeline drawing.
    MotionBlurPipeline,
    /// OMV-owned physical scene depth resolution.
    DepthResolveOmv,
    /// External provider boundary depth snapshot publication.
    DepthSnapshotExternal,
    /// Per-frame PBR present-frame servicing.
    PbrPresentService,
}

impl Interval {
    #[allow(dead_code)] // Storage arrays are read only by the implementation and tests.
    const COUNT: usize = Self::PbrPresentService as usize + 1;
}

/// Embedded effect families that a performance-profile build can skip in
/// rotation to attribute real frame-time cost per family.
///
/// Skipping uses the same `drew == false` graph state as an effect with no
/// work this frame, so pass-graph invariants (color alternation, drawing-stage
/// counting, and final-stage engine targeting) remain satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Family {
    AmbientOcclusion,
    AntiAliasing,
    FinalColor,
    Sunshafts,
    DepthOfField,
    MotionBlur,
}

impl Family {
    #[allow(dead_code)] // Used only by the schedule implementation and tests.
    const COUNT: usize = Self::MotionBlur as usize + 1;

    #[allow(dead_code)] // Used only by the schedule implementation and tests.
    fn from_index(index: u8) -> Option<Self> {
        if index < Self::COUNT as u8 {
            Some(match index {
                0 => Self::AmbientOcclusion,
                1 => Self::AntiAliasing,
                2 => Self::FinalColor,
                3 => Self::Sunshafts,
                4 => Self::DepthOfField,
                _ => Self::MotionBlur,
            })
        } else {
            None
        }
    }

    #[allow(dead_code)] // Used only by attribution logging.
    fn label(self) -> &'static str {
        match self {
            Family::AmbientOcclusion => "ambient_occlusion",
            Family::AntiAliasing => "anti_aliasing",
            Family::FinalColor => "final_color",
            Family::Sunshafts => "sunshafts",
            Family::DepthOfField => "depth_of_field",
            Family::MotionBlur => "motion_blur",
        }
    }
}

/// One completed sampled presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Read by export tooling and tests, not production UI.
pub(crate) struct FrameSample {
    /// Render epoch sealed by xNVSE `OnFramePresent`.
    pub(crate) render_epoch: u32,
    /// Accumulated event counts indexed by [`Counter`] discriminant.
    pub(crate) counters: [u64; Counter::COUNT],
    /// Accumulated performance-counter ticks indexed by [`Interval`].
    pub(crate) interval_ticks: [u64; Interval::COUNT],
    /// Number of timed spans accumulated for each [`Interval`].
    pub(crate) interval_calls: [u64; Interval::COUNT],
}

impl Default for FrameSample {
    fn default() -> Self {
        Self {
            render_epoch: 0,
            counters: [0; Counter::COUNT],
            interval_ticks: [0; Interval::COUNT],
            interval_calls: [0; Interval::COUNT],
        }
    }
}

/// RAII token for one sampled CPU interval.
///
/// Disarmed, the token carries no interval and its `Drop` performs no work.
/// Armed sampling records an ending performance-counter value only when the
/// current frame is armed for sampling.
#[must_use]
pub(crate) struct Span {
    interval: Option<(Interval, i64)>,
}

/// Add `value` to one current-frame event counter.
#[inline]
pub(crate) fn add(counter: Counter, value: u32) {
    implementation::add(counter, value);
}

/// Publish whether the frame being sealed is gameplay-representative.
///
/// The performance profile excludes menu and loading-screen frames from its
/// frame-time windows. Both flags are plain atomic stores; render callbacks
/// pay two relaxed stores per frame even in attribution builds.
#[inline]
pub(crate) fn note_frame_context(menu_open: bool, loading_screen: bool) {
    implementation::note_frame_context(menu_open, loading_screen);
}

/// Return whether the profiler is currently armed by the in-menu checkbox.
#[inline]
pub(crate) fn profiler_active() -> bool {
    implementation::profiler_active()
}

/// Arm or disarm the profiler for the remainder of this session.
///
/// Arming resets every window and accumulator so evidence starts from a
/// known state; disarming clears the skip family and all accumulators. The
/// state is never persisted to configuration.
#[inline]
pub(crate) fn set_profiler_active(active: bool) {
    implementation::set_profiler_active(active);
}

/// Track the native image-space rectangle for one composed frame.
///
/// Cropped (letterboxed) frames and rectangle changes are the evidence a
/// wrong-rectangle render path needs; both counters appear in the sampled
/// summaries. `x`/`y`/`width`/`height` are the viewport OMV composed into.
#[inline]
pub(crate) fn note_image_rect(cropped: bool, x: u32, y: u32, width: u32, height: u32) {
    implementation::note_image_rect(cropped, x, y, width, height);
}

/// Record that `family` performed actual drawing work this frame.
///
/// Unlike sampled counters, this runs every frame regardless of sampling so
/// A/B windows can normalize attributed deltas by how often the skipped
/// family actually drew. The store is one relaxed atomic increment on the
/// serialized render thread.
#[inline]
pub(crate) fn note_family_draw(family: Family) {
    implementation::note_family_draw(family);
}

/// Return whether the performance profile currently skips `family`.
///
/// A skipped family must behave exactly like an effect with no work: callers
/// commit the pass graph with `drew == false` and leave drawing-stage counts
/// untouched. Disarmed, this is a constant `false` on the atomic fast path.
#[inline]
pub(crate) fn family_skipped(family: Family) -> bool {
    implementation::family_skipped(family)
}

/// Start one named sampled CPU interval.
#[inline]
pub(crate) fn span(interval: Interval) -> Span {
    implementation::span(interval)
}

/// Seal and clear the current sampled frame at xNVSE `OnFramePresent`.
///
/// The next frame's sampling decision is made here, outside per-draw setup.
/// The returned value reports whether the just-finished frame was sampled.
#[inline]
pub(crate) fn seal_frame(render_epoch: u32) -> bool {
    implementation::seal_frame(render_epoch)
}

/// Copy the latest completed sample without taking a render-path lock.
#[inline]
#[allow(dead_code)] // Read API intentionally has no production caller.
pub(crate) fn latest_sample() -> Option<FrameSample> {
    implementation::latest_sample()
}

mod implementation {
    use super::{Counter, Family, FrameSample, Interval, Span};
    use libpsycho::os::windows::winapi::{query_performance_counter, query_performance_frequency};
    use std::fmt::Write as _;
    use std::sync::{
        LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    };

    /// Sampled frames accumulated into one `[GRAPHICS PERF SUMMARY]` line.
    pub(super) const SUMMARY_SAMPLES: u32 = 10;
    /// Frames in one A/B profile window. The first [`Self::AB_SETTLE_FRAMES`]
    /// frames let temporal effects resettle after a family switch and are
    /// excluded from the statistics.
    pub(super) const AB_WINDOW_FRAMES: u32 = 600;
    pub(super) const AB_SETTLE_FRAMES: u32 = 120;
    /// Clean per-frame intervals retained per A/B window (600-frame window
    /// minus settling cannot exceed this; overflow keeps the latest samples).
    pub(super) const AB_RING: usize = AB_WINDOW_FRAMES as usize - AB_SETTLE_FRAMES as usize;

    pub(super) static SAMPLE_PERIOD: AtomicU32 = AtomicU32::new(120);
    /// Single activation gate for every profiler entry point. Disabled is the
    /// default; the disabled path is one relaxed load and a return, with no
    /// counter, span, timer query, lock, or window accounting.
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static SAMPLE_THIS_FRAME: AtomicBool = AtomicBool::new(false);
    static FRAME_NUMBER: AtomicU32 = AtomicU32::new(0);
    static CONTEXT_CLEAN: AtomicBool = AtomicBool::new(false);
    /// Family currently skipped by the performance profile. `Family::COUNT`
    /// means none; render callbacks compare this value without allocating.
    pub(super) static SKIPPED_FAMILY: AtomicU8 = AtomicU8::new(Family::COUNT as u8);
    /// Always-on per-family draw counts. Each serialized frame's totals are
    /// swapped out at the present boundary and folded into the active A/B
    /// window, so conditional effects report how often they actually drew.
    static FAMILY_DRAWS: LazyLock<[AtomicU32; Family::COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU32::new(0)));
    static COUNTERS: LazyLock<[AtomicU64; Counter::COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));
    static INTERVAL_TICKS: LazyLock<[AtomicU64; Interval::COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));
    static INTERVAL_CALLS: LazyLock<[AtomicU64; Interval::COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));
    static SEALED_EPOCH: AtomicU32 = AtomicU32::new(0);
    static SEALED_COUNTERS: LazyLock<[AtomicU64; Counter::COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));
    static SEALED_INTERVAL_TICKS: LazyLock<[AtomicU64; Interval::COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));
    static SEALED_INTERVAL_CALLS: LazyLock<[AtomicU64; Interval::COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));

    /// One A/B measurement window over clean gameplay frames.
    pub(super) struct AbWindow {
        pub(super) family: Option<Family>,
        pub(super) settled_frames: u32,
        intervals_us: [u32; AB_RING],
        pub(super) count: usize,
        pub(super) overflow: usize,
        pub(super) family_draws: [u32; Family::COUNT],
    }

    impl Default for AbWindow {
        fn default() -> Self {
            Self {
                family: None,
                settled_frames: 0,
                intervals_us: [0; AB_RING],
                count: 0,
                overflow: 0,
                family_draws: [0; Family::COUNT],
            }
        }
    }

    impl AbWindow {
        pub(super) fn start(family: Option<Family>) -> Self {
            Self {
                family,
                ..Self::default()
            }
        }

        /// Fold one frame's per-family draw counts into the window.
        fn record_family_draws(&mut self, draws: &[u32; Family::COUNT]) {
            for (sum, value) in self.family_draws.iter_mut().zip(draws) {
                *sum += value;
            }
        }

        pub(super) fn record(&mut self, interval_us: u32) {
            if self.settled_frames < AB_SETTLE_FRAMES {
                self.settled_frames += 1;
                return;
            }
            if self.count < AB_RING {
                self.intervals_us[self.count] = interval_us;
                self.count += 1;
            } else {
                // Keep the latest samples so long menu interruptions cannot
                // dilute the window with stale frames.
                self.intervals_us[self.overflow % AB_RING] = interval_us;
                self.overflow += 1;
            }
        }

        /// Complete the window and format its one-line report.
        pub(super) fn finish(&mut self, window: u32) -> Option<String> {
            if self.count < 32 {
                // Too few clean frames to represent the workload honestly.
                return None;
            }
            let samples = &mut self.intervals_us[..self.count];
            let mean =
                samples.iter().copied().map(u64::from).sum::<u64>() / self.count.max(1) as u64;
            samples.sort_unstable();
            let median = samples[samples.len() / 2];
            let p90 = samples[samples.len() * 9 / 10];
            let family = self
                .family
                .map(|family| family.label())
                .unwrap_or("none_baseline");
            let mut report = String::with_capacity(96);
            let _ = write!(
                report,
                "[GRAPHICS PERF A/B] window={} family={} skipped mean_ms={:.2} median_ms={:.2} p90_ms={:.2} samples={}",
                window,
                family,
                mean as f64 / 1_000.0,
                f64::from(median) / 1_000.0,
                f64::from(p90) / 1_000.0,
                self.count
            );
            if self.overflow != 0 {
                let _ = write!(report, " overflow={}", self.overflow);
            }
            let frames = self.count.max(1) as f32;
            report.push_str(" drew_calls/frame:");
            for family in 0..Family::COUNT {
                let draws = self.family_draws[family];
                let label = match family {
                    0 => "ao",
                    1 => "aa",
                    2 => "final_color",
                    3 => "sunshafts",
                    4 => "dof",
                    _ => "motion_blur",
                };
                let _ = write!(report, " {label}={:.2}", draws as f32 / frames);
            }
            Some(report)
        }
    }

    /// Aggregation state owned by the serialized present boundary.
    pub(super) struct ProfileState {
        pub(super) summary_samples: u32,
        summary_first_epoch: u32,
        summary_last_epoch: u32,
        summary_menu_frames: u32,
        summary_counters: [u64; Counter::COUNT],
        summary_interval_ticks: [u64; Interval::COUNT],
        summary_interval_calls: [u64; Interval::COUNT],
        pub(super) ab_window: Option<AbWindow>,
        pub(super) ab_window_index: u32,
        last_seal_ticks: Option<i64>,
    }

    impl Default for ProfileState {
        fn default() -> Self {
            Self {
                summary_samples: 0,
                summary_first_epoch: 0,
                summary_last_epoch: 0,
                summary_menu_frames: 0,
                summary_counters: [0; Counter::COUNT],
                summary_interval_ticks: [0; Interval::COUNT],
                summary_interval_calls: [0; Interval::COUNT],
                ab_window: None,
                ab_window_index: 0,
                last_seal_ticks: None,
            }
        }
    }

    /// Events a seal produces for the serialized logging boundary.
    pub(super) enum SealReport {
        None,
        Line(String),
    }

    impl ProfileState {
        /// Accumulate one sealed sample into the summary window.
        pub(super) fn accumulate(&mut self, sample: &FrameSample) {
            if self.summary_samples == 0 {
                self.summary_first_epoch = sample.render_epoch;
            }
            self.summary_last_epoch = sample.render_epoch;
            self.summary_samples += 1;
            self.summary_menu_frames += u32::try_from(
                sample.counters[Counter::MenuFrame as usize].min(u64::from(u32::MAX)),
            )
            .unwrap_or(u32::MAX);
            for index in 0..Counter::COUNT {
                self.summary_counters[index] += sample.counters[index];
            }
            for index in 0..Interval::COUNT {
                self.summary_interval_ticks[index] += sample.interval_ticks[index];
                self.summary_interval_calls[index] += sample.interval_calls[index];
            }
        }

        /// Close the summary window and format its one-line report.
        pub(super) fn finish_summary(&mut self, frequency: u64) -> Option<String> {
            let samples = self.summary_samples;
            if samples == 0 {
                return None;
            }
            let mut report = String::with_capacity(1_024);
            let _ = write!(
                report,
                "[GRAPHICS PERF SUMMARY] samples={} epochs={}-{} menu_frames={} present_us/frame={}",
                samples,
                self.summary_first_epoch,
                self.summary_last_epoch,
                self.summary_menu_frames,
                per_frame_us(
                    self.summary_interval_ticks[Interval::PresentFrameTotal as usize],
                    self.summary_interval_calls[Interval::PresentFrameTotal as usize],
                    samples,
                    frequency,
                ),
            );
            for index in 0..Interval::COUNT {
                let calls = self.summary_interval_calls[index];
                if calls == 0 {
                    continue;
                }
                let ticks = self.summary_interval_ticks[index];
                if frequency == 0 {
                    let _ = write!(
                        report,
                        " {}_ticks={ticks}/{}calls",
                        interval_label(index),
                        calls
                    );
                } else {
                    let _ = write!(
                        report,
                        " {}={}/{}c",
                        interval_label(index),
                        per_frame_us(ticks, calls, samples, frequency),
                        per_frame(calls, samples),
                    );
                }
            }
            report.push_str(" | counts/frame:");
            let mut any_count = false;
            for (index, value) in self.summary_counters.iter().copied().enumerate() {
                if value == 0 {
                    continue;
                }
                any_count = true;
                let _ = write!(
                    report,
                    " {}={}",
                    counter_label(index),
                    per_frame(value, samples)
                );
            }
            if !any_count {
                report.push_str(" none");
            }
            *self = ProfileState {
                ab_window: self.ab_window.take(),
                ab_window_index: self.ab_window_index,
                last_seal_ticks: self.last_seal_ticks,
                ..ProfileState::default()
            };
            Some(report)
        }

        /// Fold one present-boundary interval into the A/B window when the
        /// frame was clean gameplay. The baseline window starts lazily at the
        /// first sealed clean frame so the schedule needs no explicit arming.
        pub(super) fn seal_frame_interval(
            &mut self,
            clean: bool,
            interval_us: u32,
            draws: &[u32; Family::COUNT],
        ) {
            if !clean {
                return;
            }
            if self.ab_window.is_none() {
                // Window zero measures the unmodified baseline before any
                // family is skipped, so per-family deltas always have a
                // local reference.
                self.ab_window = Some(AbWindow::start(None));
            }
            if let Some(window) = self.ab_window.as_mut() {
                window.record_family_draws(draws);
                window.record(interval_us);
            }
        }

        /// Advance the A/B schedule once the current window has consumed its
        /// frame budget. Always moves forward so a starved window cannot stall
        /// the rotation; starved windows report no statistics.
        pub(super) fn advance_ab_schedule(&mut self) -> SealReport {
            let Some(window) = self.ab_window.as_mut() else {
                return SealReport::None;
            };
            let recorded = window.count + window.overflow;
            let spent = window.settled_frames + recorded as u32;
            if spent < AB_WINDOW_FRAMES {
                return SealReport::None;
            }
            let report = window
                .finish(self.ab_window_index)
                .map_or(SealReport::None, SealReport::Line);
            self.ab_window_index += 1;
            // Window zero is the baseline; then each family once per cycle.
            let cycle_slot = self.ab_window_index % (Family::COUNT as u32 + 1);
            let family = if cycle_slot == 0 {
                None
            } else {
                Family::from_index(cycle_slot as u8 - 1)
            };
            SKIPPED_FAMILY.store(
                family.map_or(Family::COUNT as u8, |family| family as u8),
                Ordering::Release,
            );
            self.ab_window = Some(AbWindow::start(family));
            // One line per window boundary makes the skip schedule's exact
            // timeline auditable against any other evidence in the log.
            log::info!(
                "[GRAPHICS PERF A/B] family={} armed at window {}",
                family.map(Family::label).unwrap_or("none_baseline"),
                self.ab_window_index
            );
            report
        }
    }

    fn per_frame(total: u64, samples: u32) -> String {
        let samples = u64::from(samples.max(1));
        let whole = total / samples;
        let frac = ((total % samples) * 10 + samples / 2) / samples;
        if frac == 10 {
            format!("{}.9", whole + 1)
        } else {
            format!("{whole}.{frac}")
        }
    }

    fn per_frame_us(ticks: u64, _calls: u64, samples: u32, frequency: u64) -> String {
        if frequency == 0 {
            return format!("{ticks}ticks");
        }
        let micros = ticks.saturating_mul(1_000_000) / frequency;
        per_frame(micros, samples)
    }

    static PROFILE_STATE: LazyLock<Mutex<ProfileState>> =
        LazyLock::new(|| Mutex::new(ProfileState::default()));

    pub(super) fn profiler_active() -> bool {
        ACTIVE.load(Ordering::Relaxed)
    }

    pub(super) fn set_profiler_active(active: bool) {
        ACTIVE.store(active, Ordering::Release);
        SAMPLE_THIS_FRAME.store(false, Ordering::Release);
        FAMILY_DRAWS
            .iter()
            .for_each(|draw| draw.store(0, Ordering::Relaxed));
        if let Ok(mut state) = PROFILE_STATE.try_lock() {
            *state = ProfileState::default();
        }
        if !active {
            SKIPPED_FAMILY.store(Family::COUNT as u8, Ordering::Release);
        }
        // Lifecycle boundary evidence: every summary and A/B window in the
        // log can be tied to an explicit arming decision.
        log::info!(
            "[GRAPHICS PERF] profiler {} (session-only)",
            if active { "armed" } else { "disarmed" }
        );
    }

    #[inline]
    pub(super) fn note_frame_context(menu_open: bool, loading_screen: bool) {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        CONTEXT_CLEAN.store(!menu_open && !loading_screen, Ordering::Relaxed);
    }

    /// Last seen image rectangle, packed as two u64s; zero means unset.
    static LAST_IMAGE_RECT_LO: AtomicU64 = AtomicU64::new(0);
    static LAST_IMAGE_RECT_HI: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub(super) fn note_image_rect(cropped: bool, x: u32, y: u32, width: u32, height: u32) {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        if cropped {
            COUNTERS[Counter::ImageRectCropped as usize].fetch_add(1, Ordering::Relaxed);
            let lo = (u64::from(x) << 32) | u64::from(y);
            let hi = (u64::from(width) << 32) | u64::from(height);
            let changed = LAST_IMAGE_RECT_LO.swap(lo, Ordering::Relaxed) != lo
                || LAST_IMAGE_RECT_HI.swap(hi, Ordering::Relaxed) != hi;
            if changed {
                COUNTERS[Counter::ImageRectChanged as usize].fetch_add(1, Ordering::Relaxed);
            }
        } else {
            let changed = LAST_IMAGE_RECT_LO.swap(0, Ordering::Relaxed) != 0
                || LAST_IMAGE_RECT_HI.swap(0, Ordering::Relaxed) != 0;
            let _ = changed;
        }
    }

    #[inline]
    pub(super) fn note_family_draw(family: Family) {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        FAMILY_DRAWS[family as usize].fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(super) fn family_skipped(family: Family) -> bool {
        ACTIVE.load(Ordering::Relaxed) && SKIPPED_FAMILY.load(Ordering::Relaxed) == family as u8
    }

    #[inline]
    pub(super) fn add(counter: Counter, value: u32) {
        if ACTIVE.load(Ordering::Relaxed) && SAMPLE_THIS_FRAME.load(Ordering::Relaxed) {
            COUNTERS[counter as usize].fetch_add(u64::from(value), Ordering::Relaxed);
        }
    }

    #[inline]
    pub(super) fn span(interval: Interval) -> Span {
        let interval =
            if ACTIVE.load(Ordering::Relaxed) && SAMPLE_THIS_FRAME.load(Ordering::Relaxed) {
                query_performance_counter()
                    .ok()
                    .map(|start| (interval, start))
            } else {
                None
            };
        Span { interval }
    }

    pub(super) fn seal_frame(render_epoch: u32) -> bool {
        if !ACTIVE.load(Ordering::Relaxed) {
            return false;
        }
        let sampled = SAMPLE_THIS_FRAME.swap(false, Ordering::AcqRel);
        if sampled {
            for index in 0..Counter::COUNT {
                SEALED_COUNTERS[index]
                    .store(COUNTERS[index].swap(0, Ordering::AcqRel), Ordering::Relaxed);
            }
            for index in 0..Interval::COUNT {
                SEALED_INTERVAL_TICKS[index].store(
                    INTERVAL_TICKS[index].swap(0, Ordering::AcqRel),
                    Ordering::Relaxed,
                );
                SEALED_INTERVAL_CALLS[index].store(
                    INTERVAL_CALLS[index].swap(0, Ordering::AcqRel),
                    Ordering::Relaxed,
                );
            }
            // Release publishes all relaxed sealed-array writes to readers
            // that acquire the epoch. The epoch is written last deliberately.
            SEALED_EPOCH.store(render_epoch, Ordering::Release);
        }

        let frame = FRAME_NUMBER.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let period = SAMPLE_PERIOD.load(Ordering::Relaxed).max(1);
        SAMPLE_THIS_FRAME.store(frame % period == 0, Ordering::Release);

        // Aggregation and the A/B schedule run only at the serialized present
        // boundary. This lock is uncontended outside seal_frame.
        let frequency = query_performance_frequency().unwrap_or(0).max(0) as u64;
        if frequency == 0 {
            return sampled;
        }
        let Ok(mut state) = PROFILE_STATE.lock() else {
            return sampled;
        };
        let now = query_performance_counter().ok();
        // Present-boundary interval covering the frame just sealed, derived
        // between consecutive serialized seals.
        let interval_us = state.last_seal_ticks.zip(now).map(|(last, now)| {
            let delta = now.saturating_sub(last).max(0);
            u32::try_from((delta.saturating_mul(1_000_000) as u64) / frequency).unwrap_or(u32::MAX)
        });
        if now.is_some() {
            state.last_seal_ticks = now;
        }
        let clean = CONTEXT_CLEAN.load(Ordering::Relaxed);
        let draws: [u32; Family::COUNT] =
            std::array::from_fn(|index| FAMILY_DRAWS[index].swap(0, Ordering::Relaxed));
        if let Some(interval_us) = interval_us {
            state.seal_frame_interval(clean, interval_us, &draws);
        }
        let mut report = SealReport::None;
        if sampled {
            let sample = FrameSample {
                render_epoch,
                counters: std::array::from_fn(|index| {
                    SEALED_COUNTERS[index].load(Ordering::Relaxed)
                }),
                interval_ticks: std::array::from_fn(|index| {
                    SEALED_INTERVAL_TICKS[index].load(Ordering::Relaxed)
                }),
                interval_calls: std::array::from_fn(|index| {
                    SEALED_INTERVAL_CALLS[index].load(Ordering::Relaxed)
                }),
            };
            state.accumulate(&sample);
            if state.summary_samples >= SUMMARY_SAMPLES {
                report = state
                    .finish_summary(frequency)
                    .map_or(SealReport::None, SealReport::Line);
            }
        }
        if matches!(report, SealReport::None)
            && let ab_report @ SealReport::Line(_) = state.advance_ab_schedule()
        {
            report = ab_report;
        }
        match report {
            SealReport::Line(text) => log::info!("{text}"),
            SealReport::None => {}
        }
        sampled
    }

    pub(super) fn latest_sample() -> Option<FrameSample> {
        let render_epoch = SEALED_EPOCH.load(Ordering::Acquire);
        if render_epoch == 0 {
            return None;
        }
        Some(FrameSample {
            render_epoch,
            counters: std::array::from_fn(|index| SEALED_COUNTERS[index].load(Ordering::Relaxed)),
            interval_ticks: std::array::from_fn(|index| {
                SEALED_INTERVAL_TICKS[index].load(Ordering::Relaxed)
            }),
            interval_calls: std::array::from_fn(|index| {
                SEALED_INTERVAL_CALLS[index].load(Ordering::Relaxed)
            }),
        })
    }

    fn counter_label(index: usize) -> &'static str {
        const LABELS: [&str; Counter::COUNT] = [
            "shadow_entry",
            "shadow_a",
            "shadow_b",
            "shadow_c",
            "shadow_main",
            "shadow_special",
            "shadow_screenshot",
            "shadow_unknown",
            "light_traversal",
            "light_repeat",
            "shadow_slot",
            "shadow_retained",
            "set_shaders",
            "set_texture",
            "trishape",
            "tristrips",
            "pbr_admission",
            "pbr_fallback",
            "sky_admission",
            "sky_fallback",
            "color_copy",
            "depth_copy",
            "state_capture",
            "state_apply",
            "package_transition",
            "pbr_ready_query",
            "pbr_ready_entry",
            "pbr_pending_none",
            "table_positive",
            "table_miss",
            "table_entry",
            "object_memory_query",
            "sky_memory_query",
            "terrain_cache_hit",
            "terrain_cache_miss",
            "terrain_native_entry",
            "terrain_property_entry",
            "terrain_manager_entry",
            "supplemental_payload_hit",
            "supplemental_upload",
            "supplemental_discard",
            "supplemental_sampler_get",
            "supplemental_sampler_set",
            "supplemental_lights_0",
            "supplemental_lights_1_6",
            "supplemental_lights_7_12",
            "supplemental_lights_13_24",
            "sky_raw_shader",
            "menu_frame",
            "depth_resolved",
            "depth_busy",
            "depth_rejected",
            "target_clear",
            "shadow_cascade",
            "shadow_face_static",
            "shadow_face_dynamic",
            "aa_fast_fxaa",
            "aa_nfaa",
            "aa_axaa",
            "aa_dlaa",
            "aa_smaa",
            "phase_fallback",
            "image_rect_cropped",
            "image_rect_changed",
        ];
        LABELS[index]
    }

    fn interval_label(index: usize) -> &'static str {
        const LABELS: [&str; Interval::COUNT] = [
            "shadow_pre",
            "shadow_prefix",
            "shadow_post",
            "light_traversal",
            "shadow_retention",
            "pbr_admission",
            "sky_admission",
            "trishape",
            "tristrips",
            "state_capture",
            "state_apply",
            "color_copy",
            "depth_copy",
            "pbr_selector",
            "pbr_object",
            "pbr_terrain_lights",
            "pbr_supplemental_upload",
            "pbr_supplemental_sampler",
            "sky_update_constants",
            "present_total",
            "scene_pre_phase",
            "scene_post_phase",
            "final_phase",
            "world_ao",
            "fp_motion_blur",
            "ao_pipeline",
            "aa_pipeline",
            "final_color_pipeline",
            "sunshafts_pipeline",
            "dof_pipeline",
            "motion_blur_pipeline",
            "depth_resolve_omv",
            "depth_snapshot_external",
            "pbr_present_service",
        ];
        LABELS[index]
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let Some((interval, start)) = self.interval else {
                return;
            };
            let Some(end) = query_performance_counter().ok() else {
                return;
            };
            let Ok(ticks) = u64::try_from(end.saturating_sub(start)) else {
                return;
            };
            INTERVAL_TICKS[interval as usize].fetch_add(ticks, Ordering::Relaxed);
            INTERVAL_CALLS[interval as usize].fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::implementation::SAMPLE_PERIOD;
    use super::implementation::{
        AB_RING, AB_SETTLE_FRAMES, AB_WINDOW_FRAMES, SUMMARY_SAMPLES, SealReport,
    };
    use super::implementation::{AbWindow, ProfileState};
    use super::{Counter, Family, FrameSample, Interval, latest_sample, seal_frame};

    #[test]
    fn sampled_frames_publish_counts() {
        super::implementation::set_profiler_active(true);
        SAMPLE_PERIOD.store(1, std::sync::atomic::Ordering::SeqCst);
        seal_frame(12);
        super::add(Counter::SetShaders, 3);
        assert!(seal_frame(13));
        let sample = latest_sample().expect("sealed diagnostic sample");
        assert_eq!(sample.render_epoch, 13);
        assert_eq!(sample.counters[Counter::SetShaders as usize], 3);
        SAMPLE_PERIOD.store(120, std::sync::atomic::Ordering::SeqCst);
        super::implementation::set_profiler_active(false);
    }

    #[test]
    fn disarmed_profiler_is_free_and_gates_everything() {
        super::implementation::set_profiler_active(false);
        // Disabled entry points do no work and record nothing.
        super::add(Counter::SetShaders, 3);
        super::note_family_draw(Family::AmbientOcclusion);
        super::note_frame_context(true, true);
        super::note_image_rect(true, 1, 2, 3, 4);
        assert!(!seal_frame(20));
        assert!(latest_sample().is_none());
        // Arming publishes the gate and the skip schedule starts clean.
        super::implementation::set_profiler_active(true);
        assert!(super::implementation::profiler_active());
        assert!(!super::family_skipped(Family::AmbientOcclusion));
        // A span measures only while the profiler is armed and the current
        // frame is sampled; seal one frame to arm the next for sampling.
        SAMPLE_PERIOD.store(1, std::sync::atomic::Ordering::SeqCst);
        seal_frame(21);
        {
            let span = super::span(Interval::AoPipeline);
            assert!(span.interval.is_some());
        }
        seal_frame(22);
        SAMPLE_PERIOD.store(120, std::sync::atomic::Ordering::SeqCst);
        super::implementation::set_profiler_active(false);
        {
            let span = super::span(Interval::AoPipeline);
            assert!(span.interval.is_none());
        }
    }

    #[test]
    fn family_index_round_trips_and_rejects_out_of_range() {
        for index in 0..Family::COUNT as u8 {
            assert_eq!(
                Family::from_index(index).map(|family| family as u8),
                Some(index)
            );
        }
        assert!(Family::from_index(Family::COUNT as u8).is_none());
    }

    #[test]
    fn ab_window_excludes_settling_and_reports_median() {
        let mut window = AbWindow::start(Some(Family::AmbientOcclusion));
        // Settling frames are recorded but excluded from statistics.
        for _ in 0..AB_SETTLE_FRAMES {
            window.record(1_000);
        }
        assert_eq!(window.count, 0);
        for us in [15_000u32, 16_000, 17_000, 18_000] {
            window.record(us);
        }
        assert_eq!(window.count, 4);
        // A starved window must not report misleading statistics.
        assert!(window.finish(0).is_none());
        for us in 16_000u32..16_000 + AB_RING as u32 {
            window.record(us);
        }
        let report = window.finish(3).expect("window report");
        assert!(report.contains("window=3"), "{report}");
        assert!(report.contains("family=ambient_occlusion"), "{report}");
        // The four overflow writes replace the oldest kept samples.
        assert!(report.contains("median_ms=16.24"), "{report}");
        assert!(report.contains("overflow=4"), "{report}");
    }

    #[test]
    fn profile_state_summarizes_per_frame_means() {
        let mut state = ProfileState::default();
        for epoch in 0..SUMMARY_SAMPLES {
            let mut sample = FrameSample::default();
            sample.render_epoch = 100 + u32::from(epoch);
            // 1_000 ticks per frame at the 1 MHz test frequency -> 1000 us.
            sample.interval_ticks[Interval::PresentFrameTotal as usize] = 1_000;
            sample.interval_calls[Interval::PresentFrameTotal as usize] = 1;
            sample.counters[Counter::TriShapeSubmission as usize] = 25;
            state.accumulate(&sample);
        }
        let report = state.finish_summary(1_000_000).expect("summary report");
        assert!(report.contains("samples=10"), "{report}");
        assert!(report.contains("epochs=100-109"), "{report}");
        assert!(report.contains("menu_frames=0"), "{report}");
        assert!(report.contains("present_total=1000.0/1.0c"), "{report}");
        assert!(report.contains("trishape=25.0"), "{report}");
        // The window resets after reporting.
        assert_eq!(state.summary_samples, 0);
    }

    #[test]
    fn profile_state_rotates_baseline_then_families() {
        let mut state = ProfileState::default();
        state.ab_window = Some(AbWindow::start(None));
        // Drive the window past its frame budget with clean intervals.
        for _ in 0..AB_WINDOW_FRAMES {
            state.seal_frame_interval(true, 16_000, &[0; Family::COUNT]);
        }
        let report = state.advance_ab_schedule();
        let SealReport::Line(text) = report else {
            panic!("baseline window must report after its frame budget");
        };
        assert!(text.contains("family=none_baseline"), "{text}");
        // The next window skips family zero.
        assert_eq!(
            super::implementation::SKIPPED_FAMILY.load(std::sync::atomic::Ordering::Acquire),
            Family::AmbientOcclusion as u8
        );
        assert_eq!(state.ab_window_index, 1);
        // Per-family draw counts fold into the active window only on clean
        // frames and accumulate across them.
        let mut accumulating = ProfileState::default();
        accumulating.ab_window = Some(AbWindow::start(None));
        for _ in 0..4 {
            accumulating.seal_frame_interval(true, 16_000, &[1, 0, 2, 0, 0, 3]);
        }
        accumulating.seal_frame_interval(false, 16_000, &[100; Family::COUNT]);
        let window = accumulating.ab_window.as_ref().expect("active window");
        assert_eq!(window.family_draws, [4, 0, 8, 0, 0, 12]);
        // A window without clean frames never advances past its budget.
        let mut idle = ProfileState::default();
        idle.ab_window = Some(AbWindow::start(None));
        for _ in 0..AB_WINDOW_FRAMES {
            idle.seal_frame_interval(false, 16_000, &[1; Family::COUNT]);
        }
        assert!(matches!(idle.advance_ab_schedule(), SealReport::None));
        assert_eq!(idle.ab_window_index, 0);
    }
}
