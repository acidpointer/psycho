//! Compile-time-gated attribution for OMV's serialized graphics callbacks.
//!
//! The NVIDIA remediation needs cross-subsystem evidence without turning a
//! diagnostic experiment into permanent draw overhead. Normal builds compile
//! every operation in this module to an inline no-op. A build made with the
//! `graphics-diagnostics` feature must still be explicitly armed, and samples
//! only one frame out of a configured period.
//!
//! Callback writers touch fixed atomic storage only. They never allocate,
//! format text, take a lock, submit a GPU query, or write a log. The xNVSE
//! `OnFramePresent` callback seals the sampled frame; a menu or an explicit
//! diagnostic export may read the completed POD snapshot later. Timings are
//! CPU wall-clock intervals. A long interval around D3D work can indicate a
//! driver wait, but is not proof that the GPU spent the same duration executing
//! that work.

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
}

impl Counter {
    #[allow(dead_code)] // Used only by the feature-gated storage implementation.
    const COUNT: usize = Self::ShaderPackageTransition as usize + 1;
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
}

impl Interval {
    #[allow(dead_code)] // Used only by the feature-gated storage implementation.
    const COUNT: usize = Self::DepthCopy as usize + 1;
}

/// One completed sampled presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Read by attribution builds/export tooling, not production UI.
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
/// The token has no fields and no `Drop` work in a normal build. Attribution
/// builds record an ending performance-counter value only when the current
/// frame is armed for sampling.
#[must_use]
pub(crate) struct Span {
    #[cfg(any(test, feature = "graphics-diagnostics"))]
    interval: Option<(Interval, i64)>,
}

/// Arm or disarm sampled attribution.
///
/// `sample_period` is clamped to at least one. Arming is meaningful only in a
/// build with `graphics-diagnostics`; normal builds retain no runtime branch.
#[inline]
pub(crate) fn configure(armed: bool, sample_period: u32) {
    implementation::configure(armed, sample_period);
}

/// Add `value` to one current-frame event counter.
#[inline]
pub(crate) fn add(counter: Counter, value: u32) {
    implementation::add(counter, value);
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
#[allow(dead_code)] // Feature-facing read API intentionally has no production caller.
pub(crate) fn latest_sample() -> Option<FrameSample> {
    implementation::latest_sample()
}

#[cfg(any(test, feature = "graphics-diagnostics"))]
mod implementation {
    use super::{Counter, FrameSample, Interval, Span};
    use libpsycho::os::windows::winapi::query_performance_counter;
    use std::sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    };

    static ARMED: AtomicBool = AtomicBool::new(false);
    static SAMPLE_PERIOD: AtomicU32 = AtomicU32::new(1);
    static SAMPLE_THIS_FRAME: AtomicBool = AtomicBool::new(false);
    static FRAME_NUMBER: AtomicU32 = AtomicU32::new(0);
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

    pub(super) fn configure(armed: bool, sample_period: u32) {
        SAMPLE_PERIOD.store(sample_period.max(1), Ordering::Release);
        ARMED.store(armed, Ordering::Release);
        if !armed {
            SAMPLE_THIS_FRAME.store(false, Ordering::Release);
        }
    }

    #[inline]
    pub(super) fn add(counter: Counter, value: u32) {
        if SAMPLE_THIS_FRAME.load(Ordering::Relaxed) {
            COUNTERS[counter as usize].fetch_add(u64::from(value), Ordering::Relaxed);
        }
    }

    #[inline]
    pub(super) fn span(interval: Interval) -> Span {
        let interval = SAMPLE_THIS_FRAME
            .load(Ordering::Relaxed)
            .then(|| {
                query_performance_counter()
                    .ok()
                    .map(|start| (interval, start))
            })
            .flatten();
        Span { interval }
    }

    pub(super) fn seal_frame(render_epoch: u32) -> bool {
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
        SAMPLE_THIS_FRAME.store(
            ARMED.load(Ordering::Acquire) && frame % period == 0,
            Ordering::Release,
        );
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

#[cfg(not(any(test, feature = "graphics-diagnostics")))]
mod implementation {
    use super::{Counter, FrameSample, Interval, Span};

    #[inline(always)]
    pub(super) fn configure(_armed: bool, _sample_period: u32) {}

    #[inline(always)]
    pub(super) fn add(_counter: Counter, _value: u32) {}

    #[inline(always)]
    pub(super) fn span(_interval: Interval) -> Span {
        Span {}
    }

    #[inline(always)]
    pub(super) fn seal_frame(_render_epoch: u32) -> bool {
        false
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub(super) fn latest_sample() -> Option<FrameSample> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Counter, configure, latest_sample, seal_frame};

    #[test]
    fn only_armed_sampled_frames_publish_counts() {
        configure(false, 1);
        seal_frame(10);
        super::add(Counter::SetShaders, 3);
        assert!(!seal_frame(11));

        configure(true, 1);
        assert!(!seal_frame(12));
        super::add(Counter::SetShaders, 3);
        assert!(seal_frame(13));
        let sample = latest_sample().expect("sealed diagnostic sample");
        assert_eq!(sample.render_epoch, 13);
        assert_eq!(sample.counters[Counter::SetShaders as usize], 3);
        configure(false, 1);
    }
}
