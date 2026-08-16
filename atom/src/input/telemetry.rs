//! Bounded input-latency telemetry.
//!
//! Telemetry records the first player-camera consumer and xNVSE's
//! `OnFramePresent` relative to the most recent native sample. The hot path
//! performs one QPC query and bounded 32-bit atomic operations; it never logs,
//! allocates, or divides. Histograms saturate instead of wrapping so a long
//! session cannot turn old evidence into a plausible low count.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use libpsycho::os::windows::winapi::query_performance_counter;

use super::mouse::MouseAxis;

const BUCKET_UPPER_US: [u32; 11] = [
    250, 500, 1_000, 2_000, 4_000, 8_000, 12_000, 16_000, 25_000, 33_000, 50_000,
];
const BUCKET_COUNT: usize = BUCKET_UPPER_US.len() + 1;
const MAX_ACCEPTED_US: u32 = 2_000_000;

static ENABLED: AtomicBool = AtomicBool::new(false);
static MAX_ACCEPTED_TICKS: AtomicU32 = AtomicU32::new(0);
static SAMPLE_FRAME: AtomicU32 = AtomicU32::new(0);
static SAMPLE_TICK_LOW: AtomicU32 = AtomicU32::new(0);
static CONSUMER_FRAME: AtomicU32 = AtomicU32::new(0);
static PRESENT_FRAME: AtomicU32 = AtomicU32::new(0);
static INVALID_INTERVALS: AtomicU32 = AtomicU32::new(0);
static BUCKET_TICKS: [AtomicU32; BUCKET_UPPER_US.len()] =
    [const { AtomicU32::new(0) }; BUCKET_UPPER_US.len()];
static SAMPLE_TO_CONSUMER: [AtomicU32; BUCKET_COUNT] = [const { AtomicU32::new(0) }; BUCKET_COUNT];
static SAMPLE_TO_PRESENT: [AtomicU32; BUCKET_COUNT] = [const { AtomicU32::new(0) }; BUCKET_COUNT];
static MOUSE_X_SAMPLES: AtomicU32 = AtomicU32::new(0);
static MOUSE_X_COUNTS: AtomicU32 = AtomicU32::new(0);
static MOUSE_X_MICRORADIANS: AtomicU32 = AtomicU32::new(0);
static MOUSE_Y_SAMPLES: AtomicU32 = AtomicU32::new(0);
static MOUSE_Y_COUNTS: AtomicU32 = AtomicU32::new(0);
static MOUSE_Y_MICRORADIANS: AtomicU32 = AtomicU32::new(0);

/// A bounded point-in-time copy of Atom's latency histograms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetrySnapshot {
    sample_to_consumer: [u32; BUCKET_COUNT],
    sample_to_present: [u32; BUCKET_COUNT],
    invalid_intervals: u32,
    mouse_x: MouseHeadingSummary,
    mouse_y: MouseHeadingSummary,
}

/// Bounded aggregate of relative counts and applied player-heading angles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MouseHeadingSummary {
    samples: u32,
    absolute_counts: u32,
    absolute_microradians: u32,
}

impl MouseHeadingSummary {
    /// Return the number of non-zero heading updates observed.
    pub const fn samples(self) -> u32 {
        self.samples
    }

    /// Return the saturating sum of absolute relative counts.
    pub const fn absolute_counts(self) -> u32 {
        self.absolute_counts
    }

    /// Return the saturating sum of absolute applied micro-radians.
    pub const fn absolute_microradians(self) -> u32 {
        self.absolute_microradians
    }
}

impl TelemetrySnapshot {
    /// Return inclusive bucket upper bounds in microseconds.
    ///
    /// The final histogram element is the overflow bucket and has no bound.
    pub const fn bucket_upper_microseconds() -> &'static [u32; BUCKET_COUNT - 1] {
        &BUCKET_UPPER_US
    }

    /// Return sample-to-first-camera-consumer counts.
    pub const fn sample_to_consumer(self) -> [u32; BUCKET_COUNT] {
        self.sample_to_consumer
    }

    /// Return sample-to-`OnFramePresent` counts.
    pub const fn sample_to_present(self) -> [u32; BUCKET_COUNT] {
        self.sample_to_present
    }

    /// Return intervals rejected because QPC failed or exceeded two seconds.
    pub const fn invalid_intervals(self) -> u32 {
        self.invalid_intervals
    }

    /// Return the horizontal count-to-heading aggregate.
    pub const fn mouse_x(self) -> MouseHeadingSummary {
        self.mouse_x
    }

    /// Return the vertical count-to-heading aggregate.
    pub const fn mouse_y(self) -> MouseHeadingSummary {
        self.mouse_y
    }
}

/// Enable or disable collection and precompute QPC-domain bucket limits.
///
/// A non-positive or greater-than-32-bit frequency disables collection. QPC's
/// low word remains sufficient because intervals over two seconds are rejected
/// and therefore cannot approach its wrap ambiguity at supported frequencies.
pub(crate) fn configure(enabled: bool, frequency: i64) {
    let Ok(frequency) = u32::try_from(frequency) else {
        ENABLED.store(false, Ordering::Release);
        return;
    };
    if frequency == 0 {
        ENABLED.store(false, Ordering::Release);
        return;
    }

    let max_ticks = (u64::from(frequency) * u64::from(MAX_ACCEPTED_US) / 1_000_000)
        .min(u64::from(u32::MAX)) as u32;
    MAX_ACCEPTED_TICKS.store(max_ticks, Ordering::Relaxed);
    for (target, upper_us) in BUCKET_TICKS.iter().zip(BUCKET_UPPER_US) {
        let ticks = (u64::from(frequency) * u64::from(upper_us) / 1_000_000)
            .max(1)
            .min(u64::from(u32::MAX)) as u32;
        target.store(ticks, Ordering::Relaxed);
    }
    ENABLED.store(enabled, Ordering::Release);
}

/// Clear all histograms and in-flight frame markers.
pub(crate) fn reset() {
    SAMPLE_FRAME.store(0, Ordering::Relaxed);
    SAMPLE_TICK_LOW.store(0, Ordering::Relaxed);
    CONSUMER_FRAME.store(0, Ordering::Relaxed);
    PRESENT_FRAME.store(0, Ordering::Relaxed);
    INVALID_INTERVALS.store(0, Ordering::Relaxed);
    for bucket in SAMPLE_TO_CONSUMER.iter().chain(&SAMPLE_TO_PRESENT) {
        bucket.store(0, Ordering::Relaxed);
    }
    for counter in [
        &MOUSE_X_SAMPLES,
        &MOUSE_X_COUNTS,
        &MOUSE_X_MICRORADIANS,
        &MOUSE_Y_SAMPLES,
        &MOUSE_Y_COUNTS,
        &MOUSE_Y_MICRORADIANS,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
}

/// Record completion of one native sample.
pub(crate) fn mark_sample(frame_id: u32) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let Ok(tick) = query_performance_counter() else {
        saturating_increment(&INVALID_INTERVALS);
        return;
    };
    SAMPLE_TICK_LOW.store(tick as u32, Ordering::Relaxed);
    SAMPLE_FRAME.store(frame_id, Ordering::Release);
}

/// Record the first hooked player-camera axis consumer for the latest sample.
pub(crate) fn mark_camera_consumer() {
    mark_interval(&CONSUMER_FRAME, &SAMPLE_TO_CONSUMER);
}

/// Record xNVSE's presentation-boundary message for the latest sample.
pub(crate) fn mark_present() {
    mark_interval(&PRESENT_FRAME, &SAMPLE_TO_PRESENT);
}

/// Record one transformed count-to-heading pair without logging or division.
pub(crate) fn record_mouse_heading(axis: MouseAxis, counts: i32, heading: f32) {
    if !ENABLED.load(Ordering::Acquire) || counts == 0 || !heading.is_finite() {
        return;
    }
    let (samples, count_sum, angle_sum) = match axis {
        MouseAxis::X => (&MOUSE_X_SAMPLES, &MOUSE_X_COUNTS, &MOUSE_X_MICRORADIANS),
        MouseAxis::Y => (&MOUSE_Y_SAMPLES, &MOUSE_Y_COUNTS, &MOUSE_Y_MICRORADIANS),
    };
    let absolute_counts = counts.unsigned_abs();
    let microradians = (heading.abs() * 1_000_000.0)
        .round()
        .clamp(0.0, u32::MAX as f32) as u32;
    saturating_increment(samples);
    saturating_add(count_sum, absolute_counts);
    saturating_add(angle_sum, microradians);
}

/// Load the current bounded counters without stopping collection.
pub fn snapshot() -> TelemetrySnapshot {
    TelemetrySnapshot {
        sample_to_consumer: load_histogram(&SAMPLE_TO_CONSUMER),
        sample_to_present: load_histogram(&SAMPLE_TO_PRESENT),
        invalid_intervals: INVALID_INTERVALS.load(Ordering::Relaxed),
        mouse_x: load_mouse_summary(&MOUSE_X_SAMPLES, &MOUSE_X_COUNTS, &MOUSE_X_MICRORADIANS),
        mouse_y: load_mouse_summary(&MOUSE_Y_SAMPLES, &MOUSE_Y_COUNTS, &MOUSE_Y_MICRORADIANS),
    }
}

fn mark_interval(last_frame: &AtomicU32, histogram: &[AtomicU32; BUCKET_COUNT]) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let frame = SAMPLE_FRAME.load(Ordering::Acquire);
    if frame == 0 || last_frame.swap(frame, Ordering::AcqRel) == frame {
        return;
    }
    let Ok(now) = query_performance_counter() else {
        saturating_increment(&INVALID_INTERVALS);
        return;
    };
    let delta = (now as u32).wrapping_sub(SAMPLE_TICK_LOW.load(Ordering::Relaxed));
    if delta > MAX_ACCEPTED_TICKS.load(Ordering::Relaxed) {
        saturating_increment(&INVALID_INTERVALS);
        return;
    }

    let bucket = BUCKET_TICKS
        .iter()
        .position(|upper| delta <= upper.load(Ordering::Relaxed))
        .unwrap_or(BUCKET_COUNT - 1);
    saturating_increment(&histogram[bucket]);
}

fn saturating_increment(counter: &AtomicU32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn saturating_add(counter: &AtomicU32, amount: u32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

fn load_histogram(source: &[AtomicU32; BUCKET_COUNT]) -> [u32; BUCKET_COUNT] {
    let mut counts = [0; BUCKET_COUNT];
    for (count, source) in counts.iter_mut().zip(source) {
        *count = source.load(Ordering::Relaxed);
    }
    counts
}

fn load_mouse_summary(
    samples: &AtomicU32,
    counts: &AtomicU32,
    microradians: &AtomicU32,
) -> MouseHeadingSummary {
    MouseHeadingSummary {
        samples: samples.load(Ordering::Relaxed),
        absolute_counts: counts.load(Ordering::Relaxed),
        absolute_microradians: microradians.load(Ordering::Relaxed),
    }
}
