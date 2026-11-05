//! Exact signs for finite binary32 geometry. Coordinates are integers in units
//! of 2^-149. A coordinate needs at most 277 bits, a difference 278, and a
//! three-dimensional determinant at most 838; 1024 bits cover every operation.
//! A certified binary64 filter handles separated signs in nearest rounding;
//! ambiguous signs and other caller modes use integer arithmetic. No allocation
//! or floating-point control-state change is used.

/// Exact binary32-to-binary64 conversion using integer bits. CVTSS2SD may
/// otherwise flush a subnormal input when the native caller enables DAZ.
pub(super) fn exact64(value: f32) -> f64 {
    let bits = value.to_bits();
    let sign = u64::from(bits >> 31) << 63;
    let exponent = (bits >> 23) & 255;
    let fraction = bits & 0x7fffff;
    let body = if exponent == 0 {
        if fraction == 0 {
            0
        } else {
            let top = 31 - fraction.leading_zeros();
            (u64::from(top + 874) << 52) | (u64::from(fraction ^ (1 << top)) << (52 - top))
        }
    } else if exponent == 255 {
        (2047u64 << 52) | (u64::from(fraction) << 29)
    } else {
        (u64::from(exponent + 896) << 52) | (u64::from(fraction) << 29)
    };
    f64::from_bits(sign | body)
}

#[derive(Clone, Copy)]
struct Integer {
    words: [u32; 32],
    used: usize,
    negative: bool,
}

impl Integer {
    const ZERO: Self = Self {
        words: [0; 32],
        used: 0,
        negative: false,
    };

    fn coordinate(bits: u32, base: u32) -> Self {
        let exponent = (bits >> 23) & 255;
        let mantissa = (bits & 0x7fffff) | if exponent == 0 { 0 } else { 0x800000 };
        if mantissa == 0 {
            return Self::ZERO;
        }
        let shift = (exponent.saturating_sub(1) - base) as usize;
        let mut out = Self::ZERO;
        let index = shift / 32;
        let v = u64::from(mantissa) << (shift % 32);
        out.words[index] = v as u32;
        out.words[index + 1] = (v >> 32) as u32;
        out.used = index + 2;
        out.negative = bits >> 31 != 0;
        out.normalize();
        out
    }

    fn normalize(&mut self) {
        while self.used > 0 && self.words[self.used - 1] == 0 {
            self.used -= 1;
        }
        if self.used == 0 {
            self.negative = false;
        }
    }

    fn neg(mut self) -> Self {
        if self.used != 0 {
            self.negative = !self.negative;
        }
        self
    }

    fn add(self, rhs: Self) -> Self {
        let mut out = Self::ZERO;
        if self.negative == rhs.negative {
            let mut carry = 0u64;
            for i in 0..self.used.max(rhs.used) {
                let sum = u64::from(self.words[i]) + u64::from(rhs.words[i]) + carry;
                out.words[i] = sum as u32;
                carry = sum >> 32;
            }
            out.used = self.used.max(rhs.used);
            if carry != 0 {
                // All callers operate within the determinant's 838-bit bound.
                out.words[out.used] = carry as u32;
                out.used += 1;
            }
            out.negative = self.negative;
        } else {
            let order = self.used.cmp(&rhs.used).then_with(|| {
                self.words[..self.used]
                    .iter()
                    .rev()
                    .cmp(rhs.words[..rhs.used].iter().rev())
            });
            let (large, small) = if order.is_lt() {
                (rhs, self)
            } else {
                (self, rhs)
            };
            let mut borrow = 0u64;
            for i in 0..large.used {
                let sub = u64::from(small.words[i]) + borrow;
                out.words[i] = u64::from(large.words[i]).wrapping_sub(sub) as u32;
                borrow = u64::from(u64::from(large.words[i]) < sub);
            }
            out.used = large.used;
            out.negative = large.negative;
        }
        out.normalize();
        out
    }

    fn sub(self, rhs: Self) -> Self {
        self.add(rhs.neg())
    }

    fn mul(self, rhs: Self) -> Self {
        let mut out = Self::ZERO;
        if self.used == 0 || rhs.used == 0 {
            return out;
        }
        for i in 0..self.used {
            let mut carry = 0u64;
            for j in 0..rhs.used {
                let k = i + j;
                let product = u64::from(self.words[i]) * u64::from(rhs.words[j])
                    + u64::from(out.words[k])
                    + carry;
                out.words[k] = product as u32;
                carry = product >> 32;
            }
            out.words[i + rhs.used] = carry as u32;
        }
        out.used = self.used + rhs.used;
        out.negative = self.negative != rhs.negative;
        out.normalize();
        out
    }

    fn sign(self) -> i8 {
        if self.used == 0 {
            0
        } else if self.negative {
            -1
        } else {
            1
        }
    }
}

/// Sign of det(a-d, b-d, c-d). Nonfinite inputs have no geometric sign.
pub(super) fn orient(a: [f32; 3], b: [f32; 3], c: [f32; 3], d: [f32; 3]) -> Option<i8> {
    orient_bits([a, b, c, d].map(|p| p.map(f32::to_bits)))
}

// Keep the numeric boundary integer-only even under whole-program optimization.
// LLVM may replace floating-value bit-zero tests with FP comparisons, which
// treat subnormals as zero when a native caller enables DAZ. That cannot decide
// the common integer exponent or the exact geometric sign.
#[inline(never)]
fn orient_bits(points: [[u32; 3]; 4]) -> Option<i8> {
    if points
        .iter()
        .flatten()
        .any(|bits| bits & 0x7f800000 == 0x7f800000)
    {
        return None;
    }
    if let Some(sign) = filtered_sign(points) {
        return Some(sign);
    }
    let base = points
        .iter()
        .flatten()
        .copied()
        .filter(|bits| bits & 0x7fffffff != 0)
        .map(|bits| ((bits >> 23) & 255).saturating_sub(1))
        .min()
        .unwrap_or(0);
    let [a, b, c, d] = points;
    let d = d.map(|v| Integer::coordinate(v, base));
    let delta =
        |p: [u32; 3]| std::array::from_fn::<_, 3, _>(|i| Integer::coordinate(p[i], base).sub(d[i]));
    let a = delta(a);
    let b = delta(b);
    let c = delta(c);
    Some(
        a[0].mul(b[1].mul(c[2]).sub(b[2].mul(c[1])))
            .add(a[1].mul(b[2].mul(c[0]).sub(b[0].mul(c[2]))))
            .add(a[2].mul(b[0].mul(c[1]).sub(b[1].mul(c[0]))))
            .sign(),
    )
}

/// Shewchuk orient3d's first-stage error bound, with the same arithmetic order:
/// https://www.cs.cmu.edu/~quake/robust.html (predicates.c, orient3d/exactinit).
/// Binary32 inputs convert exactly using bits, bypassing DAZ. Differences,
/// products and sums are multiples of 2^-149, 2^-298 and 2^-447, respectively;
/// nonzero intermediates cannot underflow binary64, nor can their magnitudes
/// overflow it. Packed SSE2 operations use binary64 precision, without FMA.
fn filtered_sign(points: [[u32; 3]; 4]) -> Option<i8> {
    #[cfg(target_arch = "x86")]
    {
        let mut control = 0u32;
        // SAFETY: SSE2 is the supported target baseline, and the four-byte
        // stack operand is valid. STMXCSR only reads this thread's state.
        unsafe {
            core::arch::asm!("stmxcsr [{}]", in(reg) &mut control, options(nostack, preserves_flags));
        }
        if control & (0x6000 | 0x1F80) != 0x1F80 {
            return None;
        }
        use wide::f64x2;
        let [a, b, c, d] = points.map(|p| p.map(|v| exact64(f32::from_bits(v))));
        let [ax, ay, az] = std::array::from_fn(|i| a[i] - d[i]);
        let [bx, by, bz] = std::array::from_fn(|i| b[i] - d[i]);
        let [cx, cy, cz] = std::array::from_fn(|i| c[i] - d[i]);
        let [bc, cb] = (f64x2::new([bx, cx]) * f64x2::new([cy, by])).to_array();
        let [ca, ac] = (f64x2::new([cx, ax]) * f64x2::new([ay, cy])).to_array();
        let [ab, ba] = (f64x2::new([ax, bx]) * f64x2::new([by, ay])).to_array();
        let determinant = az * (bc - cb) + bz * (ca - ac) + cz * (ab - ba);
        let permanent = (bc.abs() + cb.abs()) * az.abs()
            + (ca.abs() + ac.abs()) * bz.abs()
            + (ab.abs() + ba.abs()) * cz.abs();
        const EPS: f64 = f64::EPSILON * 0.5;
        let bound = ((7.0 + 56.0 * EPS) * EPS) * permanent;
        if determinant > bound {
            return Some(1);
        }
        if -determinant > bound {
            return Some(-1);
        }
    }
    #[cfg(not(target_arch = "x86"))]
    let _ = points;
    None
}
