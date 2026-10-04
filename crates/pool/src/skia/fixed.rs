//! Skia integer arithmetic: SkFixed (16.16) and SkFDot6 (26.6).
//! Each formula mirrors `include/private/base/SkFixed.h` and
//! `src/core/SkFDot6.h` verbatim: edge coverage is computed in these
//! units, and any rounding difference changes fingerprint bytes.

pub type Fixed = i32;
pub type FDot6 = i32;

pub const FIXED_1: Fixed = 1 << 16;
pub const FIXED_HALF: Fixed = 1 << 15;
pub const MAX_S32: i32 = i32::MAX;
pub const MIN_S32: i32 = i32::MIN;

#[inline]
pub fn left_shift(v: i32, s: i32) -> i32 {
    ((v as u32) << s) as i32
}

#[inline]
pub fn left_shift64(v: i64, s: i32) -> i64 {
    ((v as u64) << s) as i64
}

#[inline]
pub fn fixed_mul(a: Fixed, b: Fixed) -> Fixed {
    ((a as i64 * b as i64) >> 16) as Fixed
}

#[inline]
pub fn fixed_div(a: Fixed, b: Fixed) -> Fixed {
    let v = left_shift64(a as i64, 16) / b as i64;
    v.clamp(MIN_S32 as i64, MAX_S32 as i64) as Fixed
}

#[inline]
pub fn fixed_round_to_int(x: Fixed) -> i32 {
    (x.wrapping_add(FIXED_HALF)) >> 16
}
#[inline]
pub fn fixed_ceil_to_int(x: Fixed) -> i32 {
    (x.wrapping_add(FIXED_1 - 1)) >> 16
}
#[inline]
pub fn fixed_floor_to_int(x: Fixed) -> i32 {
    x >> 16
}
#[inline]
pub fn fixed_round_to_fixed(x: Fixed) -> Fixed {
    (x.wrapping_add(FIXED_HALF)) & !0xFFFF
}
#[inline]
pub fn fixed_ceil_to_fixed(x: Fixed) -> Fixed {
    (x.wrapping_add(FIXED_1 - 1)) & !0xFFFF
}
#[inline]
pub fn fixed_floor_to_fixed(x: Fixed) -> Fixed {
    x & !0xFFFF
}
#[inline]
pub fn int_to_fixed(x: i32) -> Fixed {
    left_shift(x, 16)
}

#[inline]
pub fn sat_add(a: i32, b: i32) -> i32 {
    a.saturating_add(b)
}
#[inline]
pub fn sat_sub(a: i32, b: i32) -> i32 {
    a.saturating_sub(b)
}

#[inline]
pub fn abs32(v: i32) -> i32 {
    v.wrapping_abs()
}

#[inline]
pub fn clz(v: u32) -> i32 {
    v.leading_zeros() as i32
}

// ── FDot6 ──────────────────────────────────────────────────────────────────

pub const FDOT6_ONE: FDot6 = 64;
pub const FDOT6_HALF: FDot6 = 32;

#[inline]
pub fn fdot6_round(x: FDot6) -> i32 {
    (x + FDOT6_HALF) >> 6
}
#[inline]
pub fn fixed_to_fdot6(x: Fixed) -> FDot6 {
    x >> 10
}
#[inline]
pub fn fdot6_to_fixed(x: FDot6) -> Fixed {
    left_shift(x, 10)
}
/// `SkScalarToFDot6`: plain truncating cast.
#[inline]
pub fn scalar_to_fdot6(x: f32) -> FDot6 {
    (x * FDOT6_ONE as f32) as i32
}
#[inline]
pub fn fdot6_div(a: FDot6, b: FDot6) -> Fixed {
    debug_assert!(b != 0);
    if (i16::MIN as i32..=i16::MAX as i32).contains(&a) {
        left_shift(a, 16) / b
    } else {
        fixed_div(a, b)
    }
}

/// `sk_float_saturate2int`: to i32, saturating at the ends.
#[inline]
pub fn saturate2int(x: f32) -> i32 {
    // As in Skia: NaN maps to the negative end (cvttss2si behaviour).
    if x.is_nan() {
        return i32::MIN;
    }
    x.clamp(i32::MIN as f32, i32::MAX as f32) as i32
}
#[inline]
pub fn float_round(x: f32) -> f32 {
    (x + 0.5).floor()
}
#[inline]
pub fn round2int(x: f32) -> i32 {
    saturate2int(float_round(x))
}
#[inline]
pub fn floor2int(x: f32) -> i32 {
    saturate2int(x.floor())
}
#[inline]
pub fn ceil2int(x: f32) -> i32 {
    saturate2int(x.ceil())
}
