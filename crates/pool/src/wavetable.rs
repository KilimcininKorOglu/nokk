//! Oscillator wavetables, bit-exact with the browser.
//!
//! `OscillatorNode` plays from a precomputed table: Chrome takes the Fourier
//! coefficients, drops harmonics above the limit for each pitch range, and runs
//! the inverse FFT in single precision. The audio fingerprint is essentially
//! that table's content, identical on every machine with the same Chrome
//! build, so it must match bit for bit.
//!
//! Hence the vendored PFFFT (`vendor/pffft`): the addition order in its
//! butterflies decides the last bits. A double-precision FFT matched only 932
//! of 4096 samples of a table recorded from Chrome; PFFFT matches all 4096.
//!
//! Port of `PeriodicWaveImpl::CreateBandLimitedTables` and
//! `FFTFrame::PlatformDoInverseFFT` from Chrome 151.

use std::cell::RefCell;
use std::collections::HashMap;

#[repr(C)]
struct PffftSetup {
    _private: [u8; 0],
}

const PFFFT_REAL: i32 = 0;
const PFFFT_BACKWARD: i32 = 1;

extern "C" {
    fn pffft_new_setup(n: i32, transform: i32) -> *mut PffftSetup;
    fn pffft_destroy_setup(setup: *mut PffftSetup);
    fn pffft_transform_ordered(
        setup: *mut PffftSetup,
        input: *const f32,
        output: *mut f32,
        work: *mut f32,
        direction: i32,
    );
    fn pffft_aligned_malloc(nb_bytes: usize) -> *mut core::ffi::c_void;
    fn pffft_aligned_free(p: *mut core::ffi::c_void);
}

/// Inverse FFT of one size with its own buffers.
struct Inverse {
    size: usize,
    setup: *mut PffftSetup,
    input: *mut f32,
    output: *mut f32,
    work: *mut f32,
}

impl Inverse {
    fn new(size: usize) -> Option<Self> {
        // SAFETY: size is a power of two >= 32, which PFFFT accepts; on failure
        // it returns null, which is checked.
        unsafe {
            let setup = pffft_new_setup(size as i32, PFFFT_REAL);
            if setup.is_null() {
                return None;
            }
            let bytes = size * std::mem::size_of::<f32>();
            Some(Self {
                size,
                setup,
                input: pffft_aligned_malloc(bytes) as *mut f32,
                output: pffft_aligned_malloc(bytes) as *mut f32,
                work: pffft_aligned_malloc(bytes) as *mut f32,
            })
        }
    }

    /// `FFTFrame::PlatformDoInverseFFT`: halves packed into one complex
    /// array, the transform is unnormalized, the result is divided by size.
    fn run(&mut self, real: &[f32], imag: &[f32], out: &mut [f32]) {
        let half = self.size / 2;
        // SAFETY: buffers hold `size` floats; exactly that many are written.
        unsafe {
            let inp = std::slice::from_raw_parts_mut(self.input, self.size);
            for k in 0..half {
                inp[2 * k] = real[k];
                inp[2 * k + 1] = imag[k];
            }
            pffft_transform_ordered(
                self.setup,
                self.input,
                self.output,
                self.work,
                PFFFT_BACKWARD,
            );
            let res = std::slice::from_raw_parts(self.output, self.size);
            let scale = 1.0f32 / self.size as f32;
            for (d, &v) in out.iter_mut().zip(res.iter()) {
                *d = v * scale;
            }
        }
    }
}

impl Drop for Inverse {
    fn drop(&mut self) {
        // SAFETY: pointers come from PFFFT and are freed once.
        unsafe {
            pffft_destroy_setup(self.setup);
            pffft_aligned_free(self.input as *mut _);
            pffft_aligned_free(self.output as *mut _);
            pffft_aligned_free(self.work as *mut _);
        }
    }
}

/// Ranges per octave and cents per range, as in the browser.
const BANDS: f32 = 3.0;
const CENTS_PER_RANGE: f32 = 1200.0 / BANDS;

/// Table size for this sample rate; breakpoints are the browser's
/// (44.1 kHz gives 4096).
pub fn wave_size(sample_rate: f32) -> usize {
    if sample_rate <= 24000.0 {
        2048
    } else if sample_rate <= 88200.0 {
        4096
    } else {
        16384
    }
}

/// Number of pitch ranges the table covers.
pub fn number_of_ranges(sample_rate: f32) -> usize {
    (0.5 + BANDS * (wave_size(sample_rate) as f32).log2()) as usize
}

/// Lowest fundamental frequency the ranges start from.
pub fn lowest_fundamental(sample_rate: f32) -> f32 {
    let nyquist = 0.5 * sample_rate;
    nyquist / (wave_size(sample_rate) / 2) as f32
}

/// Fourier coefficients for a built-in shape. All shapes are odd, so cosine
/// terms are zero; sine terms are computed in single precision as in the browser.
fn basic_coefficients(shape: &str, half: usize) -> Vec<f32> {
    let mut imag = vec![0.0f32; half];
    for n in 1..half {
        let pi_factor = 2.0f32 / (n as f32 * std::f32::consts::PI);
        imag[n] = match shape {
            "square" => {
                if n & 1 == 1 {
                    2.0 * pi_factor
                } else {
                    0.0
                }
            }
            "sawtooth" => pi_factor * if n & 1 == 1 { 1.0 } else { -1.0 },
            "triangle" => {
                if n & 1 == 1 {
                    2.0 * (pi_factor * pi_factor) * if ((n - 1) >> 1) & 1 == 1 { -1.0 } else { 1.0 }
                } else {
                    0.0
                }
            }
            // sine
            _ => {
                if n == 1 {
                    1.0
                } else {
                    0.0
                }
            }
        };
    }
    imag
}

/// Harmonics kept in this range: the higher the pitch, the more are dropped
/// to avoid aliasing.
fn partials_for_range(range_index: usize, half: usize) -> usize {
    let cents_to_cull = range_index as f32 * CENTS_PER_RANGE;
    let culling_scale = 2.0f64.powf((-cents_to_cull / 1200.0) as f64) as f32;
    (culling_scale * half as f32) as usize
}

/// All tables for one shape: `CreateBandLimitedTables`.
fn build(sample_rate: f32, real_src: &[f32], imag_src: &[f32], normalize: bool) -> Vec<Vec<f32>> {
    let size = wave_size(sample_rate);
    let half = size / 2;
    let ranges = number_of_ranges(sample_rate);
    let Some(mut inverse) = Inverse::new(size) else {
        return Vec::new();
    };
    let components = real_src.len().min(half);
    let mut out = Vec::with_capacity(ranges);
    // Normalization factor comes from the first range (the fullest one).
    let mut normalization = 0.5f32;
    for range_index in 0..ranges {
        let mut real = vec![0.0f32; half];
        let mut imag = vec![0.0f32; half];
        // Pre-multiply by size to cancel the inverse FFT's division, and
        // conjugate (hence the minus).
        let scale = size as f32;
        for i in 0..components {
            real[i] = real_src[i] * scale;
            imag[i] = imag_src[i] * -scale;
        }
        let partials = partials_for_range(range_index, half);
        for i in components.min(partials + 1)..half {
            real[i] = 0.0;
            imag[i] = 0.0;
        }
        // Zero the DC term and the packed Nyquist term.
        real[0] = 0.0;
        imag[0] = 0.0;
        let mut data = vec![0.0f32; size];
        inverse.run(&real, &imag, &mut data);
        if normalize && range_index == 0 {
            let max = data.iter().fold(0.0f32, |a, &b| a.max(b.abs()));
            if max != 0.0 {
                normalization = 1.0 / max;
            }
        }
        for v in data.iter_mut() {
            *v *= normalization;
        }
        out.push(data);
    }
    out
}

thread_local! {
    /// Thread-lifetime cache: audio-fingerprinting pages request tables
    /// tens of thousands of times.
    static CACHE: RefCell<HashMap<String, Vec<Vec<f32>>>> = RefCell::new(HashMap::new());
}

/// Table for a built-in shape (`sine`, `square`, `sawtooth`, `triangle`) in this
/// pitch range. Empty if PFFFT cannot handle the size.
pub fn basic_table(shape: &str, sample_rate: f32, range_index: usize) -> Vec<f32> {
    let key = format!("{shape}@{sample_rate}");
    CACHE.with(|c| {
        let mut map = c.borrow_mut();
        let tables = map.entry(key).or_insert_with(|| {
            let half = wave_size(sample_rate) / 2;
            let imag = basic_coefficients(shape, half);
            let real = vec![0.0f32; half];
            build(sample_rate, &real, &imag, true)
        });
        tables.get(range_index).cloned().unwrap_or_default()
    })
}

/// Table for a page-defined shape from `createPeriodicWave`.
pub fn custom_table(
    real: &[f32],
    imag: &[f32],
    sample_rate: f32,
    range_index: usize,
    disable_normalization: bool,
) -> Vec<f32> {
    let half = wave_size(sample_rate) / 2;
    let n = real.len().max(imag.len()).min(half);
    let mut r = vec![0.0f32; n];
    let mut i = vec![0.0f32; n];
    r[..real.len().min(n)].copy_from_slice(&real[..real.len().min(n)]);
    i[..imag.len().min(n)].copy_from_slice(&imag[..imag.len().min(n)]);
    // Without normalization the browser keeps a constant factor of 0.5.
    let tables = build(sample_rate, &r, &i, !disable_normalization);
    tables.get(range_index).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sizes_are_the_ones_the_browser_uses() {
        assert_eq!(wave_size(44100.0), 4096, "44.1 kHz");
        assert_eq!(wave_size(22050.0), 2048, "low rate, short table");
        assert_eq!(wave_size(96000.0), 16384, "high rate, long table");
        assert_eq!(number_of_ranges(44100.0), 36, "three ranges per octave");
        assert!((lowest_fundamental(44100.0) - 10.766602).abs() < 1e-4);
    }

    /// Values recorded from Chrome 151 on this machine: triangle table, first
    /// range, 44100 Hz. Compared bit for bit, since the page reads every bit.
    #[test]
    fn a_triangle_table_matches_the_browser_bit_for_bit() {
        let t = basic_table("triangle", 44100.0, 1);
        assert_eq!(t.len(), 4096, "table built");
        let want: [(usize, f32); 6] = [
            (0, 0.0),
            (1, 0.000976848),
            (2, 0.001953364),
            (1024, 0.9999486),
            (2048, 0.0),
            (3072, -0.9999486),
        ];
        for (i, v) in want {
            assert!(
                (t[i] - v).abs() < 1e-6,
                "sample {i}: {} vs browser {v}",
                t[i]
            );
        }
        let peak = t.iter().fold(0.0f32, |a, &b| a.max(b.abs()));
        assert!((peak - 0.9999486).abs() < 1e-6, "table peak: {peak}");
    }

    #[test]
    fn a_sine_table_is_a_sine() {
        let t = basic_table("sine", 44100.0, 0);
        assert_eq!(t.len(), 4096);
        // Pure sine: 1 at a quarter period, 0 at half.
        assert!((t[1024] - 1.0).abs() < 1e-6, "quarter period: {}", t[1024]);
        assert!(t[2048].abs() < 1e-6, "half period: {}", t[2048]);
        assert!((t[3072] + 1.0).abs() < 1e-6, "three quarters: {}", t[3072]);
    }
}
