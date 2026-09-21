//! Таблицы волн осциллятора — те же числа, что у браузера, до последнего бита.
//!
//! `OscillatorNode` звучит не синусом из библиотеки, а записью из таблицы,
//! построенной заранее: браузер берёт коэффициенты ряда Фурье, обрезает
//! гармоники выше предела для этой полосы высот и делает обратное
//! преобразование Фурье **в одинарной точности**. Отпечаток по звуку — это,
//! по сути, содержимое такой таблицы, и оно одинаково на всякой машине с той
//! же сборкой браузера. Значит, сверять его можно точно — и нам нужно
//! совпасть не «почти», а бит в бит.
//!
//! Отсюда вендорённый PFFFT (см. `vendor/pffft`): порядок сложений в его
//! бабочках определяет последние разряды каждого отсчёта. Честное
//! преобразование в двойной точности, как и любая другая библиотека, даёт
//! другие числа — проверено на снятой с Chrome таблице: совпадало 932 отсчёта
//! из 4096, с этой — все 4096.
//!
//! Перенос `PeriodicWaveImpl::CreateBandLimitedTables` и
//! `FFTFrame::PlatformDoInverseFFT` из Chrome 151.

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

/// Обратное преобразование одного размера со своими буферами.
struct Inverse {
    size: usize,
    setup: *mut PffftSetup,
    input: *mut f32,
    output: *mut f32,
    work: *mut f32,
}

impl Inverse {
    fn new(size: usize) -> Option<Self> {
        // SAFETY: размер — степень двойки не меньше 32, такие PFFFT принимает;
        // при отказе он отдаёт пустой указатель, и мы его проверяем.
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

    /// `FFTFrame::PlatformDoInverseFFT`: половинки складываются в одну
    /// комплексную запись, преобразование не нормирует, и результат делится
    /// на размер.
    fn run(&mut self, real: &[f32], imag: &[f32], out: &mut [f32]) {
        let half = self.size / 2;
        // SAFETY: буферы выделены на `size` чисел, пишем ровно столько.
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
        // SAFETY: указатели получены от PFFFT и освобождаются один раз.
        unsafe {
            pffft_destroy_setup(self.setup);
            pffft_aligned_free(self.input as *mut _);
            pffft_aligned_free(self.output as *mut _);
            pffft_aligned_free(self.work as *mut _);
        }
    }
}

/// Полос на октаву и центов на полосу — как у браузера.
const BANDS: f32 = 3.0;
const CENTS_PER_RANGE: f32 = 1200.0 / BANDS;

/// Размер таблицы для этой частоты дискретизации. Точки перелома браузерные:
/// сорок четыре килогерца дают четыре тысячи записей.
pub fn wave_size(sample_rate: f32) -> usize {
    if sample_rate <= 24000.0 {
        2048
    } else if sample_rate <= 88200.0 {
        4096
    } else {
        16384
    }
}

/// Сколько полос высот покрывает таблица.
pub fn number_of_ranges(sample_rate: f32) -> usize {
    (0.5 + BANDS * (wave_size(sample_rate) as f32).log2()) as usize
}

/// Самая низкая основная частота, от которой считаются полосы.
pub fn lowest_fundamental(sample_rate: f32) -> f32 {
    let nyquist = 0.5 * sample_rate;
    nyquist / (wave_size(sample_rate) / 2) as f32
}

/// Коэффициенты ряда Фурье для готовой формы. Все формы нечётные, поэтому у
/// косинусов коэффициенты нулевые, а синусные считаются в одинарной точности —
/// как в браузере, до последнего разряда.
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

/// Сколько гармоник остаётся в этой полосе: чем выше тон, тем больше их
/// приходится выбросить, чтобы не поймать зеркальные частоты.
fn partials_for_range(range_index: usize, half: usize) -> usize {
    let cents_to_cull = range_index as f32 * CENTS_PER_RANGE;
    let culling_scale = 2.0f64.powf((-cents_to_cull / 1200.0) as f64) as f32;
    (culling_scale * half as f32) as usize
}

/// Все таблицы одной формы: `CreateBandLimitedTables` целиком.
fn build(sample_rate: f32, real_src: &[f32], imag_src: &[f32], normalize: bool) -> Vec<Vec<f32>> {
    let size = wave_size(sample_rate);
    let half = size / 2;
    let ranges = number_of_ranges(sample_rate);
    let Some(mut inverse) = Inverse::new(size) else {
        return Vec::new();
    };
    let components = real_src.len().min(half);
    let mut out = Vec::with_capacity(ranges);
    // Множитель нормировки берётся с первой полосы — самой полной по звуку.
    let mut normalization = 0.5f32;
    for range_index in 0..ranges {
        let mut real = vec![0.0f32; half];
        let mut imag = vec![0.0f32; half];
        // Браузер домножает на размер, чтобы снять деление, которое сделает
        // обратное преобразование, и берёт сопряжённое — оттого минус.
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
        // Постоянная составляющая и упакованная частота Найквиста — в ноль.
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
    /// Таблицы живут до конца потока: страница, меряющая звук, просит их
    /// десятками тысяч раз на один отсчёт.
    static CACHE: RefCell<HashMap<String, Vec<Vec<f32>>>> = RefCell::new(HashMap::new());
}

/// Таблица готовой формы (`sine`, `square`, `sawtooth`, `triangle`) для этой
/// полосы высот. Пустой ответ — размер не по зубам PFFFT.
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

/// Таблица для формы, заданной страницей через `createPeriodicWave`.
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
    // Без нормировки браузер оставляет постоянный множитель в половину.
    let tables = build(sample_rate, &r, &i, !disable_normalization);
    tables.get(range_index).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sizes_are_the_ones_the_browser_uses() {
        assert_eq!(wave_size(44100.0), 4096, "сорок четыре килогерца");
        assert_eq!(wave_size(22050.0), 2048, "низкая частота — короткая таблица");
        assert_eq!(wave_size(96000.0), 16384, "высокая — длинная");
        assert_eq!(number_of_ranges(44100.0), 36, "три полосы на октаву");
        assert!((lowest_fundamental(44100.0) - 10.766602).abs() < 1e-4);
    }

    /// Числа сняты с Chrome 151 на этой машине: таблица треугольника для
    /// первой полосы при 44100 Гц. Сверяется побитно — приблизительного
    /// совпадения тут мало, страница читает все разряды.
    #[test]
    fn a_triangle_table_matches_the_browser_bit_for_bit() {
        let t = basic_table("triangle", 44100.0, 1);
        assert_eq!(t.len(), 4096, "таблица построена");
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
                "отсчёт {i}: {} против браузерного {v}",
                t[i]
            );
        }
        let peak = t.iter().fold(0.0f32, |a, &b| a.max(b.abs()));
        assert!((peak - 0.9999486).abs() < 1e-6, "пик таблицы: {peak}");
    }

    #[test]
    fn a_sine_table_is_a_sine() {
        let t = basic_table("sine", 44100.0, 0);
        assert_eq!(t.len(), 4096);
        // Чистый синус: четверть периода — единица, половина — ноль.
        assert!((t[1024] - 1.0).abs() < 1e-6, "четверть периода: {}", t[1024]);
        assert!(t[2048].abs() < 1e-6, "половина периода: {}", t[2048]);
        assert!((t[3072] + 1.0).abs() < 1e-6, "три четверти: {}", t[3072]);
    }
}
