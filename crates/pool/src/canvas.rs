//! Optional real 2D canvas rasterization — the `render` feature.
//!
//! With `--features render`, the JS canvas backs its pixel operations with a real
//! [`tiny_skia`] rasterizer instead of the default JS synthesis, so `getImageData`
//! and `toDataURL` return genuine pixels of what was drawn (see docs/rendering.md).
//!
//! One [`Pixmap`] per canvas id, kept **thread-local** — nokk runs one V8 isolate
//! per worker thread, so a per-thread store needs no locking and can't leak across
//! contexts on other threads. The JS layer calls the `__pt_canvas*` natives that
//! wrap these. Covered here: fills, real glyph text (`fill_text`/`measure_text`
//! via a bundled font), vector paths (`fill_path`/`stroke_path` — the JS side
//! tessellates curves/arcs to a move/line/close verb stream), linear/radial
//! gradients (`fill_path_grad`), and image data put/get. Only `drawImage` still
//! falls back to the JS deterministic stamp; WebGL is a separate phase.

use std::cell::RefCell;
use std::collections::HashMap;

use ab_glyph::{Font, FontVec, PxScale, ScaleFont};
use tiny_skia::{
    Color, FillRule, GradientStop, LinearGradient, Paint, PathBuilder, Pixmap, Point,
    RadialGradient, Rect, Shader, SpreadMode, Stroke, Transform,
};

/// Bundled Liberation Sans (OFL, Arial-metric): последний запасной вариант,
/// когда системных шрифтов нет вовсе — в голом контейнере, например. Обычная
/// машина отвечает своими файлами, и тогда метрики совпадают с браузерными.
const FONT_BYTES: &[u8] = include_bytes!("../fonts/LiberationSans-Regular.ttf");

/// Куда смотрит система за шрифтами. Порядок как у fontconfig: сначала общие
/// каталоги, потом домашний.
const FONT_DIRS: &[&str] = &[
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    "/usr/X11R6/lib/X11/fonts",
];

/// Какой файл берёт браузер под каким именем. Снято с Chrome 151 на этой
/// машине: `16px Arial` и `16px "Liberation Sans"` дают одну и ту же ширину до
/// тысячной, потому что fontconfig подменяет метрически совместимый шрифт.
/// Семейство, которого в списке нет, браузер не находит вовсе и переходит к
/// следующему в объявлении — а если не нашлось ни одного, берёт свой основной,
/// и здесь это Liberation Serif.
const FAMILIES: &[(&str, &[&str])] = &[
    ("sans-serif", &["LiberationSans-Regular.ttf", "Arimo-Regular.ttf", "DejaVuSans.ttf"]),
    ("arial", &["LiberationSans-Regular.ttf", "Arimo-Regular.ttf"]),
    ("helvetica", &["LiberationSans-Regular.ttf", "Arimo-Regular.ttf"]),
    ("liberation sans", &["LiberationSans-Regular.ttf"]),
    // Родовой `serif` браузер на этой машине разрешает в Liberation Serif, а не
    // в DejaVu: измерено — «mmmmmmmmmmlli» на 72 пикселях даёт у него 620.05, а
    // у DejaVu 751.82. Двадцать процентов разницы видит любая страница, меряющая
    // текст, и это была единственная родовая семья, где мы расходились.
    ("serif", &["LiberationSerif-Regular.ttf", "Tinos-Regular.ttf", "DejaVuSerif.ttf"]),
    ("times new roman", &["LiberationSerif-Regular.ttf", "Tinos-Regular.ttf"]),
    ("times", &["LiberationSerif-Regular.ttf", "Tinos-Regular.ttf"]),
    ("liberation serif", &["LiberationSerif-Regular.ttf"]),
    ("monospace", &["NotoSansMono-Regular.ttf", "LiberationMono-Regular.ttf", "DejaVuSansMono.ttf"]),
    ("courier new", &["LiberationMono-Regular.ttf", "Cousine-Regular.ttf"]),
    ("courier", &["LiberationMono-Regular.ttf", "Cousine-Regular.ttf"]),
    ("liberation mono", &["LiberationMono-Regular.ttf"]),
    ("dejavu sans", &["DejaVuSans.ttf"]),
    ("dejavu serif", &["DejaVuSerif.ttf"]),
    ("dejavu sans mono", &["DejaVuSansMono.ttf"]),
    ("noto sans mono", &["NotoSansMono-Regular.ttf"]),
    // Метрически совместимые имена: этих файлов на машине нет, но fontconfig
    // подменяет их Liberation, и браузер отвечает шириной подмены — то есть
    // считает семейство существующим.
    ("arimo", &["LiberationSans-Regular.ttf"]),
    ("tinos", &["LiberationSerif-Regular.ttf"]),
    ("cousine", &["LiberationMono-Regular.ttf"]),
    // `system-ui` — шрифт рабочего стола; Chrome спрашивает его у системы
    // и получает здесь Cantarell.
    ("system-ui", &["Cantarell-Regular.otf", "NotoSans-Regular.ttf", "DejaVuSans.ttf"]),
    ("cantarell", &["Cantarell-Regular.otf"]),
];

/// Основной шрифт браузера: им меряется всё, для чего семейство не нашлось.
const FALLBACK_FAMILY: &str = "times new roman";

thread_local! {
    static CANVASES: RefCell<HashMap<u32, Pixmap>> = RefCell::new(HashMap::new());
    /// Разобранные файлы шрифтов, по имени файла. Разбор недёшев, а страница,
    /// перебирающая семейства ради отпечатка, спрашивает их сотнями.
    static LOADED: RefCell<HashMap<String, Option<&'static FontVec>>> =
        RefCell::new(HashMap::new());
    /// Decoded images, by address. A page draws the same picture many times —
    /// the challenge's beacon PNG lands on a canvas on every round — so the
    /// decode happens once and the pixels stay.
    static IMAGES: RefCell<HashMap<String, (u32, u32, Vec<u8>)>> = RefCell::new(HashMap::new());
}

/// Указатель «семейство → файл», построенный по самим шрифтам. Таблица имён у
/// нас была на девятнадцать семейств, а на машине их две сотни: страница,
/// перебирающая шрифты измерением — а это самый ходовой способ, — находила у
/// нас одиннадцать против двадцати трёх у браузера. Имя семейства читается из
/// таблицы `name` самого файла, а не угадывается по его названию.
fn font_index() -> &'static std::collections::HashMap<String, (std::path::PathBuf, bool)> {
    static INDEX: std::sync::OnceLock<std::collections::HashMap<String, (std::path::PathBuf, bool)>> =
        std::sync::OnceLock::new();
    INDEX.get_or_init(|| {
        let mut out = std::collections::HashMap::new();
        for dir in FONT_DIRS {
            let mut stack = vec![std::path::PathBuf::from(dir)];
            while let Some(d) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&d) else {
                    continue;
                };
                for e in entries.flatten() {
                    let path = e.path();
                    if path.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    let ext = path
                        .extension()
                        .and_then(|x| x.to_str())
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if ext != "ttf" && ext != "otf" && ext != "ttc" {
                        continue;
                    }
                    let Ok(bytes) = std::fs::read(&path) else {
                        continue;
                    };
                    let Ok(face) = ttf_parser::Face::parse(&bytes, 0) else {
                        continue;
                    };
                    // Обычное начертание предпочтительнее, но семейство,
                    // у которого есть только наклонное — а такие бывают, Z003
                    // из них, — всё равно существует, и браузер его находит.
                    let plain = !face.is_bold() && !face.is_italic();
                    for name in face.names() {
                        // 1 — семейство, 16 — типографское семейство.
                        if name.name_id != 1 && name.name_id != 16 {
                            continue;
                        }
                        let Some(text) = name.to_string() else { continue };
                        let key = text.to_lowercase();
                        match out.entry(key) {
                            std::collections::hash_map::Entry::Vacant(v) => {
                                v.insert((path.clone(), plain));
                            }
                            std::collections::hash_map::Entry::Occupied(mut o) => {
                                if plain && !o.get().1 {
                                    o.insert((path.clone(), true));
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    })
}

/// Найти файл шрифта по имени в системных каталогах.
fn font_path(file: &str) -> Option<std::path::PathBuf> {
    for dir in FONT_DIRS {
        let mut stack = vec![std::path::PathBuf::from(dir)];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().and_then(|n| n.to_str()) == Some(file) {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Загрузить шрифт по имени файла, один раз за поток. Утечка намеренная:
/// шрифтов конечное число, живут они до конца процесса, а `FontVec` иначе
/// пришлось бы возвращать за замыканием.
fn load(file: &str) -> Option<&'static FontVec> {
    LOADED.with(|m| {
        if let Some(hit) = m.borrow().get(file) {
            return *hit;
        }
        let got = font_path(file)
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| FontVec::try_from_vec(bytes).ok())
            .map(|f| &*Box::leak(Box::new(f)));
        m.borrow_mut().insert(file.to_string(), got);
        got
    })
}

/// Разрешить список семейств так, как его разрешает браузер: по очереди, до
/// первого, который в системе есть. Не нашлось ни одного — основной шрифт.
fn face(file: &str, bold: bool, italic: bool) -> Option<&'static FontVec> {
    if !bold && !italic {
        return load(file);
    }
    // Имена начертаний у гарнитур разные: Liberation зовёт их `-Bold`/`-Italic`
    // через `-Regular`, DejaVu приписывает `-Bold`/`-Oblique` к голому имени.
    let (stem, ext) = file.rsplit_once('.')?;
    let suffixes: &[&str] = match (bold, italic) {
        (true, true) => &["BoldItalic", "BoldOblique"],
        (true, false) => &["Bold"],
        _ => &["Italic", "Oblique"],
    };
    for suffix in suffixes {
        let name = if let Some(base) = stem.strip_suffix("-Regular") {
            format!("{base}-{suffix}.{ext}")
        } else {
            format!("{stem}-{suffix}.{ext}")
        };
        if let Some(f) = load(&name) {
            return Some(f);
        }
    }
    load(file)
}

/// Все семейства списка по порядку — для поглифной подмены.
///
/// Браузер берёт знак из первого семейства, где он есть, а не из первого
/// семейства вообще: шрифт вроде «Noto Color Emoji» латиницы не содержит, и
/// строка на нём меряется запасным. Мы мерили самим найденным шрифтом, и
/// страница, перебирающая шрифты измерением, видела найденными и те, которых
/// у неё быть не может.
fn resolve_chain(families: &str, bold: bool, italic: bool) -> Vec<&'static FontVec> {
    let mut out: Vec<&'static FontVec> = Vec::new();
    let mut push = |f: &'static FontVec| {
        if !out.iter().any(|g| std::ptr::eq(*g, f)) {
            out.push(f);
        }
    };
    for raw in families.split(',') {
        let name = raw.trim().trim_matches(['"', '\'']).to_lowercase();
        if name.is_empty() {
            continue;
        }
        if let Some((_, files)) = FAMILIES.iter().find(|(f, _)| *f == name) {
            for file in *files {
                if let Some(f) = face(file, bold, italic) {
                    push(f);
                    break;
                }
            }
            continue;
        }
        if let Some((path, _)) = font_index().get(&name) {
            if let Some(file) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(f) = face(file, bold, italic) {
                    push(f);
                }
            }
        }
    }
    if let Some(f) = FAMILIES
        .iter()
        .find(|(f, _)| *f == FALLBACK_FAMILY)
        .and_then(|(_, files)| files.iter().find_map(|f| face(f, bold, italic)))
        .or_else(bundled)
    {
        push(f);
    }
    out
}

/// Шрифт, которым рисуется этот знак: первый в цепочке, где он есть.
fn face_for(chain: &[&'static FontVec], ch: char) -> &'static FontVec {
    for f in chain {
        if f.glyph_id(ch).0 != 0 {
            return f;
        }
    }
    chain[0]
}

fn resolve(families: &str, bold: bool, italic: bool) -> Option<&'static FontVec> {
    for raw in families.split(',') {
        let name = raw.trim().trim_matches(['"', '\'']).to_lowercase();
        if name.is_empty() {
            continue;
        }
        if let Some((_, files)) = FAMILIES.iter().find(|(f, _)| *f == name) {
            for file in *files {
                if let Some(f) = face(file, bold, italic) {
                    return Some(f);
                }
            }
            continue;
        }
        // Не в таблице подмен — значит ищем семейство как оно есть.
        if let Some((path, _)) = font_index().get(&name) {
            if let Some(file) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(f) = face(file, bold, italic) {
                    return Some(f);
                }
            }
        }
    }
    FAMILIES
        .iter()
        .find(|(f, _)| *f == FALLBACK_FAMILY)
        .and_then(|(_, files)| files.iter().find_map(|f| face(f, bold, italic)))
        .or_else(bundled)
}

/// Встроенный шрифт: система без шрифтов всё равно должна что-то нарисовать.
fn bundled() -> Option<&'static FontVec> {
    LOADED.with(|m| {
        if let Some(hit) = m.borrow().get("\u{0}bundled") {
            return *hit;
        }
        let got = FontVec::try_from_vec(FONT_BYTES.to_vec())
            .ok()
            .map(|f| &*Box::leak(Box::new(f)));
        m.borrow_mut().insert("\u{0}bundled".to_string(), got);
        got
    })
}

/// Масштаб, которым `ab_glyph` рисует шрифт кегля `size_px`. `PxScale` задаёт
/// не размер em, а высоту строки, поэтому кегль надо пересчитать: без этого все
/// ширины выходят ровно во столько раз меньше браузерных, во сколько высота
/// шрифта больше его em. У Liberation Sans это 2288/2048, то есть 1,1172 — и
/// именно во столько наши измерения расходились с Chrome.
fn px_scale<F: Font>(font: &F, size_px: f32) -> PxScale {
    let upem = font.units_per_em().unwrap_or(1000.0);
    PxScale::from(size_px * font.height_unscaled() / upem)
}

/// Метрики строки, как их возвращает `measureText`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TextMetrics {
    pub width: f32,
    pub left: f32,
    pub right: f32,
    pub ascent: f32,
    pub descent: f32,
    pub font_ascent: f32,
    pub font_descent: f32,
    /// Высота строки при `line-height: normal` — подъём, спуск и просвет
    /// гарнитуры. У Liberation Sans это ровно 1,15 кегля, и раскладка без неё
    /// не сходится с браузерной ни на пиксель.
    pub line: f32,
}

/// Cap per-side pixels so a hostile page can't request an absurd allocation.
const MAX_DIM: u32 = 8192;

/// Create (or reset) a canvas surface of `w`×`h`.
pub fn create(id: u32, w: u32, h: u32) {
    let (w, h) = (w.clamp(1, MAX_DIM), h.clamp(1, MAX_DIM));
    if let Some(pm) = Pixmap::new(w, h) {
        CANVASES.with(|c| {
            c.borrow_mut().insert(id, pm);
        });
    }
}

/// Remember an image's bytes under its address, decoded to RGBA.
///
/// Without this `drawImage` had nothing to draw: an image reaches JS as lossy
/// text, so its pixels never left Rust. A page that draws a picture and reads
/// the canvas back — which is what a challenge does with the beacon it sends —
/// saw a synthesized pattern where the browser shows the picture.
pub fn remember_image(url: &str, bytes: &[u8]) -> Option<(u32, u32)> {
    let decoded = decode_rgba(bytes)?;
    let (w, h) = (decoded.0, decoded.1);
    IMAGES.with(|m| {
        let mut m = m.borrow_mut();
        // A page can load a great many pictures; keep the map from growing
        // without bound by dropping the oldest arrival when it gets large.
        if m.len() >= 256 {
            if let Some(k) = m.keys().next().cloned() {
                m.remove(&k);
            }
        }
        m.insert(url.to_string(), decoded);
    });
    Some((w, h))
}

/// PNG to RGBA. Everything else is left to the caller's fallback: the formats a
/// challenge uses for a data-bearing picture are lossless, and a lossy one
/// would not carry data anyway.
fn decode_rgba(bytes: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let decoder = png::Decoder::new(bytes);
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (info.width, info.height);
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
        return None;
    }
    let px = &buf[..info.buffer_size()];
    let rgba = match (info.color_type, info.bit_depth) {
        (png::ColorType::Rgba, png::BitDepth::Eight) => px.to_vec(),
        (png::ColorType::Rgb, png::BitDepth::Eight) => px
            .chunks_exact(3)
            .flat_map(|c| [c[0], c[1], c[2], 255])
            .collect(),
        (png::ColorType::Grayscale, png::BitDepth::Eight) => {
            px.iter().flat_map(|&g| [g, g, g, 255]).collect()
        }
        (png::ColorType::GrayscaleAlpha, png::BitDepth::Eight) => px
            .chunks_exact(2)
            .flat_map(|c| [c[0], c[0], c[0], c[1]])
            .collect(),
        _ => return None,
    };
    Some((w, h, rgba))
}

/// Draw a remembered image onto a canvas, scaled to `dw`x`dh` at `dx`,`dy`.
///
/// Nearest-neighbour and source-over, which is what a picture drawn at its own
/// size needs; a challenge reading the pixels back gets the picture it sent.
pub fn draw_image(id: u32, url: &str, dx: f32, dy: f32, dw: f32, dh: f32) -> bool {
    IMAGES.with(|m| {
        let m = m.borrow();
        let Some((sw, sh, src)) = m.get(url) else {
            return false;
        };
        let (sw, sh) = (*sw as i64, *sh as i64);
        let dw = if dw > 0.0 { dw.round() as i64 } else { sw };
        let dh = if dh > 0.0 { dh.round() as i64 } else { sh };
        if dw <= 0 || dh <= 0 {
            return false;
        }
        CANVASES.with(|c| {
            let mut c = c.borrow_mut();
            let Some(pm) = c.get_mut(&id) else {
                return false;
            };
            let (cw, ch) = (pm.width() as i64, pm.height() as i64);
            let dst = pm.pixels_mut();
            let (ox, oy) = (dx.round() as i64, dy.round() as i64);
            for ty in 0..dh {
                let py = oy + ty;
                if py < 0 || py >= ch {
                    continue;
                }
                let sy = (ty * sh / dh).clamp(0, sh - 1);
                for tx in 0..dw {
                    let px = ox + tx;
                    if px < 0 || px >= cw {
                        continue;
                    }
                    let sx = (tx * sw / dw).clamp(0, sw - 1);
                    let si = ((sy * sw + sx) * 4) as usize;
                    let (r, g, b, a) = (src[si], src[si + 1], src[si + 2], src[si + 3]);
                    let di = (py * cw + px) as usize;
                    dst[di] = tiny_skia::PremultipliedColorU8::from_rgba(
                        mul(r, a),
                        mul(g, a),
                        mul(b, a),
                        a,
                    )
                    .unwrap_or_else(|| tiny_skia::PremultipliedColorU8::from_rgba(0, 0, 0, 0).unwrap());
                }
            }
            true
        })
    })
}

/// `drawImage(sourceCanvas, …)` — один холст на другом. Браузер принимает
/// холстом всё, у чего есть пиксели: элемент, `OffscreenCanvas`, `ImageBitmap`,
/// — а у нас `drawImage` их отвергал, хотя собственный текст ошибки перечислял
/// их среди допустимых. Сборщик Cloudflare рисует так свой `OffscreenCanvas` и
/// получал исключение вместо картинки.
///
/// Вырезка задаётся в координатах источника: девятиаргументный `drawImage`
/// берёт из картинки прямоугольник, а не её целиком, и без него страница,
/// раскладывающая спрайт по клеткам, рисует одно и то же место.
#[allow(clippy::too_many_arguments)]
pub fn blit(
    dst_id: u32,
    src_id: u32,
    sx: f32,
    sy: f32,
    sw_in: f32,
    sh_in: f32,
    dx: f32,
    dy: f32,
    dw: f32,
    dh: f32,
) -> bool {
    if dst_id == src_id {
        return false;
    }
    // Пиксели источника снимаются заранее: две записи в одну карту сразу не
    // взять, а копия здесь короче, чем разделение хранилища.
    let src = CANVASES.with(|c| {
        c.borrow().get(&src_id).map(|pm| {
            (
                pm.width() as i64,
                pm.height() as i64,
                pm.data().to_vec(),
            )
        })
    });
    let Some((full_w, full_h, src)) = src else {
        return false;
    };
    if full_w <= 0 || full_h <= 0 {
        return false;
    }
    // Прямоугольник источника: по умолчанию — вся картинка.
    let (ox_s, oy_s) = (sx.round() as i64, sy.round() as i64);
    let sw = if sw_in > 0.0 { sw_in.round() as i64 } else { full_w };
    let sh = if sh_in > 0.0 { sh_in.round() as i64 } else { full_h };
    if sw <= 0 || sh <= 0 {
        return false;
    }
    let dw = if dw > 0.0 { dw.round() as i64 } else { sw };
    let dh = if dh > 0.0 { dh.round() as i64 } else { sh };
    if dw <= 0 || dh <= 0 {
        return false;
    }
    CANVASES.with(|c| {
        let mut c = c.borrow_mut();
        let Some(pm) = c.get_mut(&dst_id) else {
            return false;
        };
        let (cw, ch) = (pm.width() as i64, pm.height() as i64);
        let dst = pm.pixels_mut();
        let (ox, oy) = (dx.round() as i64, dy.round() as i64);
        for ty in 0..dh {
            let py = oy + ty;
            if py < 0 || py >= ch {
                continue;
            }
            let sy = oy_s + (ty * sh / dh).clamp(0, sh - 1);
            for tx in 0..dw {
                let px = ox + tx;
                if px < 0 || px >= cw {
                    continue;
                }
                let sx = ox_s + (tx * sw / dw).clamp(0, sw - 1);
                if sx < 0 || sx >= full_w || sy < 0 || sy >= full_h {
                    continue;
                }
                let si = ((sy * full_w + sx) * 4) as usize;
                // Источник уже помножен на альфу — как и приёмник, — поэтому
                // складываем по «source-over» прямо в этом виде.
                let (sr, sg, sb, sa) = (src[si], src[si + 1], src[si + 2], src[si + 3]);
                let di = (py * cw + px) as usize;
                let old = dst[di];
                let inv = 255 - sa as u16;
                let over = |s: u8, d: u8| -> u8 {
                    (s as u16 + (d as u16 * inv + 127) / 255).min(255) as u8
                };
                dst[di] = tiny_skia::PremultipliedColorU8::from_rgba(
                    over(sr, old.red()),
                    over(sg, old.green()),
                    over(sb, old.blue()),
                    over(sa, old.alpha()),
                )
                .unwrap_or(old);
            }
        }
        true
    })
}

/// Straight alpha to premultiplied, the form tiny-skia stores.
fn mul(c: u8, a: u8) -> u8 {
    ((u16::from(c) * u16::from(a) + 127) / 255) as u8
}

/// Drop a canvas surface (the JS wrapper was garbage-collected).
pub fn destroy(id: u32) {
    CANVASES.with(|c| {
        c.borrow_mut().remove(&id);
    });
}

/// `fillRect(x, y, w, h)` with a straight-alpha RGBA color.
pub fn fill_rect(id: u32, x: f32, y: f32, w: f32, h: f32, rgba: [u8; 4], sh: &[f32], mode: u32) {
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            if let Some(rect) = Rect::from_xywh(x, y, w, h) {
                paint_shadow(pm, sh, |sp, col| {
                    let mut p2 = Paint::default();
                    p2.set_color_rgba8(col[0], col[1], col[2], col[3]);
                    p2.anti_alias = true;
                    sp.fill_rect(rect, &p2, Transform::identity(), None);
                });
            }
            let mut paint = Paint::default();
            paint.set_color_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            paint.anti_alias = true;
            paint.blend_mode = blend_mode(mode);
            if let Some(rect) = Rect::from_xywh(x, y, w, h) {
                pm.fill_rect(rect, &paint, Transform::identity(), None);
            }
        }
    });
}

/// `clearRect(x, y, w, h)` — set the region back to transparent.
pub fn clear_rect(id: u32, x: f32, y: f32, w: f32, h: f32) {
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let mut paint = Paint::default();
            paint.set_color_rgba8(0, 0, 0, 0);
            paint.blend_mode = tiny_skia::BlendMode::Source; // overwrite, don't blend
            if let Some(rect) = Rect::from_xywh(x, y, w, h) {
                pm.fill_rect(rect, &paint, Transform::identity(), None);
            }
        }
    });
}

/// Build a [`tiny_skia::Path`] from a flat verb stream: `0,x,y` = moveTo,
/// `1,x,y` = lineTo, `4` = close. Curves and arcs are tessellated to line
/// segments on the JS side, so this stays a simple, robust decoder.
fn path_from_verbs(verbs: &[f32]) -> Option<tiny_skia::Path> {
    let mut pb = PathBuilder::new();
    let mut i = 0;
    while i < verbs.len() {
        match verbs[i].round() as i32 {
            0 if i + 2 < verbs.len() => {
                pb.move_to(verbs[i + 1], verbs[i + 2]);
                i += 3;
            }
            1 if i + 2 < verbs.len() => {
                pb.line_to(verbs[i + 1], verbs[i + 2]);
                i += 3;
            }
            4 => {
                pb.close();
                i += 1;
            }
            _ => break, // unknown/truncated verb — stop rather than misread
        }
    }
    pb.finish()
}

/// `fill()` a tessellated path with a straight-alpha RGBA color. `even_odd`
/// selects the fill rule (canvas `'evenodd'` vs default nonzero winding).
/// Тень холста. Браузер рисует её так: та же фигура, залитая цветом тени,
/// размытая по Гауссу и сдвинутая, — а поверх уже сама фигура. Без этого
/// отпечаток холста теряет почти всю краску: размытая тень покрывает весь
/// холст слабой альфой, и в отчёте это тысячи ненулевых байт.
///
/// Гаусс приближается тремя проходами коробчатого размытия — так делает и
/// Skia; сигма у Chrome равна половине `shadowBlur`.
fn gaussian_blur(data: &mut [u8], w: usize, h: usize, sigma: f32) {
    if sigma <= 0.0 || w == 0 || h == 0 {
        return;
    }
    // Настоящее ядро, а не три коробчатых прохода: приближение коробками
    // давало вдвое более широкую тень, чем у браузера, и хвост уходил не туда.
    let radius = ((sigma * 3.0).ceil() as usize).min(128);
    let mut kernel = Vec::with_capacity(radius * 2 + 1);
    let denom = 2.0 * sigma * sigma;
    let mut total = 0.0f32;
    for i in 0..=(radius * 2) {
        let x = i as f32 - radius as f32;
        let v = (-(x * x) / denom).exp();
        kernel.push(v);
        total += v;
    }
    for v in kernel.iter_mut() {
        *v /= total;
    }
    let at = |i: isize, lo: isize, hi: isize| i.clamp(lo, hi) as usize;
    // Промежуточный проход держим в вещественных числах: округление до байта
    // между проходами заметно расширяет хвост тени.
    let mut tmp = vec![0.0f32; data.len()];
    for y in 0..h {
        let row = y * w * 4;
        for x in 0..w {
            let mut acc = [0.0f32; 4];
            for (k, wgt) in kernel.iter().enumerate() {
                let sx = at(x as isize + k as isize - radius as isize, 0, w as isize - 1);
                let si = row + sx * 4;
                for ch in 0..4 {
                    acc[ch] += f32::from(data[si + ch]) * wgt;
                }
            }
            let di = row + x * 4;
            for ch in 0..4 {
                tmp[di + ch] = acc[ch];
            }
        }
    }
    for x in 0..w {
        for y in 0..h {
            let mut acc = [0.0f32; 4];
            for (k, wgt) in kernel.iter().enumerate() {
                let sy = at(y as isize + k as isize - radius as isize, 0, h as isize - 1);
                let si = (sy * w + x) * 4;
                for ch in 0..4 {
                    acc[ch] += tmp[si + ch] * wgt;
                }
            }
            let di = (y * w + x) * 4;
            for ch in 0..4 {
                data[di + ch] = acc[ch].round().clamp(0.0, 255.0) as u8;
            }
        }
    }
}

/// `[blur, dx, dy, r, g, b, a]` — пусто, когда тени нет.
fn shadow_of(sh: &[f32]) -> Option<(f32, f32, f32, [u8; 4])> {
    if sh.len() < 7 {
        return None;
    }
    let a = sh[6].round().clamp(0.0, 255.0) as u8;
    if a == 0 {
        return None;
    }
    let (blur, dx, dy) = (sh[0].max(0.0), sh[1], sh[2]);
    if blur <= 0.0 && dx == 0.0 && dy == 0.0 {
        return None;
    }
    Some((
        blur,
        dx,
        dy,
        [
            sh[3].round().clamp(0.0, 255.0) as u8,
            sh[4].round().clamp(0.0, 255.0) as u8,
            sh[5].round().clamp(0.0, 255.0) as u8,
            a,
        ],
    ))
}

/// Нарисовать тень фигуры: `draw` кладёт фигуру цветом тени на чистый холст
/// того же размера, дальше размытие и снос.
fn paint_shadow<F>(pm: &mut tiny_skia::Pixmap, sh: &[f32], draw: F)
where
    F: FnOnce(&mut tiny_skia::Pixmap, [u8; 4]),
{
    let Some((blur, dx, dy, color)) = shadow_of(sh) else {
        return;
    };
    let (w, h) = (pm.width(), pm.height());
    let Some(mut scratch) = tiny_skia::Pixmap::new(w, h) else {
        return;
    };
    draw(&mut scratch, color);
    if blur > 0.0 {
        // Сигма — половина заявленного размытия, как в спецификации холста.
        gaussian_blur(scratch.data_mut(), w as usize, h as usize, blur / 2.0);
    }
    let paint = tiny_skia::PixmapPaint::default();
    pm.draw_pixmap(
        dx.round() as i32,
        dy.round() as i32,
        scratch.as_ref(),
        &paint,
        Transform::identity(),
        None,
    );
}

/// `globalCompositeOperation` числом. Страница переключает наложение и рисует
/// пересекающиеся круги — по цвету в пересечении её и узнают; мы наложение
/// не читали вовсе, и поверх ложился просто последний круг.
fn blend_mode(i: u32) -> tiny_skia::BlendMode {
    use tiny_skia::BlendMode as B;
    match i {
        1 => B::SourceIn,
        2 => B::SourceOut,
        3 => B::SourceAtop,
        4 => B::DestinationOver,
        5 => B::DestinationIn,
        6 => B::DestinationOut,
        7 => B::DestinationAtop,
        8 => B::Plus,
        9 => B::Source,
        10 => B::Xor,
        11 => B::Multiply,
        12 => B::Screen,
        13 => B::Overlay,
        14 => B::Darken,
        15 => B::Lighten,
        16 => B::ColorDodge,
        17 => B::ColorBurn,
        18 => B::HardLight,
        19 => B::SoftLight,
        20 => B::Difference,
        21 => B::Exclusion,
        22 => B::Hue,
        23 => B::Saturation,
        24 => B::Color,
        25 => B::Luminosity,
        _ => B::SourceOver,
    }
}

pub fn fill_path(id: u32, verbs: &[f32], even_odd: bool, rgba: [u8; 4], sh: &[f32], mode: u32) {
    let Some(path) = path_from_verbs(verbs) else {
        return;
    };
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let rule0 = if even_odd { FillRule::EvenOdd } else { FillRule::Winding };
            paint_shadow(pm, sh, |sp, col| {
                let mut p2 = Paint::default();
                p2.set_color_rgba8(col[0], col[1], col[2], col[3]);
                p2.anti_alias = true;
                sp.fill_path(&path, &p2, rule0, Transform::identity(), None);
            });
            let mut paint = Paint::default();
            paint.set_color_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            paint.anti_alias = true;
            paint.blend_mode = blend_mode(mode);
            let rule = if even_odd {
                FillRule::EvenOdd
            } else {
                FillRule::Winding
            };
            pm.fill_path(&path, &paint, rule, Transform::identity(), None);
        }
    });
}

/// Decode a flat gradient descriptor into a tiny-skia [`Shader`]:
/// `[type, x0,y0, x1,y1, r0,r1, nstops, (pos,r,g,b,a)×nstops]` — `type` 0 linear,
/// 1 radial; colors are straight-alpha 0..255. Canvas's inner radius `r0` is
/// approximated away (mapped to the focal point), which is invisible for the
/// usual `r0 = 0` fingerprint gradients.
fn shader_from_grad(g: &[f32]) -> Option<Shader<'static>> {
    if g.len() < 8 {
        return None;
    }
    let ty = g[0].round() as i32;
    let (x0, y0, x1, y1, r1) = (g[1], g[2], g[3], g[4], g[6]);
    let n = g[7].max(0.0) as usize;
    let mut raw: Vec<(f32, Color)> = Vec::with_capacity(n);
    let mut idx = 8;
    for _ in 0..n {
        if idx + 5 > g.len() {
            break;
        }
        let pos = g[idx].clamp(0.0, 1.0);
        let color = Color::from_rgba8(
            g[idx + 1] as u8,
            g[idx + 2] as u8,
            g[idx + 3] as u8,
            g[idx + 4] as u8,
        );
        raw.push((pos, color));
        idx += 5;
    }
    if raw.is_empty() {
        return None;
    }
    if raw.len() == 1 {
        raw.push((1.0, raw[0].1)); // tiny-skia needs ≥2 stops; a lone stop → solid
    }
    let stops: Vec<GradientStop> = raw
        .into_iter()
        .map(|(p, c)| GradientStop::new(p, c))
        .collect();
    if ty == 1 {
        RadialGradient::new(
            Point::from_xy(x0, y0),
            Point::from_xy(x1, y1),
            r1.max(0.01),
            stops,
            SpreadMode::Pad,
            Transform::identity(),
        )
    } else {
        LinearGradient::new(
            Point::from_xy(x0, y0),
            Point::from_xy(x1, y1),
            stops,
            SpreadMode::Pad,
            Transform::identity(),
        )
    }
}

/// `fill()` a tessellated path with a linear/radial gradient (see
/// [`shader_from_grad`] for the descriptor layout).
pub fn fill_path_grad(id: u32, verbs: &[f32], even_odd: bool, grad: &[f32], sh: &[f32], mode: u32) {
    let Some(path) = path_from_verbs(verbs) else {
        return;
    };
    let Some(shader) = shader_from_grad(grad) else {
        return;
    };
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            // Тень у градиентной заливки — сплошная, цветом тени: браузер
            // размывает силуэт фигуры, а не её раскраску.
            let rule0 = if even_odd { FillRule::EvenOdd } else { FillRule::Winding };
            paint_shadow(pm, sh, |sp, col| {
                let mut p2 = Paint::default();
                p2.set_color_rgba8(col[0], col[1], col[2], col[3]);
                p2.anti_alias = true;
                sp.fill_path(&path, &p2, rule0, Transform::identity(), None);
            });
            let paint = Paint {
                shader,
                anti_alias: true,
                blend_mode: blend_mode(mode),
                ..Paint::default()
            };
            let rule = if even_odd {
                FillRule::EvenOdd
            } else {
                FillRule::Winding
            };
            pm.fill_path(&path, &paint, rule, Transform::identity(), None);
        }
    });
}

/// `stroke()` a tessellated path with `line_width` and a straight-alpha color.
pub fn stroke_path(id: u32, verbs: &[f32], line_width: f32, rgba: [u8; 4], sh: &[f32], mode: u32) {
    let Some(path) = path_from_verbs(verbs) else {
        return;
    };
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let stroke = Stroke {
                width: line_width.max(0.0),
                ..Stroke::default()
            };
            paint_shadow(pm, sh, |sp, col| {
                let mut p2 = Paint::default();
                p2.set_color_rgba8(col[0], col[1], col[2], col[3]);
                p2.anti_alias = true;
                sp.stroke_path(&path, &p2, &stroke, Transform::identity(), None);
            });
            let mut paint = Paint::default();
            paint.set_color_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            paint.anti_alias = true;
            paint.blend_mode = blend_mode(mode);
            pm.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
        }
    });
}

/// Composite a coverage-weighted straight-alpha color over one premultiplied pixel.
fn blend_over(data: &mut [u8], i: usize, rgba: [u8; 4], coverage: f32) {
    let sa = (rgba[3] as f32 / 255.0) * coverage.clamp(0.0, 1.0); // src alpha 0..1
    if sa <= 0.0 {
        return;
    }
    // src premultiplied; dst is already premultiplied (tiny-skia).
    let sr = rgba[0] as f32 / 255.0 * sa;
    let sg = rgba[1] as f32 / 255.0 * sa;
    let sb = rgba[2] as f32 / 255.0 * sa;
    let inv = 1.0 - sa;
    let out = |src: f32, dst: u8| {
        ((src + (dst as f32 / 255.0) * inv) * 255.0)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    data[i] = out(sr, data[i]);
    data[i + 1] = out(sg, data[i + 1]);
    data[i + 2] = out(sb, data[i + 2]);
    data[i + 3] = out(sa, data[i + 3]);
}

/// `fillText(text, x, y)` — rasterize real glyphs of the bundled font at `size_px`,
/// `y` being the alphabetic baseline (as canvas specifies), composited into the
/// surface. This is the fingerprint-critical op: real, deterministic text pixels
/// instead of a synthesized pattern.
pub fn fill_text(
    id: u32,
    text: &str,
    x: f32,
    y: f32,
    size_px: f32,
    rgba: [u8; 4],
    families: &str,
    bold: bool,
    italic: bool,
    sh: &[f32],
) {
    if size_px <= 0.0 || text.is_empty() {
        return;
    }
    let chain = resolve_chain(families, bold, italic);
    if chain.is_empty() {
        return;
    }
    let font = chain[0];
    CANVASES.with(|c| {
        let mut map = c.borrow_mut();
        let Some(pm) = map.get_mut(&id) else {
            return;
        };
        // Тень у надписи — те же глифы цветом тени, размытые и снесённые.
        // Челлендж рисует текст именно с тенью, и без неё пропадает не только
        // размытое пятно, но и почти всё покрытие холста.
        let glyphs = |target: &mut [u8], tw: i32, th: i32, colour: [u8; 4]| {
            let scale = px_scale(font, size_px);
            let scaled = font.as_scaled(scale);
            let mut caret = x;
            for ch in text.chars() {
                let cf = face_for(&chain, ch);
                let cscale = px_scale(cf, size_px);
                let gid = cf.glyph_id(ch);
                let glyph = gid.with_scale_and_position(cscale, ab_glyph::point(caret, y));
                if let Some(og) = cf.outline_glyph(glyph) {
                    let bb = og.px_bounds();
                    og.draw(|gx, gy, coverage| {
                        let px = bb.min.x as i32 + gx as i32;
                        let py = bb.min.y as i32 + gy as i32;
                        if px < 0 || py < 0 || px >= tw || py >= th {
                            return;
                        }
                        blend_over(target, ((py * tw + px) * 4) as usize, colour, coverage);
                    });
                }
                caret += cf.as_scaled(cscale).h_advance(gid);
            }
        };
        paint_shadow(pm, sh, |sp, col| {
            let (sw, shh) = (sp.width() as i32, sp.height() as i32);
            glyphs(sp.data_mut(), sw, shh, col);
        });
        let (pw, ph) = (pm.width() as i32, pm.height() as i32);
        let data = pm.data_mut();
        {
            glyphs(data, pw, ph, rgba);
        }
    });
}

/// `measureText(text).width` for the bundled font at `size_px`.
pub fn measure_text(
    text: &str,
    size_px: f32,
    families: &str,
    bold: bool,
    italic: bool,
) -> TextMetrics {
    if size_px <= 0.0 {
        return TextMetrics::default();
    }
    let chain = resolve_chain(families, bold, italic);
    if chain.is_empty() {
        return TextMetrics::default();
    }
    let font = chain[0];
    let scale = px_scale(font, size_px);
    let scaled = font.as_scaled(scale);
    let upem = font.units_per_em().unwrap_or(1000.0);
    // Границы чернил: браузер отдаёт их целыми по вертикали и дробными по
    // горизонтали — так же, как получаются из растеризованного контура.
    // По горизонтали браузер отдаёт границы чернил дробными, по вертикали —
    // целыми: первые берутся из контура, вторые из растра. Поэтому и здесь два
    // источника, а не один.
    let f = size_px / upem;
    let (mut ink_l, mut ink_r) = (f32::MAX, f32::MIN);
    let (mut ink_t, mut ink_b) = (f32::MAX, f32::MIN);
    let mut caret = 0.0f32;
    for ch in text.chars() {
        // Знак берётся из первого семейства цепочки, где он есть, — как в
        // браузере. Кегль при подмене считается по метрикам того шрифта.
        let cf = face_for(&chain, ch);
        let cscale = px_scale(cf, size_px);
        let cscaled = cf.as_scaled(cscale);
        let cupem = cf.units_per_em().unwrap_or(1000.0);
        let cf_ratio = size_px / cupem;
        let gid = cf.glyph_id(ch);
        if let Some(o) = cf.outline(gid) {
            ink_l = ink_l.min(caret + o.bounds.min.x * cf_ratio);
            ink_r = ink_r.max(caret + o.bounds.max.x * cf_ratio);
        }
        let glyph = gid.with_scale_and_position(cscale, ab_glyph::point(caret, 0.0));
        if let Some(og) = cf.outline_glyph(glyph) {
            let bb = og.px_bounds();
            ink_t = ink_t.min(bb.min.y);
            ink_b = ink_b.max(bb.max.y);
        }
        caret += cscaled.h_advance(gid);
    }
    let _ = f;
    let none = ink_l > ink_r;
    let flat = ink_t > ink_b;
    TextMetrics {
        width: caret,
        // Левую границу браузер отсекает к нулю, а не округляет: чернила,
        // начавшиеся на восемь десятых пикселя правее начала, дают 0, а на
        // полтора — −1. Проверено на двух гарнитурах.
        left: if none { 0.0 } else { (-ink_l).trunc() },
        right: if none { 0.0 } else { ink_r },
        ascent: if flat { 0.0 } else { -ink_t },
        descent: if flat { 0.0 } else { ink_b },
        font_ascent: (font.ascent_unscaled() / upem * size_px).round(),
        font_descent: (-font.descent_unscaled() / upem * size_px).round(),
        line: (font.ascent_unscaled() - font.descent_unscaled() + font.line_gap_unscaled())
            / upem
            * size_px,
    }
}

/// `putImageData(data, x, y)` — overwrite a `w`×`h` region with straight-alpha
/// RGBA (premultiplying into the surface). Replaces, does not blend, as the spec
/// requires. Pixels outside the surface are dropped.
pub fn put_image_data(id: u32, x: i32, y: i32, w: u32, h: u32, data: &[u8]) {
    CANVASES.with(|c| {
        let mut map = c.borrow_mut();
        let Some(pm) = map.get_mut(&id) else {
            return;
        };
        let (pw, ph) = (pm.width() as i32, pm.height() as i32);
        let out = pm.data_mut();
        for row in 0..h as i32 {
            for col in 0..w as i32 {
                let (dx, dy) = (x + col, y + row);
                if dx < 0 || dy < 0 || dx >= pw || dy >= ph {
                    continue;
                }
                let si = ((row * w as i32 + col) * 4) as usize;
                if si + 3 >= data.len() {
                    continue;
                }
                let a = data[si + 3] as u32;
                let prem = |v: u8| ((v as u32 * a + 127) / 255) as u8;
                let di = ((dy * pw + dx) * 4) as usize;
                out[di] = prem(data[si]);
                out[di + 1] = prem(data[si + 1]);
                out[di + 2] = prem(data[si + 2]);
                out[di + 3] = a as u8;
            }
        }
    });
}

/// Straight (un-premultiplied) RGBA for a `w`×`h` region at `(x, y)` — exactly what
/// canvas `getImageData` returns. Pixels outside the surface read as transparent.
pub fn get_image_data(id: u32, x: u32, y: u32, w: u32, h: u32) -> Vec<u8> {
    CANVASES.with(|c| {
        let map = c.borrow();
        let mut out = vec![0u8; (w as usize) * (h as usize) * 4];
        let Some(pm) = map.get(&id) else {
            return out;
        };
        let (pw, ph) = (pm.width(), pm.height());
        let data = pm.data(); // premultiplied RGBA8
        for row in 0..h {
            for col in 0..w {
                let (sx, sy) = (x + col, y + row);
                if sx >= pw || sy >= ph {
                    continue;
                }
                let si = ((sy * pw + sx) * 4) as usize;
                let di = ((row * w + col) * 4) as usize;
                let a = data[si + 3];
                // tiny-skia stores premultiplied alpha; getImageData is straight.
                let unmul = |v: u8| {
                    if a == 0 {
                        0
                    } else {
                        (((v as u32) * 255 + (a as u32) / 2) / a as u32).min(255) as u8
                    }
                };
                out[di] = unmul(data[si]);
                out[di + 1] = unmul(data[si + 1]);
                out[di + 2] = unmul(data[si + 2]);
                out[di + 3] = a;
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_then_read_is_exact() {
        create(1, 4, 4);
        fill_rect(1, 0.0, 0.0, 4.0, 4.0, [255, 0, 0, 255], &[], 0);
        let px = get_image_data(1, 0, 0, 1, 1);
        assert_eq!(px, vec![255, 0, 0, 255], "opaque red fill reads back red");
        clear_rect(1, 0.0, 0.0, 4.0, 4.0);
        assert_eq!(
            get_image_data(1, 0, 0, 1, 1),
            vec![0, 0, 0, 0],
            "cleared → transparent"
        );
        destroy(1);
    }

    #[test]
    fn fill_text_draws_real_glyph_pixels() {
        create(2, 40, 40);
        // Baseline near the bottom so a 24px 'H' lands inside the surface.
        fill_text(2, "H", 4.0, 30.0, 24.0, [0, 0, 0, 255], "sans-serif", false, false, &[]);
        let px = get_image_data(2, 0, 0, 40, 40);
        let opaque = px.chunks_exact(4).filter(|p| p[3] > 0).count();
        assert!(
            opaque > 20,
            "glyph 'H' must cover real pixels, got {opaque}"
        );
        destroy(2);
    }

    #[test]
    fn fill_path_triangle_covers_interior() {
        create(3, 20, 20);
        // A filled triangle: (2,2) (18,2) (10,18).
        let verbs = [0.0, 2.0, 2.0, 1.0, 18.0, 2.0, 1.0, 10.0, 18.0, 4.0];
        fill_path(3, &verbs, false, [0, 0, 255, 255], &[], 0);
        // Center of mass ~ (10, 7) is inside; a far corner is outside.
        let inside = get_image_data(3, 10, 7, 1, 1);
        let corner = get_image_data(3, 0, 19, 1, 1);
        assert!(
            inside[3] > 0 && inside[2] > 100,
            "interior filled blue, got {inside:?}"
        );
        assert_eq!(corner[3], 0, "outside the triangle stays transparent");
        destroy(3);
    }

    #[test]
    fn linear_gradient_fill_varies_across_the_rect() {
        create(4, 20, 4);
        // Linear red→blue across x=0..20, filling the whole surface via a rect path.
        let grad = [
            0.0, 0.0, 0.0, 20.0, 0.0, 0.0, 0.0, 2.0, // type,x0,y0,x1,y1,r0,r1,nstops
            0.0, 255.0, 0.0, 0.0, 255.0, // stop 0 @0.0 = red
            1.0, 0.0, 0.0, 255.0, 255.0, // stop 1 @1.0 = blue
        ];
        let verbs = [
            0.0, 0.0, 0.0, 1.0, 20.0, 0.0, 1.0, 20.0, 4.0, 1.0, 0.0, 4.0, 4.0,
        ];
        fill_path_grad(4, &verbs, false, &grad, &[], 0);
        let left = get_image_data(4, 1, 2, 1, 1);
        let right = get_image_data(4, 18, 2, 1, 1);
        assert!(
            left[0] > 150 && left[2] < 100,
            "left edge is red-ish, got {left:?}"
        );
        assert!(
            right[2] > 150 && right[0] < 100,
            "right edge is blue-ish, got {right:?}"
        );
        destroy(4);
    }

    #[test]
    fn measure_text_is_positive_and_scales() {
        let w1 = measure_text("nokk", 16.0, "sans-serif", false, false).width;
        let w2 = measure_text("nokk", 32.0, "sans-serif", false, false).width;
        assert!(w1 > 0.0, "non-empty text has width");
        assert!(
            w2 > w1 * 1.9,
            "2x font size ~doubles advance ({w1} vs {w2})"
        );
        assert_eq!(
            measure_text("", 16.0, "sans-serif", false, false).width,
            0.0,
            "empty text has zero width"
        );
    }

    /// Семейства меряются каждое своим файлом. Раньше шрифт был один на все
    /// имена, и страница, перебирающая гарнитуры измерением — самый ходовой
    /// способ снять отпечаток, — видела машину, где Arial, Times и Courier
    /// одной ширины. Числа сверены с Chrome 151 на этой машине.
    #[test]
    fn each_family_is_measured_with_its_own_file() {
        let w = |fam: &str| measure_text("mmmmmmmmmmlli", 16.0, fam, false, false).width;
        let (sans, serif, mono) = (w("Arial"), w("Times New Roman"), w("Courier New"));
        assert!(
            sans != serif && serif != mono && sans != mono,
            "three families measured the same: {sans} {serif} {mono}"
        );
        // Неизвестное имя браузер не находит и переходит к следующему.
        assert_eq!(w("NoSuchFontXYZ, Arial"), sans, "fell through to the next family");
        // Жирное начертание — другой файл, значит другая ширина.
        let bold = measure_text("mmmmmmmmmmlli", 16.0, "Times New Roman", true, false).width;
        assert!(bold > serif, "bold is not wider than regular: {bold} vs {serif}");
    }
}
