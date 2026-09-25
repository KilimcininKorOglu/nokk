//! Растр 2D-холста «как у Chrome 151»: путь строится по правилам Blink,
//! рёбра и покрытие — по Skia (аналитическое сглаживание), пиксели — по
//! lowp-конвейеру SkRasterPipeline. Поверхность — RGBA8888 premul.
//!
//! Вход — поток операций холста в координатах страницы (как их получил
//! JS, уже приведённых к float) и матрица холста; всё остальное —
//! здесь, в том же порядке и с той же арифметикой, что в браузере.

pub mod aaa;
pub mod blit;
pub mod blur;
pub mod edge;
pub mod fixed;
pub mod geometry;
pub mod gradient;
pub mod hair;
pub mod path;
pub mod pipeline;

use blit::{BlendMode, Blitter, SolidBlitter, SolidPaint, Surface};
use geometry::{nearly_equal, IRect, Matrix, Point, Rect};
use gradient::GradientDesc;
use path::{create_draw_arc_path, oval_path, CanvasPath, Drawable, FillType, Path, PathBuilder};
use pipeline::PipelineBlitter;

/// Коды операций потока пути (см. `fillOps` в JS холста).
pub const OP_MOVE: i32 = 0;
pub const OP_LINE: i32 = 1;
pub const OP_QUAD: i32 = 2;
pub const OP_CUBIC: i32 = 3;
pub const OP_CLOSE: i32 = 4;
pub const OP_ARC: i32 = 5;
pub const OP_ELLIPSE: i32 = 6;
pub const OP_RECT: i32 = 7;
/// `fillRect`: тот же прямоугольник, но маршрут `drawRect` (SkScan::AntiFillRect).
pub const OP_DRAW_RECT: i32 = 8;

/// Собрать `CanvasPath` из потока операций.
pub fn canvas_path_from_ops(ops: &[f32]) -> CanvasPath {
    let mut cp = CanvasPath::new();
    let mut i = 0usize;
    let n = ops.len();
    let take = |i: usize, k: usize| -> Option<&[f32]> { if i + k <= n { Some(&ops[i..i + k]) } else { None } };
    while i < n {
        let op = ops[i].round() as i32;
        i += 1;
        match op {
            OP_MOVE => {
                let Some(a) = take(i, 2) else { break };
                cp.move_to(a[0], a[1]);
                i += 2;
            }
            OP_LINE => {
                let Some(a) = take(i, 2) else { break };
                cp.line_to(a[0], a[1]);
                i += 2;
            }
            OP_QUAD => {
                let Some(a) = take(i, 4) else { break };
                cp.quadratic_curve_to(a[0], a[1], a[2], a[3]);
                i += 4;
            }
            OP_CUBIC => {
                let Some(a) = take(i, 6) else { break };
                cp.bezier_curve_to(a[0], a[1], a[2], a[3], a[4], a[5]);
                i += 6;
            }
            OP_CLOSE => cp.close_path(),
            OP_ARC => {
                let Some(a) = take(i, 6) else { break };
                cp.arc(a[0], a[1], a[2], a[3], a[4], a[5] != 0.0);
                i += 6;
            }
            OP_ELLIPSE => {
                let Some(a) = take(i, 8) else { break };
                cp.ellipse(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7] != 0.0);
                i += 8;
            }
            OP_RECT | OP_DRAW_RECT => {
                let Some(a) = take(i, 4) else { break };
                cp.rect(a[0], a[1], a[2], a[3]);
                i += 4;
            }
            _ => break,
        }
    }
    cp
}

/// Номер `globalCompositeOperation` из JS → `SkBlendMode` (таблица GCO).
pub fn blend_mode_from_index(i: u32) -> BlendMode {
    match i {
        1 => BlendMode::SrcIn,
        2 => BlendMode::SrcOut,
        3 => BlendMode::SrcATop,
        4 => BlendMode::DstOver,
        5 => BlendMode::DstIn,
        6 => BlendMode::DstOut,
        7 => BlendMode::DstATop,
        8 => BlendMode::Plus,
        9 => BlendMode::Src,
        10 => BlendMode::Xor,
        11 => BlendMode::Multiply,
        12 => BlendMode::Screen,
        13 => BlendMode::Overlay,
        14 => BlendMode::Darken,
        15 => BlendMode::Lighten,
        16 => BlendMode::ColorDodge,
        17 => BlendMode::ColorBurn,
        18 => BlendMode::HardLight,
        19 => BlendMode::SoftLight,
        20 => BlendMode::Difference,
        21 => BlendMode::Exclusion,
        22 => BlendMode::Hue,
        23 => BlendMode::Saturation,
        24 => BlendMode::Color,
        25 => BlendMode::Luminosity,
        _ => BlendMode::SrcOver,
    }
}

/// Краска холста: однотонная или градиент.
#[derive(Clone, Debug)]
pub enum PaintKind {
    Solid([u8; 4]),
    Gradient(GradientDesc),
}

/// Тень: размытие (радиус, сигма = половина), снос в координатах холста, цвет.
#[derive(Clone, Copy, Debug)]
pub struct Shadow {
    pub blur: f32,
    pub dx: f32,
    pub dy: f32,
    pub color: [u8; 4],
}

impl Shadow {
    /// Из описания JS `[размытие, сносX, сносY, r, g, b, a]`.
    pub fn parse(sh: &[f32]) -> Option<Shadow> {
        if sh.len() < 7 {
            return None;
        }
        let color = [sh[3] as u8, sh[4] as u8, sh[5] as u8, sh[6] as u8];
        if color[3] == 0 {
            return None;
        }
        let blur = sh[0].max(0.0);
        if blur <= 0.0 && sh[1] == 0.0 && sh[2] == 0.0 {
            return None;
        }
        Some(Shadow { blur, dx: sh[1], dy: sh[2], color })
    }
}

/// Слой рисования (DrawLooper): для тени — маска-фильтр размытия, цветовой
/// фильтр «цвет тени IN краска» и снос; для содержимого — как есть.
struct Layer {
    ctm: Matrix,
    sigma: Option<f64>,
    filter: Option<[u8; 4]>,
}

/// Что рисуем: заливку или волосяной штрих с покрытием.
#[derive(Clone, Copy)]
enum Style {
    Fill,
    /// `drawRect`: прямоугольник в координатах пользователя; под матрицей,
    /// сохраняющей прямоугольники, идёт через AntiFillRect, иначе как путь.
    Rect(Rect),
    Hairline { coverage: f32 },
}

/// `SkColorFilter::filterColor4f` для srcin: цвет тени через альфу краски,
/// как это делает `SkPaintPriv::RemoveColorFilter` для однотонной краски.
fn shadow_solid_color(paint: [u8; 4], shadow: [u8; 4]) -> [u8; 4] {
    let f = |v: u8| v as f32 * (1.0 / 255.0);
    let pa = f(paint[3]);
    let sa = f(shadow[3]);
    let spm = [f(shadow[0]) * sa, f(shadow[1]) * sa, f(shadow[2]) * sa, sa];
    // srcin: s · da
    let out = [spm[0] * pa, spm[1] * pa, spm[2] * pa, spm[3] * pa];
    // unpremul
    let inv = 1.0 / out[3];
    let inv = if inv.is_finite() { inv } else { 0.0 };
    let un = [out[0] * inv, out[1] * inv, out[2] * inv, out[3]];
    // toSkColor: pin(v·255 + 0.5, 0, 255) с отбрасыванием дроби.
    let b = |v: f32| (v * 255.0 + 0.5).clamp(0.0, 255.0) as u8;
    [b(un[0]), b(un[1]), b(un[2]), b(un[3])]
}

/// `DrawTreatAsHairline` + `modifyPaintForHairlines`: покрытие тонкого штриха.
fn hairline_coverage(line_width: f32, ctm: &Matrix) -> Option<f32> {
    if line_width == 0.0 {
        return Some(1.0);
    }
    let fast_len = |v: Point| -> f32 {
        let (mut x, mut y) = (v.x.abs(), v.y.abs());
        if x < y {
            std::mem::swap(&mut x, &mut y);
        }
        x + y / 2.0
    };
    let len0 = fast_len(ctm.map_vector(Point::new(line_width, 0.0)));
    let len1 = fast_len(ctm.map_vector(Point::new(0.0, line_width)));
    if len0 <= 1.0 && len1 <= 1.0 {
        Some((0.5 * (len0 as f64 + len1 as f64)) as f32)
    } else {
        None
    }
}

/// Один слой: краска → блиттер → (маска + размытие |) растр.
#[allow(clippy::too_many_arguments)]
fn draw_layer(data: &mut [u8], w: u32, h: u32, dev: &Path, style: Style, paint: &PaintKind, alpha: u8, mode: BlendMode, layer: &Layer) -> bool {
    let clip = IRect::from_ltrb(0, 0, w as i32, h as i32);
    let alpha_f = alpha as f32 * (1.0 / 255.0);
    // Блиттер под краску.
    let mut solid: Option<SolidBlitter> = None;
    let mut pipe: Option<PipelineBlitter> = None;
    match paint {
        PaintKind::Solid(rgba) => {
            let mut color = [rgba[0], rgba[1], rgba[2], alpha];
            if let Some(f) = layer.filter {
                color = shadow_solid_color(color, f);
            }
            let surf = Surface { data, width: w as i32, height: h as i32 };
            solid = Some(SolidBlitter::new(surf, &SolidPaint { rgba: color, mode }));
        }
        PaintKind::Gradient(desc) => {
            let Some(shader) = gradient::make_shader(desc) else { return true };
            let filter = layer.filter.map(|c| [c[0] as f32 / 255.0, c[1] as f32 / 255.0, c[2] as f32 / 255.0, c[3] as f32 / 255.0]);
            let Some(stages) = gradient::color_stages(&shader, &layer.ctm, alpha_f, filter, true) else { return true };
            let is_opaque = shader.is_opaque && alpha == 255 && filter.is_none();
            pipe = Some(PipelineBlitter::new(data, w as i32, h as i32, stages, mode, is_opaque));
        }
    }
    let blitter: &mut dyn Blitter = match (&mut solid, &mut pipe) {
        (Some(b), _) => b,
        (_, Some(b)) => b,
        _ => return true,
    };
    if let Some(sigma) = layer.sigma {
        if !blur::has_no_blur(sigma) {
            let Some(bounds) = blur::compute_mask_bounds(&dev.bounds(), &clip, sigma) else { return true };
            let mw = bounds.width();
            let mh = bounds.height();
            if mw <= 0 || mh <= 0 {
                return true;
            }
            let mut image = vec![0u8; (mw * mh) as usize];
            {
                // draw_into_mask: путь со сдвигом в маску, окно — сама маска.
                // Как SkPathData::MakeTransform + Raw(kYes): выпуклость считается
                // заново по сдвинутым точкам (transform её сбрасывает).
                let mut shifted = dev.transform(&Matrix::translate(-bounds.left as f32, -bounds.top as f32));
                shifted.resolve_convexity();
                let mut a8 = blur::A8Blitter::new(&mut image, mw, mh);
                let mclip = IRect::from_ltrb(0, 0, mw, mh);
                match style {
                    // С маской-фильтром drawRect тоже идёт как путь (kPath_RectType).
                    Style::Fill | Style::Rect(_) => aaa::anti_fill_path(&shifted, &mclip, &mut a8),
                    Style::Hairline { .. } => hair::anti_hair_path(&shifted, &mclip, &mut a8),
                }
            }
            let src = blur::Mask { bounds, row_bytes: mw as usize, image };
            let (dst, _) = blur::mask_blur(sigma, &src);
            if let Some(cr) = dst.bounds.intersect(&clip) {
                blitter.blit_mask(&dst.image, &dst.bounds, dst.row_bytes, &cr);
            }
            return true;
        }
    }
    match style {
        Style::Fill => aaa::anti_fill_path(dev, &clip, blitter),
        Style::Rect(r) => {
            if layer.ctm.rect_stays_rect() {
                // SkDraw::drawRect: две угловые точки через матрицу, sort.
                let mut pts = [Point::new(r.left, r.top), Point::new(r.right, r.bottom)];
                layer.ctm.map_points(&mut pts);
                let dev_r = Rect::from_ltrb(pts[0].x, pts[0].y, pts[1].x, pts[1].y).sorted();
                if dev_r.is_finite() {
                    hair::anti_fill_rect(&dev_r, &clip, blitter);
                }
            } else {
                aaa::anti_fill_path(dev, &clip, blitter);
            }
        }
        Style::Hairline { .. } => hair::anti_hair_path(dev, &clip, blitter),
    }
    true
}

/// Рисование пути краской с тенью: слои как у `cc::DrawLooper`.
#[allow(clippy::too_many_arguments)]
fn draw_with_layers(data: &mut [u8], w: u32, h: u32, path: &Path, ctm: &Matrix, line_width: Option<f32>, rect: Option<Rect>, paint: &PaintKind, shadow: Option<Shadow>, mode: BlendMode) -> bool {
    if !path.is_finite() {
        return true;
    }
    // Волосяной штрих: покрытие переходит в альфу краски.
    let mut alpha: u8 = 255;
    let style = match line_width {
        None => match rect {
            Some(r) => Style::Rect(r),
            None => Style::Fill,
        },
        Some(lw) => {
            let Some(coverage) = hairline_coverage(lw, ctm) else { return false };
            if coverage != 1.0 {
                if !mode.should_pre_scale_coverage() {
                    return false;
                }
                let scale = (coverage * 256.0) as i32;
                alpha = ((255 * scale) >> 8) as u8;
            }
            Style::Hairline { coverage }
        }
    };
    let mut layers: Vec<Layer> = Vec::new();
    if let Some(sh) = shadow {
        let mut m = *ctm;
        m.post_translate(sh.dx, sh.dy);
        let sigma = (sh.blur * 0.5) as f64;
        layers.push(Layer { ctm: m, sigma: Some(sigma), filter: Some(sh.color) });
    }
    layers.push(Layer { ctm: *ctm, sigma: None, filter: None });
    let clip = IRect::from_ltrb(0, 0, w as i32, h as i32);
    for layer in &layers {
        // internalQuickReject по границам пути в device space.
        let dev_bounds = layer.ctm.map_rect(&path.bounds());
        if !dev_bounds.is_finite() {
            continue;
        }
        let mut dev = path.transform(&layer.ctm);
        dev.resolve_convexity();
        if dev_bounds.intersect(&clip.to_rect()).is_none() && !rect_touches(&dev_bounds, &clip) && layer.sigma.is_none() {
            continue;
        }
        if !draw_layer(data, w, h, &dev, style, paint, alpha, mode, layer) {
            return false;
        }
    }
    true
}

/// Путь для заливки/обводки из операций холста (Blink `DrawPathInternal`).
fn path_for_ops(ops: &[f32], even_odd: bool, is_fill: bool) -> Option<Path> {
    let cp = canvas_path_from_ops(ops);
    let fill_type = if even_odd { FillType::EvenOdd } else { FillType::Winding };
    match cp.drawable() {
        Drawable::Empty => None,
        Drawable::Line(a, b) => {
            if is_fill {
                None
            } else {
                let mut bld = PathBuilder::new();
                bld.move_to(a);
                bld.line_to(b);
                Some(bld.detach())
            }
        }
        Drawable::Arc { oval, start_deg, sweep_deg, closed } => {
            if oval.is_empty() || sweep_deg == 0.0 {
                return None;
            }
            let oval = oval.sorted();
            if !closed {
                Some(create_draw_arc_path(&oval, start_deg, sweep_deg, is_fill))
            } else if nearly_equal(sweep_deg.abs(), 360.0) {
                Some(oval_path(&oval))
            } else {
                let mut b = PathBuilder::new();
                b.arc_to(&oval, start_deg, sweep_deg, false);
                b.close();
                Some(b.detach())
            }
        }
        Drawable::Path(mut p) => {
            p.fill_type = fill_type;
            Some(p)
        }
    }
}

fn ctm_of(ctm: [f32; 6]) -> Matrix {
    Matrix { sx: ctm[0], ky: ctm[1], kx: ctm[2], sy: ctm[3], tx: ctm[4], ty: ctm[5] }
}

/// `fill()` холста: поток операций, матрица холста, правило заливки,
/// краска, тень и режим наложения — в поверхность `data` (w×h RGBA premul).
#[allow(clippy::too_many_arguments)]
pub fn fill_ops_paint(data: &mut [u8], w: u32, h: u32, ops: &[f32], ctm: [f32; 6], even_odd: bool, paint: &PaintKind, shadow: Option<Shadow>, mode: u32) {
    // fillRect: один прямоугольник маршрутом drawRect.
    let mut rect = None;
    if ops.len() == 5 && ops[0] == OP_DRAW_RECT as f32 {
        let r = Rect::from_ltrb(ops[1], ops[2], ops[1] + ops[3], ops[2] + ops[4]);
        if !r.is_finite() || ops[3] <= 0.0 || ops[4] <= 0.0 {
            return;
        }
        rect = Some(r);
    }
    let Some(path) = path_for_ops(ops, even_odd, true) else { return };
    draw_with_layers(data, w, h, &path, &ctm_of(ctm), None, rect, paint, shadow, blend_mode_from_index(mode));
}

/// Однотонная заливка (совместимый вход).
pub fn fill_ops(data: &mut [u8], w: u32, h: u32, ops: &[f32], ctm: [f32; 6], even_odd: bool, rgba: [u8; 4], mode: u32) {
    fill_ops_paint(data, w, h, ops, ctm, even_odd, &PaintKind::Solid(rgba), None, mode);
}

/// `stroke()` холста. Возвращает false, если штрих не волосяной (толще
/// пикселя устройства) — тогда рисует прежний растр.
#[allow(clippy::too_many_arguments)]
pub fn stroke_ops(data: &mut [u8], w: u32, h: u32, ops: &[f32], ctm: [f32; 6], line_width: f32, paint: &PaintKind, shadow: Option<Shadow>, mode: u32) -> bool {
    let Some(path) = path_for_ops(ops, false, false) else { return true };
    draw_with_layers(data, w, h, &path, &ctm_of(ctm), Some(line_width), None, paint, shadow, blend_mode_from_index(mode))
}

fn rect_touches(r: &Rect, c: &IRect) -> bool {
    // Пустой в float прямоугольник (нулевая ширина) всё же может лежать в окне.
    r.right >= c.left as f32 && r.left <= c.right as f32 && r.bottom >= c.top as f32 && r.top <= c.bottom as f32
}

/// `getImageData`: premul → straight, как `readPixels(kUnpremul)`.
pub fn read_unpremul(data: &[u8], out: &mut [u8]) {
    blit::read_unpremul(data, out)
}

#[allow(dead_code)]
fn _unused(_b: &dyn Blitter) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn circle_ops() -> Vec<f32> {
        // Программа блока 49×44 челленджа (см. .nokk-notes/chl_canvas_ops_2026-09-25.txt).
        vec![]
    }

    #[test]
    fn arc_path_is_oval_conics() {
        let mut cp = CanvasPath::new();
        cp.arc(40.0, 40.0, 40.0, 0.0, std::f32::consts::PI * 2.0, true);
        cp.close_path();
        match cp.drawable() {
            Drawable::Arc { closed, sweep_deg, .. } => {
                assert!(closed);
                assert!((sweep_deg.abs() - 360.0).abs() < 1e-3);
            }
            _ => panic!("single arc must stay an arc"),
        }
        let _ = circle_ops();
    }

    #[test]
    fn dump_cases() {
        // NOKK_SKIA_CASES=out.json: рисует набор фигур 48×48 и пишет base64 буферов
        // (сверка с Chrome: scratchpad/cmp_cases.py).
        let Some(out) = std::env::var_os("NOKK_SKIA_CASES") else { return };
        let (w, h) = (48u32, 48u32);
        let m = OP_MOVE as f32; let l = OP_LINE as f32; let c = OP_CLOSE as f32; let q = OP_QUAD as f32;
        let cases: Vec<(&str, Vec<f32>)> = vec![
            ("A", vec![m, 9.0, 14.0, l, 93.0, 48.0, l, 46.5, 48.0, c]),
            ("F", vec![m, -9.0, 14.0, l, 40.0, 30.0, l, 9.0, 40.0, c]),
            ("K", vec![m, 9.0, 14.0, l, 9.0, 40.0, l, 116.0, 111.0, c]),
            ("T8", vec![m, 9.0, 14.0, q, 93.0, 48.0, 116.0, 111.0]),
        ];
        let mut js = String::from("{");
        for (i, (name, ops)) in cases.iter().enumerate() {
            let mut data = vec![0u8; (w * h * 4) as usize];
            fill_ops(&mut data, w, h, ops, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0], false, [128, 153, 0, 255], 0);
            let mut o = vec![0u8; data.len()];
            read_unpremul(&data, &mut o);
            let b64 = { const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; let mut s = String::new();
                for ch in o.chunks(3) { let n = ((ch[0] as u32) << 16) | ((*ch.get(1).unwrap_or(&0) as u32) << 8) | (*ch.get(2).unwrap_or(&0) as u32);
                    for k in 0..4 { if k <= ch.len() { s.push(T[((n >> (18 - 6 * k)) & 63) as usize] as char) } else { s.push('=') } } } s };
            if i > 0 { js.push(','); }
            js.push_str(&format!("\"{}\":\"{}\"", name, b64));
        }
        js.push('}');
        std::fs::write(out, js).unwrap();
    }

    #[test]
    fn partial_row_of_draw_rect_is_not_snapped() {
        // fillRect идёт маршрутом drawRect (AntiFillRect): нижняя строка 38..38.4
        // даёт покрытие 0.4 → 102, а не 0.5 → 128, как дал бы путь со снапом.
        let (w, h) = (48u32, 48u32);
        let ops = [OP_DRAW_RECT as f32, 0.0, 0.0, 100.0, 100.0];
        let mut data = vec![0u8; (w * h * 4) as usize];
        fill_ops(&mut data, w, h, &ops, [0.384, 0.0, 0.0, 0.384, 0.0, 0.0], false, [128, 153, 0, 255], 0);
        assert_eq!(data[((38 * w) * 4 + 3) as usize], 102);
        let ops = [OP_RECT as f32, 0.0, 0.0, 100.0, 100.0];
        let mut data = vec![0u8; (w * h * 4) as usize];
        fill_ops(&mut data, w, h, &ops, [0.384, 0.0, 0.0, 0.384, 0.0, 0.0], false, [128, 153, 0, 255], 0);
        assert_eq!(data[((38 * w) * 4 + 3) as usize], 128);
    }

    #[test]
    fn fills_a_scaled_circle() {
        let (w, h) = (49u32, 44u32);
        let mut data = vec![0u8; (w * h * 4) as usize];
        let ops = [
            OP_ARC as f32, 40.0, 40.0, 40.0, 0.0, std::f32::consts::PI * 2.0, 1.0, OP_CLOSE as f32,
        ];
        fill_ops(&mut data, w, h, &ops, [0.4, 0.0, 0.0, 0.4, 0.0, 0.0], false, [255, 34, 255, 255], 0);
        let px = |x: u32, y: u32| {
            let i = ((y * w + x) * 4) as usize;
            [data[i], data[i + 1], data[i + 2], data[i + 3]]
        };
        assert_eq!(px(16, 16), [255, 34, 255, 255], "centre is solid");
        assert_eq!(px(40, 40), [0, 0, 0, 0], "far corner is empty");
        assert!(px(16, 0)[3] > 0 && px(16, 0)[3] < 255, "top edge is anti-aliased: {:?}", px(16, 0));
    }
}

#[cfg(test)]
mod dump_tests {
    use super::geometry::{Conic, Matrix, Rect};
    use super::path::{oval_path, Verb};

    #[test]
    fn dump_oval_quads() {
        // Овал круга (80,40) r40 при масштабе 0.4 → device (16,0)-(48,32).
        let p = oval_path(&Rect::from_ltrb(40.0, 0.0, 120.0, 80.0));
        let d = p.transform(&Matrix::scale(0.4, 0.4));
        let mut pi = 0usize;
        let mut ci = 0usize;
        for v in &d.verbs {
            match v {
                Verb::Move => {
                    println!("M {:?}", d.pts[pi]);
                    pi += 1;
                }
                Verb::Conic => {
                    let c = Conic::new(d.pts[pi - 1], d.pts[pi], d.pts[pi + 1], d.conics[ci]);
                    let (q, n) = c.to_quads(0.25);
                    println!("C w={} {:?} -> {} quads", c.w, c.pts, n);
                    for i in 0..n {
                        println!("  Q {:?} {:?} {:?}", q[i * 2], q[i * 2 + 1], q[i * 2 + 2]);
                    }
                    pi += 2;
                    ci += 1;
                }
                other => println!("{:?}", other),
            }
        }
    }
}

#[cfg(test)]
mod convexity_tests {
    use super::geometry::{Matrix, Point, Rect};
    use super::path::{oval_path, PathBuilder};

    #[test]
    fn dump_convexity() {
        let p = oval_path(&Rect::from_ltrb(40.0, 0.0, 120.0, 80.0));
        let mut d = p.transform(&Matrix::scale(0.4, 0.4));
        d.resolve_convexity();
        println!("oval: {:?}", d.convexity);
        let mut b = PathBuilder::new();
        b.move_to(Point::new(48.0, 16.0));
        let q = [
            (48.0, 22.627415, 43.313705, 27.313705),
            (38.627415, 31.999998, 32.0, 32.0),
            (25.372581, 31.999998, 20.68629, 27.313705),
            (15.999999, 22.627415, 16.0, 16.0),
            (15.999999, 9.372582, 20.68629, 4.686291),
            (25.372581, 0.0, 32.0, 0.0),
            (38.627415, 0.0, 43.313705, 4.686291),
            (48.0, 9.372582, 48.0, 16.0),
        ];
        for (a, bb, c, dd) in q {
            b.quad_to(Point::new(a, bb), Point::new(c, dd));
        }
        b.close();
        let mut p2 = b.detach();
        p2.resolve_convexity();
        println!("quads: {:?}", p2.convexity);
    }
}

#[cfg(test)]
mod dump_quarter {
    use super::geometry::{Conic, Rect};
    use super::path::{PathBuilder, Verb};

    #[test]
    fn dump_quarter_arc() {
        let mut b = PathBuilder::new();
        b.arc_to(&Rect::from_ltrb(12.0, 10.0, 36.0, 34.0), 0.0, 90.0, false);
        b.close();
        let mut d = b.detach();
        d.resolve_convexity();
        println!("quarter convexity {:?}", d.convexity);
        let mut pi = 0usize;
        let mut ci = 0usize;
        for v in &d.verbs {
            match v {
                Verb::Move => { println!("M {:?}", d.pts[pi]); pi += 1; }
                Verb::Line => { println!("L {:?}", d.pts[pi]); pi += 1; }
                Verb::Conic => {
                    let c = Conic::new(d.pts[pi - 1], d.pts[pi], d.pts[pi + 1], d.conics[ci]);
                    let (q, n) = c.to_quads(0.25);
                    println!("C w={:?} {:?} -> {} quads", c.w, c.pts, n);
                    for i in 0..n { println!("  Q {:?} {:?} {:?}", q[i * 2], q[i * 2 + 1], q[i * 2 + 2]); }
                    pi += 2; ci += 1;
                }
                other => println!("{:?}", other),
            }
        }
    }
}

#[cfg(test)]
mod dump_quarter_conv {
    use super::geometry::Point;
    use super::path::PathBuilder;

    #[test]
    fn dump_quarter_quads_convexity() {
        for (name, verbs) in [
            ("S9q", vec![(0, 36.0, 22.0, 0.0, 0.0), (2, 36.0, 26.970562, 32.48528, 30.48528), (2, 28.970562, 34.0, 24.0, 34.0)]),
            ("S9a", vec![(0, 36.0, 22.0, 0.0, 0.0), (2, 36.0, 26.970562, 32.48528, 30.48528), (1, 24.0, 34.0, 0.0, 0.0)]),
            ("S9b", vec![(0, 32.48528, 30.48528, 0.0, 0.0), (2, 28.970562, 34.0, 24.0, 34.0), (1, 36.0, 22.0, 0.0, 0.0)]),
        ] {
            let mut b = PathBuilder::new();
            for (k, a, bb, c, d) in verbs {
                match k {
                    0 => b.move_to(Point::new(a, bb)),
                    1 => b.line_to(Point::new(a, bb)),
                    _ => b.quad_to(Point::new(a, bb), Point::new(c, d)),
                }
            }
            b.close();
            let mut p = b.detach();
            p.resolve_convexity();
            println!("{name} {:?}", p.convexity);
        }
    }
}

#[cfg(test)]
mod dump_pie_conv {
    use super::geometry::{Point, Rect};
    use super::path::PathBuilder;

    #[test]
    fn dump_pie_convexity() {
        let mut b = PathBuilder::new();
        b.arc_to(&Rect::from_ltrb(12.0, 10.0, 36.0, 34.0), 0.0, 90.0, false);
        b.line_to(Point::new(24.0, 22.0));
        b.close();
        let mut p = b.detach();
        p.resolve_convexity();
        println!("P {:?}", p.convexity);
        let mut b = PathBuilder::new();
        b.move_to(Point::new(36.0, 22.0));
        b.quad_to(Point::new(36.0, 26.970562), Point::new(32.48528, 30.48528));
        b.quad_to(Point::new(28.970562, 34.0), Point::new(24.0, 34.0));
        b.line_to(Point::new(24.0, 22.0));
        b.close();
        let mut p = b.detach();
        p.resolve_convexity();
        println!("Pq {:?}", p.convexity);
    }
}

#[cfg(test)]
mod dump_t2q_conv {
    use super::geometry::Point;
    use super::path::PathBuilder;

    #[test]
    fn dump_t2q_convexity() {
        let shapes: Vec<(&str, Vec<(u8, f32, f32, f32, f32)>)> = vec![
            ("T1", vec![(0, 10.0, 4.0, 0.0, 0.0), (2, 30.0, 4.0, 36.0, 16.0), (2, 40.0, 28.0, 30.0, 40.0), (1, 10.0, 40.0, 0.0, 0.0)]),
            ("T2", vec![(0, 10.0, 4.0, 0.0, 0.0), (2, 30.0, 4.0, 36.0, 16.0), (1, 30.0, 40.0, 0.0, 0.0), (1, 10.0, 40.0, 0.0, 0.0)]),
            ("T3", vec![(0, 38.0, 4.0, 0.0, 0.0), (2, 18.0, 4.0, 12.0, 16.0), (2, 8.0, 28.0, 18.0, 40.0), (1, 38.0, 40.0, 0.0, 0.0)]),
            ("T4", vec![(0, 10.0, 4.0, 0.0, 0.0), (2, 30.0, 4.0, 36.0, 16.3), (2, 40.0, 28.0, 30.0, 40.0), (1, 10.0, 40.0, 0.0, 0.0)]),
            ("T5", vec![(0, 10.0, 4.0, 0.0, 0.0), (2, 30.0, 4.0, 36.2, 16.7), (2, 40.1, 28.4, 30.0, 40.0), (1, 10.0, 40.0, 0.0, 0.0)]),
        ];
        for (name, verbs) in shapes {
            let mut b = PathBuilder::new();
            for (k, a, bb, c, d) in verbs {
                match k {
                    0 => b.move_to(Point::new(a, bb)),
                    1 => b.line_to(Point::new(a, bb)),
                    _ => b.quad_to(Point::new(a, bb), Point::new(c, d)),
                }
            }
            b.close();
            let mut p = b.detach();
            p.resolve_convexity();
            println!("{name} {:?}", p.convexity);
        }
    }
}
