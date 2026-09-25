//! Растр 2D-холста «как у Chrome 151»: путь строится по правилам Blink,
//! рёбра и покрытие — по Skia (аналитическое сглаживание), пиксели — по
//! lowp-конвейеру SkRasterPipeline. Поверхность — RGBA8888 premul.
//!
//! Вход — поток операций холста в координатах страницы (как их получил
//! JS, уже приведённых к float) и матрица холста; всё остальное —
//! здесь, в том же порядке и с той же арифметикой, что в браузере.

pub mod aaa;
pub mod blit;
pub mod edge;
pub mod fixed;
pub mod geometry;
pub mod path;

use blit::{BlendMode, Blitter, SolidBlitter, SolidPaint, Surface};
use geometry::{nearly_equal, IRect, Matrix, Rect};
use path::{create_draw_arc_path, oval_path, CanvasPath, Drawable, FillType, Path, PathBuilder};

/// Коды операций потока пути (см. `fillOps` в JS холста).
pub const OP_MOVE: i32 = 0;
pub const OP_LINE: i32 = 1;
pub const OP_QUAD: i32 = 2;
pub const OP_CUBIC: i32 = 3;
pub const OP_CLOSE: i32 = 4;
pub const OP_ARC: i32 = 5;
pub const OP_ELLIPSE: i32 = 6;
pub const OP_RECT: i32 = 7;

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
            OP_RECT => {
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

/// `fill()` холста: поток операций, матрица холста, правило заливки,
/// цвет и режим наложения — в поверхность `data` (w×h RGBA premul).
pub fn fill_ops(data: &mut [u8], w: u32, h: u32, ops: &[f32], ctm: [f32; 6], even_odd: bool, rgba: [u8; 4], mode: u32) {
    let cp = canvas_path_from_ops(ops);
    let fill_type = if even_odd { FillType::EvenOdd } else { FillType::Winding };
    let paint = SolidPaint { rgba, mode: blend_mode_from_index(mode) };
    let m = Matrix { sx: ctm[0], ky: ctm[1], kx: ctm[2], sy: ctm[3], tx: ctm[4], ty: ctm[5] };
    let path = match cp.drawable() {
        Drawable::Empty | Drawable::Line(..) => return,
        Drawable::Arc { oval, start_deg, sweep_deg, closed } => {
            if oval.is_empty() || sweep_deg == 0.0 {
                return;
            }
            let oval = oval.sorted();
            if !closed {
                create_draw_arc_path(&oval, start_deg, sweep_deg, true)
            } else if nearly_equal(sweep_deg.abs(), 360.0) {
                oval_path(&oval)
            } else {
                let mut b = PathBuilder::new();
                b.arc_to(&oval, start_deg, sweep_deg, false);
                b.close();
                b.detach()
            }
        }
        Drawable::Path(mut p) => {
            p.fill_type = fill_type;
            p
        }
    };
    draw_path(data, w, h, &path, &m, &paint);
}

/// `SkCanvas::drawPath` → `skcpu::Draw::drawPath` → `AntiFillPath`.
pub fn draw_path(data: &mut [u8], w: u32, h: u32, path: &Path, ctm: &Matrix, paint: &SolidPaint) {
    if !path.is_finite() {
        return;
    }
    let clip = IRect::from_ltrb(0, 0, w as i32, h as i32);
    // internalQuickReject: границы пути в device space против окна.
    let dev_bounds = ctm.map_rect(&path.bounds());
    if !dev_bounds.is_finite() || dev_bounds.intersect(&clip.to_rect()).is_none() && !rect_touches(&dev_bounds, &clip) {
        return;
    }
    let mut dev = path.transform(ctm);
    dev.resolve_convexity();
    let surf = Surface { data, width: w as i32, height: h as i32 };
    let mut blitter = SolidBlitter::new(surf, paint);
    aaa::anti_fill_path(&dev, &clip, &mut blitter);
}

fn rect_touches(r: &Rect, c: &IRect) -> bool {
    // Пустой в float прямоугольник (нулевая ширина) всё же может лежать в окне.
    r.right >= c.left as f32 && r.left <= c.right as f32 && r.bottom >= c.top as f32 && r.top <= c.bottom as f32
}

/// `SkScan::AntiFillRect` в Skia — отдельный алгоритм для `fillRect`;
/// пока прямоугольник идёт как путь (в маленьких размерах это тот же
/// `blitFatAntiRect`).
pub fn fill_rect(data: &mut [u8], w: u32, h: u32, x: f32, y: f32, rw: f32, rh: f32, ctm: [f32; 6], rgba: [u8; 4], mode: u32) {
    let ops = [OP_RECT as f32, x, y, rw, rh];
    fill_ops(data, w, h, &ops, ctm, false, rgba, mode);
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
