//! Сборка вендорённого PFFFT — того же, что лежит в Chrome 151.
//!
//! Таблицы волн осциллятора браузер строит обратным преобразованием этой
//! библиотеки в одинарной точности, и последние разряды каждого отсчёта
//! зависят от порядка сложений в её бабочках. Своя реализация даёт другие
//! числа (проверено: из 4096 отсчётов совпадало 932), а страница их сверяет.

fn main() {
    println!("cargo:rerun-if-changed=vendor/pffft/pffft.c");
    println!("cargo:rerun-if-changed=vendor/pffft/pffft.h");
    cc::Build::new()
        .file("vendor/pffft/pffft.c")
        .opt_level(2)
        .warnings(false)
        .compile("pffft");
}
