//! Builds the vendored PFFFT, the same copy Chrome 151 ships.
//!
//! Chrome builds oscillator wave tables with this library's single-precision
//! inverse FFT; the low bits of every sample depend on the summation order in
//! its butterflies. Another implementation gives different numbers (only 932
//! of 4096 samples matched), and pages fingerprint them.

fn main() {
    println!("cargo:rerun-if-changed=vendor/pffft/pffft.c");
    println!("cargo:rerun-if-changed=vendor/pffft/pffft.h");
    cc::Build::new()
        .file("vendor/pffft/pffft.c")
        .opt_level(2)
        .warnings(false)
        .compile("pffft");
}
