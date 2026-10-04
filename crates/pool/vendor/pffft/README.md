# PFFFT

Pretty Fast FFT by Julien Pommier, released under a BSD-like (FFTPACK) licence —
the full text is in the header of `pffft.c`.

This is the same file Chrome 151 ships (`third_party/pffft/src`). It is here
for fidelity, not speed: Chrome builds oscillator wave tables with this
library's single-precision inverse FFT, and the summation order in its
butterflies decides the low bits of every sample. Any other implementation,
however accurate, gives different numbers, and pages fingerprint them.

Taken from `chromium/src/+/refs/branch-heads/7922/third_party/pffft/src`.
