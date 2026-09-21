# PFFFT

Pretty Fast FFT by Julien Pommier, released under a BSD-like (FFTPACK) licence —
the full text is in the header of `pffft.c`.

Это тот же файл, что лежит в Chrome 151 (`third_party/pffft/src`), и он здесь
не ради скорости: браузер строит таблицы волн осциллятора обратным
преобразованием именно этой библиотеки, в одинарной точности, и порядок
сложений в её бабочках определяет последние разряды каждого отсчёта. Своя
реализация — хоть точная, хоть быстрая — даёт другие числа, а страница их
сверяет.

Взято из `chromium/src/+/refs/branch-heads/7922/third_party/pffft/src`.
