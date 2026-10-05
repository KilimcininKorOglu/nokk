# Installing and running nokk

## Docker images

The published image bundles the binary, glibc, and TLS roots — nothing to compile.
`:latest` is a tiny [distroless](https://github.com/GoogleContainerTools/distroless)
image (~62 MB, ~22 MB compressed):

```bash
docker run --rm -p 9222:9222 ghcr.io/koloss777/nokk:latest
```

That starts the CDP server; point Puppeteer at `ws://localhost:9222/devtools/browser/nokk`.
One-shot modes work too — just override the args:

```bash
docker run --rm ghcr.io/koloss777/nokk:latest --eval 'navigator.webdriver'   # -> false
docker run --rm ghcr.io/koloss777/nokk:latest --load https://example.com --eval 'document.title'
```

Three variants are published per release:

| Tag | Base | Notes |
|-----|------|-------|
| `:latest`, `:<version>`, `:distroless` | distroless | Light build, smallest image; no shell. The default. |
| `:debian`, `:<version>-debian` | debian-slim | Light build with a shell for `docker exec` debugging. |
| `:render`, `:<version>-render` | debian-slim + Mesa | **Real** canvas/WebGL pixels instead of synthesis, ~100 MB more at peak — see [`rendering.md`](rendering.md). |

Or build the image yourself from a checkout: `docker build -t nokk .` (add
`--target debian` or `--target render` for the other variants).

## Run the prebuilt binary

Grab the Linux x86_64 tarball from the [latest release](https://github.com/koloss777/nokk/releases/latest):

```bash
tar -xzf nokk-*-linux-x86_64.tar.gz
./nokk --eval 'navigator.webdriver'
```

That is the light build, which `npm install` and `pip install` fetch too. The release
also carries `nokk-render-*-linux-x86_64.tar.gz`: the same engine with real canvas/WebGL
rasterization compiled in, for sites that compare pixels (`cargo build --features
render,webgl` from source). Canvas 2D works anywhere; WebGL needs Mesa on the host
(`libegl1 libgl1-mesa-dri`) and falls back to synthesis without it.

## Build from source

nokk's fingerprinted transport is backed by BoringSSL (via `wreq`), so the first build
compiles it from source. You need a C/C++ toolchain, `cmake`, and `libclang`. On
Debian/Ubuntu:

```bash
sudo apt install build-essential cmake clang libclang-dev
git clone https://github.com/koloss777/nokk
cd nokk
cargo build --release
```

> No root? BoringSSL can be bootstrapped from user-space `pip` packages — see
> [`BUILD.md`](BUILD.md) for the `cmake` + `libclang` + `.cargo/config.toml`
> recipe used to build this repo without sudo.
