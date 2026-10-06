# Installing and running nokk

## Docker images

The published image bundles the binary, glibc, and TLS roots — nothing to compile.
`:latest` is a tiny [distroless](https://github.com/GoogleContainerTools/distroless)
image (~62 MB, ~22 MB compressed):

```bash
docker run --rm -p 9222:9222 ghcr.io/koloss777/nokk:latest
```

That starts the CDP server; point Puppeteer at `ws://localhost:9222/devtools/browser/nokk`.

The image listens on all interfaces, so anyone who can reach the port can drive the
browser: open any address from your machine and read its sessions. Anywhere but your
own laptop, give it a token, and connect with it:

```bash
docker run --rm -p 9222:9222 -e NOKK_TOKEN="$(openssl rand -hex 16)" ghcr.io/koloss777/nokk:latest
# ws://localhost:9222/devtools/browser/nokk?token=<the token>   (or Authorization: Bearer <the token>)
```

Without a token nokk prints a warning when it listens beyond loopback. The `--token`
flag does the same as `NOKK_TOKEN`, and the Python and npm wrappers pass a
`NOKK_TOKEN` from their environment through to the endpoint they return.
One-shot modes work too — just override the args:

```bash
docker run --rm ghcr.io/koloss777/nokk:latest --eval 'navigator.webdriver'   # -> false
docker run --rm ghcr.io/koloss777/nokk:latest --load https://example.com --eval 'document.title'
```

The page sees the container's timezone. The image has none of its own, so it reports
`America/New_York`; pass the zone that matches your exit IP, or let `--geoip-timezone` set
it per context:

```bash
docker run --rm -e TZ=Europe/Berlin -p 9222:9222 ghcr.io/koloss777/nokk:latest
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

Grab the archive for your platform from the [latest release](https://github.com/koloss777/nokk/releases/latest):

| Platform | Archive |
|---|---|
| Linux x86_64 | `nokk-<version>-linux-x86_64.tar.gz` |
| Linux ARM64 (a Raspberry Pi 5 too) | `nokk-<version>-linux-aarch64.tar.gz` |
| macOS on Apple Silicon | `nokk-<version>-macos-aarch64.tar.gz` |
| Windows x64 | `nokk-<version>-windows-x86_64.zip` |

```bash
tar -xzf nokk-*-linux-x86_64.tar.gz
./nokk --eval 'navigator.webdriver'
```

On Windows, unzip and run `.\nokk.exe` from PowerShell. The Linux binaries need glibc
2.31 or newer (Debian 11, Ubuntu 20.04, RHEL 9). The page always sees Chrome on Linux:
the fingerprint is the same whichever machine runs nokk.

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
