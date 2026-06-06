# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CMake **superbuild** that cross-compiles an ECC demo for the NXP **SE051** secure element
(aarch64 Linux target, e.g. Raspberry Pi over T=1 I2C). It contains no application source —
it orchestrates two things:

1. **mbedTLS** (`ext/mbedtls` submodule, **v2.28 LTS**) — cross-compiled static for aarch64,
   installed into `${CMAKE_BINARY_DIR}/mbedtls`. The host crypto backend.
2. **ex_ecc** — NXP Plug & Trust's `sss/ex/ecc/ex_sss_ecc.c`, built via the `app/` wrapper
   (see below) and linked against the mbedTLS from step 1. The binary is copied to
   `${CMAKE_BINARY_DIR}/ex_ecc`.

## Submodules

```bash
git submodule update --init --recursive   # after a fresh clone
```

- `ext/plug-and-trust/` — NXP/plug-and-trust ("mini" Plug & Trust package; top-level `ecc_example/`,
  `sss/`, `hostlib/`). Currently at v04.07.01.
- `ext/mbedtls/` — Mbed-TLS, pinned to the **v2.28 LTS** line. **Do not bump to 3.x** without
  also flipping `SSS_HAVE_MBEDTLS_2_X` (see "mbedTLS backend" below).

## Build

Driven through the cross toolchain in `aarch64-toolchain.cmake` (`aarch64-linux-gnu-gcc`/`g++`
must be on PATH).

```bash
cmake -S . -B build -DBUILD_JOBS=$(nproc)
cmake --build build              # builds mbedTLS, then ex_ecc -> build/ex_ecc
cmake --build build --target mbedtls   # just the mbedTLS stage
```

- `-DBUILD_JOBS=N` controls parallelism of both ExternalProject build steps (default 2).
- Clean rebuild after changing a submodule version: `rm -rf build` (ExternalProject caches
  stamps and will not otherwise notice the source change).

## mbedTLS backend (the non-obvious part)

The NXP mini package is **OpenSSL-first**: its README says "only OpenSSL is supported", and its
build glue (`ext/plug-and-trust/simw_lib.cmake`) hardcodes the OpenSSL SSS sources while
`ext/plug-and-trust/ecc_example/CMakeLists.txt` links `ssl crypto`. **But the mbedTLS path is fully
implemented in source** (`sss/src/mbedtls/fsl_sss_mbedtls_apis.c`, ~132 KB incl. its own keystore)
and the `MBEDTLS` option + feature flags exist — only the example's CMake wiring is missing.

Rather than patch the submodule, `app/CMakeLists.txt` is a thin wrapper that:

1. Sets `SSS_HAVE_MBEDTLS_2_X ON` **before** including `simw_lib.cmake`. The SSS code selects
   the 2.x vs 3.x mbedTLS API surface (`config.h` vs `mbedtls_config.h`, public vs
   `MBEDTLS_PRIVATE` struct fields, `pk_parse_key` arity) via this flag, which
   `simwlib_cmake_options.cmake` leaves unset (→ 0 = 3.x). Our submodule is 2.28, so it must be 1.
2. `include()`s `simw_lib.cmake` to reuse its source/include lists and `fsl_sss_ftr.h` generation.
3. Removes `fsl_sss_openssl_apis.c` + `keystore_openssl.c` from `SIMW_SE_SOURCES` and adds
   `fsl_sss_mbedtls_apis.c` (the mbedTLS keystore lives inside that file).
4. Links the static `libmbedtls/libmbedx509/libmbedcrypto` from the superbuild's mbedTLS prefix.

So switching the crypto backend is **not** just `-DPTMW_HostCrypto=...`; it requires this wrapper.

## Fixed PTMW options

Passed to `app`'s configure (`CMakeLists.txt`) — match the hardware/middleware when changing:

- `PTMW_Applet=SE051_H`
- `PTMW_SE05X_Ver=07_02`  (07_xx = SE051/SE052; 03_XX = SE050)
- `PTMW_HostCrypto=MBEDTLS`
- `PTMW_SE05X_Auth=PlatfSCP03`  (Platform SCP03 secure channel)

## Notes

- Out-of-source: all artifacts live under `build/`.
- The toolchain file restricts find modes to the sysroot (`CMAKE_FIND_ROOT_PATH_MODE_*`),
  so libraries/headers/packages resolve against the aarch64 target, not the host.
- `simw_lib.cmake` regenerates `ext/plug-and-trust/fsl_sss_ftr.h` on configure (writes into the
  submodule). That's expected — it's a generated file, mirroring upstream's own build.
