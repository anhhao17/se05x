# SE051 Crypto Demo

CMake **superbuild** that cross-compiles a comprehensive SE051 secure-element crypto demo
for Linux ARM targets (Raspberry Pi and similar), using **NXP Plug & Trust** (SSS API) with
**mbedTLS 2.28** as the host crypto backend.

## Features

| Category | Operations |
|---|---|
| **EC (P-256)** | Key generation, ECDSA sign/verify, ECDH key agreement, PKCS#10 CSR |
| **RSA (2048)** | Key generation, PKCS#1v1.5 sign/verify, OAEP encrypt/decrypt, PKCS#10 CSR |
| **RNG** | SE-backed hardware random number generation |

Two implementations are provided side-by-side:

- **`app/`** — C implementation (`demo_se051`), entry point `ex_sss_entry()`
- **`cpp_app/`** — C++ implementation (`se05x_crypto_app`), object-oriented SSS wrapper

### Branch `feat/pkcs11` — PKCS#11 interface

Adds a standard [PKCS#11 v2.40](https://github.com/NXPPlugNTrust/se05x-pkcs11) interface over the SE051:

- **`pkcs11_lib/`** — builds `libsss_pkcs11.so` (NXP se05x-pkcs11 plugin, mbedTLS backend)
- **`pkcs11_example/`** — C demo suite (`pkcs11_demo`) loading the library via `dlopen`:

| Demo | Operations |
|---|---|
| `run_module_info` | Library info, slot/token/mechanism list, object enumeration |
| `run_random_gen` | `C_GenerateRandom` for 1–1024 byte buffers |
| `run_digest` | SHA-1/224/256/384/512 via `C_DigestInit` / `C_Digest` |
| `run_sym_key_gen` | AES-128/192/256 + generic secret via `C_GenerateKey` |
| `run_import_object` | Import AES, generic secret, EC P-256 public key via `C_CreateObject` |
| `run_ecc` | P-256/384/521 keygen + ECDSA-SHA256/384/512 sign/verify |
| `run_rsa` | RSA-2048 keygen + PKCS#1 v1.5 sign/verify + PSS sign/verify |
| `run_ecdh_derive` | Two P-256 key pairs + shared secret via `CKM_ECDH1_DERIVE` |
| `run_hmac` | Import key + SHA-1/256/384/512 HMAC sign/verify |
| `run_encrypt_decrypt` | AES-ECB, AES-CBC roundtrip + RSA-2048 OAEP encrypt/decrypt |

## Prerequisites

### Submodules

```bash
git submodule update --init --recursive
```

### Cross-compiler toolchains

| Target | Toolchain package | Toolchain file |
|---|---|---|
| aarch64 (RPi 3/4/5 64-bit) | `gcc-aarch64-linux-gnu` | `aarch64-toolchain.cmake` |
| armhf (RPi 2/3/4 32-bit) | `gcc-arm-linux-gnueabihf` | `armhf-toolchain.cmake` |

```bash
sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu   # aarch64
sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf  # armhf
```

## Build

```bash
# aarch64 (64-bit ARM)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build

# armhf (32-bit ARM hard-float)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=armhf-toolchain.cmake
cmake --build build

# Native host build (x86_64, for development)
cmake -S . -B build
cmake --build build
```

Outputs in `build/`:

| Binary | Description |
|---|---|
| `demo_se051` | C demo (all operations in sequence) |
| `se05x_crypto_app` | C++ demo |

**Parallelism:** pass `-DBUILD_JOBS=N` (default 2) to speed up ExternalProject builds.

**Clean rebuild** after submodule changes: `rm -rf build` (ExternalProject stamp caching
will not detect source changes otherwise).

## Running

Copy the binary to the target and run with the I2C port:

```bash
scp build/demo_se051 pi@<host>:/home/pi/
ssh pi@<host> ./demo_se051 /dev/i2c-1
```

The demo runs all operations in sequence and logs results. On success each section prints `OK`.

### Verifying CSRs

The demo writes CSR files to `/tmp/` on the target:

```bash
# Verify EC CSR
openssl req -in /tmp/ec_csr.pem -noout -text

# Verify RSA CSR
openssl req -in /tmp/rsa_csr.pem -noout -text
```

## Project structure

```
.
├── CMakeLists.txt           # Superbuild — orchestrates mbedTLS + app + cpp_app
├── aarch64-toolchain.cmake  # Cross-toolchain for 64-bit ARM
├── armhf-toolchain.cmake    # Cross-toolchain for 32-bit ARM hard-float
├── app/                     # C demo (demo_se051)
│   ├── CMakeLists.txt       # mbedTLS backend wiring (OpenSSL → mbedTLS swap)
│   ├── demo_se051.h         # Key IDs, buffer sizes, prototypes
│   ├── demo_se051.c         # ex_sss_entry() dispatcher
│   ├── demo_ec.c            # EC keygen / sign-verify / ECDH / CSR
│   ├── demo_rsa.c           # RSA keygen / sign-verify / enc-dec / CSR
│   └── demo_rng.c           # Hardware RNG
├── cpp_app/                 # C++ demo (se05x_crypto_app)
│   ├── CMakeLists.txt
│   ├── se05x_crypto.hpp/.cpp  # EcKey, RsaKey, Session RAII wrappers
│   ├── csr.cpp              # PKCS#10 CSR builder (mbedTLS ASN.1)
│   └── main.cpp
└── ext/
    ├── mbedtls/             # mbedTLS v2.28 LTS (submodule)
    └── plug-and-trust/      # NXP Plug & Trust mini package v04.07.01 (submodule)
```

## Key IDs (SE object store)

All demo keys live in the safe test range `0xEF000000–0xEFFFFFFF`:

| Constant | ID | Purpose |
|---|---|---|
| `DEMO_KEY_EC_ALICE` | `0xEF000001` | EC P-256 key pair — sign/verify/CSR |
| `DEMO_KEY_EC_BOB` | `0xEF000002` | EC P-256 key pair — ECDH peer |
| `DEMO_KEY_EC_SHARED` | `0xEF000003` | ECDH derived shared secret (transient) |
| `DEMO_KEY_RSA` | `0xEF000010` | RSA 2048 CRT key pair |

Keys are generated fresh each run (existing objects at those IDs are erased first).
