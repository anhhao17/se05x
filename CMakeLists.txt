cmake_minimum_required(VERSION 3.20)
project(se051_demo_superbuild NONE)

include(ExternalProject)

set(MBEDTLS_PREFIX ${CMAKE_BINARY_DIR}/mbedtls)
set(BUILD_JOBS 2 CACHE STRING "Parallel build jobs")

# Cross-compile mbedTLS (static) for aarch64. Source is the ext/mbedtls submodule
# pinned to the v3.6 LTS line. Programs/tests are skipped to keep the build lean.
ExternalProject_Add(mbedtls
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ext/mbedtls
    CMAKE_ARGS
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_SOURCE_DIR}/aarch64-toolchain.cmake
        -DCMAKE_INSTALL_PREFIX=${MBEDTLS_PREFIX}
        -DCMAKE_BUILD_TYPE=Release
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --parallel ${BUILD_JOBS}
)

# ECC example, built against mbedTLS via the app/ wrapper (keeps the
# plug-and-trust submodule unmodified). See app/CMakeLists.txt.
ExternalProject_Add(ecc_example
    DEPENDS    mbedtls
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/app
    CMAKE_ARGS
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_SOURCE_DIR}/aarch64-toolchain.cmake
        -DPTMW_Applet=SE051_H
        -DPTMW_SE05X_Ver=07_02
        -DPTMW_HostCrypto=MBEDTLS
        -DPTMW_SE05X_Auth=PlatfSCP03
        -DMBEDTLS_PREFIX=${MBEDTLS_PREFIX}
    BUILD_COMMAND   ${CMAKE_COMMAND} --build <BINARY_DIR> --parallel ${BUILD_JOBS}
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy <BINARY_DIR>/ex_ecc ${CMAKE_BINARY_DIR}/ex_ecc
)
