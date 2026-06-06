cmake_minimum_required(VERSION 3.20)
project(se051_demo_superbuild NONE)

include(ExternalProject)

set(OPENSSL_PREFIX ${CMAKE_BINARY_DIR}/openssl)
set(BUILD_JOBS 2 CACHE STRING "Parallel build jobs")

ExternalProject_Add(openssl
    GIT_REPOSITORY  https://github.com/openssl/openssl.git
    GIT_TAG         openssl-3.3.2
    GIT_SHALLOW     TRUE
    BUILD_IN_SOURCE TRUE
    CONFIGURE_COMMAND <SOURCE_DIR>/Configure linux-aarch64
        --cross-compile-prefix=aarch64-linux-gnu-
        --prefix=${OPENSSL_PREFIX}
        --libdir=lib
        no-shared no-tests no-docs
    BUILD_COMMAND   make -j8
    INSTALL_COMMAND make install_sw
)

ExternalProject_Add(ecc_example
    DEPENDS    openssl
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/plug-and-trust/ecc_example
    CMAKE_ARGS
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_SOURCE_DIR}/aarch64-toolchain.cmake
        -DPTMW_Applet=SE051_H
        -DPTMW_SE05X_Ver=07_02
        -DPTMW_HostCrypto=OPENSSL
        -DPTMW_SE05X_Auth=PlatfSCP03
        -DOPENSSL_INCLUDE_DIR=${OPENSSL_PREFIX}/include
        -DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_PREFIX}/lib/libcrypto.a
        -DOPENSSL_SSL_LIBRARY=${OPENSSL_PREFIX}/lib/libssl.a
    BUILD_COMMAND   ${CMAKE_COMMAND} --build <BINARY_DIR> --parallel ${BUILD_JOBS}
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy <BINARY_DIR>/ex_ecc ${CMAKE_BINARY_DIR}/ex_ecc
)