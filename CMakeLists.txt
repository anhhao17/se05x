cmake_minimum_required(VERSION 3.20)
project(se051_demo_superbuild NONE)

include(ExternalProject)

set(MBEDTLS_PREFIX ${CMAKE_BINARY_DIR}/mbedtls)
set(BUILD_JOBS 2 CACHE STRING "Parallel build jobs")

# Forward the toolchain to every sub-build when cross-compiling.
# Pass -DCMAKE_TOOLCHAIN_FILE=<path> at the top level to cross-compile;
# omit it for a native host build.
if(CMAKE_TOOLCHAIN_FILE)
    get_filename_component(_toolchain_abs "${CMAKE_TOOLCHAIN_FILE}" ABSOLUTE
                           BASE_DIR "${CMAKE_SOURCE_DIR}")
    set(TOOLCHAIN_ARG -DCMAKE_TOOLCHAIN_FILE=${_toolchain_abs})
else()
    set(TOOLCHAIN_ARG "")
endif()

# Cross-compile mbedTLS (static) for aarch64. Source is the ext/mbedtls submodule
# pinned to the v3.6 LTS line. Programs/tests are skipped to keep the build lean.
ExternalProject_Add(mbedtls
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ext/mbedtls
    CMAKE_ARGS
        ${TOOLCHAIN_ARG}
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
ExternalProject_Add(app_example
    DEPENDS    mbedtls
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/app
    CMAKE_ARGS
        ${TOOLCHAIN_ARG}
        -DPTMW_Applet=SE051_H
        -DPTMW_SE05X_Ver=07_02
        -DPTMW_HostCrypto=MBEDTLS
        -DPTMW_SE05X_Auth=PlatfSCP03
        -DMBEDTLS_PREFIX=${MBEDTLS_PREFIX}
    BUILD_COMMAND   ${CMAKE_COMMAND} --build <BINARY_DIR> --parallel ${BUILD_JOBS}
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy <BINARY_DIR>/demo_se051 ${CMAKE_BINARY_DIR}/demo_se051
)

ExternalProject_Add(cpp_app
    DEPENDS    mbedtls
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cpp_app
    CMAKE_ARGS
        ${TOOLCHAIN_ARG}
        -DPTMW_Applet=SE051_H
        -DPTMW_SE05X_Ver=07_02
        -DPTMW_HostCrypto=MBEDTLS
        -DPTMW_SE05X_Auth=PlatfSCP03
        -DMBEDTLS_PREFIX=${MBEDTLS_PREFIX}
    BUILD_COMMAND   ${CMAKE_COMMAND} --build <BINARY_DIR> --parallel ${BUILD_JOBS}
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy <BINARY_DIR>/se05x_crypto_app ${CMAKE_BINARY_DIR}/se05x_crypto_app
)
