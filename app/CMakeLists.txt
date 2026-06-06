# Thin wrapper around NXP Plug & Trust's ecc_example that builds it against
# mbedTLS instead of OpenSSL, WITHOUT modifying the plug-and-trust submodule.
#
# The submodule's simw_lib.cmake hardcodes the OpenSSL host-crypto sources and
# its ecc_example/CMakeLists.txt links `ssl crypto`. We include simw_lib.cmake
# to reuse its source/include lists + feature-flag generation, then swap the
# OpenSSL apis file for the mbedTLS one and link mbedTLS.

cmake_minimum_required(VERSION 3.20)
project(ex_ecc C)

# plug-and-trust submodule lives under ext/.
set(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ext/plug-and-trust)

# The SSS sources select the mbedTLS 2.x vs 3.x API surface (config.h vs
# mbedtls_config.h, public vs MBEDTLS_PRIVATE struct fields, pk_parse_key
# signature) via SSS_HAVE_MBEDTLS_2_X. simwlib_cmake_options.cmake leaves it
# unset (-> 0 = 3.x). Our ext/mbedtls submodule is the 2.28 LTS line, so force
# 2.x mode before simw_lib.cmake regenerates fsl_sss_ftr.h.
set(SSS_HAVE_MBEDTLS_2_X ON)

# Reads PTMW_* cache vars, sets SSS_HAVE_HOSTCRYPTO_MBEDTLS, regenerates
# fsl_sss_ftr.h, and populates SIMW_SE_SOURCES / SIMW_SE_AUTH_SOURCES / SIMW_INC_DIR.
include(${SIMW_LIB_DIR}/simw_lib.cmake)

# Swap the OpenSSL backend out of the source list for the mbedTLS one.
# (The mbedTLS keystore implementation lives inside fsl_sss_mbedtls_apis.c,
#  so keystore_openssl.c is dropped with no mbedTLS replacement file.)
list(REMOVE_ITEM SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
    ${SIMW_LIB_DIR}/sss/src/keystore/keystore_openssl.c)
list(APPEND SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/mbedtls/fsl_sss_mbedtls_apis.c)

if("${PTMW_SE05X_Auth}" STREQUAL "None")
    add_executable(${PROJECT_NAME} ${SIMW_SE_SOURCES} ${SIMW_LIB_DIR}/sss/ex/ecc/ex_sss_ecc.c)
else()
    add_executable(${PROJECT_NAME} ${SIMW_SE_SOURCES} ${SIMW_SE_AUTH_SOURCES} ${SIMW_LIB_DIR}/sss/ex/ecc/ex_sss_ecc.c)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    ${SIMW_LIB_DIR}
    ${SIMW_INC_DIR}
    ${MBEDTLS_PREFIX}/include
)

# Static mbedTLS built by the superbuild. Link order matters: tls -> x509 -> crypto.
target_link_libraries(${PROJECT_NAME}
    ${MBEDTLS_PREFIX}/lib/libmbedtls.a
    ${MBEDTLS_PREFIX}/lib/libmbedx509.a
    ${MBEDTLS_PREFIX}/lib/libmbedcrypto.a
)
