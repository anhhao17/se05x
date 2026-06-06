# Thin wrapper that builds libsss_pkcs11.so using our existing ext/plug-and-trust
# and the mbedTLS backend, without modifying either submodule.
#
# The upstream se05x-pkcs11/CMakeLists.txt hardcodes SIMW_LIB_DIR to its own
# simw_lib submodule, so we replicate its logic here instead of including it.

cmake_minimum_required(VERSION 3.20)
project(sss_pkcs11 C)

set(SIMW_LIB_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/../ext/plug-and-trust)
set(SE05X_PKCS11_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ext/se05x-pkcs11)
set(PKCS11_HEADERS   ${SE05X_PKCS11_DIR}/pkcs11/published/2-40-errata-1)

# Force mbedTLS 2.x API surface before simw_lib.cmake regenerates fsl_sss_ftr.h.
set(SSS_HAVE_MBEDTLS_2_X ON)
include(${SIMW_LIB_DIR}/simw_lib.cmake)

# Swap OpenSSL backend out for mbedTLS (same as app/ and cpp_app/).
list(REMOVE_ITEM SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
    ${SIMW_LIB_DIR}/sss/src/keystore/keystore_openssl.c)
list(APPEND SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/mbedtls/fsl_sss_mbedtls_apis.c)

file(GLOB PKCS11_SE_SOURCES ${SE05X_PKCS11_DIR}/se_pkcs11/*.c)

if("${PTMW_SE05X_Auth}" STREQUAL "None")
    add_library(${PROJECT_NAME} SHARED
        ${SIMW_SE_SOURCES}
        ${PKCS11_SE_SOURCES})
else()
    add_library(${PROJECT_NAME} SHARED
        ${SIMW_SE_SOURCES}
        ${SIMW_SE_AUTH_SOURCES}
        ${PKCS11_SE_SOURCES})
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
    ${SE05X_PKCS11_DIR}/se_pkcs11/
    ${PKCS11_HEADERS}
    ${SIMW_INC_DIR}
    ${MBEDTLS_PREFIX}/include)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    PKCS11_LIBRARY
    PKCS11_SESSION_OPEN)

target_link_libraries(${PROJECT_NAME}
    ${MBEDTLS_PREFIX}/lib/libmbedtls.a
    ${MBEDTLS_PREFIX}/lib/libmbedx509.a
    ${MBEDTLS_PREFIX}/lib/libmbedcrypto.a)
