cmake_minimum_required(VERSION 3.20)
project(pkcs11_demo C)

set(SE05X_PKCS11_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ext/se05x-pkcs11)

add_executable(${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_demo.c)

# se_pkcs11/cryptoki.h sets the platform macros and includes pkcs11.h.
# pkcs11/published/2-40-errata-1/ provides pkcs11.h itself.
target_include_directories(${PROJECT_NAME} PRIVATE
    ${SE05X_PKCS11_DIR}/se_pkcs11/
    ${SE05X_PKCS11_DIR}/pkcs11/published/2-40-errata-1/)

# dlopen/dlsym to load libsss_pkcs11.so at runtime — no link-time dependency.
target_link_libraries(${PROJECT_NAME} dl)
