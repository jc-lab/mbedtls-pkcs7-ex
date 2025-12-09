cmake_minimum_required(VERSION 3.10)
project(mbedtls_pkcs7_ex)

set(MBEDTLS_PKCS7_EX_ENABLE_TESTING ON CACHE BOOL "Enable testing")

add_library(mbedtls_pkcs7_ex pkcs7_ex.c)
target_include_directories(mbedtls_pkcs7_ex PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT MbedTLS_FOUND)
    find_package(MbedTLS)
endif()

if(MBEDTLS_PKCS7_EX_ENABLE_TESTING)
    if(NOT MbedTLS_FOUND)
        message(STATUS "MbedTLS not found, using submodule.")

        set(ENABLE_TESTING "Build Mbed TLS tests" OFF FORCE)
        add_subdirectory(test/mbedtls)

        # MbedTLS submodule's library names are mbedtls, mbedx509, mbedcrypto
        set(MBEDTLS_LIBRARIES mbedtls mbedx509)
        set(MBEDTLS_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/test/mbedtls/include)
    else()
        # Assume find_package sets these variables, adjust if necessary
        set(MBEDTLS_LIBRARIES MbedTLS::mbedtls MbedTLS::mbedx509)
        set(MBEDTLS_INCLUDE_DIRS ${MbedTLS_INCLUDE_DIRS})
    endif()

    enable_testing()
    
    add_executable(pkcs7_ex_test test/test_pkcs7_ex.c)
    target_link_libraries(pkcs7_ex_test mbedtls_pkcs7_ex ${MBEDTLS_LIBRARIES})
    target_include_directories(pkcs7_ex_test PRIVATE ${MBEDTLS_INCLUDE_DIRS})

    add_test(NAME pkcs7_ex_test COMMAND
        pkcs7_ex_test
        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_cases/case1_attached
        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_cases/case2_noattrs
    )

    add_custom_target(run_tests
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endif()

target_link_libraries(mbedtls_pkcs7_ex PUBLIC ${MBEDTLS_LIBRARIES})
