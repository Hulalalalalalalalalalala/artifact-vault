cmake_minimum_required(VERSION 3.20)
project(trustpeek VERSION 0.1.0 LANGUAGES CXX)

find_package(OpenSSL REQUIRED)

add_executable(trustpeek src/main.cpp)
target_compile_features(trustpeek PRIVATE cxx_std_20)
set_target_properties(trustpeek PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(trustpeek PRIVATE OpenSSL::Crypto)

include(CTest)
if(BUILD_TESTING)
    set(TRUSTPEEK_CASES
        pem_basic
        der_basic
        pem_der_same_fields
        pem_wrong_extension
        der_wrong_extension
        pem_surrounding_whitespace
        expired_ok
        self_signed_ok
        der_marker_in_name
        pem_marker_in_name
        der_complex_names
        pem_complex_names
        pem_der_complex_names_same
        der_long_oids
        pem_long_oids
        pem_der_long_oids_same
        der_marker_trailing_newline
        der_marker_trailing_pem_block
        pem_marker_second_block
        empty_file
        whitespace_only
        pem_truncated
        der_truncated
        pem_second_block
        pem_text_before
        pem_text_after
        der_trailing_whitespace
        der_trailing_cert
        der_trailing_bytes
        public_key_only
        private_key_only
        read_directory
        read_nonexistent
        read_permission_denied
        read_directory_path_with_space
    )
    foreach(case IN LISTS TRUSTPEEK_CASES)
        add_test(
            NAME inspect_${case}
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_case.sh
                    $<TARGET_FILE:trustpeek>
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
                    ${case}
        )
    endforeach()
endif()
