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
        pem_hugging_whitespace
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
        der_control_chars
        pem_control_chars
        pem_der_control_chars_same
        time_century_utc_der
        time_century_utc_pem
        time_pivot_49_and_50
        time_mixed_tags_der
        time_mixed_tags_pem
        time_mixed_tags_not_swapped
        time_generalized_der
        time_generalized_pem
        time_pem_der_same_fields
        time_timezone_invariant
        time_expired_and_not_yet_valid_ok
        time_impossible_date_der
        time_impossible_date_pem
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
        pem_text_hugging_marker
        pem_body_trailing_nul
        pem_body_trailing_cert
        pem_body_exact_with_whitespace
        der_trailing_whitespace
        der_trailing_cert
        der_trailing_bytes
        public_key_only
        private_key_only
        read_directory
        read_nonexistent
        read_permission_denied
        read_directory_path_with_space
        read_fifo_no_writer
        read_fifo_with_writer
        read_character_device
        read_block_device
        read_socket
        symlink_to_regular
        symlink_to_directory
        symlink_to_fifo
        symlink_to_character_device
        symlink_dangling
        symlink_to_unreadable
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
