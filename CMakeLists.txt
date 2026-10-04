cmake_minimum_required(VERSION 3.20)
project(trustpeek VERSION 0.1.0 LANGUAGES CXX)

find_package(OpenSSL REQUIRED)

enable_testing()

add_executable(trustpeek src/main.cpp)
target_compile_features(trustpeek PRIVATE cxx_std_20)
set_target_properties(trustpeek PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(trustpeek PRIVATE OpenSSL::Crypto)

find_program(BASH_EXECUTABLE bash REQUIRED)
add_test(
    NAME inspect-regression
    COMMAND ${BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(inspect-regression PROPERTIES
    ENVIRONMENT "TRUSTPEEK=$<TARGET_FILE:trustpeek>;TZ=UTC;LC_ALL=C.UTF-8"
)
