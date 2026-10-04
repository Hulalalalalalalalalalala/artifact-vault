cmake_minimum_required(VERSION 3.20)
project(trustpeek VERSION 0.1.0 LANGUAGES CXX)

find_package(OpenSSL 3.0 REQUIRED Crypto)

add_executable(trustpeek src/main.cpp)
target_compile_features(trustpeek PRIVATE cxx_std_20)
set_target_properties(trustpeek PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(trustpeek PRIVATE OpenSSL::Crypto)
