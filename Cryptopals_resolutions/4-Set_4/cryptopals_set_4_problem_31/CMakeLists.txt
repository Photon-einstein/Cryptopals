# Specify the minimum version of CMake
cmake_minimum_required(VERSION 3.10)

# Set the project name
project(cryptopals_set_4_problem_31)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include Crow (header-only) and your includes
include_directories(
    include
    external/crow/include
)

# Automatically find all .cpp files in the src/ directory (but not subdirectories)
aux_source_directory(src SOURCES)

# Create the executable
add_executable(cryptopals_set_4_problem_31 ${SOURCES})

# Link OpenSSL and Crow
target_link_libraries(cryptopals_set_4_problem_31 OpenSSL::Crypto)

# Optionally, if you want to specify output directories
set_target_properties(cryptopals_set_4_problem_31 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)
