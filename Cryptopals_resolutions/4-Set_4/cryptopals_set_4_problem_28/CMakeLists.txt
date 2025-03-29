# Specify the minimum version of CMake
cmake_minimum_required(VERSION 3.10)

# Set the project name
project(cryptopals_set_4_problem_28)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories
include_directories(include)

# Automatically find all .cpp files in the src/ directory (but not subdirectories)
aux_source_directory(src SOURCES)

# Create the executable
add_executable(cryptopals_set_4_problem_28 ${SOURCES})

# Link OpenSSL libraries (crypto is typically sufficient for SHA-1 functions)
target_link_libraries(cryptopals_set_4_problem_28 OpenSSL::Crypto)

# Enable AddressSanitizer if the user wants memory checks
if (ENABLE_ASAN)
    message(STATUS "Enabling AddressSanitizer")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -g -O1 -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# Optionally, if you want to specify output directories
set_target_properties(cryptopals_set_4_problem_28 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)
