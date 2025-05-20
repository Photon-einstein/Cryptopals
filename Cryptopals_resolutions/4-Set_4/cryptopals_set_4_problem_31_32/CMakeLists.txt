# Specify the minimum version of CMake
cmake_minimum_required(VERSION 3.10)

# Set the project name
project(cryptopals_set_4_problem_31_32)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Fetch CPR
include(FetchContent)
FetchContent_Declare(
  cpr
  GIT_REPOSITORY https://github.com/libcpr/cpr.git
  GIT_TAG 1.11.2
)
FetchContent_MakeAvailable(cpr)

# Include directories
include_directories(
    include
    ./../../../external/crow/include
)

# Automatically find all .cpp files in the src/ directory (except main files)
file(GLOB COMMON_SOURCES "src/*.cpp")
list(REMOVE_ITEM COMMON_SOURCES "${CMAKE_SOURCE_DIR}/src/run_server.cpp")
list(REMOVE_ITEM COMMON_SOURCES "${CMAKE_SOURCE_DIR}/src/run_attacker.cpp")

# === Server Executable ===
add_executable(run_server
    src/run_server.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(run_server 
    OpenSSL::Crypto
    cpr::cpr
)

set_target_properties(run_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)

# === Attacker Executable ===
add_executable(run_attacker
    src/run_attacker.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(run_attacker 
    OpenSSL::Crypto
    cpr::cpr
)

set_target_properties(run_attacker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)
