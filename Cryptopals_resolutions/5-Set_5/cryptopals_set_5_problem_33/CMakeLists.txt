# Specify the minimum version of CMake
cmake_minimum_required(VERSION 3.10)

# Set the project name
project(cryptopals_set_4_problem_31_32)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Fetch fmt
include(FetchContent)
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
)

# Fetch CPR
FetchContent_Declare(
  cpr
  GIT_REPOSITORY https://github.com/libcpr/cpr.git
  GIT_TAG 1.11.2
)
FetchContent_MakeAvailable(fmt cpr)

# Include directories
include_directories(
    include
    ./../../../external/crow/include
)

# Automatically find all .cpp files in the src/ directory (except main files)
file(GLOB COMMON_SOURCES "src/*.cpp")
list(REMOVE_ITEM COMMON_SOURCES "${CMAKE_SOURCE_DIR}/src/runServer.cpp")
list(REMOVE_ITEM COMMON_SOURCES "${CMAKE_SOURCE_DIR}/src/runClient.cpp")

# === Server Executable ===
add_executable(runServer
    src/runServer.cpp
    ${COMMON_SOURCES}
)

# Manually link Boost UUID
find_package(Boost REQUIRED)  # Find Boost core
include_directories(${Boost_INCLUDE_DIRS})

target_link_libraries(runServer
    PRIVATE OpenSSL::Crypto cpr::cpr fmt::fmt
)

set_target_properties(runServer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)

# === Client Executable ===
add_executable(runClient
    src/runClient.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(runClient 
    PRIVATE OpenSSL::Crypto cpr::cpr fmt::fmt
)

set_target_properties(runClient PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)
