# Specify the minimum version of CMake
cmake_minimum_required(VERSION 3.10)

# Set the project name
project(cryptopals_set_4_problem_35)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
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
list(REMOVE_ITEM COMMON_SOURCES "${CMAKE_SOURCE_DIR}/src/runClient1.cpp")
list(REMOVE_ITEM COMMON_SOURCES "${CMAKE_SOURCE_DIR}/src/runMalloryServer.cpp")
list(REMOVE_ITEM COMMON_SOURCES "${CMAKE_SOURCE_DIR}/src/runServer.cpp")

# === Mallory Server Executable ===
add_executable(runMalloryServer
    src/runMalloryServer.cpp
    ${COMMON_SOURCES}
)

# Manually link Boost UUID
include_directories(${Boost_INCLUDE_DIRS})

target_link_libraries(runMalloryServer
    PRIVATE OpenSSL::Crypto cpr::cpr fmt::fmt
)

set_target_properties(runMalloryServer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)

# === Server Executable ===
add_executable(runServer
    src/runServer.cpp
    ${COMMON_SOURCES}
)

# Manually link Boost UUID
include_directories(${Boost_INCLUDE_DIRS})

target_link_libraries(runServer
    PRIVATE OpenSSL::Crypto cpr::cpr fmt::fmt
)

set_target_properties(runServer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)

# === Client 1 Executable ===
add_executable(runClient1
    src/runClient1.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(runClient1 
    PRIVATE OpenSSL::Crypto cpr::cpr fmt::fmt
)

set_target_properties(runClient1 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build
)
