cmake_minimum_required(VERSION 3.10)
project(cryptopals_tests_set_4_problem_31_32)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set the build type to Debug (this ensures debug symbols are included)
set(CMAKE_BUILD_TYPE Debug)

# Add extra flags for debugging (disable optimizations and include debug symbols)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

# Fetch CPR
include(FetchContent)
FetchContent_Declare(
  cpr
  GIT_REPOSITORY https://github.com/libcpr/cpr.git
  GIT_TAG 1.11.2
)
FetchContent_MakeAvailable(cpr)

# Find Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(
    ${OPENSSL_INCLUDE_DIR}
)

# Add source files (your implementation files)
set(SOURCE_FILES
    ../src/HMAC.cpp
    ../src/HMAC_SHA1.cpp
    ../src/MessageExtractionFacility.cpp
    ../src/SHA.cpp
    ../src/SHA1.cpp
    ../src/Server.cpp
)

# Add test source files
set(TEST_SOURCES
    test_hmac_sha1.cpp
    test_sha1.cpp
    test_server.cpp
)

# Define the test executable
add_executable(runTests ${TEST_SOURCES} ${SOURCE_FILES})


message(STATUS "CMAKE_SOURCE_DIR is: ${CMAKE_SOURCE_DIR}")

# Include Crow's header files
target_include_directories(runTests PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/../../../../external/crow/include
)

# Link with Google Test, OpenSSL, and pthread
target_link_libraries(runTests 
    PRIVATE ${GTEST_LIBRARIES}
    GTest::gtest
    GTest::gtest_main
    cpr::cpr 
    OpenSSL::Crypto 
    pthread
)

# Enable testing
enable_testing()
add_test(NAME cryptopals_tests_set_4_problem_31_32 COMMAND runTests)
