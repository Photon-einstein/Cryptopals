cmake_minimum_required(VERSION 3.10)
project(cryptopals_tests_set_4_problem_30)

# Set the build type to Debug (this ensures debug symbols are included)
set(CMAKE_BUILD_TYPE Debug)

# Add extra flags for debugging (disable optimizations and include debug symbols)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

# Find Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add source files (your implementation files)
set(SOURCE_FILES
    ../src/Attacker.cpp
    ../src/MessageDigest.cpp
    ../src/MD4.cpp
    ../src/MessageExtractionFacility.cpp
    ../src/Server.cpp
)

# Add test source files
set(TEST_SOURCES
    test_attacker.cpp
    test_md4.cpp
    test_server.cpp
)

# Define the test executable
add_executable(run_tests ${TEST_SOURCES} ${SOURCE_FILES})

# Link with Google Test, OpenSSL, and pthread
target_link_libraries(run_tests PRIVATE ${GTEST_LIBRARIES} OpenSSL::Crypto pthread)

# Enable testing
enable_testing()
add_test(NAME cryptopals_tests_set_4_problem_30 COMMAND run_tests)

