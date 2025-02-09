cmake_minimum_required(VERSION 3.10)
project(cryptopals_tests_set_4_problem_28)

# Find Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add source files (your implementation files)
set(SOURCE_FILES
    ../src/SHA.cpp
    ../src/SHA1.cpp
    ../src/Server.cpp
)

# Add test source files
set(TEST_SOURCES
    test_server.cpp
    test_sha1.cpp
)

# Define the test executable
add_executable(run_tests ${TEST_SOURCES} ${SOURCE_FILES})

# Link with Google Test, OpenSSL, and pthread
target_link_libraries(run_tests PRIVATE ${GTEST_LIBRARIES} OpenSSL::Crypto pthread)


# Enable testing
enable_testing()
add_test(NAME cryptopals_tests_set_4_problem_28 COMMAND run_tests)
