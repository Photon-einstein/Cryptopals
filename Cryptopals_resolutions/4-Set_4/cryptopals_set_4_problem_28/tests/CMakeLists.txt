cmake_minimum_required(VERSION 3.10)
project(cryptopals_tests_set_4_problem_28)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add source files
set(SOURCE_FILES
    ../src/Attacker.cpp
    ../src/SHA.cpp
    ../src/SHA1.cpp
    ../src/Server.cpp
)

# Add test source files
set(TEST_SOURCES
    test_attacker.cpp
    test_server.cpp
    test_sha1.cpp
)

# Define the test executable
add_executable(runTests ${TEST_SOURCES} ${SOURCE_FILES})

# Link with Google Test, OpenSSL, and pthread
target_link_libraries(runTests PRIVATE ${GTEST_LIBRARIES} OpenSSL::Crypto pthread)


# Enable testing
enable_testing()
add_test(NAME cryptopals_tests_set_4_problem_28 COMMAND runTests)
