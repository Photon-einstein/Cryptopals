#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../include/SessionData.hpp"

/**
 * @test Test the correctness of the construction of the structure of Session
 * Data.
 * @brief Test the correctness of the construction of the structure of Session
 * Data, should match the expected values.
 */
TEST(SessionDataTest,
     SessionData_WithValidInputParameters_ShouldMatchReference) {
  const unsigned int groupId{5};
  const std::string salt{
      "8f03fe9e9f8988be043f4d17489e7ef9bd2fa3e1b1ada0a286f16f8e9ad4bb06"};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  SessionData session(groupId, salt, hash, debugFlag);
  EXPECT_EQ(session._groupId, groupId);
  EXPECT_EQ(session._salt, salt);
  EXPECT_EQ(session._hash, hash);
}

/**
 * @test Test that the constructor of SessionData throws an error when
 * an invalid group ID is given as input parameter.
 * @brief Test that the constructor of SessionData throws an error when
 * an invalid group ID is given as input parameter. The error message
 * should match the expected value.
 */
TEST(SessionDataTest, SessionData_WithInvalidGroupId_ShouldThrowAnError) {
  const unsigned int groupId{0};
  const std::string salt{
      "8f03fe9e9f8988be043f4d17489e7ef9bd2fa3e1b1ada0a286f16f8e9ad4bb06"};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  try {
    SessionData session(groupId, salt, hash, debugFlag);
  } catch (const std::runtime_error &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("Invalid input parameters given."));
  }
}

/**
 * @test Test that the constructor of SessionData throws an error when
 * an invalid salt is given as input parameter.
 * @brief Test that the constructor of SessionData throws an error when
 * an invalid salt is given as input parameter. The error message
 * should match the expected value.
 */
TEST(SessionDataTest, SessionData_WithInvalidSalt_ShouldThrowAnError) {
  const unsigned int groupId{5};
  const std::string salt{""};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  try {
    SessionData session(groupId, salt, hash, debugFlag);
  } catch (const std::runtime_error &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("Invalid input parameters given."));
  }
}

/**
 * @test Test that the constructor of SessionData throws an error when
 * an invalid hash is given as input parameter.
 * @brief Test that the constructor of SessionData throws an error when
 * an invalid hash is given as input parameter. The error message
 * should match the expected value.
 */
TEST(SessionDataTest, SessionData_WithInvalidHash_ShouldThrowAnError) {
  const unsigned int groupId{5};
  const std::string salt{
      "8f03fe9e9f8988be043f4d17489e7ef9bd2fa3e1b1ada0a286f16f8e9ad4bb06"};
  const std::string hash{""};
  const bool debugFlag{false};
  try {
    SessionData session(groupId, salt, hash, debugFlag);
  } catch (const std::runtime_error &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("Invalid input parameters given."));
  }
}
