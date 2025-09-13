#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../include/MessageExtractionFacility.hpp"
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

/**
 * @test Test that the k multiplier map returned from the session data
 * matches the reference.
 * @brief Test that the k multiplier map returned from the session data
 * matches the reference. The k values are stored by group ID.
 */
TEST(SessionDataTest, SessionData_GetKMultiplierMap_ShouldMatchReference) {
  const unsigned int groupId{5};
  const std::string salt{
      "8f03fe9e9f8988be043f4d17489e7ef9bd2fa3e1b1ada0a286f16f8e9ad4bb06"};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  SessionData session(groupId, salt, hash, debugFlag);
  const std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM> &kMap =
      session._secureRemotePassword->getKMap();
  const unsigned int groupsSize{7};
  EXPECT_EQ(kMap.size(), groupsSize);
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(1).get()),
            "1A1A4C140CDE70AE360C1EC33A33155B1022DF951732A476A862EB3AB8206A5C");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(2).get()),
            "B2286EEE1033FE2BDC950CBF0ABB6FB56670E2B4D5BDA4CB203A9A96D018625D");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(3).get()),
            "05B9E8EF059C6B32EA59FC1D322D37F04AA30BAE5AA9003B8321E21DDB04E300");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(4).get()),
            "081F4874FA543A371B49A670402FDA59ECFAB53A1B850FC42E1C357CC846111E");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(5).get()),
            "13ED8E2B1E3F847DA7D4BE9DDE56C9AD9AA50EE67CDC948E4053A171EBB384DF5D"
            "6B2047D295C857C61B9504CAF00907");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(6).get()),
            "E23815ED6634AFD9F6C2EFC31B593068347B5AF87A072252A53F18019CCDB30E75"
            "1C17AD439E1A65DB22D67EF3C181CD806CDBBA608718785707156F998C4198");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(7).get()),
            "4D52644EEB89DCEB292AEA0DC86CF8D1EE820E92B7F840F2E075004249315CE5EB"
            "61FD1FE6F8DC35E51495357EC0B4E14CAF9EF159D093BAD019514927476AC5");
}
