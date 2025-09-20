#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../include/Server.hpp"

/**
 * @test Test the correctness of the construction of the Server class.
 * @brief Test the correctness of the construction of the Server class,
 * should match the expected values.
 */
TEST(ServerTest, Server_WithValidInputParameters_ShouldMatchReference) {
  const bool debugFlag{false};
  const unsigned int expectedProductionPort{18080};
  const unsigned int expectedTestPort{18081};
  const std::string expectedSrpParametersFilename{
      "../input/SrpParameters.json"};
  const unsigned int expectedDefaultGroupId{3};
  Server server(debugFlag);
  EXPECT_EQ(server.getProductionPort(), expectedProductionPort);
  EXPECT_EQ(server.getTestPort(), expectedTestPort);
  EXPECT_EQ(
      MyCryptoLibrary::SecureRemotePassword::getSrpParametersFilenameLocation(),
      expectedSrpParametersFilename);
  EXPECT_EQ(server.getDefaultGroupId(), expectedDefaultGroupId);
}

/**
 * @test Test the correctness of the construction of the Server class, with a
 * defaultGroupId provided in the constructor.
 * @brief Test the correctness of the construction of the Server class,
 * should match the expected values.
 */
TEST(ServerTest,
     Server_WithValidInputParametersWithDefaultGroupId_ShouldMatchReference) {
  const bool debugFlag{false};
  const unsigned int expectedDefaultGroupId{5};
  const unsigned int expectedProductionPort{18080};
  const unsigned int expectedTestPort{18081};
  const std::string expectedSrpParametersFilename{
      "../input/SrpParameters.json"};
  Server server(debugFlag, expectedDefaultGroupId);
  EXPECT_EQ(server.getProductionPort(), expectedProductionPort);
  EXPECT_EQ(server.getTestPort(), expectedTestPort);
  EXPECT_EQ(
      MyCryptoLibrary::SecureRemotePassword::getSrpParametersFilenameLocation(),
      expectedSrpParametersFilename);
  EXPECT_EQ(server.getDefaultGroupId(), expectedDefaultGroupId);
}

/**
 * @test Test the correctness of the construction of the Server class, with an
 * invalid defaultGroupId provided in the constructor.
 * @brief Test the correctness of the construction of the Server class,
 * should match the expected values.
 */
TEST(
    ServerTest,
    Server_WithValidInputParametersWithInvalidGroupIdLowerValueProvided_ShouldMatchReference) {
  const bool debugFlag{false};
  const unsigned int invalidGroupId{0};
  const unsigned int expectedDefaultGroupId{3};
  const unsigned int expectedProductionPort{18080};
  const unsigned int expectedTestPort{18081};
  const std::string expectedSrpParametersFilename{
      "../input/SrpParameters.json"};
  Server server(debugFlag, invalidGroupId);
  EXPECT_EQ(server.getProductionPort(), expectedProductionPort);
  EXPECT_EQ(server.getTestPort(), expectedTestPort);
  EXPECT_EQ(
      MyCryptoLibrary::SecureRemotePassword::getSrpParametersFilenameLocation(),
      expectedSrpParametersFilename);
  EXPECT_EQ(server.getDefaultGroupId(), expectedDefaultGroupId);
}

/**
 * @test Test the correctness of the construction of the Server class, with an
 * invalid defaultGroupId provided in the constructor.
 * @brief Test the correctness of the construction of the Server class,
 * should match the expected values.
 */
TEST(
    ServerTest,
    Server_WithValidInputParametersWithInvalidGroupIdHigherValueProvided_ShouldMatchReference) {
  const bool debugFlag{false};
  const unsigned int invalidGroupId{8};
  const unsigned int expectedDefaultGroupId{3};
  const unsigned int expectedProductionPort{18080};
  const unsigned int expectedTestPort{18081};
  const std::string expectedSrpParametersFilename{
      "../input/SrpParameters.json"};
  Server server(debugFlag, invalidGroupId);
  EXPECT_EQ(server.getProductionPort(), expectedProductionPort);
  EXPECT_EQ(server.getTestPort(), expectedTestPort);
  EXPECT_EQ(
      MyCryptoLibrary::SecureRemotePassword::getSrpParametersFilenameLocation(),
      expectedSrpParametersFilename);
  EXPECT_EQ(server.getDefaultGroupId(), expectedDefaultGroupId);
}
