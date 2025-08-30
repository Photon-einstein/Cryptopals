#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../include/Client.hpp"

/**
 * @test Test the correctness of the construction of the Client class.
 * @brief Test the correctness of the construction of the Client class,
 * should match the expected values.
 */
TEST(ClientTest,
     ClientConstructor_WithValidInputParameters_ShouldMatchReference) {
  const std::string expectedClientId{"Bob"};
  const bool debugFlag{false};
  const unsigned int expectedServerProductionPort{18080};
  const unsigned int expectedServerTestPort{18081};
  const std::string expectedSrpParametersFilename{
      "../input/SrpParameters.json"};
  Client client(expectedClientId, debugFlag);
  EXPECT_EQ(client.getClientId(), expectedClientId);
  EXPECT_EQ(client.getProductionPort(), expectedServerProductionPort);
  EXPECT_EQ(client.getTestPort(), expectedServerTestPort);
  EXPECT_EQ(client.getSrpParametersFilenameLocation(),
            expectedSrpParametersFilename);
}

/**
 * @test Test the correctness of the construction of the Client class, with
 * invalid input parameters given.
 * @brief Test the correctness of the construction of the Client class, with
 * invalid input parameters given.
 */
TEST(ClientTest,
     ClientConstructor_WithInvalidInputParameters_ShouldThrowAnError) {
  const std::string expectedClientId{""};
  const bool debugFlag{false};
  try {
    Client client(expectedClientId, debugFlag);
  } catch (const std::runtime_error &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("Client ID is null."));
  }
}

/**
 * @test Test the correctness of {get/set}ProductionPort in the Client class.
 * @brief Test the correctness of {get/set}ProductionPort in the Client class,
 * with valid production port provided at the setProductionPort.
 */
TEST(
    ClientTest,
    SetProductionPort_WithValidInputParametersAtSetProductionPort_ShouldMatchReference) {
  const std::string expectedClientId{"Bob"};
  const bool debugFlag{false};
  const unsigned int expectedServerProductionPort{18085};
  Client client(expectedClientId, debugFlag);
  client.setProductionPort(expectedServerProductionPort);
  EXPECT_EQ(client.getProductionPort(), expectedServerProductionPort);
}

/**
 * @test Test the correctness of {get/set}ProductionPort in the Client class.
 * @brief Test the correctness of {get/set}ProductionPort in the Client class,
 * with invalid production port provided at the setProductionPort.
 */
TEST(
    ClientTest,
    SetProductionPort_WithInvalidInputParametersAtSetProductionPort_ShouldThrowAnError) {
  const std::string expectedClientId{"Bob"};
  const bool debugFlag{false};
  const unsigned int expectedServerProductionPort{80};
  try {
    Client client(expectedClientId, debugFlag);
    client.setProductionPort(expectedServerProductionPort);
  } catch (const std::runtime_error &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("invalid production port number given, "
                                    "must be in range [1024, 49151]."));
  }
}

/**
 * @test Test the correctness of {get/set}TestPort in the Client class.
 * @brief Test the correctness of {get/set}TestPort in the Client class, with
 * valid test port provided at the setTestPort.
 */
TEST(ClientTest,
     SetTestPort_WithValidInputParametersAtSetTestPort_ShouldMatchReference) {
  const std::string expectedClientId{"Bob"};
  const bool debugFlag{false};
  const unsigned int expectedServerTestPort{18085};
  Client client(expectedClientId, debugFlag);
  client.setTestPort(expectedServerTestPort);
  EXPECT_EQ(client.getTestPort(), expectedServerTestPort);
}

/**
 * @test Test the correctness of {get/set}TestPort in the Client class.
 * @brief Test the correctness of {get/set}TestPort in the Client class, with
 * invalid test port provided at the setTestPort.
 */
TEST(ClientTest,
     SetTestPort_WithInvalidInputParametersAtSetTestPort_ShouldThrowAnError) {
  const std::string expectedClientId{"Bob"};
  const bool debugFlag{false};
  const unsigned int expectedServerTestPort{80};
  try {
    Client client(expectedClientId, debugFlag);
    client.setTestPort(expectedServerTestPort);
  } catch (const std::runtime_error &e) {
    EXPECT_THAT(
        std::string(e.what()),
        ::testing::EndsWith(
            "invalid port test number given, must be in range [1024, 49151]."));
  }
}
