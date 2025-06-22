#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/DiffieHellman.hpp"

class DiffieHellmanKeyExchangeTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _dh = std::make_unique<MyCryptoLibrary::DiffieHellman>(_debugFlag,
                                                           _groupNameDH);
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
  }

  // cppcheck-suppress unusedStructMember
  const bool _debugFlag{false};
  std::unique_ptr<MyCryptoLibrary::DiffieHellman> _dh;
  const std::string _confirmationMessage{"Key exchange complete"};
  const std::string _dhParametersFilename{"../input/DhParameters.json"};
  const std::string _groupNameDH{"rfc3526-group-18"};
};

/**
 * @test Test the correctness of method getConfirmationMessage
 * Ensures that the method getConfirmationMessage of the DH is
 * working correctly.
 */
TEST_F(DiffieHellmanKeyExchangeTest,
       GetConfirmationMessage_ShouldMatchTheReference) {
  const std::string confirmationMsg = _dh->getConfirmationMessage();
  EXPECT_EQ(confirmationMsg, _confirmationMessage);
}

/**
 * @test Test the correctness of method getDhParametersFilenameLocation
 * Ensures that the method getDhParametersFilenameLocation of the DH is
 * working correctly.
 */
TEST_F(DiffieHellmanKeyExchangeTest,
       getDhParametersFilenameLocation_ShouldMatchTheReference) {
  const std::string dhParametersFilename =
      _dh->getDhParametersFilenameLocation();
  EXPECT_EQ(dhParametersFilename, _dhParametersFilename);
}
