#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/MessageExtractionFacility.hpp"
#include "../include/Server.hpp"

class ServerTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _server = std::make_unique<Server>(_debugFlag); // Shared setup
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
  }

  std::unique_ptr<Server> _server;
  const bool _debugFlag{false};
};

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

/**
 * @test Test that the server can validate a given message with a mac
 * @brief Test that the server can validate a given message with a mac,
 * performing the following test: MD4(key server || msg) == mac
 *
 * Should return true with a matching mac
 */
TEST_F(ServerTest, validateMac_ValidMac_ShouldReturnTrue) {
  std::string msgS{"user=bob&amount=1000&timestamp=1700000000"};
  std::vector<unsigned char> msg(msgS.begin(), msgS.end());
  std::string macHexS{"b7a6cb467f0c59ffe61001651dc7ab59"};
  std::vector<unsigned char> macBin;
  macBin = MessageExtractionFacility::hexToBytes(macHexS);
  ASSERT_TRUE(_server->validateMac(msg, macBin));
}

/**
 * @test Test that the server can invalidate a given message if the mac
 * is not valid
 * @brief Test that the server can invalidate a given message with the
 * mac is not valid performing the following test:
 * MD4(key server || msg) == mac
 *
 * Should return false with a not matching mac
 */
TEST_F(ServerTest, validateMac_InvalidMacContent_ShouldReturnFalse) {
  std::string msgS{"user=bob&amount=1000&timestamp=1700000000"};
  std::vector<unsigned char> msg(msgS.begin(), msgS.end());
  std::string macHexS{"b7a6cb467f0c59ffe61001651dc7ab59"};
  std::vector<unsigned char> macBin;
  macBin = MessageExtractionFacility::hexToBytes(macHexS);
  macBin[0] ^= 0x01; // flip least significant bit
  ASSERT_FALSE(_server->validateMac(msg, macBin));
}

/**
 * @test Test that the server can invalidate a given mac if the length
 * is incorrect
 * @brief Test that the server can invalidate a given mac if the length
 * of the mac is incorrect: MD4(key server || msg) == mac
 *
 * Should throw an invalid argument exception
 */
TEST_F(ServerTest, validateMac_InvalidMacSize_ShouldThrowAnException) {
  std::string msgS{"user=bob&amount=1000&timestamp=1700000000"};
  std::vector<unsigned char> msg(msgS.begin(), msgS.end());
  std::string macHexS{"b7a6cb467f0c59ffe61001651dc7ab59"};
  std::vector<unsigned char> macBin;
  macBin = MessageExtractionFacility::hexToBytes(macHexS);
  macBin.pop_back(); // change size of a given mac
  try {
    _server->validateMac(msg, macBin);
  } catch (const std::invalid_argument &e) {
    const std::string errorMessage = "Server log | mac received in the method "
                                     "Server::validateMac does not match the " +
                                     std::to_string(MD4_DIGEST_LENGTH) +
                                     std::string(" length in bytes.");
    EXPECT_STREQ(e.what(), errorMessage.c_str());
  } catch (...) {
    FAIL() << "Expected std::invalid_argument, but got a different exception";
  }
}
