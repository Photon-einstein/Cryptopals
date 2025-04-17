#include <gtest/gtest.h>

#include <vector>

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
 * performing the following test: HMAC-SHA1(key server || msg) == mac
 *
 * Should return true with a matching mac
 */
TEST_F(ServerTest, validateMac_ValidMac_ShouldReturnTrue) {
  std::vector<unsigned char> msg, macBin;
  ASSERT_TRUE(_server->validateMac(msg, macBin));
}
