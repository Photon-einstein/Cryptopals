#include <gtest/gtest.h>

#include <string>
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
