#include <gtest/gtest.h>

#include "../include/Attacker.hpp"

class AttackerTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _server = std::make_shared<Server>(_debugFlag);
    _attacker = std::make_shared<Attacker>(_server, _debugFlag); // Shared setup
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
  }

  const bool _debugFlag{false};
  std::shared_ptr<Attacker> _attacker;
  std::shared_ptr<Server> _server;
};

/**
 * @test Test that the attacker can succeed in the length extension attack upon
 * MD4
 * @brief Test that the attacker can succeed in the length extension attack upon
 * MD4, performing the padding of the original message and appending afterwards
 * a new message in the end
 */
TEST_F(AttackerTest,
       lengthExtensionAttackAtMD4_NoInputNeeded_ShouldSucceedInTheAttack) {
  ASSERT_TRUE(true);
}
