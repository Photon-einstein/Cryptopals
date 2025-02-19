#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/Attacker.hpp"

class AttackerTest : public ::testing::Test {
protected:
  void SetUp() {
    _server = std::make_shared<Server>(_debugFlag);
    _attacker =
        std::make_shared<Attacker>(_server, _writeToFile); // Shared setup
  }

  void TearDown() {}

  const bool _debugFlag{false};
  const bool _writeToFile{false};
  std::shared_ptr<Attacker> _attacker;
  std::shared_ptr<Server> _server;
  std::string _testInput;
  std::vector<unsigned char> _input, _hash;
};

/**
 * @test Test that the attacker cannot tamper the message with a new hash
 * @brief Ensures that the test at the server checkMac detects an error, namely
 * the the attackers SHA1(message_tampered) not equal SHA1(key ||
 * message_tampered)
 */
TEST_F(
    AttackerTest,
    TamperMessageTry_TamperedMessageAndNewHashAsInput_ShouldReturnFalseFromCheckMacInTheServer) {
  const std::string messageLocation{"./../input/transaction_Alice_to_Bob.json"};
  const bool checkMacResponse = _attacker->tamperMessageTry(messageLocation);
  ASSERT_FALSE(checkMacResponse);
}
