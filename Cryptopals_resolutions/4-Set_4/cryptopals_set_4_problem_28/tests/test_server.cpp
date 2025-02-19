#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/Server.hpp"

class ServerTest : public ::testing::Test {
protected:
  void SetUp() override {
    _server = std::make_unique<Server>(_debugFlag); // Shared setup
  }

  void TearDown() override {
    // Cleanup (if needed)
  }

  std::unique_ptr<Server> _server;
  const bool _debugFlag{false};
  const std::string _testInput = R"({
    "sender": "Alice",
    "recipient": "Bob",
    "amount": 1000,
    "currency": "USD"
})";
  std::vector<unsigned char> _input, _hash;
};

/**
 * @test Test the correctness of the size of the hash function
 * in the server.
 * @brief Ensures that hash sha1 output has the correct size
 */
TEST_F(ServerTest,
       HashSHA1WithLibray_EnglishSentenceInput_ShouldMatchReferenceSize) {
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _server->hashSHA1WithLibrary(_input, _testInput);
  ASSERT_EQ(_hash.size(), 20);
}

/**
 * @test Test the prepend of the key by the server
 * @brief Ensures that what gets to be hashed by the server is hash(key ||
 * message) and not hash(message)
 */
TEST_F(
    ServerTest,
    HashSHA_EnglishSentenceInput_HashGenerateWithKeyShouldDifferFromTheHashWithoutKeyPrepended) {
  std::vector<unsigned char> hashWithoutKey = {
      0xF5, 0x0A, 0x7E, 0x42, 0x5B, 0xDC, 0x37, 0x77, 0xDA, 0xDE,
      0x70, 0xE7, 0x64, 0x78, 0x1C, 0x51, 0x8C, 0x58, 0x6A, 0xC1};
  std::vector<unsigned char> hashWithKey = {
      0x9C, 0x69, 0xAF, 0x9C, 0x10, 0x51, 0xC9, 0x8C, 0xB0, 0x67,
      0xBD, 0x6D, 0x7D, 0xDC, 0x59, 0x87, 0x63, 0xD5, 0x95, 0xD4};
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _server->hashSHA1(_input, _testInput);
  ASSERT_NE(_hash, hashWithoutKey);
  ASSERT_EQ(_hash, hashWithKey);
}
