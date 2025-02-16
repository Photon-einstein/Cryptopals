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
  std::string _testInput;
  std::vector<unsigned char> _input, _hash;
};

/**
 * @test Test the correctness of the size of the hash function
 * in the server.
 * @brief Ensures that hash sha1 output has the correct size
 */
TEST_F(ServerTest,
       HashSHA1WithLibray_EnglishSentenceInput_ShouldMatchReferenceSize) {
  _testInput = "This is a test!";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _server->hashSHA1WithLibrary(_input, _testInput);
  ASSERT_EQ(_hash.size(), 20);
}

/**
 * @test Test the correctness of the size of the hash function
 * made
 * @brief Ensures that hash sha1 output has the correct size
 */
TEST_F(ServerTest, HashSHA_EnglishSentenceInput_ShouldMatchReferenceSize) {
  _testInput = "This is a test!";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _server->hashSHA1WithLibrary(_input, _testInput);
  ASSERT_EQ(_hash.size(), 20);
}

/**
 * @test Test the checkMac behavior
 * @brief Ensures that the effect of the hash(key || message) is
 * not equal to hash(message)
 */
TEST_F(
    ServerTest,
    HashSHA_EnglishSentenceInput_HashGenerateWithKeyShouldDifferFromTheHashWithoutKeyPrepended) {
  _testInput = R"({
        "sender": "Alice",
        "recipient": "Bob",
        "amount": 1000,
        "currency": "USD"
    })";
  std::vector<unsigned char> hashWithoutKey = {
      0x26, 0x1A, 0xC8, 0xED, 0x6F, 0x30, 0x4D, 0x56, 0xF4, 0x29,
      0x1A, 0xAB, 0x2C, 0x87, 0x8D, 0x3F, 0xFF, 0x6B, 0xCB, 0xE4};
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _server->hashSHA1(_input, _testInput);
  ASSERT_NE(_hash, hashWithoutKey);
}
