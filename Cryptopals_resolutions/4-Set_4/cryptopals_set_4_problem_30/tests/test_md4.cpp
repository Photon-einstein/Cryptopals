#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/MD4.hpp"
#include "../include/MessageDigest.hpp"
#include "../include/MessageExtractionFacility.hpp"

class MD4Test : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _md4 = std::make_unique<MyCryptoLibrary::MD4>(); // Shared setup
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
  }

  // cppcheck-suppress unusedStructMember
  std::unique_ptr<MyCryptoLibrary::MD4> _md4;
  std::string _testInput;
  std::vector<unsigned char> _input, _hash;
};

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash md4 output is the expected one
 * for an empty input
 */
TEST_F(MD4Test, Hash_EmptyInput_ShouldMatchReference) {
  _testInput = "";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _md4->hash(_input);
  std::string hashHex = MessageExtractionFacility::toHexString(_hash);
  // Example expected output
  std::string expected = "31d6cfe0d16ae931b73c59d7e0c089c0";
  ASSERT_EQ(_hash.size(), MD4_DIGEST_LENGTH);
  ASSERT_EQ(hashHex, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash md4 output is the expected one
 * for a single character
 */
TEST_F(MD4Test, Hash_SingleCharacterInput_ShouldMatchReference) {
  _testInput = "a";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _md4->hash(_input);
  std::string hashHex = MessageExtractionFacility::toHexString(_hash);
  // Example expected output
  std::string expected = "bde52cb31de33e46245e05fbdbd6fb24";
  ASSERT_EQ(_hash.size(), MD4_DIGEST_LENGTH);
  ASSERT_EQ(hashHex, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash md4 output is the expected one
 * for a small string
 */
TEST_F(MD4Test, Hash_SmallStringInput_ShouldMatchReference) {
  _testInput = "abc";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _md4->hash(_input);
  std::string hashHex = MessageExtractionFacility::toHexString(_hash);
  // Example expected output
  std::string expected = "a448017aaf21d8525fc10ae87aa6729d";
  ASSERT_EQ(_hash.size(), MD4_DIGEST_LENGTH);
  ASSERT_EQ(hashHex, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash md4 output is the expected one
 * for a small english sentence
 */
TEST_F(MD4Test, Hash_SmallEnglishSentenceInput_ShouldMatchReference) {
  _testInput = "message digest";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _md4->hash(_input);
  std::string hashHex = MessageExtractionFacility::toHexString(_hash);
  // Example expected output
  std::string expected = "d9130a8164549fe818874806e1c7014b";
  ASSERT_EQ(_hash.size(), MD4_DIGEST_LENGTH);
  ASSERT_EQ(hashHex, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash md4 output is the expected one
 * for a random string
 */
TEST_F(MD4Test, Hash_RandomStringInput_ShouldMatchReference) {
  _testInput = "abcdefghijklmnopqrstuvwxyz";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _md4->hash(_input);
  std::string hashHex = MessageExtractionFacility::toHexString(_hash);
  // Example expected output
  std::string expected = "d79e1c308aa5bbcdeea8ed63df412da9";
  ASSERT_EQ(_hash.size(), MD4_DIGEST_LENGTH);
  ASSERT_EQ(hashHex, expected);
}
