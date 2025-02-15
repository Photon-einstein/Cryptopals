#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/SHA.hpp"
#include "../include/SHA1.hpp"

class SHA1Test : public ::testing::Test {
protected:
  void SetUp() override {
    sha1 = std::make_unique<MyCryptoLibrary::SHA1>(); // Shared setup
  }

  void TearDown() override {
    // Cleanup (if needed)
  }

  std::unique_ptr<MyCryptoLibrary::SHA1> sha1;
  std::string test_input;
  std::vector<unsigned char> input, expectedHash, hash;
};

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash sha1 output is the expected one
 */
TEST_F(SHA1Test, Hash_EnglishSentenceInput_ShouldMatchReference) {
  test_input = "This is a test!";
  input.insert(input.end(), test_input.begin(), test_input.end());
  auto hash = sha1->hash(input);

  // Example expected output (change as needed)
  std::vector<unsigned char> expected = {
      0x8B, 0x6C, 0xCB, 0x43, 0xDC, 0xA2, 0x04, 0x0C, 0x3C, 0xFB,
      0xCD, 0x7B, 0xFF, 0xF0, 0xB3, 0x87, 0xD4, 0x53, 0x8C, 0x33};
  ASSERT_EQ(hash.size(), 20);
  ASSERT_EQ(hash, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash sha1 output is the expected one
 * for an empty input
 */
TEST_F(SHA1Test, Hash_EmptyInput_ShouldMatchReference) {
  test_input = "";
  input.insert(input.end(), test_input.begin(), test_input.end());
  auto hash = sha1->hash(input);

  // Example expected output (change as needed)
  std::vector<unsigned char> expected = {
      0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
      0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09};
  ASSERT_EQ(hash.size(), 20);
  ASSERT_EQ(hash, expected);
}

/**
 * @test Test that the hash has the correct size
 * @brief Ensures that hash sha1 output has the correct size output
 */
TEST_F(SHA1Test,
       GetHashOutputSize__NormalClassInitialization_ShouldMatchTheCorrectSize) {
  ASSERT_EQ(sha1->getHashOutputSize(), 20);
}
