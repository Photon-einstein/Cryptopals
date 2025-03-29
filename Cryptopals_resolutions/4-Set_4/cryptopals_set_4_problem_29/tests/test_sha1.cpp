#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/SHA.hpp"
#include "../include/SHA1.hpp"

class SHA1Test : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _sha1 = std::make_unique<MyCryptoLibrary::SHA1>(); // Shared setup
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
  }

  // cppcheck-suppress unusedStructMember
  std::unique_ptr<MyCryptoLibrary::SHA1> _sha1;
  std::string _testInput;
  std::vector<unsigned char> _input, _hash;
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
  _testInput = "This is a test!";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _sha1->hash(_input);

  // Example expected output
  std::vector<unsigned char> expected = {
      0x8B, 0x6C, 0xCB, 0x43, 0xDC, 0xA2, 0x04, 0x0C, 0x3C, 0xFB,
      0xCD, 0x7B, 0xFF, 0xF0, 0xB3, 0x87, 0xD4, 0x53, 0x8C, 0x33};
  ASSERT_EQ(_hash.size(), SHA_DIGEST_LENGTH);
  ASSERT_EQ(_hash, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that hash sha1 output is the expected one
 * for an empty input
 */
TEST_F(SHA1Test, Hash_EmptyInput_ShouldMatchReference) {
  _testInput = "";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  _hash = _sha1->hash(_input);

  // Example expected output
  std::vector<unsigned char> expected = {
      0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
      0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09};
  ASSERT_EQ(_hash.size(), SHA_DIGEST_LENGTH);
  ASSERT_EQ(_hash, expected);
}

/**
 * @test Test the correctness of the tunned hash function.
 * @brief Ensures that hash sha1 output is the expected one
 */
TEST_F(SHA1Test,
       Hash_EnglishSentenceInputWithInternalRegisters_ShouldMatchReference) {
  _testInput = "This is a test!";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  uint32_t h0 = 0x67452301;
  uint32_t h1 = 0xEFCDAB89;
  uint32_t h2 = 0x98BADCFE;
  uint32_t h3 = 0x10325476;
  uint32_t h4 = 0xC3D2E1F0;
  _hash = _sha1->hash(_input, h0, h1, h2, h3, h4, _input.size());

  // Example expected output
  std::vector<unsigned char> expected = {
      0x8B, 0x6C, 0xCB, 0x43, 0xDC, 0xA2, 0x04, 0x0C, 0x3C, 0xFB,
      0xCD, 0x7B, 0xFF, 0xF0, 0xB3, 0x87, 0xD4, 0x53, 0x8C, 0x33};
  ASSERT_EQ(_hash.size(), SHA_DIGEST_LENGTH);
  ASSERT_EQ(_hash, expected);
}

/**
 * @test Test the correctness of the tunned hash function.
 * @brief Ensures that hash sha1 output is the expected one
 * for an empty input
 */
TEST_F(SHA1Test, Hash_EmptyInputWithInternalRegisters_ShouldMatchReference) {
  _testInput = "";
  _input.insert(_input.end(), _testInput.begin(), _testInput.end());
  uint32_t h0 = 0x67452301;
  uint32_t h1 = 0xEFCDAB89;
  uint32_t h2 = 0x98BADCFE;
  uint32_t h3 = 0x10325476;
  uint32_t h4 = 0xC3D2E1F0;
  _hash = _sha1->hash(_input, h0, h1, h2, h3, h4, _input.size());

  // Example expected output
  std::vector<unsigned char> expected = {
      0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
      0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09};
  ASSERT_EQ(_hash.size(), SHA_DIGEST_LENGTH);
  ASSERT_EQ(_hash, expected);
}

TEST_F(SHA1Test, MemoryLeakCheck) {
  int *ptr = new int[10]; // Memory allocated
  //delete[] ptr;  // Memory properly freed
  //  No out-of-bounds access here
}

TEST_F(SHA1Test, MemoryLeakAndOutOfBoundsCheck) {
  int *ptr = new int[10]; // Memory allocated

  // Uncommenting this would properly free the memory
  // delete[] ptr;  // Memory properly freed

  // Out-of-bounds access
  ptr[14] = 42; // Accessing memory outside of the allocated range

  // No delete[] ptr call, leading to a memory leak
  //delete[] ptr; 
}