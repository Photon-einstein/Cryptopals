#include <gtest/gtest.h>

#include "../include/EncryptionUtility.hpp"

/**
 * @test Test the correctness of the method SHA256, with an empty string
 * as input.
 * @brief Test the correctness of the method SHA256, with an empty string
 * as input, should match the reference.
 */
TEST(SHA256Test, sha256_WithEmptyString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(EncryptionUtility::sha256(""), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA256, with a short string
 * as input.
 * @brief Test the correctness of the method SHA256, with a short string
 * as input, should match the reference.
 */
TEST(SHA256Test, sha256_WithShortString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(EncryptionUtility::sha256("abc"), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA256, with the string
 * "hello world" as input.
 * @brief Test the correctness of the method SHA256, with the string
 * "hello world" as input, should match the reference.
 */
TEST(SHA256Test, sha256_WithHelloWorld_ShouldMatchReference) {
  const std::string expectedHashValue(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
  EXPECT_EQ(EncryptionUtility::sha256("hello world"), expectedHashValue);
}

// --- Edge cases ---

/**
 * @test Test the correctness of the method SHA256, with a very long
 * string composed of 'a's characters as input.
 * @brief Test the correctness of the method SHA256, with a very long
 * string composed of 'a's characters as input, should match the
 * reference.
 */
TEST(SHA256Test, sha256_WithVeryLongString_ShouldMatchReference) {
  const std::string input(1'000'000, 'a');
  const std::string expectedHashValue(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  EXPECT_EQ(EncryptionUtility::sha256(input), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA256, with a null byte
 * inside the input, should not terminate early.
 * @brief Test the correctness of the method SHA256, with a null byte
 * inside the input, should not terminate early.
 * The test should match the reference.
 */
TEST(SHA256Test, sha256_WithStringWithNullByte_ShouldMatchReference) {
  const std::string input =
      std::string("abc\0def", 7); // includes '\0' in middle
  const std::string expectedHashValue(
      "516a5e926ce20c5f4d80f00e1a01abdf14986def6588d6abeed9fce090bc660c");
  EXPECT_EQ(EncryptionUtility::sha256(input), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA256, with an input with
 * all the possible byte values 0x00-0xff.
 * @brief Test the correctness of the method SHA256, with an input with
 * all the possible byte values 0x00-0xff.
 * The test should match the reference.
 */
TEST(SHA256Test, sha256_WithAllByteValues_ShouldMatchReference) {
  std::string input;
  for (int i = 0; i < 256; i++) {
    input.push_back(static_cast<char>(i));
  }
  const std::string expectedHashValue(
      "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");
  EXPECT_EQ(EncryptionUtility::sha256(input), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA256, with an input with
 * a repeated pattern of 1000 'a' characters.
 * @brief Test the correctness of the method SHA256, with an input with
 * a repeated pattern of 1000 'a' characters.
 * The test should match the reference.
 */
TEST(SHA256Test, sha256_WithRepeatedPattern_ShouldMatchReference) {
  const std::string input(1000, 'a');
  const std::string expectedHashValue(
      "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
  EXPECT_EQ(EncryptionUtility::sha256(input), expectedHashValue);
}
