#include <gtest/gtest.h>

#include <openssl/sha.h>

#include "../include/EncryptionUtility.hpp"

/**
 * @test Test the correctness of the method SHA1, with an empty string
 * as input.
 * @brief Test the correctness of the method SHA1, with an empty string
 * as input, should match the reference.
 */
TEST(SHA1Test, sha1_WithEmptyString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
  const std::string hash{EncryptionUtility::sha1("")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA1, with a short string
 * as input.
 * @brief Test the correctness of the method SHA1, with a short string
 * as input, should match the reference.
 */
TEST(SHA1Test, sha1_WithShortString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "A9993E364706816ABA3E25717850C26C9CD0D89D");
  const std::string hash{EncryptionUtility::sha1("abc")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA1, with the string
 * "hello world" as input.
 * @brief Test the correctness of the method SHA1, with the string
 * "hello world" as input, should match the reference.
 */
TEST(SHA1Test, sha1_WithHelloWorld_ShouldMatchReference) {
  const std::string expectedHashValue(
      "2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED");
  const std::string hash{EncryptionUtility::sha1("hello world")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA_DIGEST_LENGTH * 2);
}

// --- Edge cases ---

/**
 * @test Test the correctness of the method SHA1, with a very long
 * string composed of 'a's characters as input.
 * @brief Test the correctness of the method SHA1, with a very long
 * string composed of 'a's characters as input, should match the
 * reference.
 */
TEST(SHA1Test, sha1_WithVeryLongString_ShouldMatchReference) {
  const std::string input(1'000'000, 'a');
  const std::string expectedHashValue(
      "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");
  const std::string hash{EncryptionUtility::sha1(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA1, with a null byte
 * inside the input, should not terminate early.
 * @brief Test the correctness of the method SHA1, with a null byte
 * inside the input, should not terminate early.
 * The test should match the reference.
 */
TEST(SHA1Test, sha1_WithStringWithNullByte_ShouldMatchReference) {
  const std::string input =
      std::string("abc\0def", 7); // includes '\0' in middle
  const std::string expectedHashValue(
      "487B1975D97215516D7267DFF3557C0676956056");
  const std::string hash{EncryptionUtility::sha1(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA1, with an input with
 * all the possible byte values 0x00-0xff.
 * @brief Test the correctness of the method SHA1, with an input with
 * all the possible byte values 0x00-0xff.
 * The test should match the reference.
 */
TEST(SHA1Test, sha1_WithAllByteValues_ShouldMatchReference) {
  std::string input;
  for (int i = 0; i < 256; ++i) {
    input.push_back(static_cast<char>(i));
  }
  const std::string expectedHashValue(
      "4916D6BDB7F78E6803698CAB32D1586EA457DFC8");
  const std::string hash{EncryptionUtility::sha1(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA1, with an input with
 * a repeated pattern of 1000 'a' characters.
 * @brief Test the correctness of the method SHA1, with an input with
 * a repeated pattern of 1000 'a' characters.
 * The test should match the reference.
 */
TEST(SHA1Test, sha1_WithRepeatedPattern_ShouldMatchReference) {
  const std::string input(1000, 'a');
  const std::string expectedHashValue(
      "7F9000257A4F0B9C44A3DF0C7C7A9A96FDFD5B3C");
  const std::string hash{EncryptionUtility::sha1(input)};
  EXPECT_EQ(
      hash,
      "291E9A6C66994949B57BA5E650361E98FC36B1BA"); // Actual SHA1 of 1000 'a's
  EXPECT_EQ(hash.length(), SHA_DIGEST_LENGTH * 2);
}