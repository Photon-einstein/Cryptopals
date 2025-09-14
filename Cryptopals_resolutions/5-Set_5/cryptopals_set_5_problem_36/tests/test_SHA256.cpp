#include <gtest/gtest.h>

#include <openssl/sha.h>

#include "../include/EncryptionUtility.hpp"

/**
 * @test Test the correctness of the method SHA256, with an empty string
 * as input.
 * @brief Test the correctness of the method SHA256, with an empty string
 * as input, should match the reference.
 */
TEST(SHA256Test, sha256_WithEmptyString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
  const std::string hash{EncryptionUtility::sha256("")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA256_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA256, with a short string
 * as input.
 * @brief Test the correctness of the method SHA256, with a short string
 * as input, should match the reference.
 */
TEST(SHA256Test, sha256_WithShortString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
  const std::string hash{EncryptionUtility::sha256("abc")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA256_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA256, with the string
 * "hello world" as input.
 * @brief Test the correctness of the method SHA256, with the string
 * "hello world" as input, should match the reference.
 */
TEST(SHA256Test, sha256_WithHelloWorld_ShouldMatchReference) {
  const std::string expectedHashValue(
      "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9");
  const std::string hash{EncryptionUtility::sha256("hello world")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA256_DIGEST_LENGTH * 2);
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
      "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0");
  const std::string hash{EncryptionUtility::sha256(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA256_DIGEST_LENGTH * 2);
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
      "516A5E926CE20C5F4D80F00E1A01ABDF14986DEF6588D6ABEED9FCE090BC660C");
  const std::string hash{EncryptionUtility::sha256(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA256_DIGEST_LENGTH * 2);
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
      "40AFF2E9D2D8922E47AFD4648E6967497158785FBD1DA870E7110266BF944880");
  const std::string hash{EncryptionUtility::sha256(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA256_DIGEST_LENGTH * 2);
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
      "41EDECE42D63E8D9BF515A9BA6932E1C20CBC9F5A5D134645ADB5DB1B9737EA3");
  const std::string hash{EncryptionUtility::sha256(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA256_DIGEST_LENGTH * 2);
}
