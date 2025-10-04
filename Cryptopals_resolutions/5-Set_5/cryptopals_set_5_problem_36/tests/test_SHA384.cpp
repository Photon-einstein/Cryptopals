#include <gtest/gtest.h>

#include <openssl/sha.h>

#include "../include/EncryptionUtility.hpp"

/**
 * @test Test the correctness of the method SHA384, with an empty string
 * as input.
 * @brief Test the correctness of the method SHA384, with an empty string
 * as input, should match the reference.
 */
TEST(SHA384Test, sha384_WithEmptyString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA"
      "274EDEBFE76F65FBD51AD2F14898B95B");
  const std::string hash{EncryptionUtility::sha384("")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA384_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA384, with a short string
 * as input.
 * @brief Test the correctness of the method SHA384, with a short string
 * as input, should match the reference.
 */
TEST(SHA384Test, sha384_WithShortString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED"
      "8086072BA1E7CC2358BAECA134C825A7");
  const std::string hash{EncryptionUtility::sha384("abc")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA384_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA384, with the string
 * "hello world" as input.
 * @brief Test the correctness of the method SHA384, with the string
 * "hello world" as input, should match the reference.
 */
TEST(SHA384Test, sha384_WithHelloWorld_ShouldMatchReference) {
  const std::string expectedHashValue(
      "FDBD8E75A67F29F701A4E040385E2E23986303EA10239211AF907F"
      "CBB83578B3E417CB71CE646EFD0819DD8C088DE1BD");
  const std::string hash{EncryptionUtility::sha384("hello world")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA384_DIGEST_LENGTH * 2);
}

// --- Edge cases ---

/**
 * @test Test the correctness of the method SHA384, with a very long
 * string composed of 'a's characters as input.
 * @brief Test the correctness of the method SHA384, with a very long
 * string composed of 'a's characters as input, should match the
 * reference.
 */
TEST(SHA384Test, sha384_WithVeryLongString_ShouldMatchReference) {
  const std::string input(1'000'000, 'a');
  const std::string expectedHashValue(
      "9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B"
      "07B8B3DC38ECC4EBAE97DDD87F3D8985");
  const std::string hash{EncryptionUtility::sha384(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA384_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA384, with a null byte
 * inside the input, should not terminate early.
 * @brief Test the correctness of the method SHA384, with a null byte
 * inside the input, should not terminate early.
 * The test should match the reference.
 */
TEST(SHA384Test, sha384_WithStringWithNullByte_ShouldMatchReference) {
  const std::string input =
      std::string("abc\0def", 7); // includes '\0' in middle
  const std::string expectedHashValue(
      "BC3837E347023944602DB615E0E2043D13B85E76BD2B4CAAECFF8BAF20796767"
      "353DA289710CE9A68AE124D139318F7A");
  const std::string hash{EncryptionUtility::sha384(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA384_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA384, with an input with
 * all the possible byte values 0x00-0xff.
 * @brief Test the correctness of the method SHA384, with an input with
 * all the possible byte values 0x00-0xff.
 * The test should match the reference.
 */
TEST(SHA384Test, sha384_WithAllByteValues_ShouldMatchReference) {
  std::string input;
  for (int i = 0; i < 256; ++i) { // fixed: only 0x00..0xff, not 384 bytes
    input.push_back(static_cast<char>(i));
  }
  const std::string expectedHashValue(
      "FFDAEBFF65ED05CF400F0221C4CCFB4B2104FB6A51F87E40BE6C4309386BFDEC"
      "2892E9179B34632331A59592737DB5C5");
  const std::string hash{EncryptionUtility::sha384(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA384_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA384, with an input with
 * a repeated pattern of 1000 'a' characters.
 * @brief Test the correctness of the method SHA384, with an input with
 * a repeated pattern of 1000 'a' characters.
 * The test should match the reference.
 */
TEST(SHA384Test, sha384_WithRepeatedPattern_ShouldMatchReference) {
  const std::string input(1000, 'a');
  const std::string expectedHashValue(
      "F54480689C6B0B11D0303285D9A81B21A93BCA6BA5A1B4472765DCA4DA45EE328"
      "082D469C650CD3B61B16D3266AB8CED");
  const std::string hash{EncryptionUtility::sha384(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA384_DIGEST_LENGTH * 2);
}
