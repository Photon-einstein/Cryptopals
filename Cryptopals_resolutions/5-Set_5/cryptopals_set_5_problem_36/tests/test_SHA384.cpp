#include <gtest/gtest.h>

#include "../include/EncryptionUtility.hpp"

/**
 * @test Test the correctness of the method SHA384, with an empty string
 * as input.
 * @brief Test the correctness of the method SHA384, with an empty string
 * as input, should match the reference.
 */
TEST(SHA384Test, sha384_WithEmptyString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
      "274edebfe76f65fbd51ad2f14898b95b");
  EXPECT_EQ(EncryptionUtility::sha384(""), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA384, with a short string
 * as input.
 * @brief Test the correctness of the method SHA384, with a short string
 * as input, should match the reference.
 */
TEST(SHA384Test, sha384_WithShortString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
      "8086072ba1e7cc2358baeca134c825a7");
  EXPECT_EQ(EncryptionUtility::sha384("abc"), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA384, with the string
 * "hello world" as input.
 * @brief Test the correctness of the method SHA384, with the string
 * "hello world" as input, should match the reference.
 */
TEST(SHA384Test, sha384_WithHelloWorld_ShouldMatchReference) {
  const std::string expectedHashValue(
      "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907f"
      "cbb83578b3e417cb71ce646efd0819dd8c088de1bd");
  EXPECT_EQ(EncryptionUtility::sha384("hello world"), expectedHashValue);
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
      "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
      "07b8b3dc38ecc4ebae97ddd87f3d8985");
  EXPECT_EQ(EncryptionUtility::sha384(input), expectedHashValue);
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
      "bc3837e347023944602db615e0e2043d13b85e76bd2b4caaecff8baf20796767"
      "353da289710ce9a68ae124d139318f7a");
  EXPECT_EQ(EncryptionUtility::sha384(input), expectedHashValue);
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
  for (int i = 0; i < 256; i++) { // fixed: only 0x00..0xff, not 384 bytes
    input.push_back(static_cast<char>(i));
  }
  const std::string expectedHashValue(
      "ffdaebff65ed05cf400f0221c4ccfb4b2104fb6a51f87e40be6c4309386bfdec"
      "2892e9179b34632331a59592737db5c5");
  EXPECT_EQ(EncryptionUtility::sha384(input), expectedHashValue);
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
      "f54480689c6b0b11d0303285d9a81b21a93bca6ba5a1b4472765dca4da45ee328"
      "082d469c650cd3b61b16d3266ab8ced");
  EXPECT_EQ(EncryptionUtility::sha384(input), expectedHashValue);
}
