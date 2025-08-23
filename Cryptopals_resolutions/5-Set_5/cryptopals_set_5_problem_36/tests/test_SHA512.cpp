#include <gtest/gtest.h>

#include "../include/EncryptionUtility.hpp"

/**
 * @test Test the correctness of the method SHA512, with an empty string
 * as input.
 * @brief Test the correctness of the method SHA512, with an empty string
 * as input, should match the reference.
 */
TEST(SHA512Test, sha512_WithEmptyString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c"
      "5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
  EXPECT_EQ(EncryptionUtility::sha512(""), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA512, with a short string
 * as input.
 * @brief Test the correctness of the method SHA512, with a short string
 * as input, should match the reference.
 */
TEST(SHA512Test, sha512_WithShortString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a"
      "274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  EXPECT_EQ(EncryptionUtility::sha512("abc"), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA512, with the string
 * "hello world" as input.
 * @brief Test the correctness of the method SHA512, with the string
 * "hello world" as input, should match the reference.
 */
TEST(SHA512Test, sha512_WithHelloWorld_ShouldMatchReference) {
  const std::string expectedHashValue(
      "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35b"
      "c5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
  EXPECT_EQ(EncryptionUtility::sha512("hello world"), expectedHashValue);
}

// --- Edge cases ---

/**
 * @test Test the correctness of the method SHA512, with a very long
 * string composed of 'a's characters as input.
 * @brief Test the correctness of the method SHA512, with a very long
 * string composed of 'a's characters as input, should match the
 * reference.
 */
TEST(SHA512Test, sha512_WithVeryLongString_ShouldMatchReference) {
  const std::string input(1'000'000, 'a');
  const std::string expectedHashValue(
      "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244"
      "877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
  EXPECT_EQ(EncryptionUtility::sha512(input), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA512, with a null byte
 * inside the input, should not terminate early.
 * @brief Test the correctness of the method SHA512, with a null byte
 * inside the input, should not terminate early.
 * The test should match the reference.
 */
TEST(SHA512Test, sha512_WithStringWithNullByte_ShouldMatchReference) {
  const std::string input =
      std::string("abc\0def", 7); // includes '\0' in middle
  const std::string expectedHashValue(
      "1f3108537ca81c8e53e1dfff2166866fc30b81869de3f9d2bd3a585a95794a29dab168cf"
      "b8464119620a991d9ac800f73c0ba0f32342e50ec2db63c28a7ca809");
  EXPECT_EQ(EncryptionUtility::sha512(input), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA512, with an input with
 * all the possible byte values 0x00-0xff.
 * @brief Test the correctness of the method SHA512, with an input with
 * all the possible byte values 0x00-0xff.
 * The test should match the reference.
 */
TEST(SHA512Test, sha512_WithAllByteValues_ShouldMatchReference) {
  std::string input;
  for (int i = 0; i < 256; i++) { // fixed: only 0x00..0xff, not 512 bytes
    input.push_back(static_cast<char>(i));
  }
  const std::string expectedHashValue(
      "1e7b80bc8edc552c8feeb2780e111477e5bc70465fac1a77b29b35980c3f0ce4a036a6c9"
      "462036824bd56801e62af7e9feba5c22ed8a5af877bf7de117dcac6d");
  EXPECT_EQ(EncryptionUtility::sha512(input), expectedHashValue);
}

/**
 * @test Test the correctness of the method SHA512, with an input with
 * a repeated pattern of 1000 'a' characters.
 * @brief Test the correctness of the method SHA512, with an input with
 * a repeated pattern of 1000 'a' characters.
 * The test should match the reference.
 */
TEST(SHA512Test, sha512_WithRepeatedPattern_ShouldMatchReference) {
  const std::string input(1000, 'a');
  const std::string expectedHashValue(
      "67ba5535a46e3f86dbfbed8cbbaf0125c76ed549ff8b0b9e03e0c88cf90fa634fa7b12b4"
      "7d77b694de488ace8d9a65967dc96df599727d3292a8d9d447709c97");
  EXPECT_EQ(EncryptionUtility::sha512(input), expectedHashValue);
}
