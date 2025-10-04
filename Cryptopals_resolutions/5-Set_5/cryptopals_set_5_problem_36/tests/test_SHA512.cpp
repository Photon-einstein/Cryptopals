#include <gtest/gtest.h>

#include <openssl/sha.h>

#include "../include/EncryptionUtility.hpp"

/**
 * @test Test the correctness of the method SHA512, with an empty string
 * as input.
 * @brief Test the correctness of the method SHA512, with an empty string
 * as input, should match the reference.
 */
TEST(SHA512Test, sha512_WithEmptyString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C"
      "5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E");
  const std::string hash{EncryptionUtility::sha512("")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA512_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA512, with a short string
 * as input.
 * @brief Test the correctness of the method SHA512, with a short string
 * as input, should match the reference.
 */
TEST(SHA512Test, sha512_WithShortString_ShouldMatchReference) {
  const std::string expectedHashValue(
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A"
      "274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");
  const std::string hash{EncryptionUtility::sha512("abc")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA512_DIGEST_LENGTH * 2);
}

/**
 * @test Test the correctness of the method SHA512, with the string
 * "hello world" as input.
 * @brief Test the correctness of the method SHA512, with the string
 * "hello world" as input, should match the reference.
 */
TEST(SHA512Test, sha512_WithHelloWorld_ShouldMatchReference) {
  const std::string expectedHashValue(
      "309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F989DD35B"
      "C5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F");
  const std::string hash{EncryptionUtility::sha512("hello world")};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA512_DIGEST_LENGTH * 2);
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
      "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF244"
      "877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B");
  const std::string hash{EncryptionUtility::sha512(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA512_DIGEST_LENGTH * 2);
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
      "1F3108537CA81C8E53E1DFFF2166866FC30B81869DE3F9D2BD3A585A95794A29DAB168CF"
      "B8464119620A991D9AC800F73C0BA0F32342E50EC2DB63C28A7CA809");
  const std::string hash{EncryptionUtility::sha512(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA512_DIGEST_LENGTH * 2);
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
  for (int i = 0; i < 256; ++i) { // fixed: only 0x00..0xff, not 512 bytes
    input.push_back(static_cast<char>(i));
  }
  const std::string expectedHashValue(
      "1E7B80BC8EDC552C8FEEB2780E111477E5BC70465FAC1A77B29B35980C3F0CE4A036A6C9"
      "462036824BD56801E62AF7E9FEBA5C22ED8A5AF877BF7DE117DCAC6D");
  const std::string hash{EncryptionUtility::sha512(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA512_DIGEST_LENGTH * 2);
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
      "67BA5535A46E3F86DBFBED8CBBAF0125C76ED549FF8B0B9E03E0C88CF90FA634FA7B12B4"
      "7D77B694DE488ACE8D9A65967DC96DF599727D3292A8D9D447709C97");
  const std::string hash{EncryptionUtility::sha512(input)};
  EXPECT_EQ(hash, expectedHashValue);
  EXPECT_EQ(hash.length(), SHA512_DIGEST_LENGTH * 2);
}
