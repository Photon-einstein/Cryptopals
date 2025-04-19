#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/HMAC.hpp"
#include "../include/HMAC_SHA1.hpp"
#include "../include/MessageExtractionFacility.hpp"

class HMAC_SHA1_Test : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _hmacSha1 = std::make_unique<MyCryptoLibrary::HMAC_SHA1>(); // Shared setup
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
  }

  // cppcheck-suppress unusedStructMember
  std::unique_ptr<MyCryptoLibrary::HMAC> _hmacSha1;
  std::string _testInput;
  std::vector<unsigned char> _input, _hmac;
};

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one with an english
 * input message
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_EnglishSentenceInput_ShouldMatchReference) {
  std::string key{"key"},
      message{"The quick brown fox jumps over the lazy dog"};
  std::vector<unsigned char> keyV(key.begin(), key.end());
  std::vector<unsigned char> messageV(message.begin(), message.end());
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0xde7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one for RFC2202-test-1
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_RFC2202TEST1_ShouldMatchReference) {
  std::string message{"Hi There"};
  std::vector<unsigned char> keyV(SHA1_DIGEST_LENGTH, 0x0b);
  std::vector<unsigned char> messageV(message.begin(), message.end());
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0xb617318655057264e28bc0b6fb378c8ef146be00"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one for RFC2202-test-2
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_RFC2202TEST2_ShouldMatchReference) {
  std::string key{"Jefe"}, message{"what do ya want for nothing?"};
  std::vector<unsigned char> keyV(key.begin(), key.end());
  std::vector<unsigned char> messageV(message.begin(), message.end());
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one for RFC2202-test-3
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_RFC2202TEST3_ShouldMatchReference) {
  const std::size_t messageLengthRFC2202Test3{50};
  std::vector<unsigned char> keyV(SHA1_DIGEST_LENGTH, 0xaa);
  std::vector<unsigned char> messageV(messageLengthRFC2202Test3, 0xdd);
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0x125d7342b9ac11cd91a39af48aa17b4f63f175d3"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one for RFC2202-test-4
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_RFC2202TEST4_ShouldMatchReference) {
  std::string key{"0102030405060708090a0b0c0d0e0f10111213141516171819"};
  std::vector<unsigned char> keyV = MessageExtractionFacility::hexToBytes(key);
  const std::size_t messageLengthRFC2202Test4{50};
  std::vector<unsigned char> messageV(messageLengthRFC2202Test4, 0xcd);
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0x4c9007f4026250c6bc8414f9bf50c86c2d7235da"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one for RFC2202-test-5
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_RFC2202TEST5_ShouldMatchReference) {
  std::vector<unsigned char> keyV(SHA1_DIGEST_LENGTH, 0x0c);
  std::string message{"Test With Truncation"};
  std::vector<unsigned char> messageV(message.begin(), message.end());
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one for RFC2202-test-6
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_RFC2202TEST6_ShouldMatchReference) {
  const std::size_t keyLengthRFC2202Test6{80};
  std::vector<unsigned char> keyV(keyLengthRFC2202Test6, 0xaa);
  std::string message{"Test Using Larger Than Block-Size Key - Hash Key First"};
  std::vector<unsigned char> messageV(message.begin(), message.end());
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0xaa4ae5e15272d00e95705637ce8a3b55ed402112"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}

/**
 * @test Test the correctness of the hash function.
 * @brief Ensures that  hmac-sha1 output is the expected one for RFC2202-test-7
 */
TEST_F(HMAC_SHA1_Test, HMACSHA1_RFC2202TEST7_ShouldMatchReference) {
  const std::size_t keyLengthRFC2202Test6{80};
  std::vector<unsigned char> keyV(keyLengthRFC2202Test6, 0xaa);
  std::string message{"Test Using Larger Than Block-Size Key and Larger Than "
                      "One Block-Size Data"};
  std::vector<unsigned char> messageV(message.begin(), message.end());
  std::vector<unsigned char> hmacSha1 = _hmacSha1->hmac(keyV, messageV);
  ASSERT_EQ(hmacSha1.size(), SHA1_DIGEST_LENGTH);
  std::string expected{"0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91"};
  std::string hmacSha1S = MessageExtractionFacility::toHexString(hmacSha1);
  ASSERT_EQ(hmacSha1S, expected);
}
