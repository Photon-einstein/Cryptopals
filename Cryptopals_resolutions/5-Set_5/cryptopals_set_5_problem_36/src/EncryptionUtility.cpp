#include <charconv>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>

#include "./../include/EncryptionUtility.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/**
 * @brief Generates a cryptographically secure random nonce.
 *
 * @param length The desired length of the nonce in bytes (e.g., 16 for
 * 128-bit).
 *
 * @return A string containing the nonce, in hexadecimal format.
 * @throws std::runtime_error if nonce generation fails.
 */
const std::string
EncryptionUtility::generateCryptographicNonce(const std::size_t length) {
  std::vector<unsigned char> nonce(length);
  // RAND_bytes returns 1 on success, 0 on failure
  if (RAND_bytes(nonce.data(), length) != 1) {
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    throw std::runtime_error(
        "EncryptionUtility log | generateCryptographicNonce(): "
        "Failed to generate cryptographic nonce: " +
        std::string(errorBuffer));
  }
  return MessageExtractionFacility::toHexString(nonce);
}
/******************************************************************************/
/**
 * @brief This method will perform the SHA256 of a given input.
 *
 * This method will perform the SHA256 of a given input.
 *
 * @param input The input as plaintext.
 * @return The SHA256(input) in hexadecimal format.
 **/
std::string EncryptionUtility::sha256(const std::string &input) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    throw std::runtime_error("Failed to create EVP_MD_CTX");
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP digest calculation failed");
  }
  EVP_MD_CTX_free(ctx);
  // Convert to hex string
  std::ostringstream oss;
  for (unsigned int i = 0; i < length; i++) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(hash[i]);
  }
  return oss.str();
}
/******************************************************************************/
/**
 * @brief This method will perform the SHA384 of a given input.
 *
 * This method will perform the SHA384 of a given input.
 *
 * @param input The input as plaintext.
 * @return The SHA384(input) in hexadecimal format.
 **/
std::string EncryptionUtility::sha384(const std::string &input) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    throw std::runtime_error("Failed to create EVP_MD_CTX");
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  if (EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP digest calculation failed");
  }
  EVP_MD_CTX_free(ctx);
  // Convert to hex string
  std::ostringstream oss;
  for (unsigned int i = 0; i < length; i++) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(hash[i]);
  }
  return oss.str();
}
/******************************************************************************/
/**
 * @brief This method will perform the SHA512 of a given input.
 *
 * This method will perform the SHA512 of a given input.
 *
 * @param input The input as plaintext.
 * @return The SHA512(input) in hexadecimal format.
 **/
std::string EncryptionUtility::sha512(const std::string &input) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    throw std::runtime_error("Failed to create EVP_MD_CTX");
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP digest calculation failed");
  }
  EVP_MD_CTX_free(ctx);
  // Convert to hex string
  std::ostringstream oss;
  for (unsigned int i = 0; i < length; i++) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(hash[i]);
  }
  return oss.str();
}
/******************************************************************************/