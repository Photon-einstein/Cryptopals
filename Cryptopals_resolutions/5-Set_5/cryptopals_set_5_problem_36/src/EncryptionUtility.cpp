#include <charconv>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <random>
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
/**
 * @brief Provides a lookup table mapping string names to hash functions.
 *
 * Keys are case-sensitive algorithm names (e.g., "SHA-256", "SHA-384",
 * "SHA-512").
 *
 * Each function has the signature:
 *     std::string(const std::string& input)
 * where the input is in plaintext.
 * where the output is the hexadecimal digest.
 *
 * Usage:
 *     auto& hashMap = HashUtils::getHashMap();
 *     auto digest = hashMap.at("SHA-256")("secret");
 *
 * Notes:
 * - Throws std::out_of_range if an unsupported algorithm is requested.
 * - Extend this map when adding new hash functions.
 * - Clients should not modify the returned map.
 *
 * @return A hash map mapping the string name of the hash to the
 * method implementation.
 */
const std::unordered_map<std::string, EncryptionUtility::HashFn> &
EncryptionUtility::getHashMap() {
  static const std::unordered_map<std::string, HashFn> table = {
      {"SHA-256", EncryptionUtility::sha256},
      {"SHA-384", EncryptionUtility::sha384},
      {"SHA-512", EncryptionUtility::sha512}};
  return table;
}
/******************************************************************************/
/**
 * @brief Get a map containing the minimum required salt size for various
 * cryptographic hash functions, in bytes.
 *
 * @return std::map<std::string, unsigned int> A map of hash names with the
 * minimum salt sizes, in bytes.
 */
const std::map<std::string, unsigned int> EncryptionUtility::getMinSaltSizes() {
  return {// SHA-1 (160 bits / 8 bits per byte = 20 bytes)
          {"SHA-1", 20},

          // SHA-256 (256 bits / 8 bits per byte = 32 bytes)
          {"SHA-256", 32},

          // SHA-512 (512 bits / 8 bits per byte = 64 bytes)
          {"SHA-512", 64},

          // SHA-224 (224 bits / 8 bits per byte = 28 bytes)
          {"SHA-224", 28},

          // SHA-384 (384 bits / 8 bits per byte = 48 bytes)
          {"SHA-384", 48},

          // Truncated SHA-512 variants
          {"SHA-512/224", 28},
          {"SHA-512/256", 32}};
}
/******************************************************************************/
/**
 * @brief This method generates a given password with a given length.
 *
 * This method generates a given password with a given length, the minimum
 * acceptable size of the password is 16 bytes.
 *
 * @param passwordLength The asked length of the password in bytes.
 *
 * @return The password in a string format.
 */
const std::string
EncryptionUtility::generatePassword(std::size_t passwordLength) {
  const std::size_t minPasswordSize{16}; // bytes
  if (passwordLength < minPasswordSize) {
    passwordLength = minPasswordSize;
  }
  const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "0123456789"
                            "!@#$%^&*()-_=+[]{}|;:,.<>?";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, chars.size() - 1);
  std::string password;
  for (std::size_t i = 0; i < passwordLength; ++i) {
    password += chars[dis(gen)];
  }
  return password;
}
/******************************************************************************/