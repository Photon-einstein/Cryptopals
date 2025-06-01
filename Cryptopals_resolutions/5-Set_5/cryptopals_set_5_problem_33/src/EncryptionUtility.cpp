#include "./../include/EncryptionUtility.hpp"
#include "./../include/MessageExtractionFacility.hpp"

#include <charconv>
#include <iomanip>
#include <iostream>
#include <openssl/rand.h>
#include <sstream>

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
 * @brief Generates a random initialization vector (IV)
 *
 * This method generates a random initialization vector for cryptographic
 * purposes.
 *
 * @param ivLength The desired length of the IV in bytes.
 *
 * @return A vector containing the IV generated.
 * @throws std::runtime_error if IV generation fails.
 */
std::vector<unsigned char>
EncryptionUtility::generateRandomIV(std::size_t ivLength) {
  std::vector<unsigned char> iv(ivLength);
  if (RAND_bytes(iv.data(), ivLength) != 1) {
    throw std::runtime_error("EncryptionUtility log | generateRandomIV(): "
                             "Failed to generate secure IV");
  }
  return iv;
}
/******************************************************************************/