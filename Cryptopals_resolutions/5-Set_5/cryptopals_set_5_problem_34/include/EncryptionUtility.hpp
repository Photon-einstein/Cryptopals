#ifndef ENCRYPTION_UTILITY_HPP
#define ENCRYPTION_UTILITY_HPP

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <memory>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <string>
#include <vector>

namespace EncryptionUtility {

/**
 * @brief Generates a cryptographically secure random nonce.
 *
 * @param length The desired length of the nonce in bytes (e.g., 16 for
 * 128-bit).
 *
 * @return A string containing the nonce, in hexadecimal format.
 * @throws std::runtime_error if nonce generation fails.
 */
const std::string generateCryptographicNonce(const std::size_t length);

/**
 * @brief Generates a random initialization vector (IV).
 *
 * This method generates a random initialization vector for cryptographic
 * purposes.
 *
 * @param ivLength The desired length of the IV in bytes.
 *
 * @return A vector containing the IV generated.
 * @throws std::runtime_error if the IV generation fails.
 */
std::vector<uint8_t> generateRandomIV(std::size_t ivLength);

/**
 * @brief Encrypts a plaintext message using AES-256-CBC mode
 *
 * Encrypts a plaintext message using AES-256-CBC mode, using the openssl library.
 *
 * @param plaintext The text to be encrypted.
 * @param key The key to be used in the encryption process (32 bytes for
 * AES-256).
 * @param iv The initialization vector to be used in the encryption process
 * (16 bytes).
 *
 * @return The ciphertext, in a hexadecimal string format.
 * @throws std::runtime_error if IV or key size does not meet the requirements.
 */
std::string encryptMessageAes256CbcMode(const std::string &plaintext,
                                        const std::vector<uint8_t> &key,
                                        const std::vector<uint8_t> &iv);

/**
 * @brief Decrypts a ciphertext message using AES-256-CBC mode.
 *
 * Decrypts a ciphertext message using AES-256-CBC mode using the OpenSSL
 * library.
 *
 * @param ciphertextHex The ciphertext in hexadecimal string format.
 * @param key The key used in the encryption process (32 bytes for AES-256).
 * @param iv The initialization vector used in the encryption process (16
 * bytes).
 *
 * @return The decrypted plaintext as a standard string.
 * @throws std::runtime_error if IV or key size is invalid or decryption fails.
 */
std::string decryptMessageAes256CbcMode(const std::string &ciphertextHex,
                                        const std::vector<uint8_t> &key,
                                        const std::vector<uint8_t> &iv);

/**
 * @brief Returns a formatted timestamp with the current time.
 *
 * Returns a formatted timestamp with the current time, in the format
 * "Year-month-day hour:minute:second TimeZone"
 *
 * @return The formatted time zone with the current time.
 */
std::string getFormattedTimestamp();

}; // namespace EncryptionUtility

#endif // ENCRYPTION_UTILITY_HPP
