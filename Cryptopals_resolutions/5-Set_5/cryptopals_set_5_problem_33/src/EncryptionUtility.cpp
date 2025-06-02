#include "./../include/EncryptionUtility.hpp"
#include "./../include/MessageExtractionFacility.hpp"

#include <charconv>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
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
std::vector<uint8_t> EncryptionUtility::generateRandomIV(std::size_t ivLength) {
  std::vector<uint8_t> iv(ivLength);
  if (RAND_bytes(iv.data(), ivLength) != 1) {
    throw std::runtime_error("EncryptionUtility log | generateRandomIV(): "
                             "Failed to generate secure IV");
  }
  return iv;
}
/******************************************************************************/
/**
 * @brief Encrypts a plaintext message using AES-256-CBC mode
 *
 * Encrypts a plaintext message using AES-256-CBC mode, using openssl library.
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
std::string
EncryptionUtility::encryptMessageAes256CbcMode(const std::string &plaintext,
                                               const std::vector<uint8_t> &key,
                                               const std::vector<uint8_t> &iv) {

  if (iv.size() != AES_BLOCK_SIZE) {
    throw std::runtime_error(
        "EncryptionUtility log | encryptMessageAes256CbcMode(): "
        "Initialization vector does not has the proper size of " +
        std::to_string(AES_BLOCK_SIZE) + " bytes to proceed.");
  }
  const int keyLength = EVP_CIPHER_key_length(EVP_aes_256_cbc());
  if (key.size() != keyLength) {
    throw std::runtime_error(
        "EncryptionUtility log | encryptMessageAes256CbcMode(): "
        "Key does not have the right size to proceed with encryption "
        "AES-256-CBC mode, it should have " +
        std::to_string(keyLength) + " bytes to proceed.");
  }
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  std::vector<uint8_t> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
  int len = 0, ciphertext_len = 0;

  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
  EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                    reinterpret_cast<const unsigned char *>(plaintext.data()),
                    plaintext.size());
  ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
  ciphertext_len += len;
  ciphertext.resize(ciphertext_len);
  EVP_CIPHER_CTX_free(ctx);
  return MessageExtractionFacility::toHexString(ciphertext);
}
/******************************************************************************/
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
std::string
EncryptionUtility::decryptMessageAes256CbcMode(const std::string &ciphertextHex,
                                               const std::vector<uint8_t> &key,
                                               const std::vector<uint8_t> &iv) {
  if (iv.size() != AES_BLOCK_SIZE) {
    throw std::runtime_error(
        "EncryptionUtility log | decryptMessageAes256CbcMode(): "
        "Initialization vector must be " +
        std::to_string(AES_BLOCK_SIZE) + " bytes.");
  }

  const int keyLength = EVP_CIPHER_key_length(EVP_aes_256_cbc());
  if (key.size() != keyLength) {
    throw std::runtime_error(
        "EncryptionUtility log | decryptMessageAes256CbcMode(): "
        "Key must be " +
        std::to_string(keyLength) + " bytes for AES-256-CBC mode");
  }
  std::vector<uint8_t> ciphertextBytes =
      MessageExtractionFacility::hexToBytes(ciphertextHex);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  std::vector<uint8_t> plaintext(ciphertextBytes.size());
  int len = 0, plaintext_len = 0;
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
  EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertextBytes.data(),
                    ciphertextBytes.size());
  plaintext_len = len;
  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error(
        "EncryptionUtility log | decryptMessageAes256CbcMode(): "
        "Decryption failed. Possibly due to wrong key, IV, or corrupted "
        "ciphertext.");
  }
  plaintext_len += final_len;
  EVP_CIPHER_CTX_free(ctx);
  plaintext.resize(plaintext_len);
  return std::string(plaintext.begin(), plaintext.end());
}
/******************************************************************************/