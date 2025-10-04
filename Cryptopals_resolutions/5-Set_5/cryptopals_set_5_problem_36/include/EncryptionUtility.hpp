#ifndef ENCRYPTION_UTILITY_HPP
#define ENCRYPTION_UTILITY_HPP

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <functional>
#include <map>
#include <memory>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <string>
#include <vector>

#include "./../include/MessageExtractionFacility.hpp"

namespace EncryptionUtility {

/**
 * @brief BN Custom deleter
 */
struct BnDeleter {
  void operator()(BIGNUM *bn) const noexcept { BN_free(bn); }
};

/**
 * @brief BNCtx Custom deleter
 */
struct BnCtxDeleter {
  void operator()(BN_CTX *ctx) const noexcept { BN_CTX_free(ctx); }
};

/**
 * @brief OpenSSLString deleter
 */
struct OpenSSLStringDeleter {
  void operator()(char *str) const noexcept { OPENSSL_free(str); }
};

// Type aliases for smart pointers
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;
using OsslStr = std::unique_ptr<char, OpenSSLStringDeleter>;

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
 * @brief This method will perform the SHA1 of a given input for testing
 * purposes.
 *
 * This method will perform the SHA1 of a given input.
 *
 * @param input The input as plaintext.
 * @return The SHA1(input) in hexadecimal format.
 **/
std::string sha1(const std::string &input);

/**
 * @brief This method will perform the SHA256 of a given input.
 *
 * This method will perform the SHA256 of a given input.
 *
 * @param input The input as plaintext.
 * @return The SHA256(input) in hexadecimal format.
 **/
std::string sha256(const std::string &input);

/**
 * @brief This method will perform the SHA384 of a given input.
 *
 * This method will perform the SHA384 of a given input.
 *
 * @param input The input as plaintext.
 * @return The SHA384(input) in hexadecimal format.
 **/
std::string sha384(const std::string &input);

/**
 * @brief This method will perform the SHA512 of a given input.
 *
 * This method will perform the SHA512 of a given input.
 *
 * @param input The input as plaintext.
 * @return The SHA512(input) in hexadecimal format.
 **/
std::string sha512(const std::string &input);

using HashFn = std::function<std::string(const std::string &)>;

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
const std::unordered_map<std::string, HashFn> &getHashMap();

/**
 * @brief Get a map containing the minimum required salt size for various
 * cryptographic hash functions, in bytes.
 *
 * @return std::map<std::string, unsigned int> A map of hash names with the
 * minimum salt sizes, in bytes.
 */
const std::map<std::string, unsigned int> getMinSaltSizes();

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
const std::string generatePassword(std::size_t passwordLength = 16);

/**
 * @brief Helper: Pad a byte vector to a given size.
 *
 * Pads the input vector with leading zeros so that its size matches the
 * specified size. If the input is already at least as large as the requested
 * size, it is returned unchanged.
 *
 * @param input The input vector of bytes.
 * @param size The desired total size after padding.
 * @return The padded vector of bytes.
 */
std::vector<uint8_t> padLeft(const std::vector<uint8_t> &input, size_t size);

}; // namespace EncryptionUtility

#endif // ENCRYPTION_UTILITY_HPP
