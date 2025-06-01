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
std::vector<unsigned char> generateRandomIV(std::size_t ivLength);

}; // namespace EncryptionUtility

#endif // ENCRYPTION_UTILITY_HPP
