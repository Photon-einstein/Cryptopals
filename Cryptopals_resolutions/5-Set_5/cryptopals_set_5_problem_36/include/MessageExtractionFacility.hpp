#ifndef MESSAGE_EXTRACTION_FACILITY_HPP
#define MESSAGE_EXTRACTION_FACILITY_HPP

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <iomanip>
#include <memory>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <sstream>
#include <string>
#include <vector>

namespace MessageExtractionFacility {

struct BIGNUM_deleter {
  void operator()(BIGNUM *bn) const { BN_free(bn); }
};
using UniqueBIGNUM = std::unique_ptr<BIGNUM, BIGNUM_deleter>;

/**
 * @brief This method will convert hexadecimal string to a vector of bytes.
 *
 * This method will convert hexadecimal string to a vector of bytes, using zero
 * alignment.
 *
 * @param hexStr The input to be converted.
 *
 * @return The vector of bytes resulting of the conversion.
 */
std::vector<unsigned char> hexToBytes(const std::string &hexStr);

/**
 * @brief This method converts a vector of bytes into a string in hex format.
 *
 * This method will convert a vector of bytes into a string of hexadecimal
 * characters, padded with zero.
 *
 * @param data The vector with bytes to be converted.
 *
 * @return A string containing the chars with hexadecimal format, zero padded.
 */
std::string toHexString(const std::vector<unsigned char> &data);

/**
 * This method reads the input hex string two characters at a time,
 * converts each pair into a single byte, and builds a plaintext string.
 *
 * @param hexString The input string in hexadecimal format (e.g., "48656C6C6F").
 * @return The resulting plaintext string (e.g., "Hello").
 * @throw std::invalid_argument If the input string has an odd length or
 * contains non-hexadecimal characters.
 */
std::string hexToPlaintext(const std::string &hexString);

/**
 * @brief This method will convert an hexadecimal number to an unique big
 * number.
 *
 * This method will convert an hexadecimal number to an unique big number.
 *
 * @param hexNumber The number in hexadecimal format.
 *
 * @return The number in an UniqueBIGNUM format.
 * @throws std::runtime_error if conversion fails.
 */
UniqueBIGNUM hexToUniqueBIGNUM(const std::string &hexNumber);

/**
 * @brief This method will convert a number in a BIGNUM format to
 * a hexadecimal format.
 *
 * This method will convert a number in a BIGNUM format to
 * a hexadecimal format, performing all the calculations necessary.
 *
 * @param bn The number in a BIGNUM format.
 *
 * @return The number converted to a hexadecimal format.
 * @throws std::runtime_error if conversion fails.
 */
std::string BIGNUMToHex(BIGNUM *bn);

/**
 * @brief This method will convert a number in a BIGNUM format to
 * a decimal format.
 *
 * This method will convert a number in a BIGNUM format to
 * a decimal format, performing all the calculations necessary.
 *
 * @param bn The number in a BIGNUM format.
 *
 * @return The number converted to a decimal format.
 * @throws std::runtime_error if conversion fails.
 */
std::string BIGNUMToDec(BIGNUM *bn);

/**
 * @brief Converts an unsigned int to a zero-padded hexadecimal string.
 *
 * @param value The unsigned integer to convert.
 * @param width The minimum width of the resulting hex string (default: 2).
 * @return The hexadecimal string representation, zero-padded to 'width'.
 */
std::string uintToHex(unsigned int value, size_t width = 2);

}; // namespace MessageExtractionFacility

#endif // MESSAGE_EXTRACTION_FACILITY_HPP
